"""Two-stage, fail-closed orchestration for an immutable partition operation."""

from __future__ import annotations

import json
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from agent_cli.config import load_config_at_revision
from agent_cli.paths import atomic_write
from agent_cli.providers.base import validated_result
from agent_cli.review.models import (
    ManifestFile,
    ReviewManifest,
    ReviewPackageRequest,
    ReviewResult,
)
from agent_cli.review.orchestrator import ReviewOrchestrator
from agent_cli.review.package import (
    REVIEW_INSTRUCTIONS,
    ReviewPackageBlocked,
    _manifest_hash,
    _resolve_ref,
    load_package,
    package_usage,
)
from agent_cli.review.partition import build_partition, load_partition, partition_usage


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _safe_json(path):
    if path.is_symlink() or not path.is_file():
        raise ReviewPackageBlocked(f"missing or unsafe review evidence: {path.name}")
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeError) as exc:
        raise ReviewPackageBlocked("malformed partition evidence") from exc
    if not isinstance(value, dict):
        raise ReviewPackageBlocked("partition evidence must be an object")
    return value


class PartitionOrchestrator:
    def __init__(self, providers):
        self.single = ReviewOrchestrator(providers)

    def prepare(self, request, *, integration_context_paths, **limits):
        return build_partition(
            request, integration_context_paths=integration_context_paths, **limits
        )

    def _result(self, part, status, verdict=None):
        return ReviewResult(
            status,
            verdict,
            part.root_package.manifest.reviewer_provider,
            part.root_package.path,
            part.manifest_sha256,
            None,
        )

    def _validate(self, part, request, *, trusted_partition_enabled):
        part = load_partition(part.root_package.path, root=request.root)
        manifest = part.root_package.manifest
        if (
            manifest.base_sha != _resolve_ref(request.root, request.base)
            or manifest.head_sha != _resolve_ref(request.root, request.head)
            or manifest.author_provider != request.author_provider
            or manifest.reviewer_provider != request.reviewer_provider
            or request.author_provider == request.reviewer_provider
        ):
            raise ReviewPackageBlocked(
                "partition request revisions or providers differ"
            )
        policy = load_config_at_revision(request.root, manifest.base_sha).review
        limits = part.manifest["limits"]
        if not trusted_partition_enabled or not policy.partition_enabled:
            raise ReviewPackageBlocked(
                "partition review is not enabled by the trusted base"
            )
        if (
            limits["max_aggregate_bytes"] > policy.max_aggregate_bytes
            or limits["max_aggregate_tokens"] > policy.max_aggregate_tokens
            or limits["target_bytes"] > policy.partition_target_bytes
            or request.max_package_bytes > policy.max_package_bytes
            or request.max_estimated_tokens > policy.max_estimated_tokens
        ):
            raise ReviewPackageBlocked("partition limits exceed trusted policy")
        for child in part.children:
            usage = package_usage(child)
            if (
                usage["bytes"] > request.max_package_bytes
                or usage["estimated_tokens"] > request.max_estimated_tokens
            ):
                raise ReviewPackageBlocked(
                    "partition child exceeds current context budget"
                )
        return part

    def run_partition(
        self,
        part,
        request,
        *,
        approved_manifest_sha256=None,
        trusted_partition_enabled=False,
    ):
        # Preview stays local: approval is checked before trusted policy/probing.
        part = load_partition(part.root_package.path, root=request.root)
        if approved_manifest_sha256 != part.manifest_sha256:
            return self._result(part, "manifest_pending")
        part = self._validate(
            part, request, trusted_partition_enabled=trusted_partition_enabled
        )
        state = {
            "root_manifest_sha256": part.manifest_sha256,
            "children": [],
            "integration": None,
        }
        pending = False
        failed = False
        for child in part.children:
            result = self.single.run_package(
                child,
                request,
                approved_manifest_sha256=child.manifest_sha256,
                publish=False,
            )
            if result.status != "completed":
                pending = True
                continue
            try:
                row = self._child_row(child)
            except ReviewPackageBlocked:
                pending = True
                continue
            state["children"].append(row)
            failed = failed or row["verdict"] != "pass"
        atomic_write(
            part.root_package.path / "partition-results.json", _json_bytes(state)
        )
        if pending or len(state["children"]) != len(part.children):
            return self._result(part, "review_pending")
        if failed:
            return self._result(part, "completed", "fail")
        integration = self._build_integration(part, request)
        state["integration"] = {
            "path": integration.path.name,
            "manifest_sha256": integration.manifest_sha256,
        }
        atomic_write(
            part.root_package.path / "partition-results.json", _json_bytes(state)
        )
        return self._result(part, "integration_manifest_pending")

    def _child_row(self, child):
        audit_path = child.path / "audit.jsonl"
        findings_path = child.path / "findings.json"
        audit = _safe_json(audit_path)
        payload = _safe_json(findings_path)
        raw = findings_path.read_text()
        valid = validated_result(child.manifest.reviewer_provider, payload, raw)
        if (
            valid.status != "completed"
            or audit.get("status") != "completed"
            or audit.get("manifest_sha256") != child.manifest_sha256
            or audit.get("provider") != child.manifest.reviewer_provider
            or audit.get("verdict") != valid.verdict
            or audit.get("exit_code") != 0
        ):
            raise ReviewPackageBlocked("child audit/result is incomplete or invalid")
        return {
            "path": child.path.name,
            "manifest_sha256": child.manifest_sha256,
            "audit_sha256": sha256(audit_path.read_bytes()).hexdigest(),
            "findings_sha256": sha256(findings_path.read_bytes()).hexdigest(),
            "verdict": valid.verdict,
            "output": payload,
        }

    def _validated_children(self, part):
        state = _safe_json(part.root_package.path / "partition-results.json")
        rows = [self._child_row(child) for child in part.children]
        if (
            state.get("root_manifest_sha256") != part.manifest_sha256
            or state.get("children") != rows
            or not rows
            or any(row["verdict"] != "pass" for row in rows)
        ):
            raise ReviewPackageBlocked(
                "all root-bound children must complete and pass unchanged"
            )
        return state, rows

    def _integration_context(self, part):
        _, rows = self._validated_children(part)
        paths = part.manifest["integration_context_paths"]
        if not paths:
            raise ReviewPackageBlocked("integration contracts are missing")
        context = {
            path: (part.root_package.path / "context" / path).read_bytes()
            for path in paths
        }
        name = "partition-review-results.json"
        if name in context:
            raise ReviewPackageBlocked(
                "integration context path conflicts with evidence"
            )
        context[name] = _json_bytes(
            {
                "root_manifest_sha256": part.manifest_sha256,
                "base_sha": part.root_package.manifest.base_sha,
                "head_sha": part.root_package.manifest.head_sha,
                "full_diff_sha256": part.root_package.manifest.full_diff_sha256,
                "scope": part.root_package.manifest.scope,
                "children": rows,
                "shards": part.manifest["children"],
                "required_review": "Assess protocol state, SQL policy, catalog proof, deployment isolation and test coverage across all shards. Do not pass if a necessary contract is absent.",
            }
        )
        return context

    def _build_integration(self, part, request):
        context = self._integration_context(part)
        template = part.root_package
        payload = {
            name: (template.path / name).read_bytes()
            for name in (
                "requirements.md",
                "verification.json",
                "policy.md",
                "review-schema.json",
            )
        }
        payload["diff.patch"] = b""
        files = tuple(
            ManifestFile(path, sha256(data).hexdigest(), len(data))
            for path, data in sorted(context.items())
        )
        original = template.manifest
        manifest = ReviewManifest(
            original.base_sha,
            original.head_sha,
            sha256(b"").hexdigest(),
            original.requirements_sha256,
            original.verification_sha256,
            original.policy_sha256,
            original.schema_sha256,
            original.author_provider,
            original.reviewer_provider,
            original.scope,
            files,
            0,
            datetime.now(timezone.utc).isoformat(),
        )
        size = (
            sum(map(len, payload.values()))
            + sum(map(len, context.values()))
            + len(REVIEW_INSTRUCTIONS.encode())
        )
        for _ in range(10):
            revised = replace(
                manifest, total_bytes=size + len(_manifest_hash(manifest)[1]) + 1
            )
            if revised == manifest:
                break
            manifest = revised
        self._integration_budget(part, request, manifest.total_bytes)
        path = request.root / ".agent/.runs" / f"review-{uuid.uuid4()}"
        path.mkdir(mode=0o700)
        (path / "context").mkdir(mode=0o700)
        for name, data in payload.items():
            atomic_write(path / name, data)
        for name, data in context.items():
            atomic_write(path / "context" / name, data)
        _digest, raw = _manifest_hash(manifest)
        atomic_write(path / "manifest.json", raw + b"\n")
        return load_package(path, root=request.root)

    def _integration_budget(self, part, request, size):
        limits = part.manifest["limits"]
        if (
            size > min(request.max_package_bytes, limits["target_bytes"])
            or (size + 2) // 3 > request.max_estimated_tokens
        ):
            raise ReviewPackageBlocked(
                "integration package exceeds current per-invocation budget"
            )
        usage = partition_usage(part)
        reserved = usage["integration_reserved_bytes"]
        total = usage["bytes"] - reserved + size
        tokens = usage["estimated_tokens"] - (reserved + 2) // 3 + (size + 2) // 3
        if (
            total > limits["max_aggregate_bytes"]
            or tokens > limits["max_aggregate_tokens"]
        ):
            raise ReviewPackageBlocked("integration exceeds aggregate review budget")

    def integration_package(self, part, request):
        part = load_partition(part.root_package.path, root=request.root)
        state, _ = self._validated_children(part)
        ref = state.get("integration")
        if not isinstance(ref, dict) or set(ref) != {"path", "manifest_sha256"}:
            raise ReviewPackageBlocked("integration package has not been prepared")
        if not isinstance(ref["path"], str) or Path(ref["path"]).name != ref["path"]:
            raise ReviewPackageBlocked("invalid integration location")
        package = load_package(
            request.root / ".agent/.runs" / ref["path"], root=request.root
        )
        if package.manifest_sha256 != ref["manifest_sha256"]:
            raise ReviewPackageBlocked(
                "integration manifest differs from prepared evidence"
            )
        expected = self._integration_context(part)
        template = part.root_package.manifest
        manifest = package.manifest
        if (
            manifest.base_sha != template.base_sha
            or manifest.head_sha != template.head_sha
            or manifest.scope != template.scope
            or manifest.author_provider != template.author_provider
            or manifest.reviewer_provider != template.reviewer_provider
            or package.diff_bytes != b""
            or {f.path for f in manifest.files} != set(expected)
        ):
            raise ReviewPackageBlocked("integration scope or identity drift")
        for path, data in expected.items():
            if (package.path / "context" / path).read_bytes() != data:
                raise ReviewPackageBlocked(
                    "integration evidence does not match root-bound children"
                )
        for name in (
            "requirements.md",
            "verification.json",
            "policy.md",
            "review-schema.json",
        ):
            if (package.path / name).read_bytes() != (
                part.root_package.path / name
            ).read_bytes():
                raise ReviewPackageBlocked("integration shared input drift")
        allowed = {
            "manifest.json",
            "diff.patch",
            "requirements.md",
            "verification.json",
            "policy.md",
            "review-schema.json",
            "audit.jsonl",
            "findings.json",
            *("context/" + p for p in expected),
        }
        allowed_dirs = {"context"}
        for name in allowed:
            allowed_dirs.update(
                parent.as_posix()
                for parent in Path(name).parents
                if parent.as_posix() != "."
            )
        for path in package.path.rglob("*"):
            name = path.relative_to(package.path).as_posix()
            if (
                path.is_symlink()
                or (path.is_file() and name not in allowed)
                or (path.is_dir() and name not in allowed_dirs)
                or (not path.is_file() and not path.is_dir())
            ):
                raise ReviewPackageBlocked("extra or unsafe integration content")
        self._integration_budget(part, request, package_usage(package)["bytes"])
        return package

    def run_integration(
        self,
        part,
        request,
        package,
        *,
        approved_manifest_sha256=None,
        trusted_partition_enabled=False,
    ):
        part = self._validate(
            part, request, trusted_partition_enabled=trusted_partition_enabled
        )
        expected = self.integration_package(part, request)
        if (
            expected.path != package.path
            or expected.manifest_sha256 != package.manifest_sha256
        ):
            raise ReviewPackageBlocked("unexpected integration package")
        if approved_manifest_sha256 != expected.manifest_sha256:
            return self._result(part, "manifest_pending")
        result = self.single.run_package(
            expected,
            request,
            approved_manifest_sha256=approved_manifest_sha256,
            publish=False,
        )
        if result.status != "completed":
            return self._result(part, "review_pending")
        row = self._child_row(expected)
        if row["verdict"] != "pass":
            return self._result(part, "completed", "fail")
        state, _ = self._validated_children(part)
        state["integration_result"] = row
        atomic_write(
            part.root_package.path / "partition-results.json", _json_bytes(state)
        )
        atomic_write(
            part.root_package.path / "findings.json",
            _json_bytes({"verdict": "pass", "findings": []}),
        )
        self._publish(part)
        return self._result(part, "completed", "pass")

    def clearance_valid(self, part):
        try:
            part = load_partition(
                part.root_package.path, root=part.root_package.path.parent.parent.parent
            )
            state, _ = self._validated_children(part)
            # root is repository/.agent/.runs/review-*.
            root = part.root_package.path.parent.parent.parent
            m = part.root_package.manifest
            request = ReviewPackageRequest(
                root,
                m.base_sha,
                m.head_sha,
                m.author_provider,
                m.reviewer_provider,
                (),
                "",
                {},
                part.manifest["limits"]["per_invocation_max_bytes"],
                part.manifest["limits"]["per_invocation_max_tokens"],
            )
            self._validate(part, request, trusted_partition_enabled=True)
            package = self.integration_package(part, request)
            return (
                state.get("integration_result") == self._child_row(package)
                and self._child_row(package)["verdict"] == "pass"
            )
        except (ReviewPackageBlocked, ValueError, KeyError, OSError):
            return False

    def _publish(self, part):
        if not self.clearance_valid(part):
            raise ReviewPackageBlocked("aggregate evidence is not complete")
        root = part.root_package.path.parent.parent.parent
        m = part.root_package.manifest
        findings = part.root_package.path / "findings.json"
        summary = {
            "status": "passed",
            "verdict": "pass",
            "partitioned": True,
            "author_provider": m.author_provider,
            "reviewer_provider": m.reviewer_provider,
            "base_sha": m.base_sha,
            "head_sha": m.head_sha,
            "diff_sha256": m.diff_sha256,
            "manifest_sha256": part.manifest_sha256,
            "findings_sha256": sha256(findings.read_bytes()).hexdigest(),
            "package_path": part.root_package.path.relative_to(root).as_posix(),
        }
        for name, kind in (
            ("code-review.json", "independent-code-review"),
            ("cross-review.json", "cross-provider-review"),
        ):
            atomic_write(
                root / ".agent/.runs" / name, _json_bytes({**summary, "kind": kind})
            )
        atomic_write(
            root / ".agent/.runs/adjudication.json",
            _json_bytes(
                {
                    k: summary[k]
                    for k in (
                        "status",
                        "head_sha",
                        "manifest_sha256",
                        "findings_sha256",
                        "package_path",
                    )
                }
                | {"decisions": [], "blocking_ids": []}
            ),
        )
