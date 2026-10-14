"""Two-stage, fail-closed orchestration for an immutable partition operation."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

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
from agent_cli.review.partition_retry import (
    RetryPackage,
    digest,
    retry_manifest_digest,
    validate_terminal_receipt,
)
from agent_cli.review.partition_retry import (
    load_retry as restore_retry,
)
from agent_cli.review.partition_retry import (
    preview_retry as prepare_retry,
)


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


def _retry_usage(state):
    """Count every append-only retry row against the root review budget."""
    return (
        sum(item["package_bytes"] for item in state["retry_attempts"]),
        sum(item["estimated_tokens"] for item in state["retry_attempts"]),
    )


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

    def _state(self, part):
        path = part.root_package.path / "partition-results.json"
        if not path.exists():
            return {
                "root_manifest_sha256": part.manifest_sha256,
                "children": [],
                "integration": None,
                "dispatches": {},
                "retry_attempts": [],
            }
        state = _safe_json(path)
        if (
            state.get("root_manifest_sha256") != part.manifest_sha256
            or not isinstance(state.get("children"), list)
            or not isinstance(state.get("dispatches", {}), dict)
            or not isinstance(state.get("retry_attempts", []), list)
        ):
            raise ReviewPackageBlocked("partition resume state is not root-bound")
        state.setdefault("integration", None)
        state.setdefault("dispatches", {})
        state.setdefault("retry_attempts", [])
        allowed = {f"child:{child.path.name}" for child in part.children} | {
            "integration"
        }
        unknown = set(state["dispatches"]) - allowed
        if any(
            not key.startswith("retry:") or len(key) != 70
            or any(char not in "0123456789abcdef" for char in key[6:])
            for key in unknown
        ):
            raise ReviewPackageBlocked("partition resume state has an unknown dispatch")
        counts = {}
        manifests = set()
        receipts = set()
        latest_attempts = {}
        for attempt in state["retry_attempts"]:
            required = {
                "child_path", "attempt", "retry_manifest_sha256", "receipt_sha256",
                "package_path", "source_package_path", "package_bytes",
                "estimated_tokens", "status", "result",
            }
            if (
                not isinstance(attempt, dict)
                or set(attempt) != required
                or attempt.get("child_path") not in {child.path.name for child in part.children}
                or type(attempt.get("attempt")) is not int
                or attempt["attempt"] < 1 or attempt["attempt"] > 2
                or attempt.get("status") not in {"completed", "review_pending"}
                or not isinstance(attempt.get("package_path"), str)
                or Path(attempt["package_path"]).name != attempt["package_path"]
                or not isinstance(attempt.get("source_package_path"), str)
                or Path(attempt["source_package_path"]).name != attempt["source_package_path"]
                or type(attempt.get("package_bytes")) is not int
                or attempt["package_bytes"] < 0
                or type(attempt.get("estimated_tokens")) is not int
                or attempt["estimated_tokens"] < 0
                or not isinstance(attempt.get("retry_manifest_sha256"), str)
                or len(attempt["retry_manifest_sha256"]) != 64
                or any(char not in "0123456789abcdef" for char in attempt["retry_manifest_sha256"])
                or not isinstance(attempt.get("receipt_sha256"), str)
                or len(attempt["receipt_sha256"]) != 64
                or any(char not in "0123456789abcdef" for char in attempt["receipt_sha256"])
                or (attempt["status"] == "completed" and not isinstance(attempt.get("result"), dict))
                or (attempt["status"] == "review_pending" and attempt.get("result") is not None)
            ):
                raise ReviewPackageBlocked("partition retry ledger is invalid")
            child_path = attempt["child_path"]
            counts[child_path] = counts.get(child_path, 0) + 1
            if attempt["attempt"] != counts[child_path] or counts[child_path] > 2:
                raise ReviewPackageBlocked("partition retry attempts are not monotonic")
            prior = latest_attempts.get(child_path)
            expected_source = (
                child_path if prior is None else prior["package_path"]
            )
            if (
                attempt["source_package_path"] != expected_source
                or (prior is not None and prior["status"] != "review_pending")
            ):
                raise ReviewPackageBlocked("partition retry source does not follow terminal history")
            if (
                attempt["retry_manifest_sha256"] in manifests
                or attempt["receipt_sha256"] in receipts
            ):
                raise ReviewPackageBlocked("partition retry evidence was replayed")
            manifests.add(attempt["retry_manifest_sha256"])
            receipts.add(attempt["receipt_sha256"])
            latest_attempts[child_path] = attempt
        return state

    def _marker(self, part, key, package):
        marker = self._state(part)["dispatches"].get(key)
        if marker is None:
            return None
        expected = {
            "root_manifest_sha256": part.manifest_sha256,
            "package_path": package.path.name,
            "manifest_sha256": package.manifest_sha256,
            "status": marker.get("status") if isinstance(marker, dict) else None,
        }
        if (
            not isinstance(marker, dict)
            or marker != expected
            or marker["status"] not in {"started", "completed"}
        ):
            raise ReviewPackageBlocked("partition dispatch marker is invalid")
        return marker

    def _claim_operation(self, part):
        """Serialize root state updates; flock is released if the process exits."""
        run_root = part.root_package.path.parent
        token = sha256(part.manifest_sha256.encode()).hexdigest()
        path = run_root / f"partition-operation-{token}.lock"
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                raise ReviewPackageBlocked("partition operation lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            return None
        except (OSError, ReviewPackageBlocked):
            os.close(descriptor)
            raise
        return descriptor

    def _release_operation(self, descriptor):
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def _capability_ready(self, request):
        provider = self.single.providers.get(request.reviewer_provider)
        if provider is None:
            return False
        try:
            capability = provider.detect()
        except (OSError, ValueError, RuntimeError):
            return False
        return bool(
            capability.available
            and capability.supports_json
            and capability.supports_read_only
        )

    def _set_marker(self, part, state, key, package, status):
        marker = {
            "root_manifest_sha256": part.manifest_sha256,
            "package_path": package.path.name,
            "manifest_sha256": package.manifest_sha256,
            "status": status,
        }
        prior = self._marker(part, key, package)
        if prior is not None and prior["status"] == "started" and status == "started":
            raise ReviewPackageBlocked("partition dispatch is already ambiguous")
        state["dispatches"][key] = marker
        atomic_write(
            part.root_package.path / "partition-results.json", _json_bytes(state)
        )

    def preview_retry(
        self,
        part,
        request,
        child_path,
        terminal_receipt_path,
        transport_identity,
        max_attempts=2,
    ):
        """Build an immutable retry clone and a separately approved manifest."""
        part = load_partition(part.root_package.path, root=request.root)
        state = self._state(part)
        child = next((item for item in part.children if item.path == Path(child_path)), None)
        source = child
        logical_name = child.path.name if child else None
        if source is None:
            candidate = Path(child_path)
            name = candidate.name
            prior = next(
                (item for item in reversed(state["retry_attempts"])
                 if isinstance(item, dict) and item.get("package_path") == name),
                None,
            )
            if prior is not None:
                logical_name = prior.get("child_path")
                child = next((item for item in part.children if item.path.name == logical_name), None)
                expected_source = part.root_package.path.parent / name
                if (
                    child is not None
                    and prior.get("status") == "review_pending"
                    and candidate.resolve(strict=True) == expected_source.resolve(strict=True)
                ):
                    source = load_package(candidate, root=request.root)
        if child is None or source is None:
            raise ReviewPackageBlocked("retry child is outside the prepared partition")
        original_marker = self._marker(part, f"child:{child.path.name}", child)
        if original_marker is None or original_marker["status"] != "started":
            raise ReviewPackageBlocked(
                "retry requires the original child dispatch to remain started"
            )
        prior_attempts = [
            item for item in state["retry_attempts"]
            if isinstance(item, dict) and item.get("child_path") == child.path.name
        ]
        if prior_attempts and prior_attempts[-1].get("status") != "review_pending":
            raise ReviewPackageBlocked("a terminal retry result cannot be retried")
        retry_markers = [
            (key, marker) for key, marker in state["dispatches"].items()
            if key.startswith("retry:") and isinstance(marker, dict)
            and marker.get("status") == "started"
        ]
        if retry_markers and not (
            prior_attempts
            and prior_attempts[-1].get("status") == "review_pending"
            and len(retry_markers) == 1
            and retry_markers[0][1].get("package_path") == source.path.name
        ):
            raise ReviewPackageBlocked("a prior retry dispatch is ambiguous")
        attempt = len(prior_attempts) + 1
        usage = partition_usage(part)
        limits = part.manifest["limits"]
        already_bytes, already_tokens = _retry_usage(state)
        return prepare_retry(
            part=part,
            request=request,
            child_path=child.path,
            logical_child_path=child.path.name,
            source_package=source,
            terminal_receipt_path=terminal_receipt_path,
            transport_identity=transport_identity,
            attempt=attempt,
            max_attempts=max_attempts,
            aggregate_remaining_bytes=limits["max_aggregate_bytes"] - usage["bytes"] - already_bytes,
            aggregate_remaining_tokens=limits["max_aggregate_tokens"] - usage["estimated_tokens"] - already_tokens,
            used_receipt_hashes=(
                item.get("receipt_sha256") for item in prior_attempts
            ),
        )

    def load_retry(self, part, request, manifest_path):
        part = load_partition(part.root_package.path, root=request.root)
        return restore_retry(part=part, request=request, manifest_path=Path(manifest_path))

    def run_retry(
        self,
        part,
        request,
        retry,
        *,
        approved_retry_manifest_sha256=None,
        trusted_partition_enabled=False,
    ):
        # Approval is the first gate. Do not load files, probe, or launch before it.
        if (
            not isinstance(retry, RetryPackage)
            or approved_retry_manifest_sha256 != retry.manifest_sha256
            or retry_manifest_digest(retry) != retry.manifest_sha256
        ):
            loaded = load_partition(part.root_package.path, root=request.root)
            return self._result(loaded, "manifest_pending")
        part = load_partition(part.root_package.path, root=request.root)
        lock = self._claim_operation(part)
        if lock is None:
            return self._result(part, "review_pending")
        try:
            return self._run_retry_claimed(
                part, request, retry,
                approved_retry_manifest_sha256=approved_retry_manifest_sha256,
                trusted_partition_enabled=trusted_partition_enabled,
            )
        finally:
            self._release_operation(lock)

    def _run_retry_claimed(
        self, part, request, retry, *, approved_retry_manifest_sha256,
        trusted_partition_enabled,
    ):
        if (
            approved_retry_manifest_sha256 != retry.manifest_sha256
            or retry_manifest_digest(retry) != retry.manifest_sha256
        ):
            return self._result(part, "manifest_pending")
        part = self._validate(
            part, request, trusted_partition_enabled=trusted_partition_enabled
        )
        manifest_raw = retry.manifest_path.read_bytes()
        if digest(manifest_raw.rstrip(b"\n")) != retry.manifest_sha256:
            raise ReviewPackageBlocked("retry manifest changed after preview")
        data = json.loads(manifest_raw)
        child = next((item for item in part.children if item.path.name == retry.child_path), None)
        if (
            not isinstance(data, dict)
            or set(data) != {
                "version", "root_manifest_sha256", "base_sha", "head_sha",
                "child_path", "child_manifest_sha256", "source_package_path",
                "retry_package_path", "attempt", "max_attempts",
                "input_inventory_sha256", "prior_artifacts", "terminal_receipt_path",
                "transport_identity",
            }
            or type(data.get("attempt")) is not int
            or type(data.get("max_attempts")) is not int
            or not 1 <= data.get("max_attempts", 0) <= 2
            or not 1 <= data.get("attempt", 0) <= data.get("max_attempts", 0)
            or child is None
            or data.get("base_sha") != part.root_package.manifest.base_sha
            or data.get("head_sha") != part.root_package.manifest.head_sha
            or data.get("child_path") != child.path.name
            or data.get("root_manifest_sha256") != part.manifest_sha256
            or data.get("child_manifest_sha256") != child.manifest_sha256
            or data.get("retry_package_path") != retry.package.path.name
            or data.get("attempt") != retry.attempt
        ):
            raise ReviewPackageBlocked("retry manifest identity differs from root/child")
        source_name = data.get("source_package_path")
        if not isinstance(source_name, str) or Path(source_name).name != source_name:
            raise ReviewPackageBlocked("retry source package path is invalid")
        source = (
            child if source_name == child.path.name
            else load_package(request.root / ".agent/.runs" / source_name, root=request.root)
        )
        if source.manifest_sha256 != child.manifest_sha256:
            raise ReviewPackageBlocked("retry source package differs from approved child")
        receipt, _files, prior = validate_terminal_receipt(
            part=part, child=source, request=request, receipt_path=retry.receipt_path
        )
        if (
            prior["receipt_sha256"] != retry.receipt_sha256
            or prior != data.get("prior_artifacts")
            or receipt["input_inventory_sha256"] != data.get("input_inventory_sha256")
        ):
            raise ReviewPackageBlocked("retry terminal evidence changed after preview")
        current = load_package(retry.package.path, root=request.root)
        if current.manifest_sha256 != child.manifest_sha256:
            raise ReviewPackageBlocked("retry clone manifest changed after preview")
        state = self._state(part)
        attempts = [
            item for item in state["retry_attempts"]
            if isinstance(item, dict) and item.get("child_path") == child.path.name
        ]
        if retry.attempt != len(attempts) + 1 or retry.attempt > retry.max_attempts:
            raise ReviewPackageBlocked("retry attempt is replayed or over limit")
        started_retries = [
            (key, value) for key, value in state["dispatches"].items()
            if key.startswith("retry:") and isinstance(value, dict)
            and value.get("status") == "started"
        ]
        if started_retries and not (
            attempts
            and attempts[-1].get("status") == "review_pending"
            and len(started_retries) == 1
            and started_retries[0][1].get("package_path") == source.path.name
        ):
            return self._result(part, "review_pending")
        if any(item.get("retry_manifest_sha256") == retry.manifest_sha256 for item in attempts):
            return self._result(part, "review_pending")
        key = f"retry:{retry.manifest_sha256}"
        marker = self._marker(part, key, current)
        if marker is not None:
            return self._result(part, "review_pending")
        usage = package_usage(current)
        aggregate = partition_usage(part)
        limits = part.manifest["limits"]
        used_retry_bytes, used_retry_tokens = _retry_usage(state)
        if (
            usage["bytes"] > request.max_package_bytes
            or usage["estimated_tokens"] > request.max_estimated_tokens
            or aggregate["bytes"] + used_retry_bytes + usage["bytes"] > limits["max_aggregate_bytes"]
            or aggregate["estimated_tokens"] + used_retry_tokens + usage["estimated_tokens"] > limits["max_aggregate_tokens"]
        ):
            raise ReviewPackageBlocked("retry exceeds trusted aggregate budget")
        provider = self.single.providers.get(request.reviewer_provider)
        identity_reader = getattr(provider, "retry_transport_identity", None)
        if not callable(identity_reader):
            raise ReviewPackageBlocked("provider cannot attest retry transport identity")
        try:
            actual_identity = identity_reader(current)
        except (OSError, ValueError, RuntimeError):
            raise ReviewPackageBlocked("provider retry transport identity is unavailable")
        if actual_identity != data.get("transport_identity"):
            raise ReviewPackageBlocked("retry transport identity changed after approval")
        binder = getattr(provider, "bind_retry_transport", None)
        if not callable(binder):
            raise ReviewPackageBlocked("provider cannot bind the approved retry transport")
        try:
            binder(current, data["transport_identity"])
        except (OSError, ValueError, RuntimeError):
            raise ReviewPackageBlocked("provider could not bind the approved retry transport")
        if not self._capability_ready(request):
            return self._result(part, "review_pending")
        self._set_marker(part, state, key, current, "started")
        self.single.run_package(
            current, request,
            approved_manifest_sha256=current.manifest_sha256,
            publish=False,
        )
        try:
            row = self._child_row(current)
        except ReviewPackageBlocked:
            row = None
        if row is not None:
            row["path"] = child.path.name
        attempt_record = {
            "child_path": child.path.name,
            "attempt": retry.attempt,
            "retry_manifest_sha256": retry.manifest_sha256,
            "receipt_sha256": retry.receipt_sha256,
            "package_path": current.path.name,
            "source_package_path": data["source_package_path"],
            "package_bytes": usage["bytes"],
            "estimated_tokens": usage["estimated_tokens"],
            "status": "completed" if row is not None else "review_pending",
            "result": row,
        }
        state = self._state(part)
        state["retry_attempts"].append(attempt_record)
        if row is not None:
            rows = {item["path"]: item for item in state["children"]}
            rows[child.path.name] = row
            state["children"] = list(rows.values())
            state["dispatches"][key] = {
                "root_manifest_sha256": part.manifest_sha256,
                "package_path": current.path.name,
                "manifest_sha256": current.manifest_sha256,
                "status": "completed",
            }
        atomic_write(part.root_package.path / "partition-results.json", _json_bytes(state))
        if row is None:
            # The start marker remains ambiguous and cannot be replayed.
            return self._result(part, "review_pending")
        if row["verdict"] != "pass":
            return self._result(part, "completed", "fail")
        return self._result(part, "completed", "pass")

    def _clear_marker(self, part, state, key):
        state["dispatches"].pop(key, None)
        atomic_write(
            part.root_package.path / "partition-results.json", _json_bytes(state)
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
        part = load_partition(part.root_package.path, root=request.root)
        if approved_manifest_sha256 != part.manifest_sha256:
            return self._result(part, "manifest_pending")
        lock = self._claim_operation(part)
        if lock is None:
            return self._result(part, "review_pending")
        try:
            return self._run_partition_claimed(
                part,
                request,
                approved_manifest_sha256=approved_manifest_sha256,
                trusted_partition_enabled=trusted_partition_enabled,
            )
        finally:
            self._release_operation(lock)

    def _run_partition_claimed(
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
        state = self._state(part)
        previous_rows = {}
        for row in state["children"]:
            if (
                not isinstance(row, dict)
                or row.get("path") not in {child.path.name for child in part.children}
                or row["path"] in previous_rows
            ):
                raise ReviewPackageBlocked("partition child resume rows are invalid")
            previous_rows[row["path"]] = row
        pending = False
        failed = False
        for child in part.children:
            key = f"child:{child.path.name}"
            previous = previous_rows.get(child.path.name)
            retry_attempts = [
                item for item in state["retry_attempts"]
                if isinstance(item, dict) and item.get("child_path") == child.path.name
            ]
            if retry_attempts and retry_attempts[-1].get("status") != "completed":
                pending = True
                continue
            row = self._selected_child_row(part, child)
            freshly_completed = False
            selected_key, selected_package = self._selected_child_dispatch(part, child)
            marker = self._marker(part, selected_key, selected_package)
            if previous is not None and (
                marker is None
                or marker["status"] != "completed"
                or row != previous
            ):
                pending = True
                continue
            if row is not None and marker is None:
                # An audit is reusable only when a pre-dispatch marker binds it
                # to this root and immutable child package.
                pending = True
                continue
            if retry_attempts and row is not None:
                if previous != row or marker is None or marker["status"] != "completed":
                    pending = True
                else:
                    failed = failed or row["verdict"] != "pass"
                continue
            if (
                row is not None
                and previous is None
                and marker is not None
                and marker["status"] in {"started", "completed"}
                and not freshly_completed
            ):
                pending = True
                continue
            if row is None:
                # Any audit or findings file means a prior invocation may have
                # reached the reviewer; only a clean package can start afresh.
                if marker is not None or any(
                    (child.path / name).exists()
                    for name in ("audit.jsonl", "findings.json")
                ):
                    pending = True
                    continue
                if not self._capability_ready(request):
                    pending = True
                    continue
                if self._marker(part, key, child) is not None:
                    pending = True
                    continue
                self._set_marker(part, self._state(part), key, child, "started")
                result = self.single.run_package(
                    child,
                    request,
                    approved_manifest_sha256=child.manifest_sha256,
                    publish=False,
                )
                if result.status == "completed":
                    try:
                        row = self._child_row(child)
                        freshly_completed = row is not None
                    except ReviewPackageBlocked:
                        row = None
                elif not (child.path / "audit.jsonl").exists() and not (
                    child.path / "findings.json"
                ).exists():
                    # run_package returned before provider.review; this is the
                    # only returned no-audit state that can be retried.
                    self._clear_marker(part, self._state(part), key)
                if row is None:
                    pending = True
                    continue
            state = self._state(part)
            previous_rows[child.path.name] = row
            state["children"] = [
                previous_rows[known.path.name]
                for known in part.children
                if known.path.name in previous_rows
            ]
            self._set_marker(part, state, key, child, "completed")
            failed = failed or row["verdict"] != "pass"
        if pending or len(state["children"]) != len(part.children):
            return self._result(part, "review_pending")
        if failed:
            return self._result(part, "completed", "fail")
        if state.get("integration") is None:
            integration = self._build_integration(part, request)
            state = self._state(part)
            state["integration"] = {
                "path": integration.path.name,
                "manifest_sha256": integration.manifest_sha256,
            }
            atomic_write(
                part.root_package.path / "partition-results.json", _json_bytes(state)
            )
        else:
            integration = self.integration_package(part, request)
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

    def _selected_child_dispatch(self, part, child):
        """Return the package and marker selected by the append-only retry ledger."""
        state = self._state(part)
        attempts = [
            item for item in state["retry_attempts"]
            if isinstance(item, dict) and item.get("child_path") == child.path.name
        ]
        if not attempts:
            return f"child:{child.path.name}", child
        latest = attempts[-1]
        if latest.get("status") != "completed":
            return f"retry:{latest.get('retry_manifest_sha256', '')}", child
        package_path = latest.get("package_path")
        if not isinstance(package_path, str) or Path(package_path).name != package_path:
            raise ReviewPackageBlocked("retry ledger package path is invalid")
        package = load_package(
            part.root_package.path.parent / package_path,
            root=part.root_package.path.parents[2],
        )
        return f"retry:{latest['retry_manifest_sha256']}", package

    def _selected_child_row(self, part, child):
        state = self._state(part)
        attempts = [
            item for item in state["retry_attempts"]
            if isinstance(item, dict) and item.get("child_path") == child.path.name
        ]
        if not attempts:
            try:
                return self._child_row(child)
            except ReviewPackageBlocked:
                return None
        self._validate_retry_history(part, child, attempts)
        latest = attempts[-1]
        if latest.get("status") != "completed" or not isinstance(latest.get("result"), dict):
            return None
        key, package = self._selected_child_dispatch(part, child)
        marker = self._marker(part, key, package)
        if marker is None or marker["status"] != "completed":
            return None
        try:
            row = self._child_row(package)
        except ReviewPackageBlocked:
            return None
        row["path"] = child.path.name
        if row != latest["result"]:
            return None
        return row

    def _validate_retry_history(self, part, child, attempts):
        """Revalidate every approval, receipt, and dispatch before selecting a retry."""
        request = SimpleNamespace(root=part.root_package.path.parents[2])
        run_root = part.root_package.path.parent
        previous_package = child
        for number, attempt in enumerate(attempts, start=1):
            manifest_path = run_root / f"{attempt['package_path']}.retry.json"
            retry = restore_retry(
                part=part, request=request, manifest_path=manifest_path
            )
            if (
                retry.manifest_sha256 != attempt["retry_manifest_sha256"]
                or retry.receipt_sha256 != attempt["receipt_sha256"]
                or retry.attempt != number
                or retry.child_path != child.path.name
                or retry.package.path.name != attempt["package_path"]
                or retry.manifest.get("source_package_path")
                != attempt["source_package_path"]
                or attempt["source_package_path"] != previous_package.path.name
            ):
                raise ReviewPackageBlocked(
                    "retry history no longer matches its approved evidence"
                )
            key = f"retry:{attempt['retry_manifest_sha256']}"
            marker = self._marker(part, key, retry.package)
            expected_status = (
                "completed" if attempt["status"] == "completed" else "started"
            )
            if marker is None or marker["status"] != expected_status:
                raise ReviewPackageBlocked("retry dispatch approval is not bound")
            previous_package = retry.package

    def _validated_children(self, part):
        state = self._state(part)
        rows = [self._selected_child_row(part, child) for child in part.children]
        if (
            state.get("root_manifest_sha256") != part.manifest_sha256
            or state.get("children") != rows
            or not rows
            or any(row["verdict"] != "pass" for row in rows)
        ):
            raise ReviewPackageBlocked(
                "all root-bound children must complete and pass unchanged"
            )
        for child in part.children:
            marker_key, marker_package = self._selected_child_dispatch(part, child)
            marker = self._marker(part, marker_key, marker_package)
            if marker is None or marker["status"] != "completed":
                raise ReviewPackageBlocked("child dispatch completion is unbound")
        return state, rows

    def _integration_context(self, part):
        state, rows = self._validated_children(part)
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
        evidence = {
            "root_manifest_sha256": part.manifest_sha256,
            "base_sha": part.root_package.manifest.base_sha,
            "head_sha": part.root_package.manifest.head_sha,
            "full_diff_sha256": part.root_package.manifest.full_diff_sha256,
            "scope": part.root_package.manifest.scope,
            "children": rows,
            "shards": part.manifest["children"],
            "required_review": "Assess protocol state, SQL policy, catalog proof, deployment isolation and test coverage across all shards. Do not pass if a necessary contract is absent.",
        }
        if state["retry_attempts"]:
            evidence["retry_attempts"] = [
                    {
                        "child_path": item["child_path"],
                        "attempt": item["attempt"],
                        "retry_manifest_sha256": item["retry_manifest_sha256"],
                        "receipt_sha256": item["receipt_sha256"],
                        "status": item["status"],
                    }
                    for item in state["retry_attempts"]
            ]
        context[name] = _json_bytes(evidence)
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
        retry_bytes, retry_tokens = _retry_usage(self._state(part))
        reserved = usage["integration_reserved_bytes"]
        total = usage["bytes"] - reserved + retry_bytes + size
        tokens = (
            usage["estimated_tokens"] - (reserved + 2) // 3
            + retry_tokens + (size + 2) // 3
        )
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
        lock = self._claim_operation(part)
        if lock is None:
            return self._result(part, "review_pending")
        try:
            return self._run_integration_claimed(
                part,
                request,
                expected,
                approved_manifest_sha256=approved_manifest_sha256,
                trusted_partition_enabled=trusted_partition_enabled,
            )
        finally:
            self._release_operation(lock)

    def _run_integration_claimed(
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
        key = "integration"
        state = self._state(part)
        marker = self._marker(part, key, expected)
        row = None
        freshly_completed = False
        try:
            row = self._child_row(expected)
        except ReviewPackageBlocked:
            pass
        if row is not None:
            if marker is None:
                return self._result(part, "review_pending")
            if marker["status"] == "started" and state.get("integration_result") != row:
                return self._result(part, "review_pending")
            if marker["status"] == "completed" and state.get("integration_result") != row:
                return self._result(part, "review_pending")
            if state.get("integration_result") not in (None, row):
                raise ReviewPackageBlocked("integration result differs from resume state")
            if marker is not None and marker["status"] not in {"started", "completed"}:
                raise ReviewPackageBlocked("integration dispatch marker is invalid")
        else:
            if marker is not None or any(
                (expected.path / name).exists()
                for name in ("audit.jsonl", "findings.json")
            ):
                return self._result(part, "review_pending")
            if not self._capability_ready(request):
                return self._result(part, "review_pending")
            if self._marker(part, key, expected) is not None:
                return self._result(part, "review_pending")
            self._set_marker(part, self._state(part), key, expected, "started")
            result = self.single.run_package(
                expected,
                request,
                approved_manifest_sha256=approved_manifest_sha256,
                publish=False,
            )
            if result.status == "completed":
                try:
                    row = self._child_row(expected)
                    freshly_completed = row is not None
                except ReviewPackageBlocked:
                    row = None
            elif not (expected.path / "audit.jsonl").exists() and not (
                expected.path / "findings.json"
            ).exists():
                self._clear_marker(part, self._state(part), key)
            if row is None:
                return self._result(part, "review_pending")
        if marker is not None and marker["status"] == "started" and not freshly_completed:
            return self._result(part, "review_pending")
        state = self._state(part)
        if state.get("integration_result") not in (None, row):
            raise ReviewPackageBlocked("integration result differs from resume state")
        state["integration_result"] = row
        self._set_marker(part, state, key, expected, "completed")
        if row["verdict"] != "pass":
            return self._result(part, "completed", "fail")
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
            marker = self._marker(part, "integration", package)
            return (
                marker is not None
                and marker["status"] == "completed"
                and state.get("integration_result") == self._child_row(package)
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
