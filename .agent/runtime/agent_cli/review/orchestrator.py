from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile
from typing import Mapping

from agent_cli.paths import atomic_write
from agent_cli.providers.base import ReviewRequest
from agent_cli.review.models import ReviewPackageRequest, ReviewResult
from agent_cli.review.package import (
    ReviewPackage,
    ReviewPackageBlocked,
    build_package,
    load_package,
    REVIEW_INSTRUCTIONS,
    package_usage,
    _resolve_ref,
)


class ReviewOrchestrator:
    def __init__(self, providers: Mapping[str, object]):
        self.providers = dict(providers)
        self._prepared: dict[int, ReviewPackage] = {}

    def prepare(self, request: ReviewPackageRequest) -> ReviewPackage:
        package = build_package(request)
        self._prepared[id(request)] = package
        return package

    def run(
        self,
        request: ReviewPackageRequest,
        *,
        approved_manifest_sha256: str | None = None,
    ) -> ReviewResult:
        package = self._prepared.get(id(request)) or self.prepare(request)
        return self.run_package(
            package,
            request,
            approved_manifest_sha256=approved_manifest_sha256,
        )

    def run_package(
        self,
        package: ReviewPackage,
        request: ReviewPackageRequest,
        *,
        approved_manifest_sha256: str | None = None,
    ) -> ReviewResult:
        package = load_package(package.path, root=request.root)
        usage = package_usage(package)
        if (usage["bytes"] > request.max_package_bytes
                or usage["estimated_tokens"] > request.max_estimated_tokens):
            raise ReviewPackageBlocked("review package exceeds current context budget")
        if (package.manifest.base_sha != _resolve_ref(request.root, request.base)
                or package.manifest.head_sha != _resolve_ref(request.root, request.head)):
            raise ReviewPackageBlocked("request revisions do not match review package")
        if (
            package.manifest.author_provider != request.author_provider
            or package.manifest.reviewer_provider != request.reviewer_provider
        ):
            raise ReviewPackageBlocked("request providers do not match review package")
        provider = self.providers.get(request.reviewer_provider)
        if provider is None:
            return ReviewResult(
                "review_pending",
                None,
                request.reviewer_provider,
                package.path,
                package.manifest_sha256,
                None,
            )
        if approved_manifest_sha256 != package.manifest_sha256:
            return ReviewResult(
                "manifest_pending",
                None,
                request.reviewer_provider,
                package.path,
                package.manifest_sha256,
                None,
            )
        capability = provider.detect()
        if not (
            capability.available
            and capability.supports_json
            and capability.supports_read_only
        ):
            return ReviewResult(
                "review_pending",
                None,
                request.reviewer_provider,
                package.path,
                package.manifest_sha256,
                None,
            )
        with tempfile.TemporaryDirectory(prefix="agent-review-") as directory:
            isolated = Path(directory) / "package"
            isolated.mkdir(mode=0o700)
            for name in (
                "diff.patch",
                "manifest.json",
                "policy.md",
                "requirements.md",
                "review-schema.json",
                "verification.json",
            ):
                shutil.copy2(package.path / name, isolated / name)
            shutil.copytree(package.path / "context", isolated / "context")
            atomic_write(
                isolated / "instructions.md",
                REVIEW_INSTRUCTIONS,
            )
            provider_request = ReviewRequest(
                prompt="Read instructions.md and follow it exactly.",
                repository_root=request.root,
                package_path=isolated,
                output_schema_path=isolated / "review-schema.json",
                timeout=300,
            )
            result = provider.review(provider_request)
        audit = {
            "provider": request.reviewer_provider,
            "status": result.status,
            "verdict": result.verdict,
            "manifest_sha256": package.manifest_sha256,
            "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "stdout_sha256": result.stdout_sha256,
            "exit_code": result.exit_code,
            "error": result.stderr_excerpt or None,
        }
        atomic_write(package.path / "audit.jsonl", json.dumps(audit, sort_keys=True) + "\n")
        if result.status != "completed" or result.verdict is None:
            return ReviewResult(
                "review_pending",
                None,
                request.reviewer_provider,
                package.path,
                package.manifest_sha256,
                None,
            )
        findings_payload = (result.findings_json or "{}").encode("utf-8")
        atomic_write(package.path / "findings.json", findings_payload)
        summary = {
            "status": "passed" if result.verdict == "pass" else "blocked",
            "verdict": result.verdict,
            "author_provider": request.author_provider,
            "reviewer_provider": request.reviewer_provider,
            "base_sha": package.manifest.base_sha,
            "head_sha": package.manifest.head_sha,
            "diff_sha256": package.manifest.diff_sha256,
            "manifest_sha256": package.manifest_sha256,
            "findings_sha256": sha256(findings_payload).hexdigest(),
            "package_path": package.path.resolve().relative_to(
                request.root.resolve()
            ).as_posix(),
        }
        run_root = request.root / ".agent/.runs"
        for name, kind in (
            ("code-review.json", "independent-code-review"),
            ("cross-review.json", "cross-provider-review"),
        ):
            atomic_write(
                run_root / name,
                json.dumps({**summary, "kind": kind}, sort_keys=True) + "\n",
            )
        if result.verdict == "pass":
            atomic_write(
                run_root / "adjudication.json",
                json.dumps(
                    {
                        "status": "passed",
                        "head_sha": package.manifest.head_sha,
                        "manifest_sha256": package.manifest_sha256,
                        "findings_sha256": summary["findings_sha256"],
                        "package_path": summary["package_path"],
                        "decisions": [],
                        "blocking_ids": [],
                    },
                    sort_keys=True,
                )
                + "\n",
            )
        return ReviewResult(
            "completed",
            result.verdict,
            request.reviewer_provider,
            package.path,
            package.manifest_sha256,
            result.findings_json,
        )
