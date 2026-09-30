from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class ReviewPackageRequest:
    root: Path
    base: str
    head: str
    author_provider: str
    reviewer_provider: str
    context_paths: tuple[str, ...]
    requirements: str
    verification: Mapping[str, object]
    max_package_bytes: int
    max_estimated_tokens: int = 64000


@dataclass(frozen=True)
class ManifestFile:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class ReviewManifest:
    base_sha: str
    head_sha: str
    diff_sha256: str
    requirements_sha256: str
    verification_sha256: str
    policy_sha256: str
    schema_sha256: str
    author_provider: str
    reviewer_provider: str
    scope: tuple[str, ...]
    files: tuple[ManifestFile, ...]
    total_bytes: int
    created_at: str
    full_diff_sha256: str | None = None
    omitted_generated: tuple[tuple[str, str], ...] = ()
    estimated_tokens: int = 0
    verified_renames: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        if self.verified_renames is None:
            result.pop("verified_renames")
        else:
            # Scope is still complete; factor only repeated directory prefixes.
            groups: dict[str, list[str]] = {}
            for path in self.scope:
                parts = path.split("/")
                prefix = "/".join(parts[:2]) + "/" if len(parts) > 2 else ""
                groups.setdefault(prefix, []).append(path[len(prefix):])
            result["scope"] = groups
        if self.full_diff_sha256 is None:
            # Preserve checksums for pre-projection manifests.
            for key in ("full_diff_sha256", "omitted_generated", "estimated_tokens"):
                result.pop(key)
        return result


@dataclass(frozen=True)
class ReviewFinding:
    id: str
    severity: str
    category: str
    file: str | None
    line: int | None
    evidence: str
    reasoning: str
    remediation: str
    confidence: str


@dataclass(frozen=True)
class ReviewResult:
    status: str
    verdict: str | None
    provider: str
    package_path: Path
    manifest_sha256: str
    findings_json: str | None


@dataclass(frozen=True)
class AdjudicatedFinding:
    finding: ReviewFinding
    disposition: str
    evidence_reference: str | None
    reason: str
    blocks_merge: bool
