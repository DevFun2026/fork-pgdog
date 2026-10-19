"""Create a local, unapproved owner-release receipt from historical evidence.

This exporter never publishes artifacts or writes to GitHub. It binds review and
assessment records to the original Git commits, and leaves live GitHub trust
checks to the release receipt's finalizer.
"""

import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from artifacts import owner_approval
from artifacts.owner_approval import REPOSITORY, review_metadata
from artifacts.owner_release import AUTHOR_PROVIDERS, REVIEWER_PROVIDER

QUALITY = owner_approval.QUALITY
ARTIFACTS = owner_approval.ARTIFACTS
RUN_PATHS = {
    "source-quality": QUALITY,
    "source-artifacts": ARTIFACTS,
    "workflow-quality": QUALITY,
    "workflow-artifacts": ARTIFACTS,
}
DOCUMENTS = {
    "threat-model": "docs/security/threat-model.md",
    "release-notes": "docs/releases/fork-artifacts.md",
    "migration-rollback": "docs/operations/fork-artifact-rollback.md",
    "residual-risks": "docs/security/residual-risks.md",
}
ALL_LENSES = (
    "authentication-and-authorization",
    "input-and-injection",
    "data-and-secrets",
    "session-and-cryptography",
    "business-logic-and-races",
    "supply-chain",
    "infrastructure",
    "recovery-and-auditing",
)
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_ASSESSMENT_BYTES = 256 * 1024
MAX_RECEIPT_BYTES = 32 * 1024


@dataclass(frozen=True)
class DraftExport:
    path: Path
    payload: dict[str, object]
    approval_body: str
    draft_sha256: str
    approval_body_sha256: str


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args], cwd=root, text=True, capture_output=True, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("Git identity evidence could not be read") from None
    if result.returncode:
        raise ValueError("Git identity evidence could not be verified")
    return result.stdout.strip()


def _resolve_commit(root: Path, sha: str) -> str:
    if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
        raise ValueError("Merge SHA must be a lowercase full Git commit SHA")
    resolved = _git(root, "rev-parse", "--verify", f"{sha}^{{commit}}")
    if resolved != sha:
        raise ValueError("Merge SHA is not the exact requested Git commit")
    return resolved


def _parents(root: Path, commit: str) -> tuple[str, str]:
    fields = _git(root, "rev-list", "--parents", "-n", "1", commit).split()
    if len(fields) != 3 or fields[0] != commit:
        raise ValueError("Each pull request merge must be a two-parent Git commit")
    if any(not SHA_RE.fullmatch(item) for item in fields):
        raise ValueError("Git returned a malformed commit identity")
    return fields[1], fields[2]


def _tree(root: Path, commit: str) -> str:
    tree = _git(root, "rev-parse", "--verify", f"{commit}^{{tree}}")
    if not SHA_RE.fullmatch(tree):
        raise ValueError("Git returned a malformed tree identity")
    return tree


def _ancestor(root: Path, older: str, newer: str, reason: str) -> None:
    try:
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", older, newer],
            cwd=root,
            text=True,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise ValueError(reason) from None


def _clean_head(root: Path) -> str:
    dirty = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise ValueError("Historical receipt export requires a clean committed checkout")
    head = _git(root, "rev-parse", "--verify", "HEAD^{commit}")
    if not SHA_RE.fullmatch(head):
        raise ValueError("Workflow checkout HEAD is not a full commit SHA")
    return head


def _runs_dir(root: Path) -> Path:
    runs = root / ".agent" / ".runs"
    if any(part.is_symlink() for part in (root / ".agent", runs)):
        raise ValueError("Review evidence root may not contain symlinks")
    try:
        resolved = runs.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        raise ValueError("Review evidence root must be inside this checkout") from None
    if not resolved.is_dir():
        raise ValueError("Review evidence root is not a directory")
    return resolved


def _package_path(root: Path, runs: Path, candidate: Path) -> Path:
    path = candidate if candidate.is_absolute() else root / candidate
    if path.is_symlink():
        raise ValueError("Review package path may not be a symlink")
    try:
        resolved = path.resolve(strict=True)
        if resolved.parent != runs or not resolved.name.startswith("review-"):
            raise ValueError()
    except (OSError, ValueError):
        raise ValueError("Review package must be a direct .agent/.runs/review-* directory") from None
    if not resolved.is_dir():
        raise ValueError("Review package must be a directory")
    return resolved


def _safe_evidence_file(root: Path, runs: Path, candidate: Path, *, max_bytes: int) -> tuple[Path, bytes]:
    path = candidate if candidate.is_absolute() else root / candidate
    if path.is_symlink():
        raise ValueError("Evidence file may not be a symlink")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(runs)
        info = resolved.stat()
    except (OSError, ValueError):
        raise ValueError("Evidence file must be a regular file under .agent/.runs") from None
    if not resolved.is_file() or info.st_size > max_bytes:
        raise ValueError("Evidence file is not regular or exceeds its size limit")
    data = resolved.read_bytes()
    if len(data) != info.st_size or len(data) > max_bytes:
        raise ValueError("Evidence file changed while being read")
    return resolved, data


def _partition_metadata(root: Path, package: Path, head: str, base: str):
    if (package / "partition.json").is_symlink():
        raise ValueError("Partition review manifest may not be a symlink")
    try:
        sys_path = str(root / ".agent" / "runtime")
        import sys

        if sys_path not in sys.path:
            sys.path.insert(0, sys_path)
        from agent_cli.review.partition import load_partition
        from agent_cli.review.partition_orchestrator import PartitionOrchestrator

        part = load_partition(package, root=root)
        if not PartitionOrchestrator({}).clearance_valid(part):
            raise ValueError("Partition review is incomplete or failed runtime integration")
        manifest = part.root_package.manifest
        if manifest.head_sha != head or manifest.base_sha != base:
            raise ValueError("Partition review identities differ from original Git commits")
        result_path = package / "partition-results.json"
        if result_path.is_symlink() or not result_path.is_file():
            raise ValueError("Partition review results are missing or unsafe")
        result_bytes = result_path.read_bytes()
        if len(result_bytes) > MAX_ASSESSMENT_BYTES:
            raise ValueError("Partition review results exceed the size limit")
        raw_findings = (package / "findings.json").read_bytes()
        metadata = {
            "status": "passed",
            "verdict": "pass",
            "author_provider": manifest.author_provider,
            "reviewer_provider": manifest.reviewer_provider,
            "head_sha": head,
            "base_sha": base,
            "diff_sha256": manifest.full_diff_sha256,
            "manifest_sha256": part.manifest_sha256,
            "findings_sha256": hashlib.sha256(raw_findings).hexdigest(),
            "partitioned": True,
            "audit_sha256": hashlib.sha256(result_bytes).hexdigest(),
        }
        return metadata
    except ValueError:
        raise
    except Exception as exc:
        # Runtime package parsing has several typed blocked/error variants.
        if exc.__class__.__name__ in {"ReviewPackageBlocked", "OSError", "KeyError", "TypeError"}:
            raise ValueError("Partition review is incomplete, unsafe or invalid") from None
        raise


def _review(root: Path, package: Path, head: str, base: str) -> dict[str, object]:
    if (package / "partition.json").exists():
        metadata = _partition_metadata(root, package, head, base)
    else:
        metadata, audit_hash = review_metadata(
            root, package, head, base, author_providers=AUTHOR_PROVIDERS
        )
        metadata = {**metadata, "partitioned": False, "audit_sha256": audit_hash}
    if (
        metadata.get("head_sha") != head
        or metadata.get("base_sha") != base
        or metadata.get("status") != "passed"
        or metadata.get("verdict") != "pass"
        or metadata.get("author_provider") not in AUTHOR_PROVIDERS
        or metadata.get("reviewer_provider") != REVIEWER_PROVIDER
        or not HASH_RE.fullmatch(str(metadata.get("diff_sha256", "")))
        or not HASH_RE.fullmatch(str(metadata.get("manifest_sha256", "")))
        or not HASH_RE.fullmatch(str(metadata.get("findings_sha256", "")))
        or not HASH_RE.fullmatch(str(metadata.get("audit_sha256", "")))
    ):
        raise ValueError("Historical review metadata is invalid or not bound to the original commits")
    return metadata


def _assessment(root: Path, runs: Path, candidate: Path, head: str, base: str, diff_sha: str, scope: list[str]) -> str:
    _path, data = _safe_evidence_file(root, runs, candidate, max_bytes=MAX_ASSESSMENT_BYTES)
    try:
        record = json.loads(data, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("Security assessment is malformed") from None
    assessment = record.get("assessment") if isinstance(record, dict) else None
    if not isinstance(assessment, dict):
        raise ValueError("Security assessment record is missing its assessment object")  # noqa: TRY004 -- malformed evidence fails validation
    if (
        assessment.get("head_sha") != head
        or assessment.get("base_sha") != base
        or assessment.get("diff_sha256") != diff_sha
        or assessment.get("reviewed_scope") != scope
        or assessment.get("approved_profile") != "standard"
        or assessment.get("assessed_profile") != "standard"
        or assessment.get("review_lenses") != list(ALL_LENSES)
    ):
        raise ValueError("Security assessment does not match original review identity, scope or Standard lenses")
    # The owner exception supplies GitHub authorization. A draft must never
    # represent an absent SSH signature as a successful security clearance.
    for key in ("ssh_clearance", "signature_status", "security_clearance"):
        value = assessment.get(key)
        if value is True or (isinstance(value, str) and value in {"passed", "signed", "verified"}):
            raise ValueError("Security assessment may not claim absent SSH authorization passed")
    return hashlib.sha256(data).hexdigest()


def _document_hash(root: Path, commit: str, relative: str) -> str:
    listing = _git(root, "ls-tree", commit, "--", relative)
    fields = listing.split(None, 3)
    if len(fields) != 4 or fields[0] not in {"100644", "100755"} or fields[1] != "blob" or fields[3] != relative:
        raise ValueError("Required release evidence document is missing or not a regular file in workflow tree")
    raw = subprocess.run(
        ["git", "show", f"{commit}:{relative}"], cwd=root,
        capture_output=True, check=False,
    )
    if raw.returncode:
        raise ValueError("Required release evidence document could not be read from workflow tree")
    return hashlib.sha256(raw.stdout).hexdigest()


def _write_new_file(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("Existing receipt must be preserved; choose a new output path")
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
        # Canonicalize the parent (macOS commonly exposes /tmp and /var via
        # system symlinks) and place the receipt there with exclusive linking.
        parent = parent.resolve(strict=True)
        path = parent / path.name
        fd, temporary = tempfile.mkstemp(prefix=".owner-release-draft-", dir=parent)
        temp_path = Path(temporary)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_path, 0o600)
            os.link(temp_path, path, follow_symlinks=False)
        finally:
            temp_path.unlink(missing_ok=True)
    except FileExistsError:
        raise ValueError("Existing receipt must be preserved; choose a new output path") from None
    except ValueError:
        raise
    except OSError:
        raise ValueError("Receipt draft could not be written safely") from None
    if path.is_symlink() or not path.is_file():
        raise ValueError("Receipt output is not a regular file")


def create_draft_receipt(
    root: Path,
    output: Path,
    source_merge_sha: str,
    workflow_merge_sha: str,
    source_pr: int,
    workflow_pr: int,
    source_review: Path,
    workflow_review: Path,
    source_assessment: Path,
    workflow_assessment: Path,
    ci_run_ids: dict[str, int],
    *,
    image_version: str,
    chart_version: str,
    api=None,
) -> DraftExport:
    """Write an unapproved schema-3 receipt from exact original review evidence.

    ``api`` may inject a read-only GitHub GET function for tests. The function
    captures CI run identity metadata only; the core live validator rechecks
    attempts, conclusion, job inventories and current GitHub authorization.
    """
    root = Path(root).resolve(strict=True)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("Existing receipt must be preserved; choose a new output path")
    original_head = _clean_head(root)
    source_merge = _resolve_commit(root, source_merge_sha)
    workflow_merge = _resolve_commit(root, workflow_merge_sha)
    source_base, source_head = _parents(root, source_merge)
    workflow_base, workflow_head = _parents(root, workflow_merge)
    if _tree(root, source_merge) != _tree(root, source_head):
        raise ValueError("Source merge tree differs from original reviewed source head")
    if _tree(root, workflow_merge) != _tree(root, workflow_head):
        raise ValueError("Workflow merge tree differs from original reviewed workflow head")
    _ancestor(root, source_head, workflow_head, "Source review head is not an ancestor of workflow review head")
    _ancestor(root, source_merge, workflow_base, "Source merge is not an ancestor of the workflow review base")
    _ancestor(root, source_merge, workflow_merge, "Source merge is not an ancestor of workflow merge")
    if original_head not in {workflow_head, workflow_merge} or _tree(root, original_head) != _tree(root, workflow_head):
        raise ValueError("Workflow checkout HEAD must be the reviewed workflow head or its same-tree merge")
    if type(source_pr) is not int or source_pr <= 0 or type(workflow_pr) is not int or workflow_pr <= 0 or source_pr == workflow_pr:
        raise ValueError("Source and workflow PR numbers must be positive and distinct")
    if type(ci_run_ids) is not dict or set(ci_run_ids) != set(RUN_PATHS):
        raise ValueError("Exactly four source/workflow CI run IDs are required")
    if any(type(run_id) is not int or run_id <= 0 for run_id in ci_run_ids.values()) or len(set(ci_run_ids.values())) != 4:
        raise ValueError("CI run IDs must be positive, unique integers")

    runs = _runs_dir(root)
    source_package = _package_path(root, runs, Path(source_review))
    workflow_package = _package_path(root, runs, Path(workflow_review))
    source_review_data = _review(root, source_package, source_head, source_base)
    workflow_review_data = _review(root, workflow_package, workflow_head, workflow_base)

    source_scope = sorted(_git(root, "diff", "--name-only", source_base, source_head).splitlines())
    workflow_scope = sorted(_git(root, "diff", "--name-only", workflow_base, workflow_head).splitlines())
    source_assessment_hash = _assessment(
        root, runs, Path(source_assessment), source_head, source_base,
        str(source_review_data["diff_sha256"]), source_scope,
    )
    workflow_assessment_hash = _assessment(
        root, runs, Path(workflow_assessment), workflow_head, workflow_base,
        str(workflow_review_data["diff_sha256"]), workflow_scope,
    )

    github_get = api or owner_approval.github_api
    ci_runs = []
    for role in ("source-quality", "source-artifacts", "workflow-quality", "workflow-artifacts"):
        expected_head = source_head if role.startswith("source-") else workflow_head
        run_id = ci_run_ids[role]
        record = github_get(f"repos/{REPOSITORY}/actions/runs/{run_id}")
        attempt = record.get("run_attempt") if isinstance(record, dict) else None
        if (
            not isinstance(record, dict)
            or record.get("id") != run_id
            or record.get("head_sha") != expected_head
            or record.get("path") != RUN_PATHS[role]
            or type(attempt) is not int
            or attempt <= 0
        ):
            raise ValueError("CI run metadata does not identify the exact original review head and workflow")
        ci_runs.append({
            "role": role,
            "id": run_id,
            "attempt": attempt,
            "head_sha": expected_head,
            "path": RUN_PATHS[role],
        })

    evidence = {
        "source-review-audit": str(source_review_data["audit_sha256"]),
        "workflow-review-audit": str(workflow_review_data["audit_sha256"]),
        "source-security-assessment": source_assessment_hash,
        "workflow-security-assessment": workflow_assessment_hash,
    }
    evidence.update({key: _document_hash(root, workflow_head, path) for key, path in DOCUMENTS.items()})
    authorization = {
        "method": "github-owner-reviewed-release",
        "comment_id": 0,
        "actor_id": owner_approval.OWNER_ID,
        "actor_login": owner_approval.OWNER,
        "comment_body_sha256": "0" * 64,
        "security_profile": "standard",
        "ssh_clearance": "waived-by-owner",
        "canonical_release_gate": "not-claimed",
    }
    payload = {
        "schema_version": 3,
        "repository": REPOSITORY,
        # Receipt source/workflow fields identify the merged source PR and the
        # reviewed publication-workflow merge. Review and CI records below keep
        # the original pre-merge review heads and bases unchanged.
        "source_sha": source_merge,
        "workflow_sha": workflow_merge,
        "image_version": image_version,
        "chart_version": chart_version,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "authorization": authorization,
        "provenance": {"source_pr": source_pr, "workflow_pr": workflow_pr},
        "reviews": {"source": source_review_data, "workflow": workflow_review_data},
        "ci_runs": ci_runs,
        "evidence_sha256": evidence,
    }
    try:
        from artifacts.owner_release import (
            approval_body,
            parse_owner_receipt,
            validate_standard_policy,
        )
    except ImportError:
        raise ValueError("Schema-3 owner release validator is unavailable") from None
    # Check the actual committed policy at both PR boundaries and merge commits
    # before generating an approval body or creating any draft artifact.
    validate_standard_policy(root, payload)
    body = approval_body(payload)
    if not isinstance(body, str) or not body:
        raise ValueError("Core owner approval body is invalid")
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    payload["authorization"]["comment_body_sha256"] = body_hash
    parse_owner_receipt(payload, source_merge, allow_unapproved=True)

    raw = _canonical(payload)
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError("Receipt exceeds 32 KiB")
    if _git(root, "rev-parse", "--verify", "HEAD^{commit}") != original_head or _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("Workflow checkout changed during receipt export")
    _write_new_file(output, raw + b"\n")
    digest = hashlib.sha256(raw).hexdigest()
    return DraftExport(
        path=output,
        payload=payload,
        approval_body=body,
        draft_sha256=digest,
        approval_body_sha256=body_hash,
    )
