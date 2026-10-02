"""Owner-reviewed metadata handoff from the existing local release gate."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

REPOSITORY = "DevFun2026/fork-pgdog"
SHA = re.compile(r"[0-9a-f]{40}")
HASH = re.compile(r"[0-9a-f]{64}")
REQUIRED_EVIDENCE = {"code-review", "cross-review", "security-clearance", "security-checks", "documentation-impact", "threat-model-delta", "clean-checkout-smoke", "release-notes", "migration-rollback", "residual-risks"}
FIELDS = {"schema_version", "repository", "source_sha", "base_sha", "worktree_diff_sha256", "created_at", "gate", "evidence_sha256", "artifact_checks"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def validate_version(value):
    numeric = r"(?:0|[1-9][0-9]*)"
    if not isinstance(value, str) or not re.fullmatch(rf"{numeric}\.{numeric}\.{numeric}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", value):
        raise ValueError("Expected an exact SemVer without v prefix or build metadata")
    if "-" in value:
        for part in value.split("-", 1)[1].split("."):
            if part.isdigit() and len(part) > 1 and part.startswith("0"):
                raise ValueError("SemVer prerelease numeric identifiers cannot have leading zeros")
    return value


def validate_digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("Expected a sha256 image digest")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def parse_receipt(raw, expected_hash, source_sha):
    if len(raw) > 32768:
        raise ValueError("Receipt exceeds 32 KiB")
    try:
        receipt = json.loads(raw, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("Malformed receipt JSON") from None
    if not isinstance(receipt, dict):
        raise ValueError("Unexpected receipt fields")
    if not isinstance(expected_hash, str) or not HASH.fullmatch(expected_hash) or hashlib.sha256(canonical(receipt)).hexdigest() != expected_hash:
        raise ValueError("Receipt differs from the owner-approved canonical SHA256")
    if receipt.get("schema_version") == 2:
        from artifacts.owner_approval import parse_initial_receipt
        return parse_initial_receipt(receipt, source_sha)
    if set(receipt) != FIELDS:
        raise ValueError("Unexpected receipt fields")
    if receipt["schema_version"] != 1 or isinstance(receipt["schema_version"], bool) or receipt["repository"] != REPOSITORY:
        raise ValueError("Unsupported receipt schema/repository")
    if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha) or receipt["source_sha"] != source_sha:
        raise ValueError("Receipt source differs from selected source SHA")
    if not isinstance(receipt["base_sha"], str) or not SHA.fullmatch(receipt["base_sha"]) or receipt["base_sha"] == source_sha:
        raise ValueError("Receipt requires a proper pre-integration review base")
    if receipt["worktree_diff_sha256"] != hashlib.sha256(b"").hexdigest():
        raise ValueError("Release receipt must describe a clean candidate")
    try:
        created = datetime.fromisoformat(receipt["created_at"].replace("Z", "+00:00"))
        if created.utcoffset() is None or created > datetime.now(timezone.utc):
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Invalid receipt UTC timestamp") from None
    gate = receipt["gate"]
    if not isinstance(gate, dict) or set(gate) != {"level", "status", "reasons", "executed"} or gate["level"] != "release" or gate["status"] != "passed" or gate["reasons"] != [] or gate["executed"] != ["lint", "test_full", "build", "smoke"]:
        raise ValueError("Receipt must contain the exact passed release GateResult")
    evidence = receipt["evidence_sha256"]
    if not isinstance(evidence, dict) or set(evidence) != REQUIRED_EVIDENCE or any(not isinstance(v, str) or not HASH.fullmatch(v) for v in evidence.values()):
        raise ValueError("Missing or invalid reviewed release evidence hashes")
    checks = receipt["artifact_checks"]
    if not isinstance(checks, dict) or set(checks) != {"status", "source_sha", "image_platforms", "chart", "container", "kubernetes", "container_scan", "iac_scan"} or checks["source_sha"] != source_sha or checks["image_platforms"] != ["linux/amd64", "linux/arm64"] or any(checks[k] != "passed" for k in ("status", "chart", "container", "kubernetes", "container_scan", "iac_scan")):
        raise ValueError("Both native platforms and artifact checks must pass for the selected source")
    return receipt


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=True).stdout.strip()


def create_receipt(root: Path, output: Path):
    if git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("Receipt requires a clean immutable candidate")
    source = git(root, "rev-parse", "HEAD")
    result = subprocess.run([str(root / "scripts/agent"), "verify", "release", "--timeout", "600", "--json"], cwd=root, text=True, capture_output=True)
    if result.returncode:
        raise ValueError("Existing release gate did not pass; no receipt exported")
    gate = json.loads(result.stdout, object_pairs_hook=unique_object)
    if gate.get("status") != "passed":
        raise ValueError("Existing release gate did not pass; no receipt exported")
    if git(root, "rev-parse", "HEAD") != source or git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("Candidate changed during release verification")
    runs = root / ".agent/.runs"
    review = json.loads((runs / "cross-review.json").read_text())
    base = review.get("base_sha")
    # Use the trusted runtime resolver, never an owner-selected or rewritten base.
    import sys
    sys.path.insert(0, str(root / ".agent/runtime"))
    from agent_cli.governance import resolve_trusted_base
    base, anchored = resolve_trusted_base(root, head=source)
    if anchored != source:
        raise ValueError("Source changed while resolving governance base")
    receipt = {"schema_version": 1, "repository": REPOSITORY, "source_sha": source, "base_sha": base,
               "worktree_diff_sha256": hashlib.sha256(b"").hexdigest(), "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
               "gate": gate, "evidence_sha256": {key: hashlib.sha256((runs / (key + ".json")).read_bytes()).hexdigest() for key in sorted(REQUIRED_EVIDENCE)},
               "artifact_checks": json.loads((runs / "artifacts/release-checks.json").read_text())}
    raw = canonical(receipt)
    digest = hashlib.sha256(raw).hexdigest()
    parse_receipt(raw, digest, source)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw + b"\n")
    return digest


def publish_preflight(root, raw, checksum, source, image_version, chart_version, ref, repository):
    if ref != "refs/heads/main" or repository != REPOSITORY:
        raise ValueError("Publication dispatch must come from this repository's main branch")
    receipt = parse_receipt(raw, checksum, source)
    validate_version(image_version); validate_version(chart_version)
    if receipt["schema_version"] == 2:
        import os
        from artifacts.owner_approval import validate_live
        if image_version != receipt["image_version"] or chart_version != receipt["chart_version"]:
            raise ValueError("Selected versions differ from the approved first release")
        validate_live(receipt, actor_id=os.environ.get("GITHUB_ACTOR_ID"), workflow_sha=os.environ.get("GITHUB_SHA"))
        subprocess.run(["git", "merge-base", "--is-ancestor", source, receipt["workflow_sha"]], cwd=root, check=True)
        subprocess.run(["git", "merge-base", "--is-ancestor", receipt["workflow_sha"], "origin/main"], cwd=root, check=True)
        return receipt
    subprocess.run(["git", "merge-base", "--is-ancestor", source, "origin/main"], cwd=root, check=True)
    subprocess.run(["git", "merge-base", "--is-ancestor", receipt["base_sha"], source], cwd=root, check=True)
    return receipt
