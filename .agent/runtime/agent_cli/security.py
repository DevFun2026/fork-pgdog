from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from pathlib import Path
import json
import re
import subprocess
import tempfile
from typing import Mapping


PROFILES = ("baseline", "standard", "high")
PROFILE_RANK = {name: index for index, name in enumerate(PROFILES)}
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
SCANNERS = ("dependency", "license", "sast", "iac", "container")
SCANNER_STATUSES = frozenset(
    {"passed", "failed", "skipped", "timeout", "not-configured"}
)


class SecurityPolicyError(ValueError):
    """Raised when a requested assessment weakens approved security policy."""


def validate_signed_approval(
    root: Path,
    assessment: "SecurityAssessment",
    evidence_path: Path,
    signature_path: Path,
) -> dict[str, object]:
    try:
        evidence_bytes = evidence_path.read_bytes()
        signature_bytes = signature_path.read_bytes()
        payload = json.loads(evidence_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise SecurityPolicyError(f"invalid signed security approval: {exc}") from exc
    required = {
        "schema_version",
        "decision",
        "reviewer_identity",
        "reviewer_provider",
        "author_provider",
        "assessment",
        "assessment_sha256",
        "reviewed_at",
        "provenance",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise SecurityPolicyError("security approval does not match the strict schema")
    if payload["schema_version"] != 1 or payload["decision"] != "approve":
        raise SecurityPolicyError("security approval decision is not approve")
    for field in ("reviewer_identity", "reviewer_provider", "author_provider", "reviewed_at"):
        if not isinstance(payload[field], str) or not payload[field].strip():
            raise SecurityPolicyError(f"security approval {field} is required")
    if payload["reviewer_provider"] == payload["author_provider"]:
        raise SecurityPolicyError("security reviewer must be independent from author")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", payload["reviewed_at"]):
        raise SecurityPolicyError("security approval reviewed_at must be UTC ISO-8601")
    assessment_payload = json.loads(json.dumps(assessment.to_dict(), sort_keys=True))
    canonical_assessment = json.dumps(
        assessment_payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if (
        payload["assessment"] != assessment_payload
        or payload["assessment_sha256"] != sha256(canonical_assessment).hexdigest()
        or payload["provenance"] != "ssh-signature-from-base-trusted-signer"
    ):
        raise SecurityPolicyError("security approval is stale or has the wrong scope")
    allowed = subprocess.run(
        ("git", "show", f"{assessment.base_sha}:.agent/security/allowed_signers"),
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if allowed.returncode != 0 or not allowed.stdout.strip():
        raise SecurityPolicyError("base revision has no trusted security signers")
    with tempfile.TemporaryDirectory(prefix="agent-security-approval-") as directory:
        allowed_path = Path(directory) / "allowed_signers"
        allowed_path.write_text(allowed.stdout, encoding="utf-8")
        verified = subprocess.run(
            (
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed_path),
                "-I",
                payload["reviewer_identity"],
                "-n",
                "agent-security-approval",
                "-s",
                str(signature_path),
            ),
            cwd=root,
            input=evidence_bytes,
            capture_output=True,
            check=False,
        )
    if verified.returncode != 0:
        raise SecurityPolicyError("security approval signature is not trusted")
    return {
        "path": evidence_path.relative_to(root).as_posix(),
        "sha256": sha256(evidence_bytes).hexdigest(),
        "signature_path": signature_path.relative_to(root).as_posix(),
        "signature_sha256": sha256(signature_bytes).hexdigest(),
        "reviewer_identity": payload["reviewer_identity"],
        "reviewer_provider": payload["reviewer_provider"],
        "author_provider": payload["author_provider"],
        "provenance": payload["provenance"],
    }


@dataclass(frozen=True)
class ChangeImpact:
    changed_paths: tuple[str, ...]
    trust_boundary_changed: bool = False
    external_integration: bool = False
    authentication_changed: bool = False
    sensitive_data_changed: bool = False
    session_or_crypto_changed: bool = False
    business_logic_changed: bool = False
    dependency_changed: bool = False
    infrastructure_changed: bool = False
    recovery_changed: bool = False


@dataclass(frozen=True)
class SecurityAssessment:
    approved_profile: str
    assessed_profile: str
    reviewed_scope: tuple[str, ...]
    review_lenses: tuple[str, ...]
    required_artifacts: tuple[str, ...]
    checks_performed: tuple[str, ...]
    unverified_areas: tuple[str, ...]
    residual_risks: tuple[str, ...]
    base_sha: str = ""
    head_sha: str = ""
    diff_sha256: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ReleaseContext:
    merge_status: str
    security_status: str
    threat_model_delta_required: bool
    threat_model_delta_present: bool
    scanner_statuses: Mapping[str, str]
    required_scanners: tuple[str, ...]
    clean_checkout_smoke: bool
    documentation_current: bool
    release_notes: bool
    migration_backup_rollback: bool
    residual_risks: bool


@dataclass(frozen=True)
class ReleaseAssessment:
    status: str
    reasons: tuple[str, ...]
    not_configured: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _validate_profile(profile: str) -> None:
    if profile not in PROFILE_RANK:
        raise SecurityPolicyError(f"unsupported security profile: {profile}")


def assess_change(
    *,
    approved_profile: str,
    requested_profile: str,
    change: ChangeImpact,
) -> SecurityAssessment:
    _validate_profile(approved_profile)
    _validate_profile(requested_profile)
    if PROFILE_RANK[requested_profile] < PROFILE_RANK[approved_profile]:
        raise SecurityPolicyError(
            f"cannot downgrade approved profile {approved_profile} to {requested_profile}"
        )

    lenses = {"input-and-injection", "data-and-secrets", "recovery-and-auditing"}
    if requested_profile in {"standard", "high"}:
        lenses.update({"supply-chain", "infrastructure", "business-logic-and-races"})
    if requested_profile == "high":
        lenses.update(ALL_LENSES)
    if change.authentication_changed:
        lenses.add("authentication-and-authorization")
    if change.external_integration or change.trust_boundary_changed:
        lenses.update({"input-and-injection", "data-and-secrets", "infrastructure"})
    if change.sensitive_data_changed:
        lenses.add("data-and-secrets")
    if change.session_or_crypto_changed:
        lenses.add("session-and-cryptography")
    if change.business_logic_changed:
        lenses.add("business-logic-and-races")
    if change.dependency_changed:
        lenses.add("supply-chain")
    if change.infrastructure_changed:
        lenses.add("infrastructure")
    if change.recovery_changed:
        lenses.add("recovery-and-auditing")

    required_artifacts = ["security_review", "residual_risks"]
    if change.trust_boundary_changed or change.external_integration:
        required_artifacts.append("threat_model_delta")
    scope = tuple(sorted(set(change.changed_paths))) or ("no-uncommitted-paths",)
    unverified = (
        "runtime deployment behavior outside the supplied repository evidence",
        "provider and dependency behavior not exercised by deterministic checks",
    )
    residual = (
        "AI review can miss defects and does not replace deterministic testing",
        "plaintext local memory and review packages depend on host access controls",
    )
    return SecurityAssessment(
        approved_profile=approved_profile,
        assessed_profile=requested_profile,
        reviewed_scope=scope,
        review_lenses=tuple(lens for lens in ALL_LENSES if lens in lenses),
        required_artifacts=tuple(required_artifacts),
        checks_performed=("profile-policy", "change-impact", "review-lens-selection"),
        unverified_areas=unverified,
        residual_risks=residual,
    )


def render_security_report(assessment: SecurityAssessment) -> str:
    def section(title: str, values: tuple[str, ...]) -> list[str]:
        return [f"## {title}", "", *(f"- {value}" for value in values), ""]

    lines = [
        "# Security assessment",
        "",
        f"Approved profile: `{assessment.approved_profile}`",
        f"Assessed profile: `{assessment.assessed_profile}`",
        "",
    ]
    lines.extend(section("Reviewed scope", assessment.reviewed_scope))
    lines.extend(section("Checks performed", assessment.checks_performed))
    lines.extend(section("Review lenses", assessment.review_lenses))
    lines.extend(section("Unverified areas", assessment.unverified_areas))
    lines.extend(section("Residual risk", assessment.residual_risks))
    return "\n".join(lines).rstrip() + "\n"


def release_check(context: ReleaseContext) -> ReleaseAssessment:
    unknown_required = sorted(set(context.required_scanners) - set(SCANNERS))
    if unknown_required:
        raise SecurityPolicyError(f"unknown required scanner: {unknown_required[0]}")
    reasons: list[str] = []
    if context.merge_status != "passed":
        reasons.append(f"merge gate: {context.merge_status}")
    if context.security_status != "passed":
        reasons.append(f"security review: {context.security_status}")
    if context.threat_model_delta_required and not context.threat_model_delta_present:
        reasons.append("threat-model-delta")
    not_configured: list[str] = []
    for scanner in SCANNERS:
        status = context.scanner_statuses.get(scanner, "not-configured")
        if status not in SCANNER_STATUSES:
            raise SecurityPolicyError(f"invalid scanner status for {scanner}: {status}")
        if status == "not-configured":
            not_configured.append(scanner)
        if scanner in context.required_scanners and status != "passed":
            reasons.append(f"required scanner {scanner}: {status}")
        elif status == "failed":
            reasons.append(f"scanner {scanner}: failed")
    required_flags = {
        "clean-checkout-smoke": context.clean_checkout_smoke,
        "documentation-current": context.documentation_current,
        "release-notes": context.release_notes,
        "migration-backup-rollback": context.migration_backup_rollback,
        "residual-risks": context.residual_risks,
    }
    reasons.extend(name for name, present in required_flags.items() if not present)
    return ReleaseAssessment(
        status="blocked" if reasons else "passed",
        reasons=tuple(reasons),
        not_configured=tuple(not_configured),
    )


def _git(root: Path, *arguments: str, binary: bool = False):
    result = subprocess.run(
        ("git", *arguments),
        cwd=root,
        text=not binary,
        capture_output=True,
        check=False,
        shell=False,
    )
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace") if binary else result.stderr
        raise SecurityPolicyError(f"git command failed: {error.strip()}")
    return result.stdout


def assess_repository(
    root: Path,
    *,
    approved_profile: str,
    base: str = "HEAD~1",
    head: str = "HEAD",
) -> SecurityAssessment:
    head_sha = str(_git(root, "rev-parse", "--verify", f"{head}^{{commit}}")).strip()
    try:
        base_sha = str(
            _git(root, "rev-parse", "--verify", f"{base}^{{commit}}")
        ).strip()
    except SecurityPolicyError:
        if base != "HEAD~1":
            raise
        base_sha = head_sha
    diff_bytes = bytes(_git(root, "diff", "--binary", base_sha, head_sha, binary=True))
    tracked = str(_git(root, "diff", "--name-only", base_sha, head_sha))
    untracked = subprocess.run(
        ("git", "ls-files", "--others", "--exclude-standard"),
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        shell=False,
    )
    paths = tuple(
        sorted(
            {
                item
                for item in (*tracked.splitlines(), *untracked.stdout.splitlines())
                if item
            }
        )
    )
    lowered = tuple(path.lower() for path in paths)
    change = ChangeImpact(
        changed_paths=paths,
        trust_boundary_changed=any("project-model" in path for path in lowered),
        external_integration=any("provider" in path or "integration" in path for path in lowered),
        authentication_changed=any("auth" in path for path in lowered),
        sensitive_data_changed=any("memory" in path or "secret" in path for path in lowered),
        session_or_crypto_changed=any("crypto" in path or "session" in path for path in lowered),
        business_logic_changed=any(path.startswith(("src/", "app/")) for path in lowered),
        dependency_changed=any(
            path.endswith(("lock", "lock.json", "requirements.txt", "pyproject.toml"))
            for path in lowered
        ),
        infrastructure_changed=any(
            path.startswith((".github/", ".gitlab", "infra/")) or "docker" in path
            for path in lowered
        ),
        recovery_changed=any("migration" in path or "backup" in path for path in lowered),
    )
    return replace(
        assess_change(
            approved_profile=approved_profile,
            requested_profile=approved_profile,
            change=change,
        ),
        base_sha=base_sha,
        head_sha=head_sha,
        diff_sha256=sha256(diff_bytes).hexdigest(),
    )
