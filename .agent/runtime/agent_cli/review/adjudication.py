from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agent_cli.paths import PathPolicyError, resolve_inside
from agent_cli.review.models import AdjudicatedFinding, ReviewFinding


@dataclass(frozen=True)
class ReproductionEvidence:
    reference: str
    reproduced: bool
    notes: str


def _location_exists(finding: ReviewFinding, root: Path | None) -> bool:
    if root is None or not finding.file:
        return True
    try:
        path = resolve_inside(root, finding.file)
    except PathPolicyError:
        return False
    if not path.is_file():
        return False
    if finding.line is None:
        return True
    try:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
    except UnicodeDecodeError:
        return False
    return 1 <= finding.line <= line_count


def adjudicate(
    finding: ReviewFinding,
    *,
    evidence: ReproductionEvidence | None,
    root: str | Path | None = None,
    reject: bool = False,
    rejection_reason: str | None = None,
) -> AdjudicatedFinding:
    repository = Path(root) if root is not None else None
    if reject:
        if not rejection_reason or not rejection_reason.strip():
            raise ValueError("rejection reason is required")
        return AdjudicatedFinding(
            finding,
            "rejected",
            evidence.reference if evidence else None,
            rejection_reason.strip(),
            False,
        )
    if evidence is None or not evidence.reproduced or not _location_exists(finding, repository):
        return AdjudicatedFinding(
            finding,
            "needs-evidence",
            evidence.reference if evidence else None,
            "finding has not been reproduced against a valid current location",
            finding.severity in {"critical", "high"},
        )
    return AdjudicatedFinding(
        finding,
        "confirmed",
        evidence.reference,
        evidence.notes,
        finding.severity in {"critical", "high"},
    )


def adjudicate_findings(
    findings: list[dict[str, object]],
    decisions: list[dict[str, object]],
    *,
    root: str | Path,
) -> tuple[list[dict[str, object]], tuple[str, ...]]:
    by_id: dict[str, dict[str, object]] = {}
    for decision in decisions:
        finding_id = decision.get("id")
        if not isinstance(finding_id, str) or not finding_id or finding_id in by_id:
            raise ValueError("adjudication decisions require unique non-empty finding IDs")
        by_id[finding_id] = decision
    expected_ids = {
        item.get("id") for item in findings if isinstance(item.get("id"), str)
    }
    if set(by_id) != expected_ids or len(expected_ids) != len(findings):
        raise ValueError("adjudication decisions must cover every finding exactly once")

    output: list[dict[str, object]] = []
    blocking: list[str] = []
    for raw in findings:
        finding = ReviewFinding(**raw)
        decision = by_id[finding.id]
        disposition = decision.get("disposition")
        if disposition not in {"confirmed", "rejected", "needs-evidence"}:
            raise ValueError(f"unsupported disposition for {finding.id}")
        reference = decision.get("evidence_reference")
        reason = decision.get("reason")
        if reference is not None and not isinstance(reference, str):
            raise ValueError(f"evidence_reference for {finding.id} must be a string")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"reason for {finding.id} is required")
        reproduced = disposition == "confirmed"
        result = adjudicate(
            finding,
            evidence=(
                ReproductionEvidence(reference or "", reproduced, reason.strip())
                if disposition != "rejected"
                else None
            ),
            root=root,
            reject=disposition == "rejected",
            rejection_reason=reason,
        )
        if disposition == "needs-evidence" and result.disposition == "confirmed":
            raise ValueError(f"invalid needs-evidence decision for {finding.id}")
        record = {
            "id": finding.id,
            "severity": finding.severity,
            "disposition": result.disposition,
            "evidence_reference": result.evidence_reference,
            "reason": result.reason,
            "blocks_merge": result.blocks_merge,
        }
        output.append(record)
        if result.blocks_merge:
            blocking.append(finding.id)
    return output, tuple(blocking)
