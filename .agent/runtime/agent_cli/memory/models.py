from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re


_MEMORY_ID = re.compile(r"^(?:MEM|CAND)-[A-Z0-9][A-Z0-9-]{2,}$")
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
SUPPORTED_TYPES = frozenset(
    {
        "architecture",
        "constraint",
        "decision",
        "discovery",
        "fact",
        "runbook",
        "security",
        "verification",
        "workflow",
    }
)
SUPPORTED_SENSITIVITY = frozenset({"public", "internal", "private"})
SUPPORTED_STATUS = frozenset({"active", "possibly-stale", "superseded", "revoked"})
SUPPORTED_PROVIDERS = frozenset({"claude", "gemini", "codex", "human", "import"})


@dataclass(frozen=True)
class MemoryCandidate:
    id: str
    type: str
    title: str
    summary: str
    details: str
    components: tuple[str, ...]
    paths: tuple[str, ...]
    evidence: tuple[str, ...]
    source_provider: str
    source_session: str
    branch: str
    observed_commit: str
    created_at: str
    sensitivity: str
    reuse_guidance: str

    @property
    def trust(self) -> str:
        return "local-candidate"


@dataclass(frozen=True)
class CanonicalMemory(MemoryCandidate):
    status: str
    last_verified_commit: str
    supersedes: tuple[str, ...]

    @property
    def trust(self) -> str:
        return "reviewed-canonical"


def is_repository_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts


def validate_candidate(candidate: MemoryCandidate) -> None:
    if not _MEMORY_ID.fullmatch(candidate.id):
        raise ValueError(f"invalid memory id: {candidate.id}")
    if candidate.type not in SUPPORTED_TYPES:
        raise ValueError(f"unsupported memory type: {candidate.type}")
    if candidate.sensitivity not in SUPPORTED_SENSITIVITY:
        raise ValueError(f"unsupported sensitivity: {candidate.sensitivity}")
    if candidate.source_provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"unsupported source provider: {candidate.source_provider}")
    if not _HEX_40.fullmatch(candidate.observed_commit):
        raise ValueError("observed_commit must be a 40-character lowercase hex SHA")
    for field, value in (
        ("title", candidate.title),
        ("summary", candidate.summary),
        ("details", candidate.details),
        ("source_session", candidate.source_session),
        ("branch", candidate.branch),
        ("created_at", candidate.created_at),
        ("reuse_guidance", candidate.reuse_guidance),
    ):
        if not value.strip():
            raise ValueError(f"{field} must not be empty")
    if not candidate.evidence:
        raise ValueError("evidence must not be empty")
    for value in (*candidate.paths, *candidate.evidence):
        if not is_repository_relative(value):
            raise ValueError(f"path must be repository-relative: {value}")


def validate_canonical(record: CanonicalMemory) -> None:
    validate_candidate(record)
    if not record.id.startswith("MEM-"):
        raise ValueError("canonical memory ID must start with MEM-")
    if record.status not in SUPPORTED_STATUS:
        raise ValueError(f"unsupported memory status: {record.status}")
    if not _HEX_40.fullmatch(record.last_verified_commit):
        raise ValueError("last_verified_commit must be a 40-character lowercase hex SHA")
    if any(not item.startswith("MEM-") for item in record.supersedes):
        raise ValueError("supersedes must contain canonical memory IDs")
