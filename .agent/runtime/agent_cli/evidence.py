from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
import re

from agent_cli.paths import atomic_write
from agent_cli.process import CommandResult
from agent_cli.redaction import redact


_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_COMMAND_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


@dataclass(frozen=True)
class EvidenceRecord:
    command_id: str
    commit: str
    diff_sha256: str
    exit_code: int | None
    status: str
    output_sha256: str
    tool_version: str
    started_at: str
    duration_ms: int

    def __post_init__(self) -> None:
        if not _COMMAND_ID.fullmatch(self.command_id):
            raise ValueError("invalid command_id")
        if not _HEX_40.fullmatch(self.commit):
            raise ValueError("commit must be a 40-character lowercase hex SHA")
        if not _HEX_64.fullmatch(self.diff_sha256):
            raise ValueError("diff_sha256 must be a 64-character lowercase hex hash")
        if not _HEX_64.fullmatch(self.output_sha256):
            raise ValueError("output_sha256 must be a 64-character lowercase hex hash")
        if self.status not in {"passed", "failed", "timeout", "incomplete"}:
            raise ValueError("invalid evidence status")
        if self.duration_ms < 0:
            raise ValueError("duration_ms must not be negative")
        if not self.started_at or not self.tool_version:
            raise ValueError("started_at and tool_version are required")

    def is_fresh(self, commit: str, diff_sha256: str) -> bool:
        return self.commit == commit and self.diff_sha256 == diff_sha256


class EvidenceStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def write(self, record: EvidenceRecord) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / (
            f"{record.command_id}-{record.commit[:8]}-{record.output_sha256[:8]}.json"
        )
        payload = json.dumps(
            asdict(record),
            sort_keys=True,
            indent=2,
            separators=(",", ": "),
        ) + "\n"
        atomic_write(path, payload)
        return path


def record_result(
    *,
    command_id: str,
    commit: str,
    diff_sha256: str,
    result: CommandResult,
    started_at: str,
    tool_version: str,
) -> EvidenceRecord:
    combined = redact(f"{result.stdout}\n{result.stderr}").text.encode("utf-8")
    if result.timed_out:
        status = "timeout"
    elif result.exit_code == 0:
        status = "passed"
    else:
        status = "failed"
    return EvidenceRecord(
        command_id=command_id,
        commit=commit,
        diff_sha256=diff_sha256,
        exit_code=result.exit_code,
        status=status,
        output_sha256=sha256(combined).hexdigest(),
        tool_version=tool_version,
        started_at=started_at,
        duration_ms=result.duration_ms,
    )
