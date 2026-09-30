from __future__ import annotations

from dataclasses import fields
import json
from pathlib import Path
import re
import tomllib

from agent_cli.memory.models import CanonicalMemory, validate_canonical
from agent_cli.paths import atomic_write


class MemoryPolicyError(ValueError):
    """Raised when canonical memory could override policy or lose provenance."""


_METADATA_KEYS = {
    "id",
    "type",
    "status",
    "title",
    "components",
    "paths",
    "evidence",
    "source_provider",
    "source_session",
    "branch",
    "observed_commit",
    "created_at",
    "sensitivity",
    "last_verified_commit",
    "supersedes",
}
_POLICY_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard)\s+(?:the\s+)?(?:agents\.md|policy|instructions?)\b|"
    r"\b(?:bypass|override)\s+(?:the\s+)?(?:policy|gate|instructions?)\b",
    re.IGNORECASE,
)


def validate_record(record: CanonicalMemory) -> None:
    try:
        validate_canonical(record)
    except ValueError as exc:
        message = str(exc)
        if "repository-relative" in message:
            raise MemoryPolicyError(message) from exc
        if "evidence" in message:
            raise MemoryPolicyError(message) from exc
        raise MemoryPolicyError(message) from exc
    if _POLICY_OVERRIDE.search(
        "\n".join((record.summary, record.details, record.reuse_guidance))
    ):
        raise MemoryPolicyError("memory contains a policy instruction")


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_array(values: tuple[str, ...]) -> str:
    return json.dumps(list(values), ensure_ascii=False)


def render_record(record: CanonicalMemory) -> str:
    validate_record(record)
    metadata = [
        "+++",
        f"id = {_toml_string(record.id)}",
        f"type = {_toml_string(record.type)}",
        f"status = {_toml_string(record.status)}",
        f"title = {_toml_string(record.title)}",
        f"components = {_toml_array(record.components)}",
        f"paths = {_toml_array(record.paths)}",
        f"evidence = {_toml_array(record.evidence)}",
        f"source_provider = {_toml_string(record.source_provider)}",
        f"source_session = {_toml_string(record.source_session)}",
        f"branch = {_toml_string(record.branch)}",
        f"observed_commit = {_toml_string(record.observed_commit)}",
        f"created_at = {_toml_string(record.created_at)}",
        f"sensitivity = {_toml_string(record.sensitivity)}",
        f"last_verified_commit = {_toml_string(record.last_verified_commit)}",
        f"supersedes = {_toml_array(record.supersedes)}",
        "+++",
        "",
        "## Summary",
        "",
        record.summary,
        "",
        "## Details",
        "",
        record.details,
        "",
        "## Evidence",
        "",
        *(f"- `{item}`" for item in record.evidence),
        "",
        "## Reuse guidance",
        "",
        record.reuse_guidance,
        "",
    ]
    return "\n".join(metadata)


def write_record(record: CanonicalMemory, path: str | Path) -> None:
    target = Path(path)
    if target.name != f"{record.id}.md":
        raise MemoryPolicyError("record filename must match memory ID")
    atomic_write(target, render_record(record))


def _section(body: str, heading: str, next_heading: str | None) -> str:
    start = f"## {heading}\n\n"
    if start not in body:
        raise MemoryPolicyError(f"missing {heading} section")
    value = body.split(start, 1)[1]
    if next_heading:
        marker = f"\n\n## {next_heading}\n"
        if marker not in value:
            raise MemoryPolicyError(f"missing {next_heading} section")
        value = value.split(marker, 1)[0]
    return value.strip()


def parse_record(path: str | Path) -> CanonicalMemory:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if not text.startswith("+++\n") or "\n+++\n" not in text[4:]:
        raise MemoryPolicyError("record requires TOML frontmatter")
    frontmatter, body = text[4:].split("\n+++\n", 1)
    try:
        metadata = tomllib.loads(frontmatter)
    except tomllib.TOMLDecodeError as exc:
        raise MemoryPolicyError(f"invalid TOML frontmatter: {exc}") from exc
    unknown = sorted(set(metadata) - _METADATA_KEYS)
    if unknown:
        raise MemoryPolicyError(f"unknown metadata: {', '.join(unknown)}")
    missing = sorted(_METADATA_KEYS - set(metadata))
    if missing:
        raise MemoryPolicyError(f"missing metadata: {', '.join(missing)}")

    summary = _section(body, "Summary", "Details")
    details = _section(body, "Details", "Evidence")
    evidence_body = _section(body, "Evidence", "Reuse guidance")
    reuse_guidance = _section(body, "Reuse guidance", None)
    body_evidence = tuple(
        match.group(1) for match in re.finditer(r"^- `([^`]+)`$", evidence_body, re.M)
    )
    metadata_evidence = tuple(metadata["evidence"])
    if body_evidence != metadata_evidence:
        raise MemoryPolicyError("evidence section does not match metadata")

    values = dict(metadata)
    for field in ("components", "paths", "evidence", "supersedes"):
        if not isinstance(values[field], list) or any(
            not isinstance(item, str) for item in values[field]
        ):
            raise MemoryPolicyError(f"{field} must be an array of strings")
        values[field] = tuple(values[field])
    values.update(
        summary=summary,
        details=details,
        reuse_guidance=reuse_guidance,
    )
    allowed = {field.name for field in fields(CanonicalMemory)}
    record = CanonicalMemory(**{key: value for key, value in values.items() if key in allowed})
    validate_record(record)
    if target.name != f"{record.id}.md":
        raise MemoryPolicyError("record filename must match memory ID")
    return record
