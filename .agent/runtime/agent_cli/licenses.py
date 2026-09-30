from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re


LINK = re.compile(r"\[[^\]]+\]\((https://[^)]+)\)")
SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^(?:v)?\d+(?:\.\d+){0,3}$")
REVIEWED_DATE = re.compile(r"^reviewed \d{4}-\d{2}-\d{2}$")
UNPINNED = frozenset({"main", "master", "head", "latest", "develop"})


@dataclass(frozen=True)
class LicenseAudit:
    ok: bool
    source_count: int
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _rows(text: str) -> tuple[tuple[str, ...], ...]:
    rows: list[tuple[str, ...]] = []
    in_table = False
    for line in text.splitlines():
        if line.startswith("| Source | Reviewed revision/version |"):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.startswith("|"):
            break
        cells = tuple(cell.strip() for cell in line.strip().strip("|").split("|"))
        if cells and set(cells[0]) == {"-"}:
            continue
        rows.append(cells)
    return tuple(rows)


def audit_sources(path: Path, *, notice_path: Path) -> LicenseAudit:
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return LicenseAudit(False, 0, (f"cannot read source manifest: {exc}",))
    rows = _rows(text)
    if not rows:
        errors.append("source manifest has no source rows")
    for index, cells in enumerate(rows, 1):
        if len(cells) != 5:
            errors.append(f"source row {index}: expected five fields")
            continue
        source, revision, license_name, concepts, boundary = cells
        if not LINK.search(source):
            errors.append(f"source row {index}: missing HTTPS URL")
        normalized_revision = revision.strip("`").strip()
        if normalized_revision.casefold() in UNPINNED:
            errors.append(f"source row {index}: unpinned revision")
        elif not (
            SHA.fullmatch(normalized_revision)
            or VERSION.fullmatch(normalized_revision)
            or REVIEWED_DATE.fullmatch(normalized_revision)
        ):
            errors.append(f"source row {index}: invalid revision or reviewed date")
        if not license_name or license_name.casefold() in {"unknown", "none", "n/a"}:
            errors.append(f"source row {index}: missing license")
        if len(concepts) < 8:
            errors.append(f"source row {index}: missing concepts used")
        if len(boundary) < 16:
            errors.append(f"source row {index}: missing implementation boundary")
    if "does not vendor" not in text.casefold():
        errors.append("source manifest does not declare the vendoring boundary")
    if not notice_path.is_file() or not notice_path.read_text(encoding="utf-8").strip():
        errors.append("THIRD_PARTY_NOTICES.md is missing or empty")
    return LicenseAudit(not errors, len(rows), tuple(errors))
