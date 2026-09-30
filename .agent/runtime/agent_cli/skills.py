from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re


NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
UNRESOLVED_PATTERN = re.compile(
    r"\b(?:TBD|TODO|FIXME|PLACEHOLDER)\b|implement\s+later|<[^>\n]+>",
    re.IGNORECASE,
)
PROVIDER_PATTERN = re.compile(r"\b(?:claude|gemini|agy|antigravity|codex|chatgpt)\b", re.IGNORECASE)
REQUIRED_HEADINGS = (
    "When to use",
    "Do not use",
    "Inputs",
    "Steps",
    "Stop conditions",
    "Evidence",
    "Output",
    "Failure behavior",
)


class SkillValidationError(ValueError):
    """Raised when a canonical skill violates its portable contract."""


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    body: str
    path: Path


def discover_skill_names(root: Path) -> set[str]:
    if not root.is_dir():
        return set()
    return {
        path.name
        for path in root.iterdir()
        if path.is_dir() and (path / "SKILL.md").is_file()
    }


def _frontmatter(text: str, path: Path) -> tuple[dict[str, str], str]:
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise SkillValidationError(f"{path}: missing YAML frontmatter")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise SkillValidationError(f"{path}: unterminated YAML frontmatter") from exc
    values: dict[str, str] = {}
    for line in lines[1:end]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition(":")
        if not separator or not key.strip() or not value.strip():
            raise SkillValidationError(f"{path}: invalid frontmatter line")
        values[key.strip()] = value.strip().strip('"\'')
    return values, "\n".join(lines[end + 1 :]).strip() + "\n"


def _validate_links(skill_dir: Path, body: str) -> None:
    for raw_target in LINK_PATTERN.findall(body):
        target = raw_target.split("#", 1)[0].strip()
        if not target or "://" in target or target.startswith("#"):
            continue
        parsed = PurePosixPath(target)
        if parsed.is_absolute() or ".." in parsed.parts:
            raise SkillValidationError(f"{skill_dir.name}: unsafe local reference: {target}")
        if not (skill_dir / parsed).is_file():
            raise SkillValidationError(
                f"{skill_dir.name}: missing local reference: {target}"
            )


def _load_skill(path: Path) -> Skill:
    text = path.read_text(encoding="utf-8")
    if len(text.splitlines()) > 500:
        raise SkillValidationError(f"{path}: SKILL.md exceeds 500 lines")
    metadata, body = _frontmatter(text, path)
    unknown = set(metadata) - {"name", "description", "license", "compatibility", "allowed-tools"}
    if unknown:
        raise SkillValidationError(f"{path}: unknown frontmatter field: {sorted(unknown)[0]}")
    name = metadata.get("name", "")
    description = metadata.get("description", "")
    if name != path.parent.name:
        raise SkillValidationError(f"{path}: directory/name mismatch")
    if not NAME_PATTERN.fullmatch(name) or len(name) > 64:
        raise SkillValidationError(f"{path}: invalid skill name")
    if not description.startswith("Use when ") or not 30 <= len(description) <= 500:
        raise SkillValidationError(f"{path}: description must be a specific Use when trigger")
    for heading in REQUIRED_HEADINGS:
        if f"## {heading}" not in body:
            raise SkillValidationError(f"{path}: missing heading: {heading}")
    if UNRESOLVED_PATTERN.search(body):
        raise SkillValidationError(f"{path}: unresolved placeholder")
    if PROVIDER_PATTERN.search(f"{description}\n{body}"):
        raise SkillValidationError(f"{path}: provider-specific policy is not canonical")
    _validate_links(path.parent, body)
    return Skill(name=name, description=description, body=body, path=path)


def load_skills(root: Path) -> tuple[Skill, ...]:
    names = discover_skill_names(root)
    skills = tuple(_load_skill(root / name / "SKILL.md") for name in sorted(names))
    if len({skill.name for skill in skills}) != len(skills):
        raise SkillValidationError("duplicate skill name")
    return skills
