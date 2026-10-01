from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess

from agent_cli.docs_html import render_blueprint
from agent_cli.paths import atomic_write
from agent_cli.project_model import ProjectModel, load_project_model


DOCUMENT_SECTIONS = (
    (
        "architecture-docs",
        "Focused architecture documents",
        "docs/architecture",
        ("system-context.md", "containers.md", "components.md", "data-flows.md", "deployment.md"),
    ),
    ("contracts", "Interfaces and contracts", "docs/architecture", ("contracts.md",)),
    ("adr-index", "Architecture decision records", "docs/decisions", None),
    ("security", "Security model and controls", "docs/security", None),
    (
        "operations",
        "Operations, observability, and recovery",
        "docs/operations",
        ("runbooks.md", "observability.md"),
    ),
    ("traceability", "Requirement traceability", "docs", ("traceability.md",)),
)


@dataclass(frozen=True)
class DocumentationBuild:
    summary: str
    html: str


@dataclass(frozen=True)
class DocumentationCheck:
    ok: bool
    changed: tuple[str, ...]


def render_system_summary(
    model: ProjectModel,
    *,
    generated_at: str,
    commit: str,
) -> str:
    lines = [
        f"# {model.title}",
        "",
        f"Generated: {generated_at} | Commit: {commit}",
        "",
        "## Components",
        "",
    ]
    lines.extend(
        f"- **{item.id}** — {item.name} (`{item.kind}`): {item.responsibility} "
        f"[boundary: {item.trust_boundary}]"
        for item in model.components
    )
    lines.extend(["", "## Relationships", ""])
    lines.extend(
        f"- `{item.source}` → `{item.target}` — {item.label}"
        for item in model.relationships
    )
    lines.extend(["", "## Data flows", ""])
    lines.extend(
        f"- **{item.id}**: `{item.source}` → `{item.target}`; data: "
        f"{', '.join(item.data_categories) or 'none'}; boundary: {item.trust_boundary}"
        for item in model.data_flows
    )
    lines.extend(["", "## Environments", ""])
    lines.extend(
        f"- **{item.id}** — {item.name}: {item.description}"
        for item in model.environments
    )
    return "\n".join(lines) + "\n"


def _document_title(filename: str) -> str:
    return Path(filename).stem.replace("-", " ").title()


def render_system_html(
    model: ProjectModel,
    markdown_docs: dict[str, str],
    *,
    generated_at: str,
    commit: str,
) -> str:
    return render_blueprint(
        model, markdown_docs, DOCUMENT_SECTIONS,
        generated_at=generated_at, commit=commit,
    )


def _read_focused_docs(root: Path) -> dict[str, str]:
    docs: dict[str, str] = {}
    for section_id, _title, directory, names in DOCUMENT_SECTIONS:
        base = root / directory
        candidates = (
            [base / name for name in names]
            if names is not None
            else sorted(base.glob("*.md")) if base.is_dir() else []
        )
        for path in candidates:
            if path.is_file():
                docs[f"{section_id}/{path.name}"] = path.read_text(encoding="utf-8")
    return docs


def build_docs(
    root: str | Path,
    *,
    generated_at: str,
    commit: str = "unknown",
) -> DocumentationBuild:
    repository = Path(root)
    model = load_project_model(repository / ".agent/project-model")
    docs = _read_focused_docs(repository)
    return DocumentationBuild(
        summary=render_system_summary(
            model, generated_at=generated_at, commit=commit
        ),
        html=render_system_html(
            model, docs, generated_at=generated_at, commit=commit
        ),
    )


def write_docs(
    root: str | Path,
    *,
    generated_at: str,
    commit: str = "unknown",
) -> DocumentationBuild:
    repository = Path(root)
    output = build_docs(repository, generated_at=generated_at, commit=commit)
    atomic_write(repository / "docs/architecture/system-summary.md", output.summary)
    atomic_write(repository / "docs/architecture/system.html", output.html)
    return output


def check_docs(
    root: str | Path,
    *,
    generated_at: str,
    commit: str = "unknown",
) -> DocumentationCheck:
    repository = Path(root)
    expected = build_docs(repository, generated_at=generated_at, commit=commit)
    paths = {
        "docs/architecture/system-summary.md": expected.summary,
        "docs/architecture/system.html": expected.html,
    }
    changed = tuple(
        name
        for name, content in paths.items()
        if not (repository / name).is_file()
        or (repository / name).read_text(encoding="utf-8") != content
    )
    return DocumentationCheck(ok=not changed, changed=changed)


def git_documentation_metadata(root: str | Path) -> tuple[str, str]:
    repository = Path(root)
    commit_result = subprocess.run(
        ("git", "rev-parse", "--short=12", "HEAD"),
        cwd=repository,
        text=True,
        capture_output=True,
        check=False,
    )
    date_result = subprocess.run(
        ("git", "show", "-s", "--format=%cI", "HEAD"),
        cwd=repository,
        text=True,
        capture_output=True,
        check=False,
    )
    commit = commit_result.stdout.strip() if commit_result.returncode == 0 else "unknown"
    generated_at = date_result.stdout.strip() if date_result.returncode == 0 else "unknown"
    return generated_at, commit


def committed_documentation_metadata(root: str | Path) -> tuple[str, str]:
    summary = Path(root) / "docs/architecture/system-summary.md"
    if summary.is_file():
        match = re.search(r"^Generated: (.+) \| Commit: (.+)$", summary.read_text(encoding="utf-8"), re.M)
        if match:
            return match.group(1), match.group(2)
    return git_documentation_metadata(root)
