from __future__ import annotations

from dataclasses import dataclass
from html import escape
from pathlib import Path
import re
import subprocess

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
    e = escape
    component_rows = "".join(
        "<tr>"
        f"<td>{e(item.id)}</td><td>{e(item.name)}</td><td>{e(item.kind)}</td>"
        f"<td>{e(item.responsibility)}</td><td>{e(item.trust_boundary)}</td>"
        "</tr>"
        for item in model.components
    )
    relationship_items = "".join(
        f"<li><code>{e(item.source)}</code> → <code>{e(item.target)}</code> — "
        f"{e(item.label)}</li>"
        for item in model.relationships
    )
    flow_items = "".join(
        f"<li><strong>{e(item.id)}</strong>: <code>{e(item.source)}</code> → "
        f"<code>{e(item.target)}</code>; data: "
        f"{e(', '.join(item.data_categories) or 'none')}; boundary: "
        f"{e(item.trust_boundary)}</li>"
        for item in model.data_flows
    )
    environment_items = "".join(
        f"<li><strong>{e(item.id)}</strong> — {e(item.name)}: "
        f"{e(item.description)}</li>"
        for item in model.environments
    )
    doc_sections = "".join(
        f'<section id="{e(section_id)}"><h2>{e(title)}</h2>'
        + "".join(
            f"<article><h3>{e(_document_title(name))}</h3><pre>{e(content)}</pre></article>"
            for name, content in sorted(markdown_docs.items())
            if name.startswith(section_id + "/")
        )
        + "</section>"
        for section_id, title, _directory, _names in DOCUMENT_SECTIONS
    )
    categories = ", ".join(model.data_categories) or "none"
    sensitive = ", ".join(model.sensitive_categories) or "none"
    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(model.title)}</title>
<style>:root{{font-family:system-ui,sans-serif;color:#172033;background:#f6f8fb}}body{{max-width:1100px;margin:auto;padding:2rem}}header,section,nav{{background:white;border:1px solid #d8deea;border-radius:12px;padding:1rem;margin:1rem 0}}nav{{display:flex;gap:1rem;flex-wrap:wrap}}table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #d8deea;padding:.55rem;text-align:left;vertical-align:top}}pre{{white-space:pre-wrap}}input{{padding:.5rem;min-width:18rem}}.hidden{{display:none}}@media print{{input,script{{display:none}}body{{max-width:none}}}}</style>
</head>
<body>
<header><h1>{e(model.title)}</h1><p>Generated {e(generated_at)} · Commit {e(commit)}</p><label>Search <input id="search" type="search" placeholder="Filter sections"></label></header>
<nav aria-label="Contents"><a href="#overview">Overview</a><a href="#components">Components</a><a href="#relationships">Relationships</a><a href="#data-flows">Data flows</a><a href="#environments">Environments</a><a href="#architecture-docs">Architecture</a><a href="#contracts">Contracts</a><a href="#adr-index">ADRs</a><a href="#security">Security</a><a href="#operations">Operations</a><a href="#traceability">Traceability</a><a href="#governance">Governance</a></nav>
<main>
<section id="overview"><h2>Purpose and scope</h2><p>{e(model.purpose)}</p><p>Declared data categories: {e(categories)}. Sensitive categories: {e(sensitive)}.</p></section>
<section id="components"><h2>Components</h2><table><thead><tr><th>ID</th><th>Name</th><th>Kind</th><th>Responsibility</th><th>Trust boundary</th></tr></thead><tbody>{component_rows}</tbody></table></section>
<section id="relationships"><h2>Relationships</h2><ul>{relationship_items}</ul></section>
<section id="data-flows"><h2>Data flows and trust boundaries</h2><ul>{flow_items}</ul></section>
<section id="environments"><h2>Deployment environments</h2><ul>{environment_items}</ul></section>
{doc_sections}
<section id="governance"><h2>Decisions, controls, and traceability</h2><p>See <code>docs/decisions/</code> for ADRs, <code>docs/security/</code> for controls and residual risks, and <code>.agent/.runs/</code> for commit-bound evidence. Quality gates and recovery procedures are defined by the canonical workflow.</p></section>
</main>
<script>const q=document.getElementById('search');q.addEventListener('input',()=>{{const v=q.value.toLowerCase();document.querySelectorAll('main section').forEach(s=>s.classList.toggle('hidden',v&&!s.textContent.toLowerCase().includes(v)));}});</script>
</body>
</html>
'''


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
