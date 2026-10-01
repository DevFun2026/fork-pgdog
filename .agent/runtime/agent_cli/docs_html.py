"""Offline architecture presentation; all project content is treated as data."""
from __future__ import annotations

from html import escape
from pathlib import Path
import re
import textwrap
from urllib.parse import urlsplit

from agent_cli.project_model import Component, ProjectModel

ASSETS = Path(__file__).resolve().parents[2] / "templates/docs"
TOOLING_KINDS = frozenset({
    "policy-and-skills", "automation", "generator", "local-storage",
    "adapter", "orchestrator", "python-cli",
})
INLINE = re.compile(r"`([^`]+)`|\*\*(.+?)\*\*|\[([^\]]+)\]\(([^)\s]+)\)|<(https?://[^<> ]+)>")
LIST = re.compile(r"^\s*(?:([-*])|(\d+)\.)\s+(.+)$")


def _inline(text: str) -> str:
    parts: list[str] = []
    cursor = 0
    for match in INLINE.finditer(text):
        parts.append(escape(text[cursor:match.start()]))
        code, bold, label, url, autolink = match.groups()
        if code is not None:
            parts.append(f"<code>{escape(code)}</code>")
        elif bold is not None:
            parts.append(f"<strong>{escape(bold)}</strong>")
        else:
            target = url or autolink or ""
            label = label or autolink or ""
            try:
                parsed = urlsplit(target)
                allowed = (
                    parsed.scheme in {"http", "https"} and bool(parsed.netloc)
                    or parsed.scheme == "mailto" and bool(parsed.path)
                    or target.startswith("#")
                ) and not any(ord(character) < 32 for character in target)
            except ValueError:
                allowed = False
            if allowed:
                parts.append(f'<a href="{escape(target, quote=True)}" rel="noreferrer">{escape(label)}</a>')
            else:
                parts.append(f"{escape(label)} ({escape(target)})")
        cursor = match.end()
    parts.append(escape(text[cursor:]))
    return "".join(parts)


def _table_separator(line: str) -> bool:
    cells = line.strip().strip("|").split("|")
    return bool(cells) and all(re.fullmatch(r"\s*:?-{3,}:?\s*", cell) for cell in cells)


def render_markdown(content: str) -> str:
    """Render the repository's Markdown subset without permitting raw HTML."""
    lines = content.splitlines()
    output: list[str] = []
    index = 0
    if lines and lines[0] == "---" and "---" in lines[1:]:
        end = lines.index("---", 1)
        output.append('<details class="metadata"><summary>Document metadata</summary><pre>'
                      + escape("\n".join(lines[1:end])) + "</pre></details>")
        index = end + 1

    def boundary(at: int) -> bool:
        line = lines[at]
        return (not line.strip() or bool(re.match(r"^(#{1,6})\s|^\s*```|^    |^>\s|^---$", line))
                or bool(LIST.match(line))
                or at + 1 < len(lines) and _table_separator(lines[at + 1]))

    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        if line.lstrip().startswith("```"):
            code: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].lstrip().startswith("```"):
                code.append(lines[index])
                index += 1
            output.append("<pre><code>" + escape("\n".join(code)) + "</code></pre>")
            index += 1
            continue
        if line.startswith("    "):
            code = []
            while index < len(lines) and (lines[index].startswith("    ") or not lines[index].strip()):
                code.append(lines[index][4:] if lines[index].startswith("    ") else "")
                index += 1
            output.append("<pre><code>" + escape("\n".join(code).rstrip()) + "</code></pre>")
            continue
        heading = re.match(r"^(#{1,6})\s+(.+)$", line)
        if heading:
            level = min(len(heading[1]) + 2, 6)
            output.append(f"<h{level}>{_inline(heading[2])}</h{level}>")
            index += 1
            continue
        if index + 1 < len(lines) and _table_separator(lines[index + 1]):
            headers = line.strip().strip("|").split("|")
            output.append('<div class="table-wrap"><table><thead><tr>'
                          + "".join(f"<th>{_inline(cell.strip())}</th>" for cell in headers)
                          + "</tr></thead><tbody>")
            index += 2
            while index < len(lines) and "|" in lines[index] and lines[index].strip():
                cells = lines[index].strip().strip("|").split("|")
                output.append("<tr>" + "".join(f"<td>{_inline(cell.strip())}</td>" for cell in cells) + "</tr>")
                index += 1
            output.append("</tbody></table></div>")
            continue
        item = LIST.match(line)
        if item:
            tag = "ol" if item[2] else "ul"
            output.append(f"<{tag}>")
            while index < len(lines):
                item = LIST.match(lines[index])
                if not item or ("ol" if item[2] else "ul") != tag:
                    break
                body = [item[3]]
                index += 1
                while index < len(lines) and lines[index].startswith("  ") and not boundary(index):
                    body.append(lines[index].strip())
                    index += 1
                output.append("<li>" + _inline(" ".join(body)) + "</li>")
            output.append(f"</{tag}>")
            continue
        if line == "---":
            output.append("<hr>")
            index += 1
            continue
        if line.startswith("> "):
            output.append("<blockquote>" + _inline(line[2:]) + "</blockquote>")
            index += 1
            continue
        paragraph = [line]
        index += 1
        while index < len(lines) and not boundary(index):
            paragraph.append(lines[index])
            index += 1
        output.append("<p>" + _inline(" ".join(paragraph)) + "</p>")
    return "\n".join(output)


def _ordered_nodes(nodes: tuple[Component, ...], edges: list[tuple[str, str]]) -> list[Component]:
    remaining = {node.id: node for node in nodes}
    ordered: list[Component] = []
    while remaining:
        ready = sorted(key for key in remaining if not any(
            target == key and source in remaining and source != target for source, target in edges
        ))
        key = ready[0] if ready else sorted(remaining)[0]
        ordered.append(remaining.pop(key))
    return ordered


def _graph(nodes: tuple[Component, ...], edges: list[tuple[str, str]], identifier: str, title: str) -> str:
    if not nodes:
        return '<p class="muted">No components declared in this group.</p>'
    ids = {node.id for node in nodes}
    edges = [(source, target) for source, target in edges if source in ids and target in ids]
    ordered = _ordered_nodes(nodes, edges)
    columns = min(len(nodes), 3)
    width = columns * 310 + 24
    height = ((len(nodes) + columns - 1) // columns) * 170 + 30
    positions = {node.id: (22 + number % columns * 310, 28 + number // columns * 170)
                 for number, node in enumerate(ordered)}
    parts = [f'<figure class="diagram"><div class="frame"><svg viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}">',
             f'<title>{escape(title)}</title><defs><marker id="arrow-{identifier}" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="currentColor"/></marker></defs>']
    for source, target in edges:
        x1, y1 = positions[source]
        x2, y2 = positions[target]
        if source == target:
            path = f"M{x1 + 250},{y1 + 30} C{x1 + 295},{y1 - 10} {x1 + 295},{y1 + 105} {x1 + 250},{y1 + 75}"
        elif y1 == y2:
            path = f"M{x1 + 266},{y1 + 53} L{x2 - 6},{y2 + 53}"
        else:
            path = f"M{x1 + 133},{y1 + 106} L{x1 + 133},{y1 + 132} L{x2 + 133},{y1 + 132} L{x2 + 133},{y2 - 5}"
        parts.append(f'<path data-source="{escape(source)}" data-target="{escape(target)}" d="{path}" fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#arrow-{identifier})"/>')
    for node in ordered:
        x, y = positions[node.id]
        parts.append(f'<g data-component="{escape(node.id)}"><rect x="{x}" y="{y}" width="266" height="106" rx="4" class="node"/>')
        for row, label in enumerate(textwrap.wrap(node.name, 26)[:2]):
            parts.append(f'<text x="{x + 14}" y="{y + 25 + row * 18}" class="node-name">{escape(label)}</text>')
        parts.append(f'<text x="{x + 14}" y="{y + 72}" class="node-kind">{escape(node.kind)}</text>')
        parts.append(f'<text x="{x + 14}" y="{y + 91}" class="node-boundary">{escape(node.trust_boundary)}</text></g>')
    parts.append(f'</svg></div><figcaption>{escape(title)}. Arrows show relationships declared in the canonical model; details follow below.</figcaption></figure>')
    return "\n".join(parts)


def render_blueprint(model: ProjectModel, markdown_docs: dict[str, str], sections: tuple,
                     *, generated_at: str, commit: str) -> str:
    e = escape
    navigation = [("overview", "System context"), ("relationships", "Component diagrams"),
                  ("components", "Component responsibilities"), ("data-flows", "Data & trust boundaries"),
                  ("environments", "Deployment environments")]
    navigation.extend((identifier, title) for identifier, title, _directory, _names in sections)
    navigation.append(("governance", "Governance & source"))
    numbers = {identifier: number for number, (identifier, _title) in enumerate(navigation, 1)}

    def sheet(identifier: str, title: str, content: str, source: str) -> str:
        number = numbers[identifier]
        return (f'<section class="sheet" id="{identifier}"><div class="sheet-head">'
                f'<h2><span class="section-number">{number:02d}</span> {e(title)}</h2>'
                f'<span class="sheet-num">{e(source)}</span></div>{content}</section>')

    nav = "".join(f'<li><a href="#{identifier}"><span class="n">{number:02d}</span>{e(title)}</a></li>'
                  for number, (identifier, title) in enumerate(navigation, 1))
    runtime = tuple(node for node in model.components if node.kind not in TOOLING_KINDS)
    tooling = tuple(node for node in model.components if node.kind in TOOLING_KINDS)
    edges = [(relation.source, relation.target) for relation in model.relationships]
    relationship_list = "".join(f'<li><code>{e(relation.source)}</code> → <code>{e(relation.target)}</code><span>{e(relation.label)}</span></li>' for relation in model.relationships)
    cards = "".join(f'<article class="layer"><div><h3>{e(node.name)}</h3><code class="lpath">{e(node.id)}</code><span class="tag neutral">{e(node.kind)}</span></div><div><p>{e(node.responsibility)}</p><p class="boundary">Boundary: <code>{e(node.trust_boundary)}</code></p></div></article>' for node in (*runtime, *tooling))
    flows = "".join(f'<article class="flow"><h3>{e(flow.id)}</h3><p class="route"><code>{e(flow.source)}</code> → <code>{e(flow.target)}</code></p><p>{e(", ".join(flow.data_categories) or "none")}</p><span class="tag neutral">{e(flow.trust_boundary)}</span></article>' for flow in model.data_flows)
    environments = "".join(f'<article class="environment"><h3>{e(environment.name)}</h3><code>{e(environment.id)}</code><p>{e(environment.description)}</p></article>' for environment in model.environments)
    content = [sheet("overview", "System context", f'<p class="lede">{e(model.purpose)}</p><div class="scope-note"><strong>Source of truth</strong><p>Components and diagrams represent the declared current model. Planned work is labelled in the scope and focused documents; no deployment or feature is inferred from a diagram.</p></div>', ".agent/project-model/")]
    diagrams = _graph(runtime, edges, "runtime", "Product runtime") + _graph(tooling, edges, "tooling", "Repository development and verification")
    content.append(sheet("relationships", "Component diagrams", diagrams + f'<ul class="relationships">{relationship_list}</ul>', "relationships.toml"))
    content.append(sheet("components", "Component responsibilities", f'<div class="layers">{cards}</div>', "components.toml"))
    content.append(sheet("data-flows", "Data & trust boundaries", f'<p class="lede">Sensitive categories: {e(", ".join(model.sensitive_categories) or "none")}. Declared categories: {e(", ".join(model.data_categories) or "none")}.</p><div class="flow-grid">{flows}</div>', "data-flows.toml"))
    content.append(sheet("environments", "Deployment environments", f'<div class="environment-grid">{environments}</div>', "environments.toml"))
    for identifier, title, _directory, _names in sections:
        documents = []
        for name, markdown in sorted(markdown_docs.items()):
            if name.startswith(identifier + "/"):
                title_text = Path(name).stem.replace("-", " ").title()
                documents.append(f'<details class="document"><summary>{e(title_text)}</summary><div class="document-body">{render_markdown(markdown)}</div></details>')
        content.append(sheet(identifier, title, "\n".join(documents) or '<p class="muted">No focused documents declared.</p>', _directory))
    content.append(sheet("governance", "Governance & source", '<p>Generated from canonical TOML and focused Markdown using <code>./scripts/agent docs build</code>. Check drift with <code>./scripts/agent docs check</code>.</p><p>Review evidence stays local under <code>.agent/.runs/</code>. This page contains documentation, not live query data or a production security certification.</p>', "documentation-sync"))
    facts = [(len(runtime), "product components"), (len(tooling), "tooling components"),
             (len(model.relationships), "relationships"), (len(model.data_flows), "data flows")]
    values = {
        "project_title": e(model.title), "short_title": e(model.title.split(":", 1)[0]),
        "purpose": e(model.purpose), "commit": e(commit), "generated_at": e(generated_at),
        "navigation": nav, "complete_system_content": "\n".join(content),
        "facts": "".join(f'<div class="fact"><span class="v">{number}</span><span class="k">{label}</span></div>' for number, label in facts),
        "inline_styles": (ASSETS / "architecture.css").read_text(encoding="utf-8"),
        "inline_search": (ASSETS / "architecture.js").read_text(encoding="utf-8"),
    }
    template = (ASSETS / "system.html.tmpl").read_text(encoding="utf-8")
    # Replace only placeholders in the original template, never reparse inserted data.
    return re.sub(r"{{\s*([a-z_]+)\s*}}", lambda match: values[match[1]], template)
