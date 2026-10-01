# Architecture documentation

The TOML files in `.agent/project-model/` and the focused Markdown documents
in this directory are canonical. `system-summary.md` and `system.html` are
generated views; do not edit them by hand.

```sh
./scripts/agent docs build
./scripts/agent docs check
```

The HTML view is self-contained, offline-readable, searchable, and printable.

## Presentation and publication

The blueprint renderer is in .agent/runtime/agent_cli/docs_html.py. Its shell,
styles and interaction code are canonical templates under .agent/templates/docs/.
The visual layout adapts the owner-provided Stargate architecture reference;
no Stargate product content, metrics or topology is part of this page.
System fonts and embedded SVG/CSS/JavaScript keep the artifact offline-readable.
Markdown is rendered as escaped, formatted content; raw HTML and unsafe links
remain inert. Diagrams and counts come from the canonical model.

.github/workflows/architecture-pages.yml validates documentation on relevant PRs
and manual runs. Deployment is allowed only on manual dispatch from main:

    gh workflow run architecture-pages.yml --ref main

Configure the repository's GitHub Pages source as GitHub Actions before the
first dispatch. The github-pages environment should permit main only. The
workflow stages only system.html as index.html and .nojekyll in a temporary
directory. Local run evidence and repository source are not deployed.
The intended public URL is https://devfun2026.github.io/fork-pgdog/.
