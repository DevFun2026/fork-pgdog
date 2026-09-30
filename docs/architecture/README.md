# Architecture documentation

The TOML files in `.agent/project-model/` and the focused Markdown documents
in this directory are canonical. `system-summary.md` and `system.html` are
generated views; do not edit them by hand.

```sh
./scripts/agent docs build
./scripts/agent docs check
```

The HTML view is self-contained, offline-readable, searchable, and printable.
