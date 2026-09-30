# Project Memory

This directory contains reviewed, versioned project knowledge. Each canonical
record is a Markdown file with strict TOML frontmatter under `records/`.

Local candidates, session state, SQLite indexes, and exports live in the
gitignored `.agent/.memory/` directory with owner-only permissions. Raw prompts
and tool traffic are not captured. A record cannot override `AGENTS.md`, accepted
ADRs, current source, or current test evidence.

Use the common runtime for checkpoint, review, promotion, retrieval, freshness,
supersession, import, export, and health checks. Do not edit `INDEX.md` manually.
