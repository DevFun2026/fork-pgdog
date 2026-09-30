# Claude Code Adapter

Read and follow `AGENTS.md`; it is the canonical project instruction file.

Claude Code discovers generated skills under `.claude/skills/`. Those files are
regular generated copies of `.agent/skills/`; edit the canonical source and run
`./scripts/agent adapters build` instead of editing native copies.

`.claude/settings.json` registers best-effort Project Memory context/reminder
hooks. Hook failure does not authorize broad rescanning or convert missing
context/evidence into success. Inspect capabilities with
`./scripts/agent doctor --providers --json`.
