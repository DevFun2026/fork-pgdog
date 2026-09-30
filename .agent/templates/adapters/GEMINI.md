# Gemini via Antigravity CLI (`agy`)

Read and follow `AGENTS.md`; it is the canonical project instruction file.

Antigravity CLI discovers generated skills under `.agents/skills/`, shared with
Codex. Those files are
regular generated copies of `.agent/skills/`; edit the canonical source and run
`./scripts/agent adapters build` instead of editing native copies.

`.agents/hooks.json` registers best-effort Project Memory PreInvocation/Stop
hooks. Bootstrap runs on invocation 0 only; Stop never forces another turn.
Hook failure does not authorize broad rescanning or
convert missing context/evidence into success. Inspect capabilities with
`./scripts/agent doctor --providers --json`.

The provider identity remains `gemini`; the executable is `agy`. Cross-review
must use a Gemini model, not a Claude model available through the same CLI.
See `docs/antigravity.md` for model selection, isolated API-key authentication,
and the distinction between interactive login and automated review.
