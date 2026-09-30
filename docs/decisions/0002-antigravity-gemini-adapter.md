---
id: ADR-0002
title: Execute Gemini through Antigravity CLI and share native skills
status: accepted
date: 2026-09-22
decision-makers:
  - project-owner
consulted: []
informed:
  - template-users
supersedes: null
superseded-by: null
---

# Context

The owner requested migration from Gemini CLI to `agy`. Antigravity supports
multiple model families, a different headless output contract, shared
`.agents/skills`, and PreInvocation/Stop lifecycle hooks.

# Decision

Keep the canonical `.agent/` architecture and `gemini` model-family identity.
Change its executable/flags/parser to AGY; pin a Gemini model and reject other
families. Share the Codex native skill tree instead of retaining a redundant
legacy Gemini tree. Retire only unchanged manifest-owned outputs.

Preserve the outer OS sandbox and exact-manifest egress approval. Plan mode is
not read-only enforcement. Automated review uses disposable API-key settings,
not the user's OAuth profile/keyring. Hooks inject bounded data only at initial
invocation and never force a new turn or persist raw transcripts.

# Alternatives and consequences

A bare command rename would retain incompatible flags, hooks and output
validation. Renaming the provider family to `agy` would obscure model identity
and require unnecessary historical-data migration. Importing the host profile
would expand credential/plugin exposure; that remains out of scope.

Interactive account login and automated API-key authentication are distinct.
Model entitlement and authenticated execution need a real smoke test; missing
credentials/capabilities never count as completed review. Historical Gemini CLI
evidence remains historical. This ADR updates native layout details in ADR-0001
without replacing its canonical-root decision.

# Evidence

- `docs/antigravity.md`
- `docs/superpowers/plans/2026-09-22-antigravity-migration.md`
- `.agent/tests/test_antigravity.py`
- `.agent/tests/test_acceptance.py`
