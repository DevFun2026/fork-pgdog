---
id: ADR-0001
title: Use .agent as the provider-neutral canonical root
status: accepted
date: 2026-09-21
decision-makers:
  - project-owner
consulted: []
informed:
  - template-users
supersedes: null
superseded-by: null
---

# Context

Claude Code, Gemini CLI, and Codex use different native instruction and skill
locations. Maintaining separate authoritative content would create policy,
workflow, memory, and security drift.

# Decision drivers

- One reviewable source of truth must govern every supported provider.
- Native provider discovery must still work without copying policy by hand.
- Generated files must be reproducible and drift-detectable.
- Local memory and review runs must remain private runtime state.

# Considered options

## Maintain each provider root independently

This is simple initially, but duplicates policy and makes cross-provider parity
dependent on manual synchronization.

## Use one provider's native root as canonical

This reduces duplication but gives one provider special authority and leaks its
conventions into the other adapters.

## Use `.agent/` as a provider-neutral canonical root

Canonical policies, skills, schemas, workflows, templates, project model, and
runtime live under `.agent/`. Generated `.agents/`, `.claude/`, `.gemini/`,
`AGENTS.md`, `CLAUDE.md`, and `GEMINI.md` remain thin native adapters.

# Decision

Use `.agent/` as the only authoritative agent-project root. Generate and verify
provider-native adapters from it. Store private SQLite memory and review runs in
ignored `.agent/.memory/` and `.agent/.runs/` directories.

# Rationale

The neutral root gives every provider the same reviewed contracts while keeping
native discovery ergonomic. Deterministic generation and manifest checks turn
adapter parity into a machine-verifiable invariant.

# Consequences

- Canonical behavior changes must start in `.agent/`.
- Direct edits to generated adapters are rejected as drift.
- Provider-specific capabilities stay in runtime adapters, not policy content.
- Template users must keep `.agent/.memory/` and `.agent/.runs/` untracked.

# Risks and mitigations

- A generator defect could affect every provider; golden tests and adapter
  drift checks mitigate this.
- Provider CLI changes can break an adapter; capability probes and fail-closed
  real-CLI smoke tests surface the incompatibility.
- Generated roots may look authoritative; headers and `AGENTS.md` state the
  authority order explicitly.

# Follow-up

- Run `./scripts/agent adapters check` and `./scripts/agent docs check` in CI.
- Record provider versions and real-CLI limitations in acceptance evidence.
- Supersede this ADR if the canonical root or generation strategy changes.

# Evidence

- `docs/superpowers/specs/2026-09-21-agent-project-template-design.md`
- `docs/superpowers/plans/2026-09-21-agent-project-template.md`
- `.agent/tests/test_adapters.py`
- `.agent/tests/test_acceptance.py`
- `docs/security/threat-model.md`
