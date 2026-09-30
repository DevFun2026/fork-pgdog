---
name: architecture-design
description: Use when components, data flows, trust boundaries, deployment topology, or consequential dependencies must be designed or changed.
---

# Architecture Design

Keep the canonical model and human-readable explanation aligned.

## When to use

- A change creates or alters components, interfaces, flows, storage, environments, or boundaries.

## Do not use

- Do not invent architecture for a local refactor with no structural consequence.

## Inputs

- Approved spec, `.agent/project-model/`, current architecture docs, security profile, and deployment evidence.

## Steps

1. Model responsibilities, ownership, interfaces, dependencies, and failure isolation.
2. Define data categories, sources, destinations, retention, and trust-boundary crossings.
3. Compare at least viable alternatives and expose operational/security tradeoffs.
4. Update canonical project-model TOML and focused `docs/architecture/` sources.
5. Run `./scripts/agent docs build` and `./scripts/agent docs check`.

## Stop conditions

- Stop if a consequential choice lacks an owner or requires an unapproved new dependency/service.

## Evidence

- Model diff, diagrams or tables, validation result, and linked decisions.

## Output

- Valid project model and synchronized deterministic architecture documents.

## Failure behavior

- A stale or invalid generated document blocks completion; do not hand-edit generated HTML.
