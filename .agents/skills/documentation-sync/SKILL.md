---
name: documentation-sync
description: Use when behavior, public contracts, components, data flows, security boundaries, deployment, or consequential dependencies change.
---

# Documentation Sync

Treat documentation impact as a tested part of the change.

## When to use

- A change affects what users, maintainers, operators, or reviewers need to know.

## Do not use

- Do not edit generated architecture HTML or summaries by hand.

## Inputs

- Diff, spec/ADR, project model, focused docs, templates, and documentation-impact schema under `.agent/`.

## Steps

1. Classify impact as `updated` with non-empty paths or `none` with a specific rationale.
2. Update canonical project-model TOML and focused Markdown before generated outputs.
3. Run `./scripts/agent docs build` and then `./scripts/agent docs check`.
4. Verify links, escaped project content, deterministic output, and offline readability of `docs/architecture/system.html`.
5. Store the validated documentation-impact artifact for the current change.

## Stop conditions

- Stop merge when required docs are stale, untraceable, or contradicted by code/model evidence.

## Evidence

- Source paths, generated paths, docs-check output, diff identity, and rationale.

## Output

- Synchronized focused docs, summary, HTML, and documentation-impact record.

## Failure behavior

- Generator or drift failure blocks completion; preserve the source/generator distinction.
