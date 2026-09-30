---
name: ui-design-system
description: Use when an interface needs reusable visual tokens, component states, or scoped page overrides consistent with an existing or approved design direction.
---

# UI Design System

## When to use

Several screens share a visual language or a change risks component drift.

## Do not use

For backend-only work, a single settled style fix, or a wholesale redesign not
requested by the user. Do not require a new token framework for a small product.

## Inputs

Approved UX brief, incumbent styles/components, brand assets, stack, supported
platforms/themes, and content ranges. Use bounded `.agent/` context retrieval.

## Steps

1. Inventory existing tokens and components in the affected surface. Distinguish
   observed values from proposals; preserve the existing visual authority.
2. Read the [token contract](references/token-contract.md) and use the
   [master template](assets/design-master.md) to record only reusable decisions.
3. Map primitive values to semantic roles and affected component states. Resolve
   aliases, foreground/background pairings, focus, disabled, pending and error.
4. Use the [page delta](assets/page-design.md) for genuine exceptions, referencing
   the master version and exact tokens/components rather than copying the master.
5. Verify affected states with representative content, small viewport and zoom.
   Record observed evidence separately from untested proposals. Send substantive
   visual changes for approval and hand the contract to implementation.

## Stop conditions

Missing brand authority, conflicting master/page decisions or unresolved tokens
block final design approval, not unrelated discovery work.

## Evidence

Current source paths, adopted values versus proposals, alias mapping, paired
state checks, viewport/content evidence, and scoped exception rationale.

## Output

`docs/design/MASTER.md` plus affected `docs/design/pages/SLUG.md` only when needed.
An inline delta is sufficient for a small change to an established system.

## Failure behavior

Do not claim a palette is accessible without measurement or replace missing
brand values with supposedly existing ones. Mark proposals and verification gaps.
