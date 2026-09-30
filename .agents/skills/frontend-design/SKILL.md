---
name: frontend-design
description: Use when building or refining an approved user interface with product-specific visual direction, responsive states, and implementation evidence in the existing frontend stack.
---

# Frontend Design

## When to use

Translate an approved interface brief into a working surface, or refine a
bounded existing surface without changing its product purpose.

## Do not use

For backend-only tasks, unapproved new product behavior, or design-only requests
that do not authorize product-code changes.

## Inputs

Approved brief and relevant design master/page delta, existing stack/components,
actual content/assets, acceptance criteria and available verification tools.
Retrieve only the applicable `.agent/` project context.

## Steps

1. Resolve affected source paths and reuse working components. Read the
   [visual direction method](references/visual-direction.md) when composition
   or styling needs decisions; skip re-discovery for settled small changes.
2. State the layout/content hierarchy and critique it against the brief before
   implementing. New consequential choices need approval, not a hidden redesign.
3. Implement the approved states with semantic controls and actual data contracts.
   Apply the normal plan/test-first workflow for behavior. Use the existing stack;
   a visual skill does not authorize a framework, asset download or dependency.
4. Exercise empty, pending, errors, partial results and completion; include long
   localized content, keyboard/focus and responsive behavior where applicable.
5. Use the [handoff template](assets/implementation-handoff.md) to connect changed
   components to acceptance IDs and real checks. Inspect available rendered
   evidence; record browser/visual gaps separately and request UX review if needed.

## Stop conditions

Do not invent domain policy, publish mock data as real, or implement unapproved
irreversible actions. Design-only handoffs stop before product-code changes.

## Evidence

Changed paths, acceptance/state mapping, command results and rendered checks with
viewport/browser details; clearly separate plans, reports and observed results.

## Output

Requested interface change plus a bounded handoff under
`docs/design/implementation/SLUG.md` or inline for small changes.

## Failure behavior

No browser access means visual checks remain unverified, not passed. Preserve
useful implementation evidence and name the exact missing check/tool.
