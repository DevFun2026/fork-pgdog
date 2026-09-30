---
name: ux-discovery
description: Use when an interface needs user journeys, task priorities, interaction states, or an evidence-backed UX brief before visual design or implementation.
---

# UX Discovery

## When to use

An interface task is unclear about people, outcomes, navigation, or recovery.

## Do not use

For backend-only work, a settled cosmetic edit, or claims of research without
participants or evidence. Reuse an approved brief instead of interviewing again.

## Inputs

Requested outcome, existing screens and product constraints, available research,
actors/devices, and current decisions. Retrieve only relevant `.agent/` context.

## Steps

1. Separate observed evidence, stakeholder reports, assumptions, and unknowns.
   Ask only questions that materially change scope or task safety.
2. Read the [journey method](references/journeys.md). Map the primary task,
   alternate paths, permissions, and recoverable versus irreversible actions.
3. Use the [brief template](assets/ux-brief.md) for a new or changed flow.
   Assign stable journey/state/acceptance IDs, not a persona fiction.
4. Cover actual content ranges, small screens, language, empty/loading/error and
   partial results; identify what the interface cannot decide for the backend.
5. Present decisions and the smallest testable handoff. Seek approval for new
   consequential choices; mark unapproved assumptions without blocking unrelated
   exploration. Hand the approved brief to design or implementation as needed.

## Stop conditions

No implementation of unresolved high-impact actions or fabricated user findings.

## Evidence

Source references and dates, labeled assumptions, actor/task/state coverage,
acceptance IDs, open questions with owners, and approval status.

## Output

A scoped `docs/design/flows/SLUG.md` brief, or an inline brief for a small task;
link existing evidence rather than reproducing it.

## Failure behavior

If research or product decisions are missing, provide a provisional brief with
limits and the next useful validation; do not label it user-validated.
