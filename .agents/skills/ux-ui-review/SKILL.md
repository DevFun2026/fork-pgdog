---
name: ux-ui-review
description: Use when an interface change needs evidence-backed review of task completion, interaction states, accessibility, responsive content, or design-system consistency.
---

# UX/UI Review

## When to use

Review an implemented interface, a prototype, or a bounded design artifact.

## Do not use

As a replacement for correctness/security review, real user research, or
independent cross-provider clearance. A read-only review does not authorize fixes.

## Inputs

Scope/diff identity, brief and acceptance IDs, design master/page delta, affected
source and available rendered/test evidence. Reuse related `.agent/` findings
by ID rather than repeating an entire code or security review.

## Steps

1. State artifact type and evidence available: source, rendered state, interaction
   recording, measurement or stakeholder report. Select relevant checks from the
   [review method](references/review-method.md), not every possible audit category.
2. Trace the primary task and consequential state transitions. Check selection
   scope, feedback, permissions and recovery against the actual product contract.
3. Inspect semantics, keyboard/focus, forms, localized content, responsive states
   and approved design consistency. Exercise a browser when available; don't infer
   interaction success from screenshots or conformance from a scanner.
4. Use the [report template](assets/ux-review.md). Each finding needs location or
   supplied-evidence reference, impact, reproduction/reasoning and a scoped remedy.
   Distinguish confirmed defects from questions needing runtime/server evidence.
5. Prioritize by user impact, deduplicate existing findings, and return coverage
   with pass/fail/incomplete for the reviewed scope. Send accepted fixes through
   normal implementation and verification, without weakening existing gates.

## Stop conditions

Missing required evidence prevents a passing verdict. Stop before claiming
device, accessibility or usability validation that was not performed.

## Evidence

Source/diff or artifact identity, finding IDs, acceptance links, actual commands
or interaction observations, browser/viewport/state and explicitly untested scope.

## Output

`docs/reviews/SLUG-ux.md` or a concise inline report; no automatic numerical
health score or compliance certification.

## Failure behavior

Return source-backed findings with incomplete coverage when browser or design
inputs are absent. Do not invent paths, line numbers, screenshots or positive tests.
