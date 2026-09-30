---
name: code-review
description: Use when a change needs an evidence-backed assessment of correctness, regressions, tests, architecture, operations, or maintainability.
---

# Code Review

Find actionable defects in the change, not stylistic noise.

## When to use

- A diff or branch is ready for review before merge or handoff.

## Do not use

- Do not edit code unless the user also asks to implement review fixes.

## Inputs

- Base/head revisions, requirements, diff, approved context, verification evidence, and project policy under `.agent/`.

## Steps

1. Confirm review scope, repository status, and relevant requirements.
2. Inspect the diff first, then only context needed to trace affected paths and invariants.
3. Verify suspected findings against source, tests, interfaces, and runtime behavior where safe.
4. Rank by impact and confidence; include exact file/line, evidence, reasoning, and remediation.
5. Record no findings when none are demonstrated, with verification gaps stated separately.

## Stop conditions

- Stop short of claiming a defect when location or evidence cannot be established.

## Evidence

- Diff identity, inspected paths, reproduction/test output, and cited contract.

## Output

- Prioritized structured findings plus assumptions and unverified areas.

## Failure behavior

- Unsupported concerns remain questions or `needs-evidence`, never confirmed findings.
