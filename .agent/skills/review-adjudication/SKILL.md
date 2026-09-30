---
name: review-adjudication
description: Use when reviewer findings must be confirmed, rejected, or held for evidence before merge decisions.
---

# Review Adjudication

Reviewer output is an input to verification, not an automatic verdict.

## When to use

- Independent or cross-review findings exist and need disposition.

## Do not use

- Do not reject a finding because it is inconvenient or accept one without reproducing its claim.

## Inputs

- Structured findings, reviewed revision/package, source location, reproduction evidence, tests, and requirements.

## Steps

1. Resolve each cited file and line against the reviewed head revision.
2. Reproduce the claimed behavior or trace the violated invariant.
3. Mark `confirmed` only with evidence, `rejected` only with an explicit reason, otherwise `needs-evidence`.
4. Add a regression test before fixing confirmed code defects.
5. Record one decision for every finding in the JSON decisions document.
6. Run `./scripts/agent adjudicate --package PACKAGE --file DECISIONS.json`.
7. Block merge for confirmed or unresolved Critical/High findings and keep lower severities visible.

## Stop conditions

- Stop merge while any Critical/High finding is confirmed or lacks enough evidence for safe disposition.

## Evidence

- Finding ID, disposition, command or source reference, reason, fix commit, and re-verification.

## Output

- A manifest-, head-, and findings-checksum-bound `.agent/.runs/adjudication.json` plus the human-readable review summary.

## Failure behavior

- Missing location or reproduction becomes `needs-evidence`; silence is not rejection.
