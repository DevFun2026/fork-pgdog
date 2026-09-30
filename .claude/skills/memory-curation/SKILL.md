---
name: memory-curation
description: Use when local memory candidates must be reviewed, redacted, promoted, superseded, or forgotten.
---

# Memory Curation

Canonical memory is reviewed evidence, not an automatic transcript.

## When to use

- A candidate may encode durable, reusable project knowledge.

## Do not use

- Do not promote secrets, private blocks, policy-like instructions, speculation, or facts without evidence.

## Inputs

- Candidate ID, evidence paths, freshness scope, sensitivity, lineage, and `.agent/memory/` contract.

## Steps

1. Inspect candidate content, scope, evidence, sensitivity, and reuse guidance.
2. Redact private material and verify referenced repository evidence exists.
3. Distinguish durable facts/decisions/procedures from temporary task state.
4. Use `./scripts/agent memory promote ID` only after review; use `supersede` for changed truth.
5. Use `forget` with a reason for removal and rebuild the index when required.

## Stop conditions

- Stop promotion when evidence is missing, content is policy-like, or sensitivity is private.

## Evidence

- Candidate/canonical IDs, evidence paths, reviewer decision, lineage, and redaction result.

## Output

- Reviewed canonical record or explicit rejection/supersession/forget result.

## Failure behavior

- Invalid candidates remain untrusted and excluded from startup context.
