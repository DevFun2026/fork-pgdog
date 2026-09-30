---
name: security-review
description: Use when a change affects exposure, identity, authorization, inputs, sensitive data, cryptography, dependencies, infrastructure, or recovery.
---

# Security Review

Report checked scope and residual risk rather than absolute safety.

## When to use

- Security-relevant change impact exists or merge/release policy requires full review.

## Do not use

- Do not treat AI analysis, a scanner, or a checklist as certification.

## Inputs

- Approved profile, threat-model delta, project model, diff, data classification, scanner/test evidence, and prior findings.

## Steps

1. Fetch and resolve the remote default branch as the immutable trusted base; run `./scripts/agent security --json` and verify its base SHA, head SHA, and scope include the complete change. Reject `HEAD` or an intermediate feature commit as base.
2. Review identity/authorization, inputs/injection, secrets/data, session/crypto, business logic/races, supply chain, infrastructure, and recovery.
3. Trace changed trust boundaries and data flows to concrete controls and tests.
4. Correlate deterministic scanner results without suppressing manual design findings.
5. Record findings, unverified areas, required follow-up, and residual risks with owners.
6. For clearance, bind the complete assessment plus canonical digest in the strict security-approval JSON, use an independent reviewer, and verify its detached SSH signature against `.agent/security/allowed_signers` from the assessed base revision.

## Stop conditions

- Stop release when required review, scanner, threat-model delta, or risk disposition is missing.

## Evidence

- Profile, scope, lenses, commands, versions, findings, control evidence, residual risks, signed approval identity, and approval checksum.

## Output

- Scope-bounded security clearance or explicit blocked/incomplete result.

## Failure behavior

- Missing tooling is not configured or blocked according to policy; it never becomes a clean result.
