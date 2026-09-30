---
name: threat-modeling
description: Use when assets, actors, trust boundaries, external integrations, sensitive data, or abuse paths are introduced or changed.
---

# Threat Modeling

Model what can go wrong before relying on controls.

## When to use

- Design or change impact alters security-relevant structure or data flow.

## Do not use

- Do not claim complete security coverage from a checklist or model review.

## Inputs

- Project model, approved security profile, data classification, change scope, and existing `docs/security/threat-model.md`.

## Steps

1. Identify assets, actors, capabilities, entry points, flows, stores, and trust boundaries.
2. Enumerate abuse cases including injection, traversal, secret exposure, tampering, replay, races, dependency compromise, privilege misuse, and recovery failure.
3. Map each threat to prevent, detect, respond, and recover controls plus verification evidence.
4. Record added, removed, and changed items as a threat-model delta.
5. Run `./scripts/agent security --json` and preserve unverified areas and residual risks.

## Stop conditions

- Stop release when a triggered delta, control owner, or risk disposition is missing.

## Evidence

- Model revision, abuse cases, control links, test/scanner evidence, and human risk decisions.

## Output

- Current threat model and change-specific delta.

## Failure behavior

- Unknown exposure remains an explicit residual risk, never an implied pass.
