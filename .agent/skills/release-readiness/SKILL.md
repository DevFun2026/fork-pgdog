---
name: release-readiness
description: Use when a verified change is being prepared for a tag, deployment, distribution archive, or production handoff.
---

# Release Readiness

Release is a stricter evidence boundary than merge.

## When to use

- A candidate revision may be shipped or distributed.

## Do not use

- Do not infer release readiness from a passing unit suite alone.

## Inputs

- Current merge evidence, security clearance, threat-model delta, scanner statuses, clean-checkout smoke, docs, release notes, migration/backup/rollback, and residual risks.

## Steps

1. Confirm all evidence is tied to the candidate commit and diff.
2. Configure scanner argument arrays, dedicated non-mutating version commands, and explicit external support paths under the corresponding `[security.scanner_*]` tables, then execute every required dependency, license, SAST, IaC, and container check with `agent release run-scanner`; status and tool identity must be runtime-derived without recursively hashing repository scan targets.
3. Build and smoke-test a clean checkout or release archive without local ignored state.
4. Verify docs drift, release notes, compatibility, migration, backup, rollback, and risk ownership.
5. Bind the three reviewed documents with `agent release record`, then run the clean archive smoke.
6. Run `./scripts/agent verify release --json` and preserve the machine-readable result.

## Stop conditions

- Stop on failed, stale, skipped, timed-out, or missing required evidence.

## Evidence

- Candidate revision, exact commands, tool versions, artifact checksums, gate result, and approval record.

## Output

- Passed, blocked, or incomplete release-readiness record with no hidden gaps.

## Failure behavior

- Optional unsupported tooling is explicit `not-configured`; required unsupported tooling blocks.
