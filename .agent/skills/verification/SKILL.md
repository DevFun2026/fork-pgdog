---
name: verification
description: Use when preparing to claim that work is correct, complete, fixed, mergeable, or release-ready.
---

# Verification

Fresh observable evidence precedes every completion claim.

## When to use

- Before commit handoff, merge, release, or any statement that behavior passes.

## Do not use

- Do not reuse stale output from another commit or diff.

## Inputs

- Acceptance criteria, configured commands, current Git identity/diff, required artifacts, and prior evidence metadata.

## Steps

1. Select the smallest gate matching the claim: quick, merge, or release.
2. Run the exact command now, inspect exit code and complete relevant output, and verify expected tests were discovered.
3. Run `./scripts/agent verify quick|merge|release --json` as appropriate.
4. Check documentation, security, review, migration, and residual-risk artifacts required by that gate.
5. State passed, blocked, or incomplete with exact gaps.

## Stop conditions

- Stop before a success claim when a required command is missing, skipped, timed out, stale, or failing.

## Evidence

- Command, exit code, test count, tool version, commit, diff checksum, timestamp, and artifact paths.

## Output

- Scope-bounded verification result and remaining limitations.

## Failure behavior

- Treat uncertainty as incomplete and policy failure as blocked; never convert either to success.
