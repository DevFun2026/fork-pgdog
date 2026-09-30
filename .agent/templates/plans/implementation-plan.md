# Implementation Plan

**Goal:** State the observable outcome.

**Approved inputs:** Link the spec, ADRs, architecture, threat model, and approval.

**Scope / non-goals:** Define exact boundaries.

## Preflight

- Confirm repository status, commands, dependencies, permissions, and baseline evidence.

## Task N: Behavior

**Files:** list creates/modifies/tests.

**Contract:** inputs, outputs, invariants, errors, compatibility.

1. Write the focused failing test and expected reason.
2. Run RED and capture evidence.
3. Implement the minimum behavior.
4. Run GREEN and related regression checks.
5. Update architecture/security/docs/migration artifacts when triggered.
6. Commit the exact task scope.

## Final acceptance

- Full verification, independent review, cross-review, adjudication, security,
  docs drift, clean-checkout smoke, release/rollback, and residual risks.
