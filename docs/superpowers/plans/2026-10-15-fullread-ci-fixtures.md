# Full-read CI fixture integration repair

Scope derives from the approved full-read specification and the human instruction to complete every non-waived merge/release gate before shipping 0.2.2. Preserve Standard security, exact review-hash approval, all test selections and owned temporary database isolation. This repairs fixture delivery for existing tests; it does not change SQL admission or waive CI.

## Evidence and expected behavior

At candidate 94fc20f5, the coverage workflow failed 20 tests before assertions because PGDOG_PROFILE_TEST_FIXTURE_DIR was absent. The normal local gate passed with the owned fixture environment present. The fork verification workflow separately reported strict-read-all failure without retained raw detail; diagnose that failure independently before selecting its fix.

## Execution

1. Reproduce the coverage command/environment mismatch through a focused workflow and producer lifecycle regression. RED must show that coverage cannot currently receive the owned fixture directory for its command lifetime.
2. Add an explicit fixed coverage mode to scripts/workspace_read_tests.py and wire .github/workflows/tests.yml to it. Preserve the default nextest command, exact coverage arguments/output path, subprocess argv execution, preparation validation and cleanup on success/error. No arbitrary shell command interface or hard-coded dummy fixture path.
3. Reproduce strict-read-all with the same pinned owned images and the external profile fixture environment removed. Distinguish Docker sandbox/availability failures from test failures. Select the smallest fix only after evidence; record it here before implementation.
4. Run focused RED/GREEN, full producer/workflow tests, docs/adapters and fresh canonical verification. Validate a clean committed CI candidate and all required remote checks before starting its new immutable AGY package, so known CI failures do not waste review egress.
5. Obtain the fresh exact manifest approval for the changed candidate and complete every child plus separately approved integration. Preserve all prior package/audit evidence at its original head. Merge and publish only after all non-waived gates and the final source-bound owner payload approval.

## Ownership and rollback

Coverage worker owns producer, its tests and the coverage workflow. Primary owns this plan, integration and any separately evidenced strict-read repair. Restore a failed patch by reverting only its scoped changes; never reset or rewrite old review markers, audits, private schema captures or unrelated checkout changes. No live icondo database or Kubernetes mutation is part of this repair.

## Confirmed readiness repair

An owned PG12 startup probe reproduced socket readiness while `listen_addresses` was empty, followed immediately by the missing-socket SQL error. Container logs bound that window to the official image's temporary initialization server shutting down before the final server starts. Two other probes reached the final server and succeeded. The original remote strict-read failure remains unattributed because its raw output was not retained.

Require TCP loopback readiness inside the same network-disabled owned container before catalog SQL. The temporary server does not listen on TCP. Add a deterministic regression that models temporary socket readiness and asserts that DDL waits for final-server readiness, plus a timeout case that never runs DDL and still removes the owned container. Keep the existing bounded wait, image pins, private fixtures, and SQL safety behavior.
