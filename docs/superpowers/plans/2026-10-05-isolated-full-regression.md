# Isolated full regression

**Goal:** Run the complete existing regression gate without modifying the
PostgreSQL instance already listening on the developer machine's port 5432.

**Approved inputs:** Strict endpoint spec and implementation plan; user's
2026-10-05 approval to continue resolving local verification/review blockers.

**Scope:** Test fixture portability and disposable local runner only. Production
query policy, review limits, required checks and external publication stay under
their existing contracts.

## Owned native strict fixture

Files: `scripts/strict_read_fixture.py`, `scripts/verify-pgdog`,
`tests/artifacts/test_strict_read_isolation.py`, `docs/VERIFICATION.md`.

Add explicit `docker|native` selection, with Docker remaining the default.
Native mode requires PostgreSQL 18 binaries and creates a new private data
directory inside its temporary fixture directory. Start only that server on a
generated loopback port, initialize its database with generated credentials,
and record the exact child PID for cleanup. Reject unsupported versions and
unknown modes; never reuse an ambient database or daemon. Full regression
passes the explicitly selected mode to both strict fixture invocations.

1. Demonstrate failing tests for native ownership, explicit connection target,
   version rejection, mode selection and cleanup.
2. Implement the fixture; run those tests and actual native strict protocol tests.
3. Keep private logs and credentials in the owned temporary directory; sanitize
   inherited database settings exactly as the Docker fixture already does.

## Disposable Linux runner

Use an ignored runner Dockerfile with the repository's pinned Rust toolchain,
PostgreSQL 18, nextest 0.9.78, Toxiproxy 2.12.0, Node.js and bubblewrap for the agent-runtime
mock-provider tests. Use one build job and debug
artifacts to fit local resources. No host networking, published database port,
host Docker socket or privileged container is needed. Copy a local checkout
into the runner, excluding host build artifacts and credentials.

The runner drops all Linux capabilities and uses `seccomp=unconfined` plus
`systempaths=unconfined` to permit bubblewrap's nested user/PID/proc namespaces.
These options are local test infrastructure only. No host filesystem mount or
Docker socket is present. A separate probe must prove the complete namespace
operation before running the mock-provider suite.

Create a fresh native PostgreSQL cluster with SCRAM authentication inside that runner on its isolated
localhost:5432 with the settings required by `integration/setup.sh`. Bootstrap
legacy databases only there. Run the unchanged mandatory checks through
`agent verify review` with native strict fixture selection. Copy back logs and
gate evidence with source identity; record any failures as failures, and delete
only the recorded runner container. No existing host service is touched.

The existing shallow-clone governance test must advertise `main` as its source
remote's default before cloning only `feature`. Test that fixture correction on
Linux Git with RED/GREEN, preserving the missing-anchor assertion and leaving
the governance resolver unchanged. Its pre-existing failure is separate from
the endpoint implementation. Cache cleanup is limited to identified PgDog
compiler/task cache IDs; no global Docker prune is part of verification.

Rename the fixture-dependent catalog test in
`applications/pgdog/pgdog/src/backend/schema/read_policy/tests.rs` to the existing
`strict_read` naming convention. Demonstrate its absence from the default
nextest selection and actual execution in the owned core fixture, preserving
every assertion. Do not skip it or accept an absent fixture.

## Acceptance and remaining gates

Require isolation tests and native protocol tests to pass before using the new
mode. Full regression must finish with actual command exit codes; resource or
dependency failures do not count as clearance. Fresh evidence must match the
reviewed source. The independent package size blocker requires its own approved
review design and exact manifest approval before provider egress. No commit,
push, merge or publication follows automatically from this plan.

## Additional regression found during integration

The named-slot integration case exposed a reporting race in
`SHOW REPLICATION_SLOTS`: it captured `now` before taking the slot snapshot, so
a concurrent transaction timestamp newer than `now` became null when
`duration_since` failed. The command now snapshots first, then captures `now`,
and reports a future timestamp as age zero while preserving null for a missing
timestamp. Deterministic unit coverage passed for past, future and missing
values. The focused integration case compiled but could not reach its assertion
because the environment denied the test connection with `Operation not
permitted`; this remains an environment blocker, not a passing integration
result.
