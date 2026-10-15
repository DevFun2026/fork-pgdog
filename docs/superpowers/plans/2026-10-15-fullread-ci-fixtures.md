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

## Fresh dependency advisory remediation

The fresh dependency scanner at CI-repair commit `38ba7d74` fails on four October 14 RustSec advisories, RUSTSEC-2026-0346 through RUSTSEC-2026-0349, affecting locked rustls 0.23.45. Official RustSec advisories identify 0.23.46 as patched: [0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html), [0347](https://rustsec.org/advisories/RUSTSEC-2026-0347.html), [0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html), [0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html). Preserve the no-exceptions advisory policy and use Cargo to resolve only the rustls patch update; inspect any additional resolution changes before accepting them. This keeps the TLS library/API and trust boundary, rather than changing providers or disabling checks.

The existing failed dependency scan is RED evidence. Verify lock consistency and a fresh dependency scan after the update, then run existing TLS reload and complete endpoint/workspace gates on the final committed candidate. Record crypto and dependency impact under the existing Standard profile; do not claim canonical SSH clearance under the owner-waived route. Keep the interrupted pre-patch full-gate evidence incomplete and preserve its logs; it is not clearance for the patched candidate.

## Integration failure localization

At `133b094c`, CI copy-data reports one missing final destination row, and two-PC reports two prepared transactions on each shard after its 15-second recovery deadline. Existing logs cannot attribute the copy deficit to either transfer hop or establish why recovery missed its deadline. The relevant engine and test paths are unchanged by the full-read candidate; that observation does not dismiss either failure or prove a timing explanation.

Add diagnostic-only evidence without altering successful workloads or assertions. At the quiescent first-hop copy cutover, emit only fixed synthetic table labels and source/first-hop integer counts; query failures, including partial stdout followed by an error, must fail closed. Preserve the final equality assertions. On the existing two-PC timeout, latch failure, observe fixed-shard integer counts for at most five additional live seconds, stop only the existing owned process, and query counts once after shutdown. Neither late completion nor diagnostic errors may convert that timeout into PASS. Do not print rows, keys, GIDs, raw PgDog logs, SQL results other than these counts, or connection/exception details.

Use focused test-first checks for count errors, placement, failure preservation, timing, cleanup and temporary import stubs. Reproduce only in disposable owned databases, with every port/config bound to the verified owned server and exact process cleanup. A native private reproduction may use random loopback ports and private config copies; it must never recreate the fixed test databases on an ambient PostgreSQL instance. Diagnose observed outcomes before proposing any runtime fix or deadline change. Keep release blocked until required CI and current-head canonical gates pass, with new review approval for the final immutable candidate.
