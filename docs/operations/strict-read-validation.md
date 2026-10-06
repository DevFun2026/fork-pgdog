# Strict read endpoint validation record

Date: 2026-10-05. Scope: the uncommitted strict-read/write feature above baseline
`960942d4254a547d459d44545151f30380ae3173`. No commit, push, registry publication,
or deployment to an existing cluster has been performed. This record describes
local evidence and outstanding gates; it is not release or security clearance.

## Observed checks

Task-local logs are under ignored `.agent/.runs/strict-read/`; they are evidence
from this workstation, not files that CI can assume exist. Reproducible commands
are in [the operations guide](strict-read-endpoints.md) and `docs/VERIFICATION.md`.

| Check | Result / evidence |
| --- | --- |
| Pre-feature executable | Built from the baseline, checksum retained; new CLI flag rejected specifically as unknown, exit 2 |
| Owned PostgreSQL 18 suite | 2 unrestricted baseline, 18 strict protocol and 51 core tests passed; `strict-all-final.log` |
| Transaction pool / parser off / full prepared mode | 18/18 passed after endpoint canary addition; `protocol-transaction-off-full.log` |
| Startup and buffer framing/logging | 23 tests passed serially, including real TCP framing; `startup-buffer-full.log` |
| Typed parameter bounds | Real `$1025` acceptance reproduced RED, now denied; both typed resolver tests GREEN; declared Parse OID budget tested separately |
| Timeout cancellation | Locked backend remained after socket close (RED); bounded CancelRequest + discard fixed it; 18 protocol tests GREEN while the conflicting lock remained held |
| Chart and harness | 64 artifact tests passed; both strict read/write examples linted, rendered and packaged; shell syntax and ShellCheck passed |
| Rust quick gate | Passed format, warnings-denied workspace Clippy and configured library tests; `quick-final.json` |
| Docs/model/adapters/skills | Generated docs build/check, adapter check and 25-skill check passed |
| SAST | Semgrep 1.178.0: 849 scanned paths, 11 rules, zero findings/errors at the scanner checkpoint |
| Dependency / license | Required `cargo-deny` executable is unavailable; both configured scans failed, not passed |
| Production Dockerfile build | Failed with `cannot allocate memory` / exit 102 under Docker's 2 CPU / 4 GiB limit |
| Local test image | Passed Linux arm64 build, image config digest `sha256:da1a08884b4f2e6f865c7760b70464f720764a2537bfafbb39f16d43af38bbd5`; test-only Dockerfile disables LTO, uses opt-level 1, 16 codegen units and one build job; production Dockerfile unchanged |
| Paired Kind smoke | Passed on the local test image with mandatory TLS and empty users; read/write Service behavior, snapshots, drain/migrate/restart, immutable manifest, invalid configcheck and zero runtime restarts; `kind-smoke.json` |
| IaC / container scan | Trivy 0.74.0 passed the configured HIGH/CRITICAL scans; final local results in `.agent/.runs/scanners/{iac,container}.json`; container coverage is the test image, not the unbuilt production image |

Local image tag: `fork-pgdog:strict-read-local-test`. The image source manifests
retain file digests and the test Dockerfile digest. Comparing the captured Docker
context to the final tree found only the later integration canary test changed;
all runtime source, manifests and dependency inputs match the image snapshot.
A dirty-source candidate does not use the baseline SHA as a release revision.
The lower-optimization test image cannot establish a successful full-LTO release
build or a Linux amd64 result.

The first Kind run exposed missing TLS file paths in the smoke-generated TOML;
the operator examples were already correct. After fixing the harness, one run
had a five-second connection timeout immediately after rollout. Its cause was not
attributed. The final mandatory-TLS run passed without connection retries and
without runtime container restarts. The harness now retains failure diagnostics
and waits a bounded interval only for post-rollout connection errors; SQL errors
and policy denials are not retried. Owned clusters were cleaned up.

## Acceptance mapping

| Spec ID | Evidence and limit |
| --- | --- |
| A1–A2 | DML-capable nonowner/non-superuser app on both endpoints; SQL positive/negative matrix with direct row/schema/sequence snapshots; tokio-postgres prepared/binary values |
| A3 | Entire simple batch admitted before execution; trailing writes, dollar quotes, Unicode and nested modifying CTE cases; parser depth/node/count budgets |
| A4 | Raw Parse/Bind/Describe/Execute/Flush/Sync; suspended portal after statement Close, named reprepare across epochs, implicit/explicit I/T/E and discard-until-Sync recovery |
| A5 | Unknown/prepared identity and stale proof negatives; parser-off + transaction/full-prepared variant; SQL PREPARE/EXECUTE denied |
| A6 | Startup exact-frame/key limits, unsafe backend string mode, raw Fastpath/orphan COPY denial, SET/role/READ WRITE/plugin/admin/replication/config restrictions |
| A7 | Live catalog proof rejects overloaded candidates, views/RLS/custom types/expression indexes; full scalar cast/operator/aggregate and btree/hash support closure; endpoint candidate-set canary passed: direct-qualified control advances its sequence/raises marker; read endpoint returns policy 0A000 and preserves sequence state |
| A8 | Same-backend protected READ ONLY setup and acknowledgement tests; internal commands preserve unnamed statements and Flush behavior; client prepare/bind/describe/execute require current proof |
| A9 | Explicit failure recovery, idle/active cancel, partial messages, backend loss before Sync, timeout while holding a conflicting lock, repeated passthrough authentication and pool reuse; uncertain backend discarded |
| A10 | Paired render selectors/args/mounts and historical source-binary CLI rejection verified; no claim about pulling/testing published 0.1.0 |
| A11 | Actual paired Kind Service test passed: TLS passthrough, no application credentials in users.toml, DML denials with snapshots, successful write/read visibility, drain around DDL, manifest restart and invalid init |
| A12 | Owned unrestricted DML and quick library regressions; full legacy upstream driver/Toxiproxy suite unrun |

## Review adjudication

Two smaller same-provider workers contributed scoped implementation and review.
This does not satisfy the repository's cross-provider review/signature gate.

- Accepted and fixed: strict raw SQL appeared in oversized-message logging;
  bounded startup framing and retained parameter vectors were missing; timeout
  socket close could leave a PostgreSQL lock waiter active. Each has concrete
  behavioral RED/GREEN coverage.
- Accepted and fixed: strict configuration misclassified the mandatory shard-0
  vector as sharding; idle extended COMMIT attempted to finish an absent backend
  transaction. Both regressions were reproduced before correction.
- Rejected with evidence: integer/smallint/bigint/decimal/real/boolean/char aliases
  were thought to be unresolved. Actual parser normalization and resolver tests
  pass. A proposed control/data prepared-name collision was already guarded by
  the unconditional namespace check.
- Accepted evidence gap, now closed: added endpoint-level candidate-set canary
  to the SQL matrix. A qualified owner call proves the public overload can mutate
  a sequence; the supported unqualified endpoint query is denied with policy
  `0A000` and leaves the sequence unchanged. This does not claim PostgreSQL would
  select that public overload under a pg_catalog-first search path. All 18 owned
  protocol tests passed after the addition.

- Accepted harness review findings: missing-relation probes must match the exact
  policy error, final read/write Pods must be Running/Ready with a ready PgDog
  container and no runtime restarts, and failed Kind creation must not authorize
  deletion of an existing cluster. A mocked name-collision test reproduced the
  last issue before ownership was moved after successful creation; UUID names
  further reduce collisions. Kind handles its own failed-create cleanup.
- Scoped nonblocking note: synthetic, short-lived fixture credentials are passed
  to kubectl exec environment arguments inside the owned cluster. These are not
  application/operator secrets; the production examples continue to use existing
  Secrets and application-supplied passthrough credentials.

## Outstanding gates and operational limits

The full legacy test command expects PostgreSQL on 5432, which is occupied by an
existing service not owned by this task. Its database has not been altered or used
as a destructive fixture. `cargo-nextest` and Toxiproxy prerequisites are also
unavailable in the bounded local lookup. Run the documented full suite in its own
prepared environment before merge.

Security assessment and review-package preview return
`trusted governance base must be a proper ancestor distinct from HEAD`:
HEAD still equals the freshly fetched remote main baseline. An authorized local
feature commit is needed before these tools can bind the complete change. No
review content has been sent to another provider. Exact package approval,
independent review, required scanner results and signed security clearance remain
outstanding. Merge/release gates have not passed.

Only the pinned PostgreSQL 18 catalog and the documented conservative SQL/type
surface are supported. Operators must control DDL/role changes and drain/restart
read instances; DBAs, PostgreSQL binaries and native extensions remain trusted.
Roles must meet the nonowner/no-CREATE conditions. Access to the unrestricted
write Service still permits the role's granted writes. See the operations guide
and [residual risks](../security/residual-risks.md) before staging deployment.
