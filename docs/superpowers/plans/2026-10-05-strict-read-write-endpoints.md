# Strict Read and Write Endpoints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` with
> the user's manager-led delegation policy. Work task by task with explicit
> file ownership and RED/GREEN evidence. No recursive delegation or Git commits
> without authorization. `superpowers:executing-plans` is the fallback if smaller
> workers are unavailable; report that limitation rather than substituting a
> supposedly cheaper worker with the same or a larger model.

**Goal:** Two Kubernetes endpoints share a PostgreSQL backend and application
identity, while the strict-read endpoint rejects mutations and unsupported SQL
through independent admission and PostgreSQL READ ONLY enforcement.

**Architecture:** Two releases of one chart use separate processes, Services and
pools. Immutable process policy, a protected relation manifest, per-session
statement/portal identity and a guarded transaction state machine enforce read
admission independently of routing. The unrestricted endpoint preserves existing
behavior.

**Tech Stack:** Existing Rust workspace/locked dependencies, `pg_raw_parse`,
Tokio, existing PostgreSQL protocol types, PostgreSQL 18 fixtures, tokio-postgres,
psql, Python unittest, Helm and isolated Docker/Kind harnesses. No new runtime
dependency is planned.

**Spec:** [Approved specification](../specs/2026-10-05-strict-read-write-endpoints-design.md).
The user approved the written spec with “approve” on 2026-10-05. The execution
method is already selected by the standing manager-led delegation instruction.
The user approved implementation on 2026-10-05; execution is in progress.

**Planning baseline:** Source HEAD `960942d4254a547d459d44545151f30380ae3173`.
The approved spec is an untracked local file; preserve it. Read-only worker input
covered core integration and test/Helm harnesses; the primary owns this plan's
interfaces, dependency ordering and self-review.

## Global constraints

- CLI `--query-policy unrestricted|strict-read`, default `unrestricted`;
  `--read-policy-file` is mandatory for strict-read. Neither can be downgraded by
  reload, a user/database setting, SQL, plugins or client startup parameters.
- Chart `queryPolicy` uses those values; `readPolicy.existingConfigMap` supplies
  `read-policy.toml`. Both runtime and configcheck receive the strict arguments.
  Published `0.1.0` is not a strict-read-capable artifact.
- Manifest uses `schema_revision`, `[[databases]]`, `name` and `relations` only;
  reject empty/duplicate entries, invalid identifiers, unknown fields and wildcards.
  Load an immutable snapshot and content digest; ConfigMap updates require restart.
- Preserve passthrough auth and the operator's credential/TLS handling. Test with
  a DML-capable, non-owner, non-superuser account, not a database-enforced reader
  that could mask missing proxy enforcement.
- The spec's ordinary-table/type/aggregate allowlist is the upper bound. Deny
  opaque dependencies, UDFs, views, RLS, foreign/partitioned/inherited/temporary
  tables, SQL PREPARE/EXECUTE, COPY, EXPLAIN and unrecognized AST/protocol forms.
- Inspect original SQL before prepared rewriting, mirroring, routing or backend
  work. Inspect every statement of a simple Query before forwarding any of it.
  Fastpath FunctionCall and orphan COPY messages have no AST and need explicit gates.
- Protect server-side Parse/Bind/Describe/planning as well as Execute. Separate
  user-visible transaction state from internal read transaction state.
- Implicit extended transactions end at Sync, closing their portals. Explicit
  transactions and their portals can survive Sync. Never keep a hidden transaction
  alive after returning autocommit ReadyForQuery I.
- Use two Helm releases, not a two-workload redesign of one release. Preserve
  Kubernetes 1.28+, Helm 3.8+, ClusterIP:6432, current TLS/drain/hardening defaults.
- Controlled DDL migrations drain/readmit strict instances with a reviewed schema
  revision. Arbitrary native extensions, external effects and malicious DBAs are
  outside the supported trust boundary; do not advertise AST-only purity.
- Keep security profile `standard` and all existing independent review, signature
  and release gates. Feature implementation does not authorize deployment to an
  existing cluster, registry publication, commit, push, merge or new dependencies.

## Review focus

1. Parse/Describe can trigger backend work before Execute; both must remain
   behind the transaction and catalog gate (Tasks 2, 4, 5; test
   `strict_read_parse_describe_has_no_unguarded_backend_work`).
2. Bind-time type input and index/operator/aggregate support code can hide
   side effects; a matching SQL/function name is not authorization (Task 3;
   `strict_read_rejects_hidden_object_dependencies`).
3. Flush may require CommandComplete before Sync. Buffering that response until
   Sync can deadlock a driver; commit failure still needs an ErrorResponse before
   final ReadyForQuery (Tasks 4, 6; `strict_read_flush_does_not_wait_for_sync`).
4. Renaming/reusing an unnamed statement, closing its parent, catalog drift and
   global prepared-cache hits must not transfer authorization (Tasks 3, 5, 6;
   `strict_read_statement_portal_identity_is_session_scoped`).
5. A failed endpoint rollout, older image, config reload or ConfigMap update
   must not create a writable read Service (Tasks 1, 7, 8;
   `strict_read_old_binary_and_policy_reload_fail_closed`).

## Preflight and evidence rules

- [ ] Recheck `git status --short --branch`; preserve the spec and unrelated work.
  Follow the worktree skill at execution time if isolation is needed; carry the
  approved spec/plan without staging, committing or overwriting unrelated files.
- [ ] Read the approved spec, relevant canonical skills and
  [verification runbook](../../VERIFICATION.md). Check Rust/toolchain, Docker,
  PostgreSQL client, Helm, Kind and disk availability before fixture work.
  No tools were installed or daemons/clusters accessed during planning.
- [ ] Capture a runnable pre-feature binary from the baseline above into an
  ignored task directory, together with its checksum/source identity. This is
  the real old-CLI compatibility fixture, not a mock or a claim about publication.
  If building is blocked, record that explicitly; do not invent old-image evidence.
- [ ] Establish baseline with `./scripts/agent verify quick --timeout 3600 --json`.
  Record existing environment/product failures separately. `quick` does not run
  the PgDog binary's core tests, so it cannot substitute for the commands below.
- [ ] Core tests use `./scripts/pgdog cargo test --locked -p pgdog --bin pgdog`;
  PgDog has no library target. Verify matching test discovery/counts, not just an
  exit code for a filter that selected zero tests.
- [ ] Store task-local RED/GREEN logs in `.agent/.runs/strict-read/`, with command,
  source/diff identity, exit code and selected test count. A fixture/DNS/compiler
  failure or compile-only missing module is not proof of the intended behavior.
  A denial test already passing under a deny-all implementation is regression
  coverage, not new RED evidence; use the missing intended positive behavior.
- [ ] Do not run upstream `integration/setup.sh` on shared PostgreSQL. The new
  runner owns its disposable fixture. The existing full gate still needs its
  separately prepared PostgreSQL/Toxiproxy fixtures as documented in the runbook.
- [ ] Keep each task as a reviewable diff/checkpoint. Commit boundaries are listed
  below for future authorized Git work; none grants commit permission now.

## File ownership and dependency graph

Let `P = applications/pgdog/pgdog/src` and
`I = applications/pgdog/integration/rust`; these abbreviations apply only to this
table. Task paths below are repository-relative, not alternate directories.

| Owner | Create | Integrate/modify |
| --- | --- | --- |
| Policy worker, gpt-6-luna high | `P/frontend/read_policy/{mod,policy,manifest,error,admission,session,tests}.rs` | Registration in `P/frontend/mod.rs` by primary |
| Catalog worker, gpt-6-luna high, sequential with shared policy types | `P/backend/schema/read_policy/{mod,rows,registry,resolve,tests}.rs`, `catalog.sql` | `P/backend/schema/mod.rs`; internal parameterized server-query helpers only if required |
| Primary manager | `P/frontend/read_policy/transaction.rs`, `P/frontend/client/query_engine/strict_read.rs` | CLI/main/config reload validation, Client/QueryEngine context, request dispatch, connection, exchange/error/transaction paths |
| Fixture worker, gpt-6-luna high | `I/tests/strict_read.rs`, `I/tests/strict_read_support/{mod,wire,cases}.rs`, `applications/pgdog/integration/strict_read/{bootstrap.sql,read.toml,write.toml,read-policy.toml,users.toml}`, `scripts/strict-read-tests.sh` | `.config/nextest.toml`, `scripts/verify-pgdog`, CI registration after primary review |
| Helm worker, gpt-6-luna medium | `charts/fork-pgdog/examples/strict-read/{read-values.yaml,write-values.yaml,read-policy.toml}` | Chart schema/templates/NOTES, artifact validation/tests, `scripts/helm-smoke.sh` |
| Primary manager | `docs/operations/strict-read-endpoints.md` | Model, threat model, verification/operator docs and generated architecture outputs |

Never schedule more than two workers concurrently. Give each worker its exact
owned files, required interfaces, tests, no-recursive-delegation instruction and
the instruction that others are working in the repository: do not revert their
edits. Primary alone edits central QueryEngine/Client files to avoid conflicts.

Dependency order:

```text
T0 fixture/baseline -> T1 process policy -> T2 syntax/protocol admission
                                  T2 -> T3 catalog proof
                           T0 + T1 -> T4 transaction feasibility
                        T2 + T3 + T4 -> T5 enforcement integration
                                  T5 -> T6 complete wire/driver acceptance
                           T1 + T2 -> T7 Helm source work (not deployment)
                             T6 + T7 -> T8 two-Service smoke and CI
                                  T8 -> T9 docs/security/final review
```

T3 and T4 can run concurrently only after the primary freezes their interfaces.
T7 can run beside core work. No strict artifact is releasable until T5-T9 pass.

## T0: Owned fixtures and a reproducible baseline

**Files:** Create the fixture/runner files in the ownership table plus
`tests/artifacts/test_strict_read_isolation.py`; modify
`applications/pgdog/.config/nextest.toml` and `scripts/verify-pgdog` when registering
the dedicated suite. Reuse current protocol framing patterns from
`applications/pgdog/integration/rust/src/utils.rs` where applicable, but do not
reuse its fixed endpoint or superuser assumptions.

**Interface:** `scripts/strict-read-tests.sh --pgdog-bin ABS_PATH --phase
baseline|protocol|all` owns a unique Docker fixture and read/write process group,
exports generated `PGDOG_STRICT_TEST_CONFIG` JSON with loopback addresses,
synthetic role names and protected credential-file paths, and exits nonzero on
missing tools, readiness timeout, zero tests, failed assertions or cleanup errors.
The baseline phase selects only tests named `strict_read_baseline_*` and does not
require the new flag; protocol selects the remaining dedicated integration cases.
The all phase runs both groups and the PgDog binary's `strict_read` core cases
with the same owned fixture configuration. Each selection must discover tests.

- [ ] Write harness tests asserting unique resource names, loopback-only published
  ports, no default kubecontext, no arbitrary DATABASE_URL override and cleanup
  restricted to recorded PIDs/container IDs. RED:
  `python3 -m unittest discover -s tests/artifacts -p 'test_strict_read_isolation.py' -v`.
- [ ] Implement fixture ownership using the already pinned PostgreSQL 18 image
  from `tests/artifacts/kubernetes/postgres.yaml`; reuse the repository pin, not
  a floating tag. Allocate/check task-specific ports without stopping occupants.
  Owner creates tables/functions for negative cases; app gets DML/sequence grants
  without ownership, superuser or trusted-schema CREATE permissions.
- [ ] Implement a baseline test asserting the app can SELECT/INSERT/UPDATE/DELETE
  directly and via unrestricted PgDog, cannot ALTER/CREATE trusted objects, and
  the backend snapshots can detect row/schema/sequence changes.
- [ ] Reuse existing tokio-postgres/bytes dependencies for the dedicated
  `--test strict_read` target. Add raw wire support for controlled fixture auth;
  never switch the application test role to superuser to simplify authentication.
  Missing config is a failure, never an ignored test or successful early return.
- [ ] Register the dedicated binary separately from legacy integration fixtures:
  exclude only `binary(strict_read)` from the old integration profile's default
  selection and add a mandatory `scripts/strict-read-tests.sh --pgdog-bin "$PGDOG_BIN" --phase all`
  phase to `scripts/verify-pgdog`. Until new behavior exists this suite is expected
  to fail; no passing full-gate claim is made for intermediate commits.
- [ ] GREEN baseline command:
  `bash scripts/strict-read-tests.sh --pgdog-bin "$PWD/applications/pgdog/target/debug/pgdog" --phase baseline`.
  Run the old binary's configcheck with `--query-policy strict-read` and assert
  unknown-argument failure, not a missing config/database error. Checkpoint T0.

## T1: Immutable process policy and manifest

**Files:** Create `frontend/read_policy/{mod,policy,manifest,error,tests}.rs` under
`applications/pgdog/pgdog/src/`; modify that source tree's `frontend/mod.rs`,
`cli.rs`, `main.rs`, `config/mod.rs`, `frontend/client/mod.rs` and
`frontend/error.rs` for policy error conversion.

**Interfaces:** `QueryPolicy::{Unrestricted,StrictRead}` derives Clap ValueEnum.
`ReadManifest::parse(bytes: &[u8]) -> Result<ReadManifest, PolicyError>` is pure.
`ProcessPolicy::load(mode: QueryPolicy, path: Option<&Path>) ->
Result<Arc<ProcessPolicy>, PolicyError>` loads one immutable snapshot. It holds
mode, parsed manifest and `ManifestDigest([u8; 32])` using the existing
`aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes)` implementation.
`ProcessPolicy::validate_config(&ConfigAndUsers) -> Result<(), PolicyError>` checks
the forbidden feature combinations. Production initializes this once before
listener startup; tests inject an Arc rather than mutate a global policy.

- [ ] Add CLI/configcheck tests named `strict_read_cli_and_manifest_contract`:
  default is unrestricted; strict without manifest, invalid enum/path, unknown
  fields, blank revision, duplicate aliases/relations and malformed/wildcard
  names fail; quoted identifiers parse as identifiers, not executable SQL.
  Assert both `run` and `configcheck` recognize the same policy flags.
- [ ] RED: `./scripts/pgdog cargo test --locked -p pgdog --bin pgdog strict_read_cli_and_manifest_contract -- --nocapture`.
  Expected behavioral failure is absent/incorrect policy validation, not a skipped
  test. Add any compile-only seam before recording behavior RED.
- [ ] Implement validation before configcheck's early successful exit and again
  against the effective runtime configuration after env/URL overrides. Reject
  strict plugins, mirrors, rewrites, replication and multishard configurations.
  Only normal run and configcheck may use strict mode; backend-mutating CLI
  subcommands cannot run under it. Reject raw-query logging in strict mode.
  Incompatible hot reload leaves the previous accepted configuration active.
- [ ] Propagate the same Arc to every Client, including passthrough-created pools.
  Do not place process mode in the hot-reloaded ArcSwap config. A manifest volume
  update/reload cannot change mode, digest or allowed objects until restart.
  While T2-T5 are incomplete, strict mode denies all client query execution;
  it must never call unrestricted forwarding as a temporary implementation.
  Install the process-policy validation hook before the first config store, so
  neither initial loading nor `config::set` can briefly publish an incompatible
  snapshot. A failed reload must not mutate the accepted snapshot or policy.
- [ ] GREEN the same command and
  `./scripts/pgdog cargo test --locked -p pgdog --bin pgdog frontend::read_policy -- --nocapture`.
  Assert log/error output contains reason codes, never manifest SQL or secrets.
  Checkpoint T1; primary reviews mode propagation before dependent tasks.

## T2: Complete SQL and raw-message admission

**Files:** Create `applications/pgdog/pgdog/src/frontend/read_policy/admission.rs`;
extend policy tests/errors; primary integrates raw-gate call sites in
`frontend/client_request.rs`, `frontend/client/query_engine/mod.rs` and
`frontend/client/mod.rs`. Read `net/protocol_message.rs` without changing unrelated
protocol semantics.

**Interfaces:** `admit_sql(sql: &str) -> Result<AdmittedSql, PolicyError>` returns
original SQL, a SHA-256 fingerprint, `Vec<ReadAction>` and `CatalogRequirements`.
`ReadAction` is Select, Begin with `ReadIsolation::{ReadUncommitted,ReadCommitted,
RepeatableRead,Serializable}`, Commit, Rollback or ShowReadOnly.
`CatalogRequirements` records relation/function/operator/type
references and parameter-type requirements; it is not authorization.
`gate_message(message: &ProtocolMessage) -> Result<(), PolicyError>` explicitly
handles SQL-less messages. `PolicyError::sqlstate() -> &'static str` maps known
writes to 25006, unsupported to 0A000, syntax to 42601, protocol to 08P01.

- [ ] Write tests proving these assertions using the actual parser:
  `admit_sql("SELECT 1").is_ok()`;
  `admit_sql("SELECT 1; DELETE FROM app.orders").unwrap_err().sqlstate() == "25006"`;
  SELECT INTO, locking SELECT and nested modifying CTE are denied even with
  comments/quoted strings; unknown nodes do not inherit a parent's allow decision.
  Add supported nested SELECT/UNION/CASE/aggregate positives and error-code tests.
- [ ] RED/GREEN command:
  `./scripts/pgdog cargo test --locked -p pgdog --bin pgdog frontend::read_policy::tests::admission -- --nocapture`.
  Record intended positive/negative failure before implementing the exhaustive
  visitor. Use `pg_raw_parse::parse` and a full node walk, not the router's first
  statement or mutates flag. Reject unsupported populated AST fields as well as
  unsupported top-level nodes. Bound the policy walk to depth 128, 65,536 AST
  nodes and 1,024 statements per message; larger input gets 0A000. Preserve the
  existing wire framing limits and add exact boundary tests for these policy limits.
- [ ] Write message tests for F, orphan d/c/f, replication, internal
  EnsurePrepared/PrepareFromClient variants and unknown Other packets. Allow only
  recognized lifecycle/extended packets; generated internal packets require
  provenance from an admitted request rather than a client-supplied bypass bit.
- [ ] Place admission ahead of `rewrite_extended` and query-text logging as well
  as mirror/rewrite/routing work. Validate every original simple Query in full
  before existing split logic can forward a subset. Preserve untouched Parse
  content and type OIDs before name rewriting.
- [ ] GREEN message-order tests with a recording backend asserting zero forwarded
  client packets for denied batches and F/COPY attempts. Parser off/auto, cache
  hits and single-shard routing must not skip this gate. Checkpoint T2.

## T3: Trusted catalog resolution and object proof

**Files:** Create `applications/pgdog/pgdog/src/backend/schema/read_policy/`
`{mod,rows,registry,resolve,tests}.rs` and `catalog.sql`; register in
`backend/schema/mod.rs`. Extend T2 requirement types only through primary review.

**Interfaces:** `CatalogIdentity` contains backend database/role OIDs, connection
identity, transaction generation, manifest digest and schema revision.
`CatalogSnapshot::load(server: &mut Server, requirements: &CatalogRequirements)
-> Result<CatalogSnapshot, PolicyError>` is async and uses bound ServerRequest
parameters on that same protected connection, never a round-robin connection.
The loader verifies active READ ONLY transaction state before its catalog work;
an idle/writable/unknown server state is an error even if the caller passes an
apparently valid identity.
`verify_objects(policy: &ProcessPolicy, admitted: &AdmittedSql, catalog:
&CatalogSnapshot, identity: CatalogIdentity) -> Result<CatalogProof, PolicyError>`
is pure. Proof fields are private and bind SQL/type identity plus catalog identity;
only successful verification constructs one. Proof cannot cross transaction epochs.

- [ ] Write pure row-fixture tests for exact qualified relations/OIDs, false
  built-in name matches, untrusted aggregates/transitions, type IO/cast/operator
  functions, index expressions/predicates/access methods/opclasses and generated
  dependencies. Reject RLS/rules/views/foreign/partition/inheritance/temp objects,
  unsupported column types, cycles/unknown dependencies and unsafe role attributes.
  Known plain tables and built-in scalar operations/aggregates must pass.
- [ ] RED/GREEN command:
  `./scripts/pgdog cargo test --locked -p pgdog --bin pgdog backend::schema::read_policy -- --nocapture`.
  Implement a conservative resolver: a name/overload/search_path ambiguity or
  uncertain parameter coercion is denial, not an attempt to imitate PostgreSQL's
  entire resolver. Resolve the actual candidates visible to the effective role
  and search_path; enforce the spec registry by OID/signature/provenance.
- [ ] Use fully qualified, constant catalog SQL with bound identifier values/OIDs.
  Do not execute EXPLAIN, client Parse, arbitrary functions or object deparsing
  that can invoke untrusted code to obtain proof. Load enough metadata to inspect
  transitive planning/execution dependencies, including the underlying functions
  of approved aggregates and operators. Unknown server/catalog shapes deny.
- [ ] Define typed catalog rows for relations/namespaces/ownership, inheritance,
  attributes/types/type IO/collations, operators/casts, functions/aggregates,
  indexes/access methods/opclasses/support functions and role capabilities.
  In v1 reject nonempty index expressions/predicates and generated column
  expressions rather than add a PostgreSQL internal-node-tree interpreter.
  Ordinary indexes still require reviewed access-method/opclass support code.
  Missing dependencies and unresolved/cyclic untrusted paths deny; a small OID,
  `pg_catalog` name or volatility flag by itself is not proof of a built-in.
- [ ] Add isolated PostgreSQL cases in the T0 suite which install shadowed names,
  custom types/operators/index expressions, views and RLS via the owner account.
  The reader must refuse them before any canary side effect. Ordinary unqualified
  names are accepted only when resolution unambiguously matches the manifest.
  Missing permission/catalog/backend failures deny with bounded diagnostics.
- [ ] **Feasibility gate C:** demonstrate trusted-object proof without running
  client-controlled code. If supported objects cannot be proved conservatively,
  stop integration and present the concrete conflict; do not weaken the approved
  registry or silently admit opaque objects. Checkpoint T3 after pure and fixture
  tests pass; a schema revision string alone is not proof of freshness.

## T4: Internal read-only transactions and protocol feasibility

**Owner:** Primary. **Files:** Create
`applications/pgdog/pgdog/src/frontend/read_policy/transaction.rs` and
`frontend/client/query_engine/strict_read.rs`; modify QueryEngine's `connect.rs`,
`query.rs`, `start_transaction.rs`, `end_transaction.rs`, `context.rs` and test
`mod.rs`; create `test/strict_read_transaction.rs` in that directory.

**Interfaces:** `ReadTxState::{Idle,Implicit,Explicit,FailedExplicit}` is separate
from client `Transaction`. It tracks backend identity, generation and an
in-flight internal exchange tag. The new QueryEngine methods are
`async fn ensure_read_transaction(&mut self, context: &mut QueryEngineContext<'_>,
action: &ReadAction) -> Result<CatalogIdentity, Error>` and
`async fn finish_read_cycle(&mut self, context: &mut QueryEngineContext<'_>,
success: bool) -> Result<(), Error>`. The first obtains the selected backend,
starts READ ONLY and checks its acknowledgement before client backend work. The
second finishes an implicit cycle and consumes internal responses before one
client ReadyForQuery. Both use the engine's selected backend, never another pool.

- [ ] Add recording-backend and live-fixture tests before modifying exchange
  behavior. Assert internal BEGIN READ ONLY precedes client Parse/Bind/Describe;
  failed setup forwards none. Test Query, Parse-only+Sync, named/unnamed prepared
  statements, Flush, portal suspension/continuation and multiple Execute messages.
  RED: `./scripts/pgdog cargo test --locked -p pgdog --bin pgdog strict_read_transaction -- --nocapture`.
- [ ] Implement explicit BEGIN interception/forcing, COMMIT/ROLLBACK and failed
  transaction recovery. Reject READ WRITE, savepoints, chained/2PC modes and
  unsupported control mixing. A held backend and a newly checked-out backend
  must take the same enforcement path, including session pooling.
- [ ] Implement implicit cycles and internal reply tagging, preserving unnamed
  statement/portal state: an internal simple Query can destroy an unnamed
  statement, so use distinct internal prepared identities in a reserved namespace
  that cannot collide with client/global names. Catalog queries follow the same
  non-destructive rule. Explicit client COMMIT/ROLLBACK acknowledgements remain
  visible; synthetic housekeeping acknowledgements do not.
- [ ] At implicit Sync, close cycle-owned portals and finish the transaction;
  never hold it across ReadyForQuery I. Explicit Sync preserves T/E and eligible
  portals. Between Flush and Sync admit only the specified extended continuation;
  reject simple/control interleaving without transferring transaction ownership.
- [ ] Test `strict_read_flush_does_not_wait_for_sync`: row data and per-statement
  CommandComplete may precede Sync, as PostgreSQL requires. Do not wait for Sync
  before satisfying Flush. That statement acknowledgement is not a transaction
  success claim: a later internal commit failure must surface ErrorResponse
  before final ReadyForQuery. One Sync produces exactly one ReadyForQuery.
- [ ] Test denial/backend errors/cancel/timeout/disconnect, failed internal COMMIT,
  duplicate Sync and partial packets. Uncertain state closes/discards the backend;
  implicit errors roll back, explicit errors remain failed until rollback.
  Do not return a busy/unverified backend to any pool.
- [ ] **Feasibility gate T:** GREEN the recording cases and real PostgreSQL cases,
  with no extra command tags/RFQ states and no unnamed-statement loss. This must
  pass before enabling admitted client queries in T5. Unresolved wire-state
  behavior is a design conflict, not permission to ship a parser-only guard.

## T5: Per-client statement/portal enforcement integration

**Files:** Policy worker creates `frontend/read_policy/session.rs`; primary
integrates `frontend/client/{mod.rs,query_engine/context.rs,query_engine/mod.rs,
query_engine/rewrite.rs,query_engine/strict_read.rs}`, `frontend/client_request.rs`
and `frontend/prepared_statements/{mod.rs,rewrite.rs}` under the PgDog source tree.
Create `frontend/client/query_engine/test/strict_read_session.rs` and register it.

**Interfaces:** `PolicySession` owns original named/unnamed statement identity,
declared/inferred parameter types, portal bindings and original SQL fingerprints.
Define `PreparedReadStatement` holding AdmittedSql, parameter OIDs and generation;
`BoundReadPortal` refers to that immutable statement generation and bind/type
identity. Methods are `observe_parse(&mut self, parse: &Parse, sql: AdmittedSql)
-> Result<(), PolicyError>`, `observe_bind(&mut self, bind: &Bind) -> Result<(),
PolicyError>`, `resolve_execute(&self, execute: &Execute) -> Result<&BoundReadPortal,
PolicyError>` and `observe_close(&mut self, close: &Close) -> Result<(), PolicyError>`.
They never derive permission from the global statement cache. Closing a nonexistent
name remains idempotent. A bound portal retains its statement snapshot after
statement Close, as verified against PostgreSQL; transaction end invalidates it. `end_cycle(&mut self, explicit: bool)` invalidates implicit portals;
`end_transaction(&mut self)` clears transaction proofs/portals. CatalogProof is
required before forwarding each client backend preparation/bind/execution unit.

- [ ] Write `strict_read_statement_portal_identity_is_session_scoped`, proving a
  second session/global cache hit cannot inherit approval; test unnamed replacement,
  repeated Parse names, Close effects, unknown portal, declared/inferred type
  changes, cross-database alias and stale schema/manifest identity.
- [ ] RED/GREEN command:
  `./scripts/pgdog cargo test --locked -p pgdog --bin pgdog strict_read_session -- --nocapture`.
  Stage state updates until protocol success so a denied Parse/Bind cannot leave
  an executable portal or authorize old SQL under a reused name.
- [ ] Wire T2 -> protected backend from T4 -> T3 proof -> existing execution.
  Proof must be fresh for the same user/database/backend transaction. Routing
  may select the server; it cannot authorize the SQL. Revalidate at Execute,
  including when the prepared statement existed before the current transaction.
  `Client` owns `Option<PolicySession>` and QueryEngineContext borrows it; legacy
  mirror contexts may have None, but strict engine mode with missing session
  policy is an error, never an implicit unrestricted path. Admission is based
  on the immutable engine policy, not merely the presence of this optional field.
- [ ] Protect SQL-less messages before ClientRequest query extraction, parser
  split, admin shortcuts and raw streaming. Suppress unsafe direct SQL logging
  on strict paths. Reject unsupported startup options before backend auth/query
  forwarding; retain existing auth failures and TLS behavior.
- [ ] Test that policy rejection aborts an explicit client transaction even when
  it never reached PostgreSQL; internal and client E/T/I state must agree on later
  COMMIT/ROLLBACK and skipped commands through Sync. Verify error mappings
  25006/0A000/42601/08P01/25P02 at the wire, not just Rust enum values.
- [ ] Enable strict query execution only after feasibility gates C and T pass.
  Run policy/catalog units plus strict transaction/session tests and relevant
  existing `frontend::client::query_engine::test` regressions with prepared
  repository fixtures. Checkpoint T5 for independent same-provider code review;
  this review does not replace cross-provider security clearance.

## T6: Full owned-fixture acceptance matrix

**Files:** Extend the T0 dedicated `--test strict_read` target/support modules,
fixture SQL/config and runner; primary fixes only proven core regressions in its
owned modules. The existing driver matrix and Toxiproxy setup remain intact.

- [ ] Encode spec A1-A9/A12 as named cases. The read/write endpoints use the same
  backend and app account; each rejected mutation gets a direct-backend
  row/schema/sequence snapshot assertion, not only an expected client error.
- [ ] Cover simple batches with trailing writes, modifying CTEs, SELECT INTO,
  locking SELECT, role/GUC escape, startup parameters, unsupported functions and
  objects, Fastpath and orphan COPY. Include UTF-8/quoted/dollar-quoted input and
  bounded generated nested AST/message-sequence variants without new dependencies.
- [ ] Cover named/unnamed prepared queries, Describe-only, binary/text parameters,
  Flush before Sync, partial messages, pipelines, portal lifetimes, Close/rebind,
  error recovery, failed commit, timeout, cancel and backend/pool reconnect.
  Exercise the spec's restricted startup/driver SQL surface; document unsupported
  driver initialization instead of silently enabling arbitrary SET.
- [ ] RED each genuinely missing behavior before fixing it; already-green cases
  are retained as regressions. Run:
  `bash scripts/strict-read-tests.sh --pgdog-bin "$PWD/applications/pgdog/target/debug/pgdog" --phase protocol`.
  The runner calls `./scripts/pgdog cargo test --locked -p integration_tests_rust
  --test strict_read -- --test-threads=1` and psql commands against owned fixtures.
- [ ] Repeat with routing parser off/auto, supported pooling/prepared rewrite
  modes, passthrough-created pools and repeated authentication. Validate incompatible
  feature combinations and reload are rejected, not skipped.
- [ ] GREEN `--phase all` and review bounded logs/test counts. Compare baseline
  unrestricted results; no claim of compatibility with SQL the spec excludes.
  Checkpoint T6 only when every required case executes successfully.

The existing integration profile runs legacy tests against its own fixtures;
the dedicated target is always run by the required strict runner. This separation
must be asserted in the harness/CI tests so a nextest-filter change cannot turn
strict-read coverage into a silently omitted suite.

## T7: Helm interface, validation and operator examples

**Files:** Modify `charts/fork-pgdog/values.yaml`, `values.schema.json`,
`templates/{_helpers.tpl,deployment.yaml,NOTES.txt}`;
`scripts/artifacts/chart_checks.py`; `tests/artifacts/{test_chart.py,test_chart_checks.py}`.
Create the three strict-read example files in the ownership table.

**Interface:** `queryPolicy` defaults to `unrestricted`;
`readPolicy.existingConfigMap` defaults to empty. Strict mode requires a nonempty
ConfigMap reference, mounted read-only at `/etc/pgdog/read-policy/read-policy.toml`.
Runtime and configcheck include the same `--query-policy strict-read` and
`--read-policy-file /etc/pgdog/read-policy/read-policy.toml` arguments. Unrestricted
mode with a readPolicy reference is rejected as contradictory operator intent.

- [ ] Write render/schema tests for defaults, each enum, unknown keys, missing
  reference, both container argv/mounts and unchanged hardening/ports. RED:
  `python3 -m unittest discover -s tests/artifacts -p 'test_chart*.py' -v`.
- [ ] Implement conditional args/mounts, exact ConfigMap key and closed schema;
  no Helm `tpl` evaluation of operator content. Extend the artifact checker for
  conditional args/mounts while preserving one Deployment and Service per release.
  Use image digest precedence unchanged for runtime and configcheck.
- [ ] Render releases `pgdog-read` and `pgdog-write` separately and assert disjoint
  selectors, the same chosen image/backend, only read carrying strict policy.
  Do not add a public LoadBalancer or change existing Services on upgrade.
- [ ] Provide complete synthetic examples, including the protected policy manifest,
  passthrough/auth/Secret prerequisites, exact service DNS names and explicit
  restart after policy ConfigMap changes. State that 0.1.0 lacks this feature.
- [ ] GREEN chart tests and
  `python3 scripts/verify-artifacts chart --values charts/fork-pgdog/examples/values.yaml`,
  then the same command using `examples/strict-read/read-values.yaml` and
  `examples/strict-read/write-values.yaml`. Checkpoint T7; no release-version bump
  or publication is inferred from a render pass.

## T8: Two-Service Kubernetes smoke and required CI coverage

**Files:** Extend `scripts/helm-smoke.sh`,
`tests/artifacts/{test_smoke_isolation.py,kubernetes/postgres.yaml}`,
and existing `.github/workflows/{fork-quality.yml,artifact-quality.yml}` for
required phase/tool registration. Preserve manual publish workflows unchanged.

- [ ] Extend isolation tests first, then add the paired scenario after existing
  smoke phases. Create both releases plus the reviewed manifest and app roles
  inside the uniquely owned Kind cluster; preserve the private kubeconfig and
  cleanup trap. Never select or delete the user's current cluster.
- [ ] Build candidate image locally:
  `docker build -f applications/pgdog/Dockerfile -t fork-pgdog:strict-read-dev .`.
  Run `bash scripts/helm-smoke.sh --image fork-pgdog:strict-read-dev`.
  Assert Service DNS read success/write denial, write endpoint success, direct
  backend unchanged after every rejected mutation and disjoint Pod selectors.
- [ ] Exercise explicit rollout after manifest change, controlled drain/migration/
  schema-epoch restart, and failed strict configcheck. Test the real baseline
  binary/image's strict-argument rejection; label baseline-source evidence
  accurately rather than asserting a published-image check was performed.
- [ ] Register the owned strict suite as a required full-gate step and paired
  smoke in the existing native artifact jobs. Keep PR/manual triggers and native
  amd64/arm64 validation. Do not make a private registry login a prerequisite for
  tests that can use local built images.
- [ ] Run artifact tests plus strict/full fixture runs; retain bounded failure
  evidence on every phase. A missing Docker/Kind/network/SDK prerequisite is a
  blocker, never an ignored pass. Checkpoint T8 only with observed results.

## T9: Documentation, security impact, review and handoff

**Files:** Create `docs/operations/strict-read-endpoints.md`; update
`docs/operations/containers-and-helm.md`, `docs/VERIFICATION.md`,
`docs/architecture/deployment.md`, `docs/security/{threat-model,security-controls,residual-risks}.md`
and `.agent/project-model/{components,relationships,data-flows,environments}.toml`.
These security documents already exist; update them rather than create duplicates.

- [ ] Document CLI/chart/manifest contract, supported SQL/types/functions, role
  and DDL trust assumptions, errors, driver limitations, paired install, schema
  migration and rollback. Document generated filenames and active manifest digest,
  never suggest the manifest label itself proves database freshness.
- [ ] Model strict process, catalog/policy and transaction boundaries; update the
  threat/control mapping for A1-A12 and preserve standard security profile.
  No native adapter change is planned. Run `./scripts/agent docs build`,
  `./scripts/agent docs check`, `./scripts/agent adapters check` and
  `./scripts/agent skills check`; never hand-edit generated HTML/summary.
- [ ] Run `./scripts/agent verify quick --timeout 3600 --json`, then
  `./scripts/agent verify review --timeout 3600 --json` with all required owned and
  legacy fixtures. Correlate suite counts and spec acceptance matrix; quick alone
  is not sufficient. Record unsupported/unverified versions and driver modes.
- [ ] Before diff-bound review/security evidence, ensure every newly created
  candidate file is included in the assessed Git change. Stage only explicit
  candidate paths when the gate's diff hashing requires it; preserve unrelated
  staged work and inspect the complete index/worktree scope. Staging is not a
  commit. If immutable-commit evidence is required, prepare the reviewed change
  and obtain the necessary Git authorization instead of omitting new files.
- [ ] Resolve the trusted remote default branch for the complete-change security
  assessment and run `./scripts/agent security --json`. Run dependency, license,
  SAST, IaC and container scanners through the current repository commands; bind
  current source/image before scans. Reassess the whole candidate, not only a
  worker's patch or a conveniently chosen intermediate base.
- [ ] Perform independent code review and adjudicate each finding with evidence.
  A smaller same-provider worker is useful review, not cross-provider clearance.
  Preview the bounded cross-review package with the approved spec as requirements;
  obtain approval for its exact manifest hash before egress. Missing provider,
  stale manifest, signer or mandatory scan remains a gate failure.
- [ ] At an authorized merge boundary run
  `./scripts/agent verify merge --timeout 3600 --json`. Release additionally needs
  current release evidence/security signature and `verify release`; neither merge
  nor release is part of current plan execution authorization.
- [ ] Final report maps A1-A12 to observed tests, lists image/source identities,
  explains compatibility and operational limits, and separates local passing
  checks from unrun CI/production evidence. Checkpoint T9; do not claim the feature
  is deployed or publicly released on the basis of local verification.

## Acceptance coverage

| Spec evidence | Owning tasks |
| --- | --- |
| A1 / A2 | T2-T6, repeated through Services in T8 |
| A3 | T2 batch preflight and T6 no-forwarding proof |
| A4 | T4 transaction cycle, T5 registry, T6 raw wire/driver |
| A5 | T1 incompatible paths, T2 forced parsing, T5 cache identity, T6 |
| A6 | T1 startup/config, T2 raw gate, T5/T6 protocol/state |
| A7 | T3 object proof plus T6 owner-created negative fixtures |
| A8 | T4 observed backend ordering plus T5 integration and T6 |
| A9 | T4/T5 lifecycle and T6 fault/reuse cases |
| A10 | T0 real baseline CLI and T7/T8 chart/runtime checks |
| A11 | T8 paired Kind smoke and migration epoch |
| A12 | T6 driver/unrestricted regressions and T9 full gates |

## Rollback, stop conditions and review status

- No data/schema migrations are introduced by the feature. Test-only bootstrap
  changes are confined to owned fixtures. Preserve operator Secret/manifest
  versions; Helm rollback cannot restore externally managed objects.
- A partial implementation remains unavailable to strict client traffic. Never
  implement a compatibility fallback from strict to unrestricted.
- Feature rollback stops read traffic or restores a previously verified strict
  image/policy revision. Do not point the read Service at the write release or
  legacy 0.1.0. The separately managed unrestricted release remains available.
- Stop on failed feasibility C/T, an unprovable object dependency, uncovered raw
  forwarding, or an unresolved high-impact review finding. Present the exact
  failing requirement instead of silently expanding supported SQL or lowering
  the approved assurance boundary.
- This plan was approved for implementation on 2026-10-05. The execution record
  below supersedes prospective checklists when reporting observed results. A task
  that includes an unrun full gate is not marked complete merely because its
  implementation is present.

## Execution record — 2026-10-05

Implementation is in the working tree above baseline
`960942d4254a547d459d44545151f30380ae3173`, with no commit, push or deployment
to an existing cluster. Two `gpt-6-luna` workers handled bounded policy/catalog,
test, chart and review work; the primary integrated enforcement and verification.

| Task | Observed state |
| --- | --- |
| T0 | Owned fixture runner and historical baseline executable verified; unrestricted SELECT/DML baseline passes |
| T1–T2 | Immutable manifest/config/CLI and original-AST/raw-protocol admission implemented and tested |
| T3 | Full pinned PG18 metadata, typed resolver and negative catalog tests pass; endpoint canary evidence is recorded in the validation report |
| T4–T5 | Protected transaction, session statement/portal identity, Flush/Sync and fault handling pass owned runtime tests; legacy query-engine suite remains unrun |
| T6 | Owned baseline/protocol/core matrix and parser-off transaction/full-prepared variant implemented; exact final results are in the validation report |
| T7 | 64 artifact tests and both strict read/write chart example validations pass |
| T8 | Paired Kind smoke passed using the local Linux arm64 test image with mandatory TLS; the full-LTO production image build is blocked by the current 4 GiB Docker limit |
| T9 | Docs/model/threat delta updated; full upstream regression, independent review, required scans and release clearance are separate outstanding gates |

Implementation refinements preserve the approved boundary: strict enforcement uses
a dedicated raw protocol path, and the Kind test is a separate
`scripts/strict-read-helm-smoke.sh` invoked by the existing artifact pipeline.
Bound portals survive statement Close; tests confirmed this PostgreSQL behavior.
Startup and parameter budgets were added after review found retained-input risks.
Timeout now sends a bounded CancelRequest before discarding a backend; a real lock
wait regression proved that dropping only the client socket was insufficient.

See [validation and review record](../../operations/strict-read-validation.md)
for acceptance mapping, evidence, build limitations and unverified scope.
