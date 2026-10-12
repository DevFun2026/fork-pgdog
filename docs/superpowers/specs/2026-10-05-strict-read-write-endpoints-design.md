# Strict read and write endpoints

Date: 2026-10-05
Status: Written specification approved by the user on 2026-10-05.
Implementation status: Not implemented. The published 0.1.0 artifacts do not
provide this feature.

## Approval and intent

The user requested two PgDog hostnames: a read endpoint that rejects
data-modifying queries, and a write endpoint with normal PostgreSQL behavior.
The backend can remain the same PostgreSQL host. The user explicitly selected
rejection of queries/functions whose safety is unknown over full SQL
compatibility, then approved the proposed two-Deployment/two-Service direction
with “Chốt”. The user then approved this written specification with “approve”
on 2026-10-05, authorizing preparation of the implementation plan. Implementation
and publication are not implied by the document's existence.

The observable outcome is that the same write-capable application account can
read through either endpoint, but cannot execute a data/schema/sequence mutation
through the read endpoint within the trust boundary below. Authentication remains
the existing configured mechanism, including passthrough authentication. This feature does not introduce
stored application passwords or a reader-to-writer identity mapping.

## Scope and security contract

The strict endpoint has two mandatory controls:

1. A fail-closed SQL/protocol admission policy, independent of routing. A
   statement is allowed only when its complete structure and referenced object
   classes are within the supported read surface below.
2. PostgreSQL READ ONLY transactions owned by PgDog, established before any
   accepted client statement is prepared, described, planned, or executed by
   the backend. Merely setting `default_transaction_read_only` is insufficient.

The contract concerns application data/schema/sequence mutations submitted
through this endpoint. It does not mean zero PostgreSQL disk writes: statistics,
temporary query work, and ordinary server housekeeping are outside this
contract. Query errors and client cancellation must never weaken either control.

AST classification alone is not proof that arbitrary SELECT is side-effect free.
Views, functions, operators, casts, types, RLS policies and extensions can execute
hidden code. The first version deliberately rejects unsupported objects and
expressions rather than claiming transparency for all existing SQL.

The trusted computing base includes PgDog, PostgreSQL, the reviewed PostgreSQL
built-ins, the cluster operator, and DBA-managed schema definitions. Application
roles may have DML privileges, but must not be superusers, own trusted schema
objects, create/replace trusted routines, change roles to more privileged users,
or install extensions. Schema/function/extension DDL must occur through a
controlled migration boundary described below. Arbitrary native extensions,
remote side effects, or a malicious DBA are not made safe by SQL parsing or a
read-only transaction. Such objects must not enter the accepted read surface.

This is an endpoint policy, not a replacement for PostgreSQL role permissions:
the same account can still write through the write endpoint or a separately
reachable PostgreSQL server. Network/role restrictions remain the operator's
responsibility if callers must be prevented from reaching those paths.

## Deployment and endpoint identity

Use two instances of the existing chart, with separate releases, Deployments,
Services, configuration and pools. Use the same new image digest for both.

```text
read Service  -> PgDog process: strict-read  -> one PostgreSQL backend
write Service -> PgDog process: unrestricted -> the same PostgreSQL backend
```

Release names `pgdog-read` and `pgdog-write` produce the existing chart's Service
names `pgdog-read-fork-pgdog` and `pgdog-write-fork-pgdog`. In namespace `pgdog`,
clients use those names with `.pgdog.svc.cluster.local:6432`. Additional DNS aliases
are optional operator configuration. The Services must have disjoint selectors.

Do not infer policy from DNS, startup `application_name`, database aliases or a
client-supplied parameter. PostgreSQL startup does not reliably convey the
hostname used by the client. The destination process owns the policy.

Two listeners in one process were considered but are not selected: they would
require listener identity propagation and shared-pool isolation changes. Two
releases reuse the existing chart shape and allow separate scaling and rollback.
A chart that creates both workloads in one release is outside this version.

## Proposed public interface

Add an explicit process argument:

```text
--query-policy unrestricted
--query-policy strict-read
```

The default is `unrestricted`, preserving existing installations. The policy is
immutable for the process lifetime; configuration reload cannot downgrade it.
Changing the policy requires a new process. Database/user settings, routing
comments, plugins and startup parameters cannot override it.

Add chart value `queryPolicy`, an enum with the same two values and default
`unrestricted`. For `strict-read`, both the runtime and configcheck containers
must receive the explicit CLI argument. Legacy/default installs need not emit
the new argument. An old binary must fail on the unknown strict-read argument;
it must never silently start the read Service in unrestricted mode.

The strict instance additionally requires a protected, versioned read-surface
manifest, referenced through a new `--read-policy-file` argument. The manifest
identifies the permitted database aliases and exact schema-qualified ordinary
tables, together with the operator's schema revision identifier. No wildcard,
function-name override, or client-supplied entry is allowed. The chart mounts it
from an existing ConfigMap using `readPolicy.existingConfigMap` and key
`read-policy.toml`. These are proposed additions, not existing chart features.

Example of the proposed manifest shape:

```toml
schema_revision = "application-schema-revision"

[[databases]]
name = "app"
relations = ["app.orders", "app.customers"]
```

The manifest is an upper bound on access, not proof of safety. PgDog must resolve
objects using safe catalog queries and validate their supported object/type
classes inside the protected backend context. Missing manifest, missing schema
revision, failed resolution, unsupported object, or mismatched database must
deny traffic. Syntax validation alone may pass configcheck, but runtime readiness
must not imply that unverified backend objects have been approved.

Load and validate an immutable manifest snapshot at startup. Empty/duplicate
database entries, malformed relation identifiers and unknown fields are errors.
Catalog lookup must use parameterized identifiers/values, never interpolate
manifest or client strings into executable SQL. Changes to the referenced
ConfigMap require an explicit restart; a projected volume update cannot change
the running policy. Record the manifest content digest with the schema revision
to identify the active policy. Passthrough authentication may defer catalog
validation until a user first connects; absent credentials must never result in
an implicit approval or a fallback query path.

Existing users Secrets, TLS inputs and passthrough settings remain in use.
Existing plaintext/hashed credential handling is not broadened by this feature.
No credentials or SQL query text are written into the read-surface manifest.

## Supported read surface for the first version

The manifest and conservative object checks are an intentional compatibility
cost of the user's choice to reject unknown behavior. They are not a general
SQL sandbox or automatic function-purity analysis.

| Input | Strict-read behavior |
| --- | --- |
| SELECT literals, parameters and approved base-table columns | Allow after expression/type checks |
| JOIN, subquery, UNION/INTERSECT/EXCEPT, filtering, ordering and limits | Allow only when every nested branch is accepted |
| WITH whose CTE bodies are all accepted SELECTs | Allow |
| INSERT/UPDATE/DELETE/MERGE, including CTE bodies | Reject |
| SELECT INTO and row-locking SELECT | Reject |
| DDL, privilege changes, maintenance, notification and replication commands | Reject |
| COPY in either direction, CALL, DO, SQL PREPARE/EXECUTE/DEALLOCATE | Reject in this version |
| EXPLAIN, including EXPLAIN ANALYZE | Reject in this version |
| Direct function calls not in the built-in registry | Reject |
| SET/RESET, SET ROLE, session authorization and transaction-mode changes | Reject, except the proxy-owned transaction controls below |
| Unknown AST nodes, parse errors, unresolved SQL or objects | Reject |

Support PostgreSQL's standard scalar bool, integer, numeric, floating-point,
text/string, bytea, date/time, interval and uuid types and their reviewed built-in
comparison/arithmetic/conversion operations. The implementation must maintain an
explicit registry of supported operations; a matching name alone is insufficient.
User-defined types, domains, operators, casts, collations and overloaded function
implementations are unsupported. Unsupported expressions fail closed even if
PostgreSQL itself could execute them.

The initial function/aggregate registry is limited to built-in `count`, `sum`,
`avg`, `min`, and `max` over supported types, plus SQL CASE/COALESCE/NULLIF
expressions whose operands and comparison behavior are supported. No general
configuration option may approve an arbitrary function name. `nextval`, `setval`,
`set_config`, advisory-lock functions, large-object mutation functions and
extension/user-defined functions are rejected. Function identity must be resolved
to the trusted PostgreSQL implementation/signature, including aggregate transition
and final functions; schema qualification by itself is not sufficient proof.

Initially allow only ordinary, non-partitioned, non-inherited base tables on
the relation manifest, with supported column types, no rewrite rules and no RLS
policies. Views, foreign tables, partition hierarchies, temporary tables and
system/catalog relations are not accepted client query targets in this version.
PgDog's own bounded catalog queries are internal operations, not client exceptions.
SELECTs must not invoke unreviewed expression/index/operator code during planning
or execution; table/index expression dependencies must be checked, or the object
must be rejected. The read-surface validator must not assume that checking the
outer table alone checks all code that PostgreSQL can invoke.

Both admission and database transaction enforcement are required. The
implementation must not silently replace this contract with a keyword blacklist,
the router's read/write result, or a function volatility flag.

## Validation ordering and protocol behavior

Validate original SQL before mirroring, rewrites, plugin hooks, routing, or any
client-controlled backend messages. In particular, strict admission must precede
the existing `rewrite_extended` path or retain the untouched Query/Parse payload
and validate it independently before that rewrite can affect any backend work.
Prepared-name rewriting must preserve the admitted SQL/type identity; generated
or rewritten SQL cannot inherit approval merely from an earlier routing result.
Read mode forces policy parsing even when
the routing parser is off/automatic. Read mode rejects configurations enabling
plugins, mirroring, arbitrary query rewrites, logical replication, admin-database
access or multiple shards; those paths are outside this first version. No policy
check may be skipped because a request is unsharded, cached or session-pooled.

For simple Query messages, validate every statement in the original message
before forwarding any statement. If one is denied, deny the entire message.
All-read batches are supported. Batches mixing transaction-control statements
with data queries are rejected in this version. No claim of atomic admission is
made across separate client messages or an unbounded network stream.

Support extended Parse/Bind/Describe/Execute/Close/Flush/Sync, including named and
unnamed statements and parameterized SELECT. Bind/Execute must refer to a
validated statement and portal in the correct client session. Missing/stale
state is denied. Validate Parse and Describe before backend preparation, not
only at Execute; server planning/type conversion may itself call code. SQL-level
PREPARE/EXECUTE is intentionally rejected even though wire-level prepared
statements are supported.

Parsing/classification caches must not grant policy authorization. Recheck the
immutable policy and the current trusted schema context when statements execute;
reuse must not carry admission across endpoint, user, database, type signature
or schema revision. Keep catalog metadata and prepared plans inside the same
controlled migration epoch. No positive decision based on an expired or unknown
schema context may be reused.

Extended errors must obey PostgreSQL synchronization: send one ErrorResponse,
discard the affected exchange through Sync, then send the appropriate
ReadyForQuery. Denial in an explicit transaction marks it failed until rollback.
Later read requests must recover normally after the required synchronization.
Unsupported protocol messages must not fall through to raw backend forwarding.
Explicitly reject Fastpath FunctionCall (`F`), replication startup/streaming,
and CopyData/CopyDone/CopyFail, including orphan COPY messages with no SQL AST.
The endpoint never enters COPY mode. FunctionCall denial follows its own
ErrorResponse/ReadyForQuery cycle; unexpected COPY or malformed protocol state
returns a protocol violation and closes the connection when synchronization
cannot be established. Terminate and correctly scoped cancellation retain their
normal connection-lifecycle purpose.

## Transactions and connection lifecycle

The strict endpoint must establish and acknowledge READ ONLY before forwarding
client SQL, including Parse/Describe-only traffic. Do not assume a newly checked
out pooled connection has safe defaults. Startup `options` and other parameters
that can change transaction mode, role or search_path are rejected. Only supported
identity, database, application-name and UTF-8 encoding parameters are accepted;
arbitrary session GUC forwarding is disabled for strict-read.

Explicit standalone BEGIN/START TRANSACTION without a mode, or with READ ONLY,
is accepted and executed as READ ONLY. Supported isolation levels may be retained.
READ WRITE, transaction chaining, two-phase transaction commands and client
SAVEPOINT commands are unsupported and rejected in the first version. Standalone
COMMIT and ROLLBACK are supported with normal PostgreSQL observable semantics.
SHOW of the two read-only GUCs may be served as read-only metadata; arbitrary SET
or function-mediated mode changes are never accepted. A driver requiring other
session bootstrap SQL is outside the initial compatibility claim.

For client autocommit, PgDog owns an internal read-only transaction around the
accepted execution unit. A simple all-read batch retains one transaction boundary.
An extended execution cycle may span Flush and a suspended portal before Sync;
its backend transaction remains bound for that cycle. While it is open, only
admitted extended operations, Flush, Close and Sync can continue it. A simple
Query or a client transaction-control command requires synchronization first;
unsupported interleaving is rejected rather than changing transaction ownership.

For autocommit, Sync is the end of the cycle: commit on success or roll back on
error, close all cycle-owned portals (including suspended portals), and then
report ReadyForQuery I. No hidden transaction survives that Sync. Executing such
a portal afterward requires a new Bind. If the client disconnects or times out
without Sync, roll back/discard. In an explicit user transaction, Sync does not
commit; suspended portals may remain until Close or transaction end and the
client observes T/E. These rules follow PostgreSQL's extended-protocol transaction
and portal lifetimes rather than inventing a hidden transaction across Sync.

Internal BEGIN/COMMIT/ROLLBACK acknowledgements and transaction statuses are not
exposed as extra client messages. Idle autocommit clients observe ReadyForQuery I;
explicit transactions observe T/E as appropriate. Preserve row descriptions,
command tags and statement errors. Do not report successful completion if the
internal transaction cleanup/commit failed. Internal commands must not destroy
or replace the client's unnamed prepared statement or portal.

Failure to start/verify the read-only backend transaction denies execution.
Cancellation, disconnect, timeout and backend errors roll back or discard the
connection; uncertain protocol/transaction state is never returned to the pool.
Separate read/write processes prevent pools from crossing endpoint policies.
Pool reuse and passthrough-created pools must follow these rules identically.

## Schema changes and trust freshness

This version does not promise safe concurrent schema/routine/index/extension
migration while strict readers remain active. Operators must stop admission and
drain the read release before such migrations, update/review the relation manifest
and schema revision, then restart the strict process with fresh catalog state.
Ordinary DML through the write endpoint does not require draining readers.

Within an epoch, relation/type/routine identity changes detected during validation
invalidate admission and require revalidation; errors never fall back to a name
match. This operational boundary is part of the security contract, not a claim
that the schema revision string proves the database is unchanged. A deployment
that cannot control DDL needs a stronger catalog-invalidation/locking design
before enabling this strict feature.

## Errors, visibility and operational behavior

Known forbidden writes return SQLSTATE 25006 with a stable message identifying
the strict read endpoint. Unsupported but not proven-writing SQL/objects return
0A000; malformed SQL returns 42601. Transaction failure recovery uses 25P02 where
PostgreSQL requires it. Auth failures retain their existing behavior.

Diagnostics include endpoint policy and a bounded reason code, not raw SQL,
parameters, passwords or result data. Startup logs expose the chosen policy and
schema revision. Invalid strict configuration fails startup/configcheck rather
than silently relaxing policy. Backend/catalog validation failures deny affected
requests and must be distinguishable from query-policy rejections.

Keep existing Service type, TLS, resources and drain behavior. This feature does
not publish a load balancer, grant direct database access, rotate credentials or
deploy to a live cluster. The write release retains existing behavior when the
new settings are absent. The read release requires a newly verified image/chart;
switching it to an older unrestricted image is not an acceptable rollback.
Rollback of the feature removes read traffic or restores a previously verified
strict image, while the separately managed write release remains available.

## Required acceptance evidence

Tests must run against isolated PostgreSQL fixtures, never the user's shared
database. Use the same DML-capable, non-owner, non-superuser account and backend
for both endpoints; a read-only test role alone would mask a broken proxy guard.

| ID | Required evidence |
| --- | --- |
| A1 | Ordinary SELECT, approved JOIN/subquery/CTE/aggregate and parameterized queries succeed through read; normal read/write succeeds through write |
| A2 | DML, DDL, sequence mutation, COPY, SELECT INTO, row locks and modifying CTEs fail on read; direct backend checks confirm no application-data/schema/sequence change |
| A3 | A simple message with a safe first statement and denied later statement forwards no client statement; comments, strings, dollar quoting and nested SQL cannot bypass classification |
| A4 | Named/unnamed prepared queries, Parse+Describe without Execute, multiple Executes, Flush, suspended portals, Close and Sync preserve results and denial/recovery behavior; implicit portals end at Sync, explicit portals can survive it, and interleaving never leaks a hidden transaction |
| A5 | SQL PREPARE/EXECUTE, unknown prepared/portal identities, parser-off/auto and cached routing never bypass policy |
| A6 | READ WRITE, SET/RESET, startup options, set_config, role changes, admin/replication/plugin routes, Fastpath FunctionCall, orphan COPY data/control messages and malformed input fail closed |
| A7 | Hidden-code objects, shadowed/overloaded built-ins, unsupported types/casts/operators, views/RLS/foreign tables and stale object identities are denied; ordinary allowed objects still work |
| A8 | Every backend client prepare/describe/execution occurs within enforced READ ONLY; explicit and implicit transaction paths are observed independently of the admission tests |
| A9 | Error, timeout, cancel, disconnect, failed COMMIT, pool reuse and passthrough-created pools never leak an open or writable transaction; driver-visible I/T/E states remain correct |
| A10 | Two Helm releases render disjoint selectors/config and the same pinned image/backend; strict flag reaches runtime and configcheck; old binaries fail rather than run unrestricted |
| A11 | Isolated Kubernetes smoke connects through both Services and repeats read/write denial plus backend mutation checks, including rollout and controlled schema-epoch restart |
| A12 | Existing unrestricted-mode regression tests pass; unsupported strict driver behavior is documented rather than counted as compatibility |

Protocol tests must include psql simple queries and at least one existing extended
protocol driver fixture. Use property/fuzz-style generated nested AST and message
sequence cases where they add coverage beyond named regressions. A code-only
review or a parser-unit-test pass is not evidence of endpoint enforcement.

## Threat-model delta and implementation boundaries

New assets: endpoint policy, admitted statement/portal identity, read-surface
manifest, trusted catalog epoch and the backend transaction state.

New boundary: untrusted application SQL/protocol enters a strict process and may
reach a write-capable backend identity only after both controls succeed.

Principal threats are nested/multi-statement write smuggling, prepared-state
confusion, parser/cache bypass, SQL rewrite/plugin egress, GUC/role escape, hidden
database code, catalog drift, writable pool reuse and deployment-policy mismatch.
Admission checks, transaction enforcement, isolated pools, protected manifests,
controlled migrations and A1-A12 are the corresponding controls/evidence.

The approved security profile remains `standard`. Independent same-provider
design feedback is not the repository's cross-provider review or signed security
clearance. Implementation must update the canonical project model, threat model,
operator docs, configuration reference, chart schema/examples and generated docs.
Required verification/review/merge/release gates and manifest-bound egress approval
remain applicable at their respective boundaries.

Expected implementation touchpoints are CLI/configcheck and process initialization;
frontend query admission, prepared/portal state, transaction/error handling;
bounded backend catalog validation and read-only transaction setup; Helm values,
schema and runtime/configcheck mounts/arguments; and artifact/integration tests.
Do not repurpose the existing routing-oriented database/user `read_only` setting.

The implementation plan must begin with failing tests and a bounded protocol
feasibility checkpoint for autocommit wrapping, unnamed statements, suspended
portals and the trusted-object validator. If those cannot satisfy this contract,
report the specific conflict and revise the design before shipping; do not lower
the guarantees or claim partial parser filtering implements the feature.

## Source evidence

- [Current single listener and process](../../../applications/pgdog/pgdog/src/main.rs)
  and [startup parameters](../../../applications/pgdog/pgdog/src/net/messages/hello.rs).
- [Existing read_only contract](../../../applications/pgdog/pgdog-config/src/database.rs)
  explicitly permits client SET overrides.
- [Query admission ordering](../../../applications/pgdog/pgdog/src/frontend/client/query_engine/mod.rs)
  and [optional routing parser](../../../applications/pgdog/pgdog/src/frontend/client/query_engine/rewrite.rs).
- [Multi-statement routing](../../../applications/pgdog/pgdog/src/frontend/router/parser/query/split.rs)
  currently documents first-statement routing limitations.
- [Existing explicit transaction handling](../../../applications/pgdog/pgdog/src/frontend/client/query_engine/start_transaction.rs)
  and [direct execution path](../../../applications/pgdog/pgdog/src/frontend/client/query_engine/query.rs)
  do not supply the universal protected transaction boundary specified here.
- [Chart naming](../../../charts/fork-pgdog/templates/_helpers.tpl),
  [Deployment](../../../charts/fork-pgdog/templates/deployment.yaml), and
  [operator guide](../../operations/containers-and-helm.md).
- [PostgreSQL transaction restrictions](https://www.postgresql.org/docs/current/sql-set-transaction.html)
  and [function behavior](https://www.postgresql.org/docs/current/xfunc-volatility.html).
- [PostgreSQL protocol, portal lifetimes and Sync](https://www.postgresql.org/docs/current/protocol-flow.html).

## Handoff

This written specification was approved after consistency/link checks and a
bounded design review. The next artifact is the versioned implementation plan,
which remains subject to user review before execution. No product code, image
build/publication, commit, push or Kubernetes deployment is authorized by this
specification approval alone.
