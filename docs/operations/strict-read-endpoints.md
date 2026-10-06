# Strict read and write endpoints

Run two independent releases of the same feature-capable PgDog build. The read
release uses `--query-policy strict-read --read-policy-file /etc/pgdog/read-policy/read-policy.toml`;
the write release uses the default `unrestricted` policy. Each has its own Service,
process and pools. Two DNS aliases pointing to one unrestricted listener do not
provide this boundary: PostgreSQL startup does not convey the destination DNS name.

This change has no published image/chart version yet. Image/chart `0.1.0` cannot
run strict mode. Validate the exact new build and complete the repository's review
and release gates before using it with application traffic.

## Database and SQL contract

Strict mode targets PostgreSQL 18 and compares its supported catalog objects to
the pinned registry in `backend/schema/read_policy/registry-pg18.json`. A different
major version or a catalog mismatch is a denial, including queries without FROM.
The PostgreSQL server binary, built-in implementations, DBAs and controlled schema
epoch are trusted. This is not a sandbox for arbitrary native extensions or a
malicious DBA.

Use the same DML-capable application role on both endpoints. The role must not be
superuser, BYPASSRLS, CREATEDB, CREATEROLE, a replication role, a role member, or the
owner of the database or selected tables. It must not have CREATE on the database,
search-path schemas or referenced schemas. Keep ownership and migrations in a
separate operator role. The role may retain INSERT/UPDATE/DELETE grants for the
write endpoint. PostgreSQL GRANT/REVOKE remains the authority for data access.

A read manifest is a closed TOML document. Its database names are PgDog aliases;
relations are an exact upper bound of schema-qualified ordinary tables:

```toml
schema_revision = "app-migration-0042"

[[databases]]
name = "app"
relations = ["public.orders", "public.customers"]
```

The manifest is loaded once, fingerprinted and shared immutably by the process.
It does not certify an object by name. Each protected backend transaction must
prove the actual role, relation, type, operator, aggregate, cast and planner
support metadata before forwarding client SQL. Missing metadata, ambiguous type
resolution and unknown dependencies are rejected.

The supported surface is deliberately narrow:

- SELECT with proven built-in scalar types, ordinary columns, literals, explicit
  supported casts, arithmetic/comparison operators, CASE, COALESCE and NULLIF.
- count, sum, avg, min and max over supported arguments; explicit ON joins,
  ordinary subqueries, nonrecursive CTEs and compatible set operations.
- Standalone BEGIN/START TRANSACTION, optionally READ ONLY and an isolation level;
  standalone COMMIT/ROLLBACK; SHOW transaction_read_only and
  SHOW default_transaction_read_only.
- Simple queries and the named/unnamed PostgreSQL extended protocol, including
  prepared statements, Describe, Flush, suspended portals, Close and Sync.

Everything else is denied. This includes DML/DDL, modifying CTEs, SELECT INTO,
locking SELECT, COPY, EXPLAIN, SQL PREPARE/EXECUTE, SET/RESET/role changes,
unknown functions (including stored functions), whole-row/custom-type values,
arrays, windows, recursive CTEs, savepoints and chained/two-phase transactions.
Uncertain coercions, NATURAL/USING joins and driver initialization outside this
surface can be rejected even when a DBA considers them harmless.

Views, foreign/partitioned/inherited/temp tables, RLS/rules, generated columns,
custom column types/collations, expression/partial indexes, unreviewed index
support, CHECK/exclusion/foreign-key constraints and expression statistics are
outside v1. Tables must use the ordinary heap access method and reviewed plain
btree indexes. Inspect the exact catalog proof and run application queries before
adding tables to the manifest.

Catalog proof also checks complete operator/function candidate sets, scalar
casts, and the built-in btree/hash support families used by joins, sorting and
aggregation. An added overload or support member is a denial until reviewed.
The offline `scripts/read_policy_registry.py` tool reproduces reviewed metadata
from a pinned fixture capture; never refresh the registry from an application
database merely to make a denial disappear.

All simple-query batch statements are admitted before any is forwarded. A trailing
write rejects the whole batch. The process also opens and acknowledges a backend
READ ONLY transaction, independent of the client's transaction state. Internal
commands have reserved names and their command tags/ReadyForQuery are hidden.
An explicit transaction becomes failed after a denial and needs ROLLBACK or
COMMIT-as-rollback; an implicit cycle is finished at Sync. A failed or uncertain
backend is discarded. The global prepared-statement cache cannot grant approval.

Diagnostics contain bounded reason codes, without SQL text or bind values.
Writes use `25006`, unsupported SQL/objects use `0A000`, syntax uses `42601`,
unsupported protocol uses `08P01`, and a failed explicit transaction uses `25P02`.
Startup accepts only user, database, application_name and UTF8 client_encoding.
Role defaults must preserve UTF8 and standard_conforming_strings=on. Drivers
that send startup options or SET commands need compatible configuration.

SQL text is limited to 1 MiB per admitted request; retained statement and portal
snapshots share an 8 MiB SQL budget per client. A buffered protocol cycle is
limited to 8 MiB and 4,096 messages. Prepared statement/portal names have a
1,024-byte limit and each registry accepts at most 1,024 entries. A statement
accepts at most 1,024 declared parameters, and inferred parameter references
cannot exceed `$1024`. These limits
may reject otherwise valid application queries.

## Kubernetes installation

Use the examples under `charts/fork-pgdog/examples/strict-read/`. Replace the image
placeholder with a reviewed immutable build, and replace the backend/database in
both values files. For this environment the backend hostname can be
`staging-postgres.database.svc.cluster.local`; the actual database name and PgDog
alias must match the manifest and application connection string.

Passthrough authentication accepts application credentials at connection time.
The chart still mounts its required users.toml file, which may contain `users = []`;
no application password needs to be stored there. `passthrough_auth = "enabled"`
requires TLS. Provision the client TLS Secret, backend TLS verification and network
rules for the actual environment before routing application credentials.

Create the policy ConfigMap and install separate releases after reviewing values:

```sh
kubectl -n database create configmap pgdog-read-policy \
  --from-file=read-policy.toml=./read-policy.toml
helm upgrade --install pgdog-read ./charts/fork-pgdog -n database \
  -f ./read-values.yaml
helm upgrade --install pgdog-write ./charts/fork-pgdog -n database \
  -f ./write-values.yaml
```

With the default chart naming, application endpoints are:

| Purpose | Host and port |
| --- | --- |
| Read | `pgdog-read-fork-pgdog.database.svc.cluster.local:6432` |
| Write | `pgdog-write-fork-pgdog.database.svc.cluster.local:6432` |

The initContainer and runtime receive identical policy flags and the same
read-only ConfigMap mount. A missing/invalid manifest prevents startup. Plugins,
mirroring, rewrites, sharding, replication, raw SQL logging and incompatible
execution modes are rejected at startup and config publication/reload.
Use an explicitly configured primary on shard 0. Automatic role discovery,
background schema loading and schema-admin users are incompatible with strict
mode; background LSN/Aurora discovery is disabled for the strict process.

## Migration and rollback

Drain and stop read traffic before DDL or changes to roles/functions/catalog
objects. Apply the controlled migration through the owner/write path, review the
new catalog and supported queries, update the manifest/schema revision, then
restart the read release. A ConfigMap update or PgDog reload alone does not update
the running policy. Resume traffic only after the read and write smoke checks pass.
Keep the previous manifest, values and image identity for rollback. Do not roll
back a guard by pointing the read Service at the unrestricted release; stop read
traffic instead. Helm history does not restore an external ConfigMap or database
schema for you.

## Verification

The disposable fixture runner uses loopback ports, UUID Docker resources and
synthetic roles; it never uses an ambient DATABASE_URL/KUBECONFIG. It requires the
pinned PostgreSQL 18 fixture image locally. Build the current binary, then run:

```sh
./scripts/pgdog cargo build --locked -p pgdog --bin pgdog
bash scripts/strict-read-tests.sh \
  --pgdog-bin "$PWD/applications/pgdog/target/debug/pgdog" --phase all
bash scripts/strict-read-tests.sh \
  --pgdog-bin "$PWD/applications/pgdog/target/debug/pgdog" --phase protocol \
  --pooler-mode transaction --query-parser off --prepared-statements full
```

`all` runs current unrestricted DML regressions, strict raw-wire/driver tests and
core catalog/transaction tests. The separate `baseline` phase additionally checks
the saved pre-change executable's rejection of the new CLI flags; that historical
experiment requires `.agent/.runs/strict-read/pgdog-baseline` and is not silently
skipped. Existing upstream integration fixtures remain separate.

The paired Kubernetes smoke script builds an isolated Kind cluster with a private
kubeconfig. A local suite pass is not a published artifact, independent security
clearance or evidence about an existing production cluster.
