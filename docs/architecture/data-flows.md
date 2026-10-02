# Data flows and trust boundaries

## Database traffic

1. A client sends PostgreSQL startup/authentication messages and SQL to PgDog.
2. PgDog authenticates the client, selects a pool and routes the query to a
   configured PostgreSQL backend.
3. Backend credentials and SQL cross the proxy-to-database boundary.
4. PostgreSQL results return through PgDog to the client.

The model declares SQL queries, database credentials and query results as
sensitive data. Pooling and query routing are existing upstream behavior.
An end-to-end per-member audit trail for the intended deployment has not been
implemented or validated as part of this repository setup.

## Development traffic

1. Canonical configuration and project-model data enter the local runtime.
2. Verification writes commit-bound metadata under .agent/.runs/.
3. Private memory candidates can be reviewed before promotion into records.
4. Review packages pass containment, deny rules, size limits, redaction and
   exact manifest approval before provider egress.
5. Provider findings return as untrusted structured data for adjudication.

These source-review calls are development operations. They do not send live
PostgreSQL query traffic to the planned LLM agent. That future boundary requires
its own authorization, data minimization and audit design.
## Fork artifact and deployment flows

Repository source and locked dependencies enter a pinned native container builder.
Bounded synthetic manifests and the actual built image enter Trivy checks; only
explicit native archives/metadata move between CI jobs. A protected owner-approved
manual job copies tested OCI bytes to GHCR and publishes a chart pinned to the
combined image digest. Operator Helm/image pulls cross the registry boundary.
Existing configuration/users/TLS objects enter read-only Pod mounts; database
credentials stay in operator Secrets, outside inline chart/CI artifacts. No LLM
process or PostgreSQL server is installed by this chart.
