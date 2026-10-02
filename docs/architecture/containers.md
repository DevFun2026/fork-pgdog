# Containers and major units

## Product runtime

- PgDog proxy: Rust Cargo workspace under applications/pgdog/; its executable
  handles PostgreSQL connections, authentication, pooling and query forwarding.
- PostgreSQL backends: external database servers, including primaries, replicas
  or shards depending on pgdog.toml. They execute SQL and return results.
- PostgreSQL clients: psql, application drivers or other compatible clients.
- Local Docker demo: applications/pgdog/docker-compose.yml builds fork-pgdog:local
  from the repository-root Dockerfile and starts three PostgreSQL shards.
- Fork artifact builder: pinned Ubuntu/Rust stages compile the locked workspace
  and plugin without official PgDog base images or Git/private build context.
- Helm release: charts/fork-pgdog creates a hardened stateless PgDog Pod,
  configcheck initContainer, ClusterIP PostgreSQL Service and token-disabled
  ServiceAccount; existing backend/users/config/TLS objects are operator-owned.
- GHCR image/chart destinations are owned by DevFun2026 and paired by digest
  after protected manual publication. Local source/runtime validation does not
  establish that first external publication has occurred.

## Development and documentation

- Canonical core: .agent/ policies, skills, schemas, templates and project model.
- Runtime: Python 3.11 standard-library CLI invoked through scripts/agent.
- Review engine and provider adapters: approved, bounded source review packages
  and validated independent findings, outside the database query path.
- Project Memory: private local candidates and reviewed project records.
- Documentation generator: canonical TOML and focused Markdown are rendered
  into system-summary.md and the self-contained system.html.
- CI wrappers: pull-request or manual validation; publishing is manual.

The planned LLM agent is not yet a runtime process or container in this model.
