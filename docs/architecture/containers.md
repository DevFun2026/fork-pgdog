# Containers and major units

## Product runtime

- PgDog proxy: Rust Cargo workspace under applications/pgdog/; its executable
  handles PostgreSQL connections, authentication, pooling and query forwarding.
- PostgreSQL backends: external database servers, including primaries, replicas
  or shards depending on pgdog.toml. They execute SQL and return results.
- PostgreSQL clients: psql, application drivers or other compatible clients.
- Local Docker demo: applications/pgdog/docker-compose.yml starts the upstream
  PgDog image and three PostgreSQL shards. It does not run a fork-specific LLM
  agent. The fork image is built separately from applications/pgdog/Dockerfile.

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
