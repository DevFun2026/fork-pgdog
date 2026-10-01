# Component responsibilities

## PgDog source

The upstream proxy is in applications/pgdog/pgdog/src/:

- frontend/: receives client sessions and coordinates query execution.
- backend/: manages backend pools and PostgreSQL server connections.
- auth/ and config/: authentication and configuration handling.
- net/: PostgreSQL wire messages and network primitives.
- admin/, api/ and stats/: administration and observability interfaces.
- plugin/: upstream plugin integration.

Related workspace crates hold shared configuration, statistics, PostgreSQL
types and plugin interfaces. Existing features are documented in README.md and
upstream documentation at https://docs.pgdog.dev/.

## Repository tooling

The Python runtime keeps configuration, path handling, process execution,
verification evidence and independent review boundaries explicit. Evidence is
bound to Git identities. The documentation generator escapes model and Markdown
content into a standalone HTML file; it does not read .agent/.memory/ or publish
local .agent/.runs/ evidence.

The coding-agent tooling is distinct from the planned product LLM agent. The
latter has no implemented component or API contract yet.
