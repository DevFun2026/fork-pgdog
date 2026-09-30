# PgDog fork

PgDog source, Cargo workspace, examples, plugins, integration tests and application documentation live in [`applications/pgdog/`](applications/pgdog/README.md).
Repository governance and CI configuration remain at the root.

## Development

From the repository root:

```sh
./scripts/pgdog cargo build --locked --workspace
./scripts/pgdog cargo fmt --all -- --check
./scripts/agent verify quick --json
```

Full test fixtures and merge gates are described in [verification](docs/VERIFICATION.md).
For direct Cargo commands, first `cd applications/pgdog`.

## Containers

Build with the repository root as context (the build includes Git metadata):

```sh
docker build -f applications/pgdog/Dockerfile -t pgdog .
docker compose -f applications/pgdog/docker-compose.yml up
```

## CI

Validation runs on pull requests or manual dispatch. Pushes and commits do not independently trigger CI.
Package, release and benchmark follow-up workflows require manual dispatch.
GitLab pipelines run only for merge requests or manual web runs.
Merge and independent review gates remain required; manual-only publishing does not authorize a release.
