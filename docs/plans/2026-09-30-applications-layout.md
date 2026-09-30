# PgDog application layout and CI events

## Approved scope

The owner requested merging the verified PgDog changes, moving all application
source into `applications/`, and running CI only for pull requests or manual
runs. The owner explicitly retained merge gates; unresolved CI failures must be
fixed before merge.

## Layout

Use `applications/pgdog/` as the complete Rust workspace: crates, integration
fixtures, examples, plugins, SDK, Cargo/toolchain/config files, Docker assets,
upstream application docs and workspace scripts. Keep repository governance,
agent runtime, generated agent adapters, root license and GitHub workflows at
root. Root `scripts/pgdog` forwards commands with the application as cwd. Root
verification keeps repository checks at root and runs Rust checks in the app.

## CI and path contracts

Validation workflows support `pull_request` and `workflow_dispatch`. Packaging
and release operations remain manual only. Remove push, schedule, release,
merge-group and callback triggers. GitLab accepts merge-request or web/manual
pipelines only. Update working directories, action input paths, caches, artifacts,
Docker contexts, schema generation, dependency paths and documentation links.
Keep inherited source-relative paths inside the workspace unchanged.

## Verification

- Prove moved source blob/mode identity except explicitly edited path consumers.
- Parse every workflow and assert all event triggers are PR/manual only.
- Validate Cargo workspace metadata, shell syntax, format, lint and build.
- Run agent runtime and focused relocation/CI regression tests.
- Run full Rust/PostgreSQL suite on fresh dedicated fixtures and hosted PR CI.
- Retain independent review and exact-manifest approval before merging new code.
