# PgDog fork and verification workflow

Generated: 2026-09-30T14:33:07+07:00 | Commit: e394507e6774

## Components

- **canonical-core** — Canonical Agent Core (`policy-and-skills`): Defines provider-neutral policy, 21 core skills and four task-routed UX/UI skills, schemas, artifact templates, and lifecycle contracts. UX/UI references are read per phase and retain source notices; no external skill runtime is installed. [boundary: local-repository]
- **ci-wrappers** — CI Wrappers (`automation`): Invokes the same repository-owned quality gates on hosted CI without duplicating policy. [boundary: hosted-ci]
- **docs-generator** — Documentation Generator (`generator`): Validates the canonical project model and generates deterministic architecture views. [boundary: local-repository]
- **pgdog-proxy** — PgDog Proxy (`rust-service`): Implements PostgreSQL protocol handling, authentication, pooling, routing, and SQL execution forwarding. Existing upstream behavior; no production deployment configured by this import. [boundary: proxy-process]
- **postgresql** — PostgreSQL (`database`): Executes forwarded queries. Verification uses isolated PostgreSQL 18 fixtures; production infrastructure is outside this repository setup. [boundary: database-process]
- **project-memory** — Project Memory (`local-storage`): Stores private candidates locally; retrieves fresh canonical summaries with ranked top-k and bounded context. [boundary: local-repository]
- **provider-adapters** — Provider Adapters (`adapter`): Shares generated skills across Claude, Codex, and Gemini via agy; runs bounded review packages inside a fail-closed OS read sandbox. AGY pins a Gemini model, validates terminal schema output, and uses disposable API-key-mode settings without host profiles. [boundary: provider-cli-process]
- **review-engine** — Cross-Review Engine (`orchestrator`): Builds budgeted review packages with proven generated-copy deduplication and full Git change binding; enforces reviewer independence and validates findings. [boundary: local-repository]
- **runtime** — Agent Runtime (`python-cli`): Runs configuration, evidence, workflow, documentation, review, security, and release commands. [boundary: local-repository]
- **sql-client** — PostgreSQL Client (`client`): Sends PostgreSQL protocol messages and credentials; integration tests use synthetic users and data. [boundary: client-process]

## Relationships

- `ci-wrappers` → `runtime` — invokes repository-owned gates
- `sql-client` → `pgdog-proxy` — authenticates and sends PostgreSQL protocol messages
- `canonical-core` → `runtime` — defines policy and command contracts
- `docs-generator` → `canonical-core` — reads canonical model and focused documentation
- `pgdog-proxy` → `postgresql` — opens backend connections and forwards queries
- `review-engine` → `provider-adapters` — runs approved packages inside an OS read sandbox
- `runtime` → `project-memory` — validates lifecycle and privacy rules
- `runtime` → `review-engine` — starts fail-closed review operations

## Data flows

- **backend-query**: `pgdog-proxy` → `postgresql`; data: database-credentials, sql-query; boundary: proxy-to-database
- **backend-results**: `postgresql` → `pgdog-proxy`; data: query-results; boundary: database-to-proxy
- **ci-evidence**: `ci-wrappers` → `runtime`; data: configuration, evidence-metadata; boundary: hosted-ci-to-repository
- **client-query**: `sql-client` → `pgdog-proxy`; data: database-credentials, sql-query; boundary: client-to-proxy
- **client-results**: `pgdog-proxy` → `sql-client`; data: query-results; boundary: proxy-to-client
- **documentation-model**: `canonical-core` → `docs-generator`; data: configuration; boundary: local-repository
- **memory-checkpoint**: `runtime` → `project-memory`; data: memory-record; boundary: local-private-storage
- **review-egress**: `review-engine` → `provider-adapters`; data: project-source, review-package; boundary: local-to-provider-process

## Environments

- **github-actions** — GitHub Actions: Pull-request or manual validation only; publishing is manual. GitHub-hosted Ubuntu 24.04 Rust/unit/integration CI and template runtime tests. Independent review needs approved local evidence; upstream-only Codecov and Bencher credentials are not required.
- **gitlab-ci** — GitLab CI: Merge-request or manual web pipelines only. Python 3.11 jobs invoke the same runtime commands and retain redacted failure evidence.
- **local** — Local developer environment: macOS with sandbox-exec or Linux/WSL with Bubblewrap, Python 3.11+, and optional authenticated provider CLIs.
