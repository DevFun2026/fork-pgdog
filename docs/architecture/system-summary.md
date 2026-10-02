# PgDog fork: system architecture

Generated: 2026-10-01T14:10:07+07:00 | Commit: 135b4f471761

## Components

- **artifact-registry** — Owned GHCR Artifacts (`registry`): Destination ghcr.io/devfun2026/fork-pgdog and charts/fork-pgdog. Stores versioned images/chart paired by digest after authorized manual publication; first external publication remains unverified. [boundary: external-registry]
- **canonical-core** — Canonical Agent Core (`policy-and-skills`): Defines provider-neutral policy, 21 core skills and four task-routed UX/UI skills, schemas, artifact templates, and lifecycle contracts. UX/UI references are read per phase and retain source notices; no external skill runtime is installed. [boundary: local-repository]
- **ci-wrappers** — CI Wrappers (`automation`): Invokes repository-owned PR/manual quality gates, native image/chart validation and isolated Kubernetes smoke. Architecture Pages and fork artifact publication are manual; artifact writes require owner-reviewed release receipt and protected packages environment. [boundary: hosted-ci]
- **container-builder** — Fork Container Builder (`build-tooling`): Builds applications/pgdog/Dockerfile from pinned Ubuntu/Rust bases with Cargo.lock and plugin; excludes Git/private context. Produces native OCI archives verified before publication. [boundary: hosted-ci]
- **docs-generator** — Documentation Generator (`generator`): Validates the canonical project model and generates deterministic architecture views. [boundary: local-repository]
- **helm-release** — Fork Helm Release (`deployment-tooling`): Standalone charts/fork-pgdog creates a stateless Linux Deployment, configcheck initContainer, PostgreSQL-only Service and token-disabled ServiceAccount. No database or durable 2PC WAL provisioned. [boundary: operator-to-cluster]
- **kubernetes-pod** — Hardened PgDog Pod (`container-runtime`): Runs UID/GID 10001 with read-only root/mounts, bounded tmp, TCP liveness and backend-aware HTTP readiness, and image SIGINT with bounded drain. Verified locally in isolated Kind; production infrastructure remains operator-owned. [boundary: cluster-workload]
- **operator-secrets** — Operator Configuration and Secrets (`external-configuration`): Provides pgdog.toml via one inline/existing ConfigMap/Secret source, required existing users.toml Secret and optional TLS files. External changes/restoration require explicit operator rollout and version management. [boundary: cluster-secret-store]
- **pgdog-proxy** — PgDog Proxy (`rust-service`): Contains the application workspace at applications/pgdog/ and implements PostgreSQL protocol handling, authentication, pooling, routing, and SQL execution forwarding. Existing upstream behavior; no production deployment configured by this import. [boundary: proxy-process]
- **postgresql** — PostgreSQL (`database`): Executes forwarded queries. Verification uses isolated PostgreSQL 18 fixtures; production infrastructure is outside this repository setup. [boundary: database-process]
- **project-memory** — Project Memory (`local-storage`): Stores private candidates locally; retrieves fresh canonical summaries with ranked top-k and bounded context. [boundary: local-repository]
- **provider-adapters** — Provider Adapters (`adapter`): Shares generated skills across Claude, Codex, and Gemini via agy; runs bounded review packages inside a fail-closed OS read sandbox. AGY pins a Gemini model, validates terminal schema output, and uses disposable API-key-mode settings without host profiles. [boundary: provider-cli-process]
- **review-engine** — Cross-Review Engine (`orchestrator`): Builds budgeted review packages with proven generated-copy deduplication, verified unchanged-rename path tables and full Git change binding. Recomputes blob/mode proofs before egress; changed sensitive files stay blocked. Enforces reviewer independence and validates findings. [boundary: local-repository]
- **runtime** — Agent Runtime (`python-cli`): Runs configuration, evidence, workflow, documentation, review, security, and release commands. [boundary: local-repository]
- **sql-client** — PostgreSQL Client (`client`): Sends PostgreSQL protocol messages and credentials; integration tests use synthetic users and data. [boundary: client-process]

## Relationships

- `container-builder` → `artifact-registry` — protected publish copies exact verified archives and pairs chart by digest
- `ci-wrappers` → `container-builder` — builds/tests each native archive without write credentials
- `ci-wrappers` → `runtime` — invokes repository-owned gates
- `sql-client` → `pgdog-proxy` — authenticates and sends PostgreSQL protocol messages
- `canonical-core` → `runtime` — defines policy and command contracts
- `docs-generator` → `canonical-core` — reads canonical model and focused documentation
- `helm-release` → `kubernetes-pod` — installs stateless hardened Deployment and configcheck
- `helm-release` → `artifact-registry` — retrieves exact chart version and image digest after publication
- `kubernetes-pod` → `pgdog-proxy` — runs PgDog as PID 1 with SIGINT drain
- `pgdog-proxy` → `postgresql` — opens backend connections and forwards queries
- `review-engine` → `provider-adapters` — runs approved packages inside an OS read sandbox
- `runtime` → `project-memory` — validates lifecycle and privacy rules
- `runtime` → `review-engine` — starts fail-closed review operations
- `operator-secrets` → `kubernetes-pod` — mounts protected configuration/users/TLS read-only

## Data flows

- **backend-query**: `pgdog-proxy` → `postgresql`; data: database-credentials, sql-query; boundary: proxy-to-database
- **backend-results**: `postgresql` → `pgdog-proxy`; data: query-results; boundary: database-to-proxy
- **chart-image-deployment**: `artifact-registry` → `helm-release`; data: configuration, project-source; boundary: registry-to-operator-cluster
- **ci-evidence**: `ci-wrappers` → `runtime`; data: configuration, evidence-metadata; boundary: hosted-ci-to-repository
- **client-query**: `sql-client` → `pgdog-proxy`; data: database-credentials, sql-query; boundary: client-to-proxy
- **client-results**: `pgdog-proxy` → `sql-client`; data: query-results; boundary: proxy-to-client
- **documentation-model**: `canonical-core` → `docs-generator`; data: configuration; boundary: local-repository
- **memory-checkpoint**: `runtime` → `project-memory`; data: memory-record; boundary: local-private-storage
- **native-artifact-egress**: `container-builder` → `artifact-registry`; data: evidence-metadata, project-source; boundary: protected-ci-to-registry
- **operator-config-mount**: `operator-secrets` → `kubernetes-pod`; data: configuration, database-credentials; boundary: secret-store-to-workload
- **review-egress**: `review-engine` → `provider-adapters`; data: project-source, review-package; boundary: local-to-provider-process

## Environments

- **ghcr** — GHCR packages environment: Manual main-only package workflow consumes owner-approved genuine release receipt, source ancestry and new versions. Protected packages environment reviewers gate writes/OIDC. Registry visibility and first publication are separately authorized external setup; no release clearance is claimed without signed security evidence.
- **github-actions** — GitHub Actions: Pull-request or manual validation only; publishing is manual. GitHub-hosted Ubuntu 24.04 Rust/unit/integration CI and template runtime tests. Independent review needs approved local evidence; upstream-only Codecov and Bencher credentials are not required.
- **github-pages** — GitHub Pages: Public static architecture reference at https://devfun2026.github.io/fork-pgdog/. The architecture-pages workflow validates on PRs and publishes only after manual dispatch from main. It uploads only index.html and .nojekyll, not repository files or local evidence. First publication requires Actions-based Pages setup and a protected github-pages environment. This host has no database access or LLM runtime.
- **gitlab-ci** — GitLab CI: Merge-request or manual web pipelines only. Python 3.11 jobs invoke the same runtime commands and retain redacted failure evidence.
- **kubernetes** — Operator Kubernetes: Helm 3.8+/Kubernetes 1.28+ stable API target. Local Kind 0.33.0/Kubernetes 1.36.4 smoke with Helm 4.1.3 is verified; pinned Helm 3.19.0/native amd64+arm64 CI is authored and requires an actual run. Production network/TLS/Secret policy and durable 2PC storage remain external.
- **local** — Local developer environment: macOS with sandbox-exec or Linux/WSL with Bubblewrap, Python 3.11+, and optional authenticated provider CLIs.
