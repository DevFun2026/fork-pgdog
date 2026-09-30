# Project AI Template

Generated: 2026-09-22T16:06:36+07:00 | Commit: 6a44fb6c2a3f

## Components

- **canonical-core** — Canonical Agent Core (`policy-and-skills`): Defines provider-neutral policy, 21 core skills and four task-routed UX/UI skills, schemas, artifact templates, and lifecycle contracts. UX/UI references are read per phase and retain source notices; no external skill runtime is installed. [boundary: local-repository]
- **ci-wrappers** — CI Wrappers (`automation`): Invokes the same repository-owned quality gates on hosted CI without duplicating policy. [boundary: hosted-ci]
- **docs-generator** — Documentation Generator (`generator`): Validates the canonical project model and generates deterministic architecture views. [boundary: local-repository]
- **project-memory** — Project Memory (`local-storage`): Stores private candidates locally; retrieves fresh canonical summaries with ranked top-k and bounded context. [boundary: local-repository]
- **provider-adapters** — Provider Adapters (`adapter`): Shares generated skills across Claude, Codex, and Gemini via agy; runs bounded review packages inside a fail-closed OS read sandbox. AGY pins a Gemini model, validates terminal schema output, and uses disposable API-key-mode settings without host profiles. [boundary: provider-cli-process]
- **review-engine** — Cross-Review Engine (`orchestrator`): Builds budgeted review packages with proven generated-copy deduplication and full Git change binding; enforces reviewer independence and validates findings. [boundary: local-repository]
- **runtime** — Agent Runtime (`python-cli`): Runs configuration, evidence, workflow, documentation, review, security, and release commands. [boundary: local-repository]

## Relationships

- `ci-wrappers` → `runtime` — invokes repository-owned gates
- `canonical-core` → `runtime` — defines policy and command contracts
- `docs-generator` → `canonical-core` — reads canonical model and focused documentation
- `review-engine` → `provider-adapters` — runs approved packages inside an OS read sandbox
- `runtime` → `project-memory` — validates lifecycle and privacy rules
- `runtime` → `review-engine` — starts fail-closed review operations

## Data flows

- **ci-evidence**: `ci-wrappers` → `runtime`; data: configuration, evidence-metadata; boundary: hosted-ci-to-repository
- **documentation-model**: `canonical-core` → `docs-generator`; data: configuration; boundary: local-repository
- **memory-checkpoint**: `runtime` → `project-memory`; data: memory-record; boundary: local-private-storage
- **review-egress**: `review-engine` → `provider-adapters`; data: project-source, review-package; boundary: local-to-provider-process

## Environments

- **github-actions** — GitHub Actions: Linux merge gate plus macOS and Linux runtime tests; provider secrets are restricted to protected jobs.
- **gitlab-ci** — GitLab CI: Python 3.11 jobs invoke the same runtime commands and retain redacted failure evidence.
- **local** — Local developer environment: macOS with sandbox-exec or Linux/WSL with Bubblewrap, Python 3.11+, and optional authenticated provider CLIs.
