# Agent Project Template Design

**Date:** 2026-09-21

**Status:** Draft for user review

**License:** Apache-2.0

**Target platforms:** macOS and Linux; Windows through WSL

**Target agents:** Claude Code, Gemini CLI, and Codex/ChatGPT coding agents

## 1. Executive Summary

This repository will be a technology-agnostic project template for AI-assisted software development. It will define one canonical workflow for Claude, Gemini, and Codex while preserving thin provider-specific adapters where their discovery mechanisms or CLI contracts differ.

The template will cover the full project lifecycle: repository discovery, brainstorming, specification, architecture, ADRs, threat modeling, planning, implementation, verification, independent review, cross-provider review, security review, documentation, and release readiness.

The design has four central properties:

1. `.agent/` is the canonical source for skills, policy, workflow, schemas, runtime, memory, and source attribution.
2. Review and release claims require reproducible evidence tied to the current commit and diff.
3. Cross-review uses a provider different from the implementation provider and fails closed when that independence cannot be established.
4. Project knowledge is preserved through a two-tier, local-first Project Memory so a new agent session can recover relevant context without scanning the entire repository.

## 2. Goals

- Provide one reusable repository template for arbitrary languages and frameworks.
- Keep the workflow consistent across Claude Code, Gemini CLI, and Codex.
- Package repeatable procedures as Agent Skills-compatible `SKILL.md` directories.
- Support automated cross-provider review through already-installed and authenticated CLIs.
- Prevent code or secrets from leaving the repository without explicit, reviewable scope.
- Maintain living architecture, security, decision, plan, review, and evidence documents.
- Generate one self-contained HTML document that describes the whole system for human readers.
- Preserve compact, searchable project knowledge across sessions and providers.
- Run the template tooling with Python 3.11+ and the standard library only.
- Enforce progressive quality gates without forcing the full release workflow during every development iteration.

## 3. Non-Goals for Version 1

- Native Windows support outside WSL.
- A hosted orchestration service, hosted memory service, or cloud dashboard.
- Direct provider API integration; version 1 invokes installed CLIs.
- Automatic installation or authentication of Claude, Gemini, or Codex.
- Automatic merge, push, deployment, or ADR acceptance.
- Framework-specific profiles.
- A desktop application, IDE extension, or background HTTP daemon.
- Capturing every prompt, tool input, or tool output.
- Semantic vector search or a vector database.
- Claims of security compliance or complete vulnerability coverage.

## 4. Design Principles

### 4.1 One canonical source

`AGENTS.md` and `.agent/` define shared behavior. `CLAUDE.md`, `GEMINI.md`, `.claude/`, `.gemini/`, and `.agents/` are thin provider adapters or generated discovery surfaces. Provider adapters may translate inputs and outputs but may not weaken policy or gates.

### 4.2 Progressive disclosure

Persistent instructions remain short. Detailed procedures live in skills and are loaded only when relevant. Project Memory retrieval follows index, timeline, then full-record retrieval rather than injecting all historical context.

### 4.3 Evidence before assertions

Test, review, and release status must be supported by command results, tool versions, exit codes, timestamps, hashes, and the commit being verified. Evidence from an older commit is stale.

### 4.4 Fail closed at trust boundaries

Missing required tools, unknown implementation-provider identity, secret detection, malformed reviewer output, stale evidence, or an unavailable independent reviewer block the affected merge or release gate.

### 4.5 Local-first and private by default

Version 1 has no telemetry, cloud sync, background daemon, or project-memory network service. Provider calls happen only through an explicit review operation whose package is previewed and scanned first.

### 4.6 Human authority remains explicit

Agents may draft specifications, plans, ADRs, findings, memories, and release artifacts. They may not silently accept ADRs, promote unreviewed memory as canonical truth, downgrade security policy, or approve their own implementation.

## 5. Repository Architecture

```text
.
├── AGENTS.md
├── CLAUDE.md
├── GEMINI.md
├── LICENSE
├── NOTICE
├── README.md
├── THIRD_PARTY_NOTICES.md
│
├── .agent/
│   ├── VERSION
│   ├── config.toml
│   ├── compatibility.toml
│   ├── skills/
│   ├── workflows/
│   ├── policies/
│   ├── schemas/
│   ├── templates/
│   ├── adapters/
│   ├── sources/
│   ├── runtime/agent_cli/
│   ├── tests/
│   ├── fixtures/
│   ├── project-model/
│   ├── memory/
│   ├── .memory/
│   └── .runs/
│
├── .agents/skills/
├── .claude/skills/
├── .gemini/skills/
│
├── docs/
│   ├── architecture/
│   ├── decisions/
│   ├── plans/
│   ├── reviews/
│   ├── security/
│   ├── evidence/
│   └── superpowers/specs/
│
├── scripts/agent
├── .github/workflows/agent-quality.yml
└── .gitlab-ci.yml
```

`.agent/.memory/` and `.agent/.runs/` are local, permission-restricted, and gitignored. `.agent/memory/records/` contains reviewed canonical memory and is committed.

## 6. Project Lifecycle

The workflow state machine is:

```text
DISCOVERED
  -> DESIGNED
  -> PLAN_APPROVED
  -> IMPLEMENTING
  -> LOCALLY_VERIFIED
  -> CODE_REVIEWED
  -> CROSS_REVIEWED
  -> SECURITY_CLEARED
  -> RELEASE_READY
```

Transitions require the artifacts and evidence defined by the target state. A workflow may return to an earlier state when requirements change, findings are confirmed, evidence becomes stale, or architecture/security assumptions no longer hold.

## 7. Skill Catalog

Version 1 includes the following canonical skills:

| Skill | Purpose | Required output |
|---|---|---|
| `project-bootstrap` | Initialize a repository without changing product source | Reviewed project configuration and baseline |
| `repository-discovery` | Map source, dependencies, tests, boundaries, and risks | Repository discovery report |
| `brainstorming` | Refine intent, constraints, alternatives, and success criteria | Approved design direction |
| `writing-spec` | Define behavior, non-goals, acceptance criteria, and edge cases | Reviewable specification |
| `architecture-design` | Define system context, containers, components, and flows | Architecture documents and model changes |
| `architecture-decision` | Record consequential choices | Proposed or accepted ADR |
| `threat-modeling` | Identify assets, actors, boundaries, abuse cases, and mitigations | Threat-model delta |
| `writing-plan` | Break approved work into verifiable tasks | Implementation plan |
| `test-driven-development` | Enforce RED-GREEN-REFACTOR where applicable | Test and implementation evidence |
| `systematic-debugging` | Reproduce and isolate unexpected behavior before fixing | Root-cause report and regression evidence |
| `verification` | Run scoped or full checks and record trustworthy results | Evidence manifest |
| `code-review` | Review correctness, tests, architecture, and maintainability | Structured findings and verdict |
| `cross-review` | Send a bounded review package to an independent provider | Provider result and audit manifest |
| `review-adjudication` | Reproduce and classify review findings | Confirmed, rejected, or needs-evidence decisions |
| `security-review` | Review trust boundaries and security risk | Security findings and residual risk |
| `documentation-sync` | Keep architecture and operational documentation current | Documentation-impact declaration |
| `release-readiness` | Verify full release criteria | Release-readiness report |
| `workflow-retrospective` | Propose workflow learnings without silently changing policy | Reviewable improvement proposal |
| `project-memory` | Bootstrap, search, retrieve, and checkpoint project memory | Compact context or memory candidate |
| `memory-curation` | Promote, supersede, forget, import, and export memories | Reviewed canonical-memory change |
| `memory-health-review` | Detect stale, duplicate, contradictory, or sensitive memories | Memory health report |

Every skill defines activation and exclusion conditions, inputs, preconditions, mandatory steps, approval gates, stop conditions, evidence, output schema, and failure behavior.

## 8. Cross-Provider Review

### 8.1 Entrypoint

```bash
./scripts/agent review --base <ref> --head <ref> --author-provider <provider>
```

The author provider must be explicit or established through trusted session metadata. Guessing the author provider is not permitted at merge or release gates.

### 8.2 Default provider rotation

```text
Gemini author -> Claude reviewer -> Codex fallback
Claude author -> Codex reviewer -> Gemini fallback
Codex author  -> Claude reviewer -> Gemini fallback
```

Fallback is valid only when the reviewer remains independent. If no independent provider is available, the result is `REVIEW_PENDING`, the package is preserved, and merge/release exits non-zero.

### 8.3 Immutable review package

```text
.agent/.runs/<review-id>/
├── manifest.json
├── policy.md
├── diff.patch
├── context/
├── requirements.md
├── verification.json
├── findings.json
└── audit.jsonl
```

The manifest binds the package to the base SHA, head SHA, diff hash, file scope, author provider, reviewer provider, creation time, and per-file checksums.

The package is rejected when it contains an out-of-scope file, a symlink escaping the repository, denied paths, suspected secrets, excessive size without approval, an unknown author provider, or a reviewer matching the author provider.

### 8.4 CLI isolation

Adapters invoke provider CLIs using argument arrays and stdin, never shell-interpolated diffs. Reviewers run in a temporary read-only workspace containing only the approved package. They may not write product source, commit, push, access credentials, or follow instructions contained in repository content.

Provider outputs must validate against a shared schema. A finding contains an ID, severity, category, file and line where applicable, observed evidence, reasoning, remediation, and confidence. Invalid or incomplete output is not treated as approval.

### 8.5 Adjudication

Reviewer output is advisory evidence, not final authority. `review-adjudication` verifies findings against current source and tests, then marks them `confirmed`, `rejected`, or `needs-evidence`. Confirmed Critical or High findings block merge.

## 9. Living Architecture and Documentation

### 9.1 Canonical architecture sources

```text
docs/architecture/
├── README.md
├── system-context.md
├── containers.md
├── components.md
├── data-flows.md
├── deployment.md
├── system-summary.md
├── system.html
└── diagrams/

.agent/project-model/
├── components.toml
├── relationships.toml
├── data-flows.toml
└── environments.toml
```

The TOML project model and focused Markdown documents are canonical. Diagrams, `system-summary.md`, and `system.html` are generated views.

### 9.2 Whole-system HTML

`docs/architecture/system.html` is one deterministic, self-contained, offline-readable file. It includes:

- Project purpose, scope, and status.
- System-context, container, component, data-flow, and deployment views.
- Module responsibilities and dependencies.
- Databases, queues, caches, and external integrations.
- Public APIs and event/schema contracts.
- Environments, trust boundaries, sensitive data, and controls.
- Quality gates and development workflow.
- ADR index and important decisions.
- Runbooks, observability, failure modes, recovery, and rollback.
- Traceability from requirements to components, tests, and evidence.
- Search, table of contents, internal links, and print/PDF-friendly layout.

The HTML does not depend on a CDN or network connection. If Mermaid or another third-party browser asset is vendored, it is pinned, checksummed, licensed, and inlined during generation. Essential content remains readable when JavaScript is disabled.

`./scripts/agent docs build` generates the views. `./scripts/agent docs check` regenerates to a temporary location and fails when committed outputs drift.

### 9.3 Architecture decisions

ADRs capture context, drivers, considered options, decision, rationale, consequences, risks, and follow-up. Agents may draft ADRs, but only explicit human or repository governance may mark them Accepted. Accepted ADRs are superseded rather than rewritten historically.

### 9.4 Documentation impact

Every merge declares either updated documentation files or a reason no documentation changes are required. Changes to public contracts, boundaries, data flows, security models, deployment topology, or consequential dependencies require documentation review.

## 10. Security Model

### 10.1 Security profiles

`project-bootstrap` proposes `baseline`, `standard`, or `high`, but a human approves the profile. Agents may not silently lower it.

The project configuration records exposure, credential handling, sensitive-data categories, and required checks.

### 10.2 Review lenses

Security review covers:

- Authentication, authorization, and tenant isolation.
- Input handling, injection, SSRF, path traversal, and unsafe parsing.
- Secrets, personal data, logs, retention, and leakage.
- Sessions, tokens, cryptography, and key management.
- Business logic, races, replay, and idempotency.
- Dependencies, lockfiles, build scripts, and supply-chain risk.
- Infrastructure, containers, CI/CD, networks, and least privilege.
- Error handling, auditing, abuse prevention, recovery, and residual risk.

Threat modeling is performed early and updated when assets, actors, trust boundaries, or data flows change.

### 10.3 Security statements

The system never reports that a project is absolutely secure. It reports the reviewed scope, checks performed, findings, unverified areas, and residual risks. AI review does not replace deterministic scanners and tests; scanners and tests do not replace design review and threat modeling.

## 11. Progressive Quality Gates

### 11.1 Quick gate

- Validate `.agent/config.toml`.
- Run relevant formatter, lint, and changed tests.
- Scan the working scope for secrets and denied files.
- Avoid external reviewer calls during ordinary edit loops.

### 11.2 Merge gate

- Run all required project commands.
- Require evidence tied to the current HEAD.
- Validate documentation impact.
- Require independent code review and cross-provider review.
- Block confirmed Critical or High findings.
- Fail when required checks are skipped.

### 11.3 Release gate

- Include the merge gate.
- Require full security review and threat-model delta.
- Run configured dependency, license, SAST, IaC, and container checks.
- Build and smoke-test from a clean checkout.
- Produce SBOM/provenance when supported by the project ecosystem.
- Require release notes, migration instructions, backup considerations, rollback, and residual-risk documentation.

### 11.4 Evidence contract

Each command record includes command ID, commit, timestamps, duration, exit code, tool version, output checksum, and status. Raw output containing sensitive information is not committed. Missing required tools, skipped required checks, or stale evidence fail merge/release.

## 12. Runtime and Configuration

### 12.1 Runtime

The runtime uses Python 3.11+ and the standard library. It is executed directly from `.agent/runtime/agent_cli/`; it is not installed into the product environment.

`scripts/agent` is a small POSIX shim that locates a compatible `python3`, reports a clear error when unavailable, invokes the runtime, and preserves its exit code.

### 12.2 Configuration

`.agent/config.toml` stores project commands as argument arrays rather than shell strings:

```toml
[project]
name = "example"
security_profile = "standard"

[commands]
format_check = ["tool", "format", "--check"]
lint = ["tool", "lint"]
test_changed = ["tool", "test", "changed"]
test_full = ["tool", "test"]
build = ["tool", "build"]
smoke = ["tool", "smoke"]

[review]
enabled = true
require_independent_provider = true
max_package_bytes = 500000
provider_order = ["claude", "codex", "gemini"]

[documentation]
system_html = "docs/architecture/system.html"

[memory]
enabled = true
startup_char_budget = 12000
local_retention_days = 90
```

Project commands execute without a shell unless the user explicitly configures and approves a shell boundary.

### 12.3 Command surface

```text
agent init
agent doctor
agent discover
agent workflow start|status
agent verify quick|merge|release
agent review
agent security
agent docs build|check|serve
agent memory <subcommand>
agent release check
```

`init` detects and proposes configuration but does not install dependencies or modify product source. `doctor` checks tool availability, versions, and capabilities without displaying credentials or sending code.

## 13. CI Architecture

Quality logic remains inside the repository runtime. GitHub Actions, GitLab CI, and generic CI integrations are thin wrappers that call the same commands used locally.

AI credentials are not exposed to fork or other untrusted jobs. Cross-review runs locally with committed redacted evidence or in a protected trusted-CI job. CI validates that the review manifest belongs to the exact commit and diff under evaluation.

Core runtime tests execute on macOS and Linux. Provider contract tests use mocks by default and real CLIs only in explicit, credentialed smoke environments.

## 14. Project Memory

### 14.1 Purpose

Project Memory prevents each new provider or session from rescanning the whole repository. It stores compact, evidence-linked knowledge while keeping repository policy, current source, tests, and accepted ADRs authoritative.

### 14.2 Storage tiers

```text
.agent/memory/
├── README.md
├── INDEX.md
└── records/MEM-*.md

.agent/.memory/
├── memory.db
├── candidates/
├── sessions/
└── exports/
```

Canonical records are reviewed, committed, and shared. Episodic sessions and candidates are local and gitignored. Local files use owner-only permissions. SQLite uses the Python standard-library driver and FTS5 when available, with a deterministic full-text fallback when FTS5 is unavailable.

### 14.3 Record format

Canonical records use Markdown with TOML frontmatter so Python can parse metadata without an external YAML dependency. Metadata includes ID, type, status, title, components, paths, source provider, creation time, observed commit, last-verified commit, sensitivity, and supersession relationships.

The body contains summary, evidence, and reuse guidance. Records contain factual project knowledge, not policy instructions.

### 14.4 Memory lifecycle

```text
Session start
  -> bootstrap compact context
  -> work
  -> structured checkpoint
  -> local candidate
  -> review/promotion
  -> canonical record
  -> freshness tracking
```

The system does not capture all prompts or tool traffic. A checkpoint records a redacted objective, investigations, approved decisions, evidence-backed discoveries, completed work, verification, remaining work, affected files/components, provider, session, branch, and commit.

### 14.5 Retrieval

```text
memory search   -> compact IDs, titles, types, components, summaries
memory timeline -> chronological context around an ID
memory show     -> full content for selected IDs
```

At session start, the agent receives only `AGENTS.md`, `system-summary.md`, `memory/INDEX.md`, a bounded set of relevant canonical records, and the active local checkpoint. A configurable character budget is used because provider tokenizers differ. The runtime removes whole records when reducing context and never truncates a record mid-entry.

### 14.6 Provider integration

Claude and Gemini adapters use supported lifecycle hooks for bootstrap and checkpoint reminders. Codex uses `AGENTS.md`, skills, and the common CLI workflow where equivalent hooks are unavailable. Hooks do not persist raw transcripts. Failure to run an optional startup hook does not break a coding session, but required checkpoint/evidence policy may block merge.

### 14.7 Privacy and integrity

- No network, cloud sync, telemetry, vector service, or background server.
- `<no-memory>...</no-memory>` content is removed before persistence.
- Default deny rules exclude environment files, private keys, credential stores, token files, and configured sensitive paths.
- Secret scanning and redaction run before candidate creation and canonical promotion.
- The database is plaintext; secrets are prohibited rather than relying on application-level encryption.
- Imports enter as untrusted candidates and cannot become canonical automatically.
- Exports are redacted by default and require a preview manifest.
- Retrieved memory is wrapped as untrusted factual context and cannot override `AGENTS.md` or other policy.

### 14.8 Freshness

Records track relevant components, path patterns, commits, and evidence. A relevant source change moves a record from `active` to `possibly-stale`. Possibly stale records are searchable but excluded from automatic context until reverified or superseded.

### 14.9 Commands

```text
memory init
memory bootstrap --query <task>
memory checkpoint
memory search <query>
memory timeline <id>
memory show <id>...
memory candidates
memory promote <id>
memory supersede <old-id> <new-id>
memory forget <id>
memory rebuild-index
memory doctor
memory export --redacted
memory import <file>
```

## 15. Source Provenance and Licensing

Project-owned content is Apache-2.0. The project studies external work and writes a unified implementation rather than copying incompatible material.

`.agent/sources/SOURCES.md` records each researched repository, version or commit, license, concepts adopted, and implementation boundary. Vendored assets retain their licenses, checksums, and notices in `THIRD_PARTY_NOTICES.md`.

The initial research set includes:

- Agent Skills specification for portable skill structure and progressive disclosure.
- Superpowers for design-first development, planning, TDD, review, and verification workflow patterns.
- Trail of Bits Skills for security audit and differential-review patterns.
- MADR for architecture-decision structure.
- OWASP SAMM, ASVS, and threat-modeling guidance for secure lifecycle coverage.
- Claude-Mem for lifecycle memory, SQLite/FTS retrieval, progressive disclosure, privacy tags, and structured checkpoints.

## 16. Error Handling

- User/configuration errors return stable non-zero exit codes and actionable messages.
- Provider/network/quota failures preserve resumable review state and never become approval.
- Partial writes use temporary files followed by atomic replacement.
- SQLite changes use transactions.
- Interrupted sessions remain recoverable and are not silently marked complete.
- Generated-document failures leave committed outputs unchanged.
- Malformed imported data is quarantined as an untrusted candidate or rejected.
- Redaction incidents are reported without echoing the detected secret.

## 17. Verification Strategy

- Unit tests use `unittest` and temporary directories.
- Fixture repositories exercise multiple synthetic stacks without requiring those stacks.
- Golden tests cover generated manifests, compact context, and `system.html`.
- Mock CLIs cover Claude, Gemini, and Codex success, failure, timeout, quota, malformed output, and provider-identity cases.
- Security tests cover prompt injection, command injection, path traversal, symlink escape, secret handling, untrusted imports, and redaction.
- Memory tests cover privacy tags, deterministic indexing, FTS fallback, stale detection, supersession, bounded injection, and policy non-override.
- Optional real-provider smoke tests record exact versions and limitations.
- Clean-checkout release smoke verifies generated artifacts and repository usability.

## 18. Acceptance Criteria

Version 1 is complete only when all of the following are demonstrated:

1. A clean macOS and Linux checkout can run `./scripts/agent doctor`.
2. `init` creates reviewed configuration without changing product source.
3. Claude, Gemini, and Codex consume the same canonical policy and skills.
4. Adapter drift detection passes.
5. Mock cross-review succeeds for all provider directions.
6. Same-provider review, missing CLI, detected secret, escaped path, oversized unapproved scope, or invalid output fails closed.
7. Evidence is rejected when its commit or diff hash is stale.
8. Quick, merge, and release gates have clear passing and failing fixtures.
9. Critical security-boundary tests pass.
10. Architecture, ADR, threat-model, and documentation-impact artifacts validate.
11. `system.html`, `system-summary.md`, indexes, and other generated files reproduce deterministically.
12. Source and license audit reports no unattributed dependency or vendored asset.
13. GitHub Actions and GitLab CI invoke the same runtime used locally.
14. Claude, Gemini, and Codex retrieve the same canonical memory record.
15. A new session receives useful context without scanning the entire repository.
16. Search, timeline, and show enforce progressive disclosure.
17. Secrets and `<no-memory>` content do not appear in SQLite, generated indexes, or exports.
18. Imports cannot bypass candidate review, stale memory is not auto-injected, and memory cannot override policy.
19. The README demonstrates a complete workflow from initialization through release check.
20. Real-CLI smoke results state the tested versions and remaining verification limits.

## 19. References

- Agent Skills specification: <https://agentskills.io/specification>
- Superpowers: <https://github.com/obra/superpowers>
- Trail of Bits Skills: <https://github.com/trailofbits/skills>
- MADR: <https://github.com/adr/madr>
- OWASP SAMM: <https://owasp.org/projects/samm>
- OWASP ASVS: <https://owasp.org/projects/asvs>
- OWASP Threat Modeling Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html>
- Claude-Mem: <https://github.com/thedotmack/claude-mem>
- Claude-Mem architecture: <https://docs.claude-mem.ai/architecture/overview>
- Claude-Mem search architecture: <https://docs.claude-mem.ai/architecture/search-architecture>
- Claude Code project memory: <https://code.claude.com/docs/en/memory>
- Gemini CLI context files: <https://geminicli.com/docs/cli/gemini-md/>
- Gemini CLI headless mode: <https://geminicli.com/docs/cli/headless/>
- Codex non-interactive mode: <https://developers.openai.com/es-419/docs/non-interactive-mode>
