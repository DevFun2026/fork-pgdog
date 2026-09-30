# Project AI Template

A provider-neutral project starter for AI-assisted software delivery. Claude
Code, Gemini via Antigravity CLI (`agy`), and Codex use the same canonical policy, 21 core workflow skills plus 4 on-demand UX/UI skills,
Project Memory, architecture model, evidence gates, cross-provider review, and
security/release process.

The repository separates two things deliberately:

- `.agent/`, `scripts/agent`, provider adapters, tests, and documentation are
  **template tooling**.
- The application code you add beside them is **product code**. The tooling
  governs and verifies it but is not an application framework or runtime
  dependency.

## Requirements

- Git 2.30 or newer.
- Python 3.11 or newer; the runtime uses only the standard library.
- macOS or Linux for the shipped shell entry points and CI smoke tests.
- At least one supported provider CLI only when running real cross-review.
- `sandbox-exec` on macOS or Bubblewrap (`bwrap`) on Linux for provider-backed
  review. Review fails closed when the host sandbox is unavailable.

Check the local environment without installing anything:

```sh
./scripts/agent doctor --providers --json
```

## Start a project

Use GitHub's **Use this template**, or clone and point the remote at your own
repository:

```sh
git clone https://github.com/DevFun2026/Project-AI-Template.git my-project
cd my-project
```

Before initialization, review these choices with the project owner:

- project name and exposure;
- executable format/lint/test/build/smoke commands;
- `baseline`, `standard`, or `high` security profile;
- credential and sensitive-data handling;
- provider order and review-package byte limit;
- exact provider command arrays and required security scanners;
- local memory budget and retention.

Record the approved values in `.agent/config.toml`, or copy and review
`.agent/templates/init-answers.json`, then run:

```sh
./scripts/agent init --answers init-answers.json
./scripts/agent doctor --json
./scripts/agent adapters check
./scripts/agent docs check
```

Without `--answers`, `agent init` validates the existing configuration. With
`--answers`, it deterministically writes `.agent/config.toml`. It then builds
generated
provider adapters and architecture outputs, and initializes private local
memory. It does not create or modify product source.

## Lifecycle

The canonical entry point is `AGENTS.md`; provider files are intentionally thin.
For context profiles, ranked memory, generated-copy review deduplication and
planning tiers, see [Context efficiency](docs/context-efficiency.md).
Agents discover the applicable `.agent/skills/*/SKILL.md` and follow this flow:

1. Repository discovery and focused Project Memory retrieval.
2. Brainstorming and explicit approval of consequential choices.
3. Behavioral specification, architecture, ADR, and threat model.
4. Dependency-ordered implementation plan.
5. Test-driven implementation and systematic debugging.
6. Fresh verification and ordinary code review.
7. Independent cross-provider review and evidence-based adjudication.
8. Security review, deterministic documentation sync, and release readiness.

For routine editing, use the quick gate:

```sh
./scripts/agent verify quick --json
```

A newly cloned template intentionally reports `incomplete` until real project
commands are configured. Missing or skipped commands never become a pass.

## UX/UI when needed

Use `./scripts/agent workflow guide --task interface` to select discovery,
design-system, frontend-design or UX/UI review. References and artifact templates
are loaded by phase; backend-only work does not need them. See
[UX/UI guide](docs/ux-ui.md), [source audit](.agent/sources/UX_UI_AUDIT.md) and
[third-party notices](THIRD_PARTY_NOTICES.md). Selected documentation is adapted
with attribution, not installed as an external skill pack.

## Project Memory

Project Memory avoids rescanning the whole repository every time a new agent or
session starts. It uses three layers:

1. compact bootstrap/index context;
2. focused search and lineage metadata;
3. explicitly selected full records.

```sh
./scripts/agent memory init
./scripts/agent memory bootstrap --query "authentication architecture"
./scripts/agent memory search "token rotation"
./scripts/agent memory timeline MEM-EXAMPLE-001
./scripts/agent memory show MEM-EXAMPLE-001
./scripts/agent memory doctor --json
```

To checkpoint durable learning, create a JSON file containing every
`MemoryCandidate` field (`id`, `type`, `title`, `summary`, `details`,
`components`, `paths`, `evidence`, `source_provider`, `source_session`,
`branch`, `observed_commit`, `created_at`, `sensitivity`, and
`reuse_guidance`) and run:

```sh
./scripts/agent memory checkpoint --file candidate.json
```

Checkpointing creates an untrusted local candidate. Promotion is separate and
reviewed:

```sh
./scripts/agent memory promote CAND-EXAMPLE-001
```

The SQLite database and run artifacts live under ignored, owner-only
`.agent/.memory/` and `.agent/.runs/`. Canonical reviewed memory is Markdown in
`.agent/memory/records/`. Secrets, `<no-memory>` blocks, private records,
untrusted imports, and stale records are excluded from startup context.

## Cross-provider review

The reviewer must differ from the author provider. First run the configured
merge commands to produce fresh review inputs, then build a bounded package
without egress:

Review and security evidence are always anchored to the fetched remote default
branch (`refs/remotes/origin/HEAD`, with `origin/main` or `origin/master` as
fallback). The anchor must be a proper ancestor of `HEAD`. A supplied `--base`
is only an assertion and must resolve to that same SHA; `HEAD` and intermediate
feature commits are rejected. After cloning, use `git remote set-head origin -a`
if the remote default-branch reference is missing.

```sh
./scripts/agent verify review --json
./scripts/agent review \
  --base origin/main \
  --head HEAD \
  --author-provider codex \
  --reviewer-provider claude \
  --context docs/architecture/system-summary.md
```

The command returns `manifest_pending` (exit 4) with a package path and SHA-256.
Inspect the providers, paths, scope, and byte count. Only after exact approval,
resume the same immutable package:

```sh
./scripts/agent review \
  --base origin/main \
  --head HEAD \
  --author-provider codex \
  --reviewer-provider claude \
  --package .agent/.runs/review-UUID \
  --approve-manifest MANIFEST-SHA256
```

Before provider execution, the runtime revalidates diff, context, requirements,
verification, policy, schema, paths, secrets, size, provider independence, and
every checksum. The provider runs inside an OS sandbox that can read only the
approved package, exact external executable/support files, and system runtime
files. Interpreted/npm-style CLIs receive a read-only mount of their resolved
external package bundle; repository-contained executables/support files and
caller-supplied host file/directory grants and inline interpreter/module
commands are rejected before capability probing. The first package-build call
does not execute or probe a provider. Only after exact manifest approval does a
no-network/no-credential capability probe run inside the OS boundary; a
successful probe is followed by the credentialed review invocation.
No-network probes also strip proxy variables; credentialed review diagnostics
redact provider keys and proxy URLs.
HOME and temporary output are isolated, and process output is file-size bounded.
Configure command arrays under
`[review.provider_commands]`. The runtime forwards only a small common network/
locale environment plus provider-specific API-key variables; unrelated host
variables and credential files are excluded. Claude receives only `Read`,
AGY uses a pinned Gemini model and advisory plan mode (the outer OS sandbox
enforces read-only access), and Codex starts child commands with an empty
environment policy. Timeout, quota, missing CLI/sandbox, malformed output, or
checksum drift remains `review_pending`; it never approves a change.

The `gemini` provider now executes `agy`, not Gemini CLI. Antigravity and Codex
share generated `.agents/skills`; `.agents/hooks.json` handles AGY memory hooks.
Automated AGY review uses disposable API-key-mode settings and only
`GEMINI_API_KEY`, never the host login profile or keychain. See
[Antigravity setup and migration](docs/antigravity.md) for model selection,
authentication limitations, and the current CLI contract.

Use `.agent/templates/reviews/adjudication-decisions.json` to record exactly one
decision per finding, then bind the decisions to the reviewed package:

```sh
./scripts/agent adjudicate \
  --package .agent/.runs/review-UUID \
  --file adjudication-decisions.json
```

Confirmed or unresolved Critical/High findings block merge. Rejections require
an explicit reason. A clean pass creates an empty bound adjudication artifact.

## Architecture and whole-system HTML

Edit canonical `.agent/project-model/*.toml` and focused Markdown under
`docs/architecture/` or `docs/security/`, then regenerate:

```sh
./scripts/agent docs build
./scripts/agent docs check
```

Open `docs/architecture/system.html` in any browser for the self-contained,
offline whole-system view. It embeds no remote scripts, styles, fonts, or data.
Generated `system.html` and `system-summary.md` must not be hand-edited.

## Merge and release gates

Merge verification requires full configured commands, current documentation
impact, independent code review, and cross-review evidence:

```sh
./scripts/agent verify merge --json
```

Release adds security clearance, triggered threat-model delta, required scanner
results, clean-checkout smoke, documentation, release notes,
migration/backup/rollback, and residual risks:

```sh
./scripts/agent security --base origin/main --head HEAD --json
./scripts/agent security --base origin/main --head HEAD \
  --approval-evidence .agent/.runs/security-approval.json \
  --approval-signature .agent/.runs/security-approval.json.sig --json
./scripts/agent release run-scanner --scanner dependency
./scripts/agent release run-scanner --scanner license
./scripts/agent release run-scanner --scanner sast
./scripts/agent release record --artifact release-notes \
  --file docs/releases/release-notes.md
./scripts/agent release record --artifact migration-rollback \
  --file docs/releases/migration-rollback.md
./scripts/agent release record --artifact residual-risks \
  --file docs/security/residual-risks.md
bash scripts/release-smoke.sh
./scripts/agent verify release --json
```

The first security command produces a scope-bound incomplete assessment. To
create clearance, copy `.agent/templates/security/security-approval.json` into
the ignored `.agent/.runs/` directory, then copy the first command's complete
`assessment` and `assessment_sha256` values into it. Sign the JSON with
`ssh-keygen -Y sign -n agent-security-approval`. The reviewer identity/key must already exist in the
base revision's `.agent/security/allowed_signers`; adding a signer in the same
change cannot authorize that change. The second form verifies the strict JSON
schema, complete assessment, author/reviewer independence, detached SSH
signature, and a freshly recomputed assessment from Git/config. Configure exact
argument arrays under `[security.scanner_commands]`, dedicated non-mutating
version commands under `[security.scanner_version_commands]`, and explicit tool
dependencies under `[security.scanner_support_paths]`; `run-scanner` executes
without a shell and derives status/tool identity from the process rather than
accepting a claimed pass. Repository scan-target directories are bound through
Git identity and are never recursively read as tool identity. Explicit external
support directories are recursively manifested; direct and flag-value support
files are checksummed.
Release/scanner records and clean-smoke evidence are
bound to the exact HEAD, working-tree diff, configured command/set, tool
identity, strict result schema, and output checksum, and are rejected when stale
or tampered.

Optional unsupported scanners are recorded as `not-configured`. Any scanner
marked required must pass.

## CI

`.github/workflows/agent-quality.yml` and `.gitlab-ci.yml` run the repository
runtime instead of reimplementing policy in YAML. Untrusted jobs receive no
provider secrets. Provider-backed review belongs in a protected/manual job after
manifest approval. See `docs/ci-integration.md` before making the manual merge
contract a required check.

Validate release contents from a clean `git archive`:

```sh
bash scripts/release-smoke.sh
```

## Acceptance evidence

The deterministic suite covers the complete starter workflow, all six mock
cross-provider directions, privacy/security boundaries, generated-file drift,
and clean-export smoke. The current evidence and the line-by-line review of all
20 design criteria are committed here:

- `docs/evidence/template-acceptance.json`
- `docs/reviews/template-final-review.md`

Real-provider smoke uses a generated public fixture, never repository source.
At the recorded snapshot, Codex completed a schema-valid read-only review;
Claude and the old Gemini CLI were capability-compatible but unauthenticated.
That snapshot is historical, not evidence for the AGY migration. Current AGY
verification is recorded in [the migration guide](docs/antigravity.md).
Hosted CI status is also kept separate from local success.

## Failure recovery

- `incomplete`: supply missing configuration, tool, timeout result, or evidence;
  do not weaken the gate.
- `blocked`: fix the policy violation or obtain the required human decision.
- `review_pending`: reuse the preserved review package with the same approved
  manifest after provider/environment recovery.
- adapter drift: edit `.agent/` sources, run `agent adapters build`, then check.
- docs drift: edit model/Markdown sources, build, then check.
- memory corruption or staleness: run memory doctor, exclude unsafe records,
  repair/review, and rebuild the index.

Never delete `.agent/.runs/review-*` while a review may need to resume. Preserve
unrelated Git changes during all recovery work.

## Updates and provenance

Pull template changes into a branch, review `.agent/` policy/runtime changes,
regenerate adapters/docs, and run the full unit suite plus release smoke before
merging. Never copy a provider-native generated skill back into canonical
sources.

Source ideas, reviewed revisions, licenses, and clean-room boundaries are in
`.agent/sources/SOURCES.md`; notices are in `THIRD_PARTY_NOTICES.md`. Audit them:

```sh
./scripts/agent licenses audit --json
```

## Non-goals

- No application framework, language stack, cloud, or deployment vendor is
  selected for product code.
- No provider CLI, account, credential, scanner, dependency, or plugin is
  installed automatically.
- No source is sent to a model without bounded manifest approval.
- No transcript or model output is promoted directly to canonical memory.
- No AI/scanner result is described as absolute security or certification.
- No automatic commit, push, merge, release, migration, deployment, or
  destructive recovery occurs without the user's authorization.

## License

Apache-2.0. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.
