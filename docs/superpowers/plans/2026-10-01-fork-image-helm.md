# Fork image and OCI Helm chart implementation plan

> **For agentic workers:** Use `superpowers:executing-plans` for native execution,
> or `superpowers:subagent-driven-development` if the owner explicitly selects
> delegated execution. Complete one task and its verification before moving on.
> Do not create commits without owner authorization.

**Goal:** Build this fork's own non-root amd64/arm64 image and installable Helm
chart, validate their behavior, and prepare gated manual GHCR publication.

**Architecture:** A root-context multi-stage Dockerfile builds the workspace and
plugin without official PgDog bases. A standalone chart connects to operator-owned
PostgreSQL backends and Secrets. Read-only validation precedes manual publication
of an image manifest and a chart pinned to that manifest's digest.

**Tech stack:** Existing Rust 1.96/Cargo.lock, Docker Buildx, Helm, Kubernetes/Kind,
Python 3.11 standard library, Bash, existing agent gates and Cosign action. Use
pinned PyYAML for test-only YAML parsing, Skopeo for OCI archive transport and
pinned Trivy for artifact scans;
the chart and application gain no runtime dependency on these tools.

**Approved inputs:** [Specification](../specs/2026-10-01-fork-image-helm-design.md),
[ADR-0003](../../decisions/0003-fork-owned-image-and-oci-chart.md), current
[verification runbook](../../VERIFICATION.md) and
[threat model](../../security/threat-model.md). The owner approved the written
specification on 2026-10-01. The owner approved this plan and native execution on 2026-10-01. Local source implementation is prepared; native CI and formal release verification remain pending. No artifact publication is implied.

## Scope and global constraints

- Image `ghcr.io/devfun2026/fork-pgdog`; chart `charts/fork-pgdog`; OCI chart
  `oci://ghcr.io/devfun2026/charts/fork-pgdog`.
- Initial chart `0.1.0`, appVersion `0.1.60`; published image digest takes
  precedence over tags. No official PgDog image/chart dependencies.
- Helm 3.8+ and Kubernetes 1.28+ stable API target. Record exact tested versions;
  do not claim every version was tested. Preserve Linux arm64 `+lse` constraints.
- Service defaults to ClusterIP:6432; listener 6432, HTTP readiness 9090, one
  replica, Pod grace 150s. Example PgDog shutdown bounds are 120s plus 10s.
- Non-root, read-only root, no privilege escalation, all capabilities dropped,
  RuntimeDefault seccomp, ServiceAccount token disabled, bounded writable tmp.
- Exactly one TOML config source; required existing users Secret; optional TLS
  Secret. No credentials in inline values/NOTES or broad artifact uploads.
- Stateless Deployment only; no durable per-replica 2PC WAL, PostgreSQL chart,
  Terraform, LLM agent, protocol/routing change or historical-doc rewrite.
- PR/manual validation; manual publishing only. Keep existing review/security
  trust anchors and standard profile. Missing evidence blocks publication.
- Preserve current dirty spec/ADR/generated docs. No commit, push, merge, tag,
  registry dispatch, signer enrollment or production access is authorized yet.

## Review focus

1. Missing/conflicting inputs must fail before a deployable chart is emitted;
   unknown keys such as inline credentials must not disappear silently (Task 2).
2. Existing Secret/ConfigMap changes need an explicit rollout; documentation must
   not promise automatic reload or Helm rollback of external state (Tasks 2/7).
3. Backend outage must remove readiness without a liveness restart loop; an
   in-flight query must drain on SIGINT during Pod deletion (Task 4).
4. Older approved source SHAs differ from the dispatch SHA; provenance, image
   digest and packaged chart must bind to the selected source (Tasks 5/6).
5. GHCR auth/network errors, concurrent releases and partial publishing must not
   be mistaken for a nonexistent tag or permit overwriting a release (Task 6).

## Preflight and known boundaries

- [ ] Recheck `git status --short --branch`; retain the approved design files.
  Read selected canonical skills fully at execution time; use bootstrap with
  focused task terms. Do not rescan unrelated source.
- [ ] Check Docker daemon/Buildx, disk capacity, Helm, kubectl, Kind, Rust,
  clang/mold dependencies and pinned tool-download availability. Local installed
  clients at planning time: Helm 4.1.3, kubectl 1.36.1, Kind 0.33.0; daemon and
  cluster health have not been verified. CI tests a pinned Helm 3 version as well
  as local Helm 4; no dependency installation is performed during planning.
- [ ] Follow the existing macOS verification runbook: resolve the SDK under
  `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/`;
  pass that verified path via `SDKROOT` and remove inherited obsolete `LDFLAGS`
  for the verification process only. Prior Clippy failed while reading the CLT
  SDK's `arm64e.x1` architecture; do not edit global shell/Xcode configuration.
- [ ] Establish dedicated PostgreSQL/Toxiproxy fixtures for repository full
  gates. Never run upstream destructive fixture setup on shared databases.
- [ ] Verify newly selected Docker bases/tool releases and pin multi-platform
  manifest digests, action commit SHAs and download checksums from primary
  sources. Do not invent pin values or use a tag-only substitution as completion.
- [ ] For release, note two existing governance constraints: `allowed_signers`
  has no enrolled signer; `resolve_trusted_base` requires the fetched remote
  default branch to be a proper ancestor of candidate HEAD. Obtain release
  evidence on the immutable candidate before integration, preserving that
  candidate SHA through an authorized fast-forward. Do not retarget a trusted
  remote ref or use an intermediate caller-selected base to manufacture a pass.
- [ ] Implement locally and prepare publish sources even while release authority
  is unavailable. Record unavailable signatures/review/credentials separately;
  never mark external distribution complete before Task 9.

## File responsibilities

| Unit | Paths |
| --- | --- |
| Build/version | `applications/pgdog/Dockerfile`, `applications/pgdog/pgdog/build.rs`, new `applications/pgdog/pgdog/build_metadata.rs`, root `.dockerignore` |
| Chart | `charts/fork-pgdog/Chart.yaml`, `values.yaml`, `values.schema.json`, `.helmignore`, `templates/{_helpers.tpl,deployment.yaml,service.yaml,serviceaccount.yaml,configmap.yaml,NOTES.txt}`, `examples/values.yaml` |
| Artifact checks | `scripts/container-smoke.sh`, `scripts/verify-artifacts`, `scripts/artifacts/{__init__.py,chart_checks.py,release_receipt.py,registry.py,package_chart.py,scan.py}`, `tests/artifacts/` |
| Kubernetes fixture | `tests/artifacts/kubernetes/{kind.yaml,postgres.yaml,values.yaml}`, `scripts/helm-smoke.sh` |
| Test/tool pins | `tests/artifacts/requirements.txt`, `tests/artifacts/tool-versions.json` |
| CI | new `.github/workflows/artifact-quality.yml`, rewritten `.github/workflows/package.yml`, `.github/actions/sign-and-attest-image/action.yml` |
| Retired build path | `.github/workflows/package-base.yml`, `applications/pgdog/docker/Dockerfile.base-builder`, `Dockerfile.base-runtime` |
| Active demos | Main Compose and PgDog service definitions in `examples/{immich,pgbouncer_benchmark,grafana_prometheus}` |
| Model/docs | `.agent/project-model/{components,relationships,data-flows,environments}.toml`, `.agent/config.toml`, focused architecture/security/release/deployment docs |

New `scripts/artifacts/` modules separate parsing/validation, registry operations,
packaging and scanner integration. `scripts/verify-artifacts` is their thin CLI
entrypoint. Tests use `unittest`, fixture subprocesses and test-only PyYAML.
No native skill/adapter file changes are needed.

## Task 1: Self-contained image and source revision (AC1, AC2)

**Files:** Build/version and test/tool pins above; create
`tests/artifacts/test_build_metadata.py`, `test_container_contract.py` and
`scripts/container-smoke.sh`.

**Interfaces:** `resolve_revision(explicit: Option<&str>, git: Option<&str>,
fallback: &str) -> Result<String, &'static str>` in `build_metadata.rs` returns
the short seven-character commit or package-version fallback. Explicit input
must be a full 40-hex SHA. `container-smoke.sh IMAGE EXPECTED_VERSION` checks a
locally available image and returns nonzero on any missing runtime capability.

- [ ] Write tests for valid explicit source SHA, absent Git fallback, invalid
  revision rejection, no official base references, no Git/credential context,
  non-root execution, SIGINT metadata, plugin and PostgreSQL tool availability.
  Compile pure metadata tests with `rustc --test` via unittest; missing tools
  fail explicitly. Assert a supplied SHA `0123456789abcdef0123456789abcdef01234567`
  produces `0123456`, and absent inputs produce `0.1.60`.
- [ ] RED: `python3 -m unittest discover -s tests/artifacts -p 'test_build*.py' -v`;
  missing resolver fails. Run contract tests against the old Dockerfile; official
  base references violate the intended independence contract. Record raw output.
- [ ] Implement resolver and `build.rs` integration. Add optional
  `PGDOG_BUILD_REVISION` build ARG/env and `cargo:rerun-if-env-changed`; use Git
  only if its command succeeds with a valid SHA, otherwise fall back to package
  version. Preserve the existing C compilation. Exclude all `.git` from Docker
  context instead of copying local Git configuration into a builder.
- [ ] Build from pinned Ubuntu 24.04 stages, install pinned Rust matching the
  workspace, native clang/mold/CMake/OpenSSL dependencies and PostgreSQL 18
  runtime tools. Build pgdog/plugin with `--locked` and preserve FEATURES.
  Set numeric UID/GID 10001, working directory `/pgdog`, SIGINT and direct
  executable entrypoint. Add OS package cleanup, license/source labels and
  context exclusions for `.env*`, credentials/private state and build outputs.
- [ ] GREEN: run metadata/contract tests, then
  `docker build -f applications/pgdog/Dockerfile --build-arg PGDOG_BUILD_REVISION=<HEAD_SHA> -t fork-pgdog:local .`
  and `bash scripts/container-smoke.sh fork-pgdog:local <HEAD_SHORT_SHA>`.
  Verify actual `configcheck`, CA path, `pg_dump --version`, ELF plugin loading
  with synthetic config and execution with read-only root plus tmpfs.
- [ ] Build each architecture natively on its corresponding CI runner, exporting
  a Buildx OCI archive. Import its selected platform into the local Docker daemon
  with Skopeo for smoke and compare the loaded image ID to the archive's config
  digest. Transport the same verified archive to publishing; never rebuild it.
  Never silently skip an architecture. Record base, archive checksums and
  resulting image/config digests/platforms in evidence.
- [ ] Checkpoint only Task 1 files; commit only after explicit Git authorization.

## Task 2: Renderable chart and validation (AC3)

**Files:** Chart inventory; `scripts/artifacts/chart_checks.py`,
`tests/artifacts/test_chart.py`, `test_chart_checks.py` and CLI entrypoint.

**Interfaces:** `verify-artifacts chart --values PATH [--chart PATH]` runs Helm
lint/template/package plus parsed manifest checks, returning nonzero on invalid
operator input or contract drift. `validate_rendered_chart(documents: list[dict],
values: dict) -> None` checks Kubernetes contracts and shipped TOML with tomllib.

- [ ] Write subprocess-based chart tests for all three config-source modes,
  TLS on/off, custom ports, resources/scheduling and imagePullSecrets. Assert
  digest `sha256:` plus 64 hex characters overrides tag for both main/init
  containers; selectors stay stable across metadata additions.
- [ ] Add negative cases for zero/multiple config sources, missing users Secret,
  digest/port/replica type errors, conflicting fixed labels, unknown credential
  keys, and non-Linux node selectors. Test special TOML characters/newlines as
  literal data; never execute operator text through `tpl`.
- [ ] RED: `python3 -m unittest discover -s tests/artifacts -p 'test_chart*.py' -v`;
  missing chart/helper fails rather than skipping. Retain the intended failures.
- [ ] Implement chart templates and closed schema using exact defaults from
  the spec. Helpers validate fixed metadata keys and produce consistent names,
  labels, image refs and required-value diagnostics. Preserve full TOML string
  contents in ConfigMap; use an inline-config checksum only when owned.
- [ ] Render security context identically for main/init; mount only config,
  users, optional TLS and a 64Mi tmp emptyDir. Set Linux node selection,
  dedicated ServiceAccount without token/RBAC, configcheck initContainer,
  startup/liveness TCP and readiness HTTP. Bound all probe timing values.
- [ ] Tests parse every shipped TOML example and require port/health/shutdown
  alignment. Document that Helm itself cannot parse external TOML or inspect
  live Secret contents. Default values without operator inputs intentionally
  fail; lint/package always use a valid synthetic example.
- [ ] GREEN: run Task 2 tests and
  `scripts/verify-artifacts chart --values charts/fork-pgdog/examples/values.yaml`.
  Assert no plaintext passwords or rendered Secret object; NOTES contains only
  connection/configuration guidance. Test local Helm 4 and pinned Helm 3 in CI.
- [ ] Checkpoint only chart/checker/test files; commit remains authorization-gated.

## Task 3: Retire upstream distribution references (AC8)

**Files:** Main `applications/pgdog/docker-compose.yml`; PgDog services in
`applications/pgdog/examples/immich/docker-compose.yml`,
`examples/pgbouncer_benchmark/docker-compose.yml`,
`examples/grafana_prometheus/docker-compose.yml`; root README;
retired package-base workflow and two Dockerfile.base files;
`tests/artifacts/test_distribution_paths.py`.

**Interfaces:** Active demos build with repository-root context and
`applications/pgdog/Dockerfile`, using `fork-pgdog:local` without registry access.
Other applications' images, ports, volumes and synthetic demo data remain intact.

- [ ] Test parsed Compose models for each named demo: PgDog build context resolves
  to root, Dockerfile resolves correctly, no official PgDog image; preserve all
  unrelated services. Assert maintained README Helm commands reference the owned
  local/OCI chart and clarify first publication availability.
- [ ] RED: run distribution-path tests; current Compose/README fail on official
  PgDog artifacts. Do not search-and-replace attribution or Git dependency URLs.
- [ ] Change only active PgDog service build/image sections and installation
  documentation. Retire the obsolete base release workflow/Dockerfiles as reviewed
  versioned removals; do not delete ignored files or published registry artifacts.
- [ ] GREEN: `python3 -m unittest discover -s tests/artifacts -p 'test_distribution_paths.py' -v`
  and `docker compose -f <each_named_compose> config --quiet` for all four paths.
  Record preserved service names/mounts. No Compose `up` against existing instances.
- [ ] Checkpoint exact Task 3 scope, retaining upstream notices and historical docs.

## Task 4: Isolated Kubernetes integration and rollback (AC4, AC5)

**Files:** `scripts/helm-smoke.sh`, Kubernetes fixtures,
`tests/artifacts/test_smoke_isolation.py`.

**Interfaces:** `helm-smoke.sh --image IMAGE [--chart PACKAGE_OR_DIRECTORY]`
creates a unique Kind cluster, a private temporary kubeconfig, a dedicated
namespace and synthetic PostgreSQL 18/Secret fixtures. It never changes the
user's current context. Cleanup targets only its exact created cluster.

- [ ] Test command isolation with fake kind/kubectl/helm executables: every
  Kubernetes command has the private kubeconfig/context/namespace; occupied
  ports, startup failure and trap cleanup cannot touch unrelated clusters.
  Timeouts produce nonzero status and retain sanitized diagnostic metadata.
- [ ] RED: run isolation tests against the absent harness; they fail for missing
  behavior. Implement the minimum isolated harness, with loopback-only ports,
  explicit resource labels, bounded polling and tool/node digest pins.
- [ ] Install chart with the locally loaded image and actual synthetic users
  Secret. Run `SELECT 1` and a write/read round-trip via Service; wrong password
  must fail. Check actual UID, token absence, read-only config/TLS mounts and
  configcheck rejection of malformed TOML. Mount missing Secret must prevent
  startup, not be counted as readiness success.
- [ ] Stop only fixture backends, wait for HTTP readiness failure, and assert
  PgDog restart count does not increase across more than a liveness failure
  window. Restore the fixture and require SQL to recover. Do not infer this
  behavior from probe YAML alone.
- [ ] Start a bounded `pg_sleep` query through the Service, confirm it is active
  in fixture `pg_stat_activity`, gracefully delete its Pod, and require successful
  query completion plus SIGINT drain logs and no SIGTERM-immediate-exit log.
  Ensure replacement Pod becomes usable before the scenario ends.
- [ ] Change inline config and upgrade: verify checksum and actual Pod rollout;
  exercise `helm rollback` and SQL. Rotate an external config/users Secret,
  explicitly roll out, then verify SQL again. Demonstrate docs do not imply
  external objects are restored by Helm rollback.
- [ ] GREEN: isolation tests and `bash scripts/helm-smoke.sh --image fork-pgdog:local`.
  Save timestamps/query results/restart counts and sanitized logs under local
  `.agent/.runs/artifacts/`; never upload Secret contents or dump Pod environments.
- [ ] Checkpoint integration harness/fixtures only; list actual tested runtime
  versions and any stop-signal compatibility boundary.

## Task 5: Read-only CI and artifact security checks (AC2, AC6, AC8)

**Files:** `.github/workflows/artifact-quality.yml`, `.agent/config.toml`,
`scripts/artifacts/scan.py`, `tests/artifacts/test_workflows.py`,
`test_scan.py`, tool pins. No changes to unrelated upstream/binary workflows.

**Interfaces:** `verify-artifacts scan --scanner iac|container` invokes pinned
Trivy with argument arrays; `.agent/.runs/artifacts/scan-binding.json` binds generated scan input,
image digest/source SHA and current worktree hash. A missing/mismatched binding,
scanner or database update is a failure. Local test-only images are not releases.

- [ ] Add workflow tests that parse YAML structurally (including `on` correctly)
  and reject push/tag/pull_request_target triggers, publish/login/OIDC permissions
  in validation, floating action references, missing native platform jobs,
  missing required chart/smoke checks and unconditional artifact upload of
  `.agent/.runs` or credentials.
- [ ] Add scanner tests for stale input bindings, wrong image digest, update
  failure, wrong tool version and command injection characters. Test a mocked
  scanner exit independently of real findings; tool absence never skips a test.
- [ ] RED: run workflow/scanner tests; missing validation workflow/bindings fail.
- [ ] Implement PR/manual workflow using `ubuntu-24.04` and `ubuntu-24.04-arm`.
  Pin actions to verified SHAs; full checkout without persisted credentials;
  build and smoke each native image without registry login/push. Run chart/unit
  tests and isolated Kind integration. Use per-platform cache keys; cache failures
  may fall back to clean build, never skip smoke. Upload only explicit sanitized
  test/scan manifests and checksums, never private review state.
- [ ] Pin test-only PyYAML, Skopeo and tool releases/checksums, install in CI/temporary
  local environment only. Configure IaC/container scanner arrays and non-mutating
  version commands, extend required scanner list to include `iac` and `container`,
  retaining `dependency`, `license`, `sast` and standard profile. Render chart to
  a bounded local input directory; scan both Dockerfile/manifests and the bound
  built image. Fail on Critical/High findings; no unreviewed ignore policy.
- [ ] GREEN: workflow/scanner tests, real
  `./scripts/agent release run-scanner --scanner iac --timeout 600` and
  `./scripts/agent release run-scanner --scanner container --timeout 600` against
  prepared bound artifacts. Run the existing dependency/license/SAST commands
  and retain runtime-derived results. Coverage gaps remain explicit.
- [ ] Validate workflow syntax with a pinned actionlint release and record tool
  identities; do not install a GitHub runner plugin or dispatch CI without approval.
- [ ] Checkpoint validation/scanner changes; required-scanner additions are part
  of this reviewed plan, with no weakening of any existing governance control.

## Task 6: Manual publish preflight, receipt and artifact pairing (AC6, AC7)

**Files:** `.github/workflows/package.yml`,
`.github/actions/sign-and-attest-image/action.yml`,
`scripts/artifacts/{release_receipt,registry,package_chart}.py`,
`tests/artifacts/{test_release_receipt,test_registry,test_package_chart}.py`.

**Interfaces and trust:**

- `verify-artifacts receipt --output PATH` runs the existing release gate on a
  clean immutable candidate and exports bounded canonical JSON metadata only
  after a real pass. It does not import fabricated gate states.
- Receipt fields: `schema_version`, `repository`, `source_sha`, `base_sha`,
  `worktree_diff_sha256`, `created_at`, `gate` (exact passed GateResult),
  `evidence_sha256` (sorted hashes of the verified review/security/scanner,
  threat-model/docs/clean-smoke/release records), `artifact_checks` (actual image,
  chart/integration checks with digests/status). No prompt, private review text,
  Secret, host path or credential payload is exported.
- The owner reviews the receipt against local evidence and approves its exact
  canonical SHA256 before dispatch. The protected manual workflow consumes that
  approved receipt JSON and checksum as inputs, along with `source_sha`,
  `image_version`, `chart_version`. This is an owner-approved handoff of existing
  gate evidence, not an independently authenticated remote rerun. The receipt
  hash is its integrity binding; owner approval is the trust decision.
- After merge, the remote default branch can equal the release source, which
  the existing diff-review gate correctly rejects as a new assessment base.
  Consume the already approved pre-integration receipt without forging remote
  refs, rewriting review bases or relabeling it as a new post-merge gate run.
  If integration changes source SHA, regenerate and review all candidate evidence.
- `verify-artifacts publish-preflight` validates inputs/receipt before write
  permissions; `package-chart --source DIR --image-digest DIGEST --image-version
  VERSION --chart-version VERSION --output DIR` modifies a temporary chart copy,
  sets digest/version, lints/renders/packages it and returns its file checksum.

- [ ] Write tests for actual gate failure producing no receipt, non-clean HEAD,
  absent signed security approval and missing required scans. Assert receipt
  exports metadata only and binds exactly the release GateResult/evidence.
  Reject duplicate JSON keys, unexpected fields, oversized input (>32KiB),
  stale status/source hash, invalid SemVer/digest and wrong expected receipt hash.
- [ ] Test temporary Git graphs: main dispatch only, full SHA reachable from
  main, legitimate older approved SHA, unrelated SHA rejection, changed source
  requiring fresh evidence. Test that an approved pre-merge receipt is not
  misrepresented as a post-merge runtime assessment. No base-ref manipulation.
- [ ] Test registry response classification: only authenticated confirmed
  manifest absence permits new tags; 401/403/429/5xx/network failures block.
  Existing image or chart SemVer tags block even if the image digest matches.
  Test pre-check and final publish race using serialized repository workflow
  concurrency; external writers remain a documented registry-admin risk.
- [ ] Test packaged chart version, appVersion and image digest against a fake
  combined manifest, no source-file mutation, stable selectors and chart-last
  failure ordering. Test provenance with dispatch SHA different from source SHA.
- [ ] RED: execute receipt/registry/chart-package unit tests. Missing helpers and
  current manual packaging without receipt/source binding fail intentionally.
- [ ] Implement strict parsers and subcommands using subprocess argument arrays.
  All receipt/version/SHA inputs enter scripts via env/files, never injected into
  shell command text. Registry credentials are read only by the publish job;
  preflight uses read-only access and cannot execute the receipt contents.
- [ ] Rewrite manual package workflow: require `refs/heads/main`; preflight pins
  source ancestry and approved receipt hash. Build/test both platforms without
  write credentials; export verified OCI archives and metadata. Use an explicit
  protected `packages` environment on publishing jobs, with owner review of
  source/versions/receipt digest before package write/OIDC capabilities.
- [ ] Publishing copies the exact tested OCI archives with Skopeo's
  `--all --preserve-digests` (fail if preservation is impossible), then creates
  a combined manifest; signs/attests per-platform and combined digests. Pass the
  checked-out source SHA to the signing action instead of trusting `GITHUB_SHA`;
  validate the explicit SHA and record the dispatch workflow separately.
  Preserve actual Git dependency resolution in BuildKit provenance where supplied;
  do not describe hand-authored source metadata as complete dependency provenance.
- [ ] Publish SHA and exact version tags without `latest`, then verify the
  combined manifest/platforms and signatures. Only then package/push the chart
  with that digest and record both artifact digests/source SHA in the job summary.
  Signatures, inspect and chart push failures fail the job; no false success
  from a prior step. Never rebuild different bytes after the successful smoke.
- [ ] GREEN: helper/workflow tests and actionlint. Run fake-registry pipeline tests
  before any GHCR egress. The absence of a trusted signer currently prevents a
  passing release receipt and therefore real publication; do not auto-enroll a
  key or generate a sample receipt marked passed for production use.
- [ ] Checkpoint publish/helper/provenance changes; all Git/external actions
  still await their explicit authorization.

## Task 7: Documentation, model, risks and release records (AC8)

**Files:** Model inventory; `docs/architecture/{containers,deployment,contracts,data-flows}.md`,
`docs/security/{threat-model,security-controls,residual-risks}.md`,
`docs/operations/containers-and-helm.md`, `docs/VERIFICATION.md`,
`docs/releases/fork-artifacts.md`, `docs/operations/fork-artifact-rollback.md`;
generated architecture outputs; focused documentation tests.

- [ ] Add contract tests for required source/image/chart mapping and operator
  commands using synthetic config/Secrets. Parse all shipped TOML/YAML examples;
  forbid invented published versions/digests or claims that external config
  rolls back automatically. Existing docs fail until the new flow is documented.
- [ ] Update model components/relationships/flows/environments for container
  builder, GHCR image/chart artifacts, Helm release, Kubernetes Pod and operator
  Secret mounts. Label implemented sources versus unverified external deployment.
- [ ] Document local build/install, private/public pulls, TLS paths, probes,
  bounded drain, external-object rollout, resources, arm64 CPU requirements,
  stateless WAL limit, first publication, receipt approval and partial-release
  recovery. Include operator responsibility for TLS/network/Secret policy.
- [ ] Add threat-model delta with control/test owners from the spec, including
  owner-approved receipt integrity, registry-admin races and no trusted signer.
  Add release notes, migration/rollback and residual-risk documents for existing
  `agent release record` interfaces. No enrollment or governance ref changes.
- [ ] GREEN: docs tests, `./scripts/agent docs build`,
  `./scripts/agent docs check`, `./scripts/agent adapters check`,
  `./scripts/agent skills check`, `git diff --check`.
  Inspect generated changes; never hand-edit generated HTML/native adapters.
- [ ] Checkpoint exact docs/model scope; generated metadata may need rebuilding
  and fresh evidence after an authorized commit.

## Task 8: Whole-change verification and review

Dependencies: Tasks 1–7. Completion of local implementation does not imply
mergeability, release clearance or registry publication.

- [ ] Run all artifact unit/contract tests, image smoke, all four Compose config
  checks, chart lint/template/package and isolated Kubernetes integration against
  the final source. Record actual platforms/versions and test counts.
- [ ] Run current `./scripts/agent verify quick --timeout 3600 --json` and
  `./scripts/agent verify review --timeout 3600 --json` with verified process-local
  SDK/fixtures. Run all required scanners; retain nonzero/timeout status explicitly.
- [ ] After authorized commits, prepare a clean candidate and fetch the remote
  default branch. Ensure a proper ancestor and current docs/evidence. Preview an
  independent-provider review package with requirements set to the approved spec;
  obtain exact manifest-hash approval before provider egress. Do not substitute
  an author-provider subagent for independent cross-provider review.
- [ ] Adjudicate each finding with evidence; confirmed Critical/High blocks.
  Apply authorized fixes test-first and refresh affected evidence/review packages.
- [ ] Prepare full signed security clearance and threat-model-delta evidence.
  No signer enrollment is performed in this feature; enrollment is a separately
  authorized governance change already required by repository policy.
- [ ] Record the three reviewed release documents with
  `./scripts/agent release record --artifact <release-notes|migration-rollback|residual-risks> --file <task7_document>`;
  run `bash scripts/release-smoke.sh`, then current merge/release gates on the
  exact clean candidate. `scripts/verify-artifacts receipt` requires a fresh real
  release pass; no manual status-file substitution.
- [ ] Review receipt metadata and checksum locally with the owner. If no signed
  clearance exists, hand off locally verified code and the concrete release
  blocker; publish jobs must remain blocked.
- [ ] Integrate/push only when authorized and gates pass. Preserve approved source
  SHA by fast-forward; otherwise re-review the resulting candidate and gate it
  before integration. Do not claim a gate passes against an unrelated revision.

## Task 9: Authorized first publication and pull-back verification (AC7)

Dependencies: Task 8, owner approval of receipt checksum, Git integration,
GHCR credentials/permissions, protected environment setup and publication.

- [ ] Obtain explicit authorization for any required environment/GHCR visibility
  setup and manual dispatch. Default private visibility is supported; no public
  settings are changed implicitly. Never ask to approve an unbuilt artifact.
- [ ] Dispatch once with full source SHA, versions and the reviewed receipt/hash.
  Preserve workflow run ID and inspect each stage; don't call a queued job done.
- [ ] Pull chart and image from GHCR by their reported digests. Verify image
  platforms/source labels/signatures and packaged chart versions/image digest;
  install the pulled chart/image in a new isolated cluster and repeat SQL/drain
  smoke. Record actual retrieval/install evidence; restore no production objects.
- [ ] On partial failure, identify exact published state. Do not overwrite a
  version or use a mutable tag as rollback. Clean orphaned registry digests only
  under a separate explicit deletion authorization; otherwise record them.
- [ ] Final handoff lists artifact references/digests, tested platforms/versions,
  install instructions, gate status, unverified scope and risk owners. Avoid
  absolute security or all-Kubernetes compatibility claims.

## Commit boundaries and rollback

Tasks define reviewable checkpoints, not permission to create commits. Once
authorized, stage explicit task files, inspect staged diff, and commit only the
verified scope. Do not stage `.agent/.runs`, local Secrets, generated receipt
state or unrelated edits. Existing dirty approved docs are intentional.

Development rollback is a reviewed revert of task commits, preserving operator
Secrets/databases and previous registry artifacts. Cluster rollback uses Helm
revision plus recorded image digest; externally owned config/Secret restoration
is separate. No automatic database/schema migration occurs in this chart.

## Final acceptance matrix

| Criterion | Owning tasks | Evidence |
| --- | --- | --- |
| AC1 | 1 | Clean build and actual non-root runtime/tool/plugin smoke |
| AC2 | 1, 5, 6 | Both native platform tests, OCI archives, combined manifest |
| AC3 | 2 | Positive/negative Helm tests and packaged manifest inspection |
| AC4 | 4 | Isolated SQL/auth/outage/config/upgrade results |
| AC5 | 4 | Active query completion, SIGINT logs, bounded termination/rollback |
| AC6 | 5, 6 | Parsed workflow contracts, receipt/parser/registry failure tests |
| AC7 | 6, 9 | Authorized run, digest/signature pull-back and fresh chart install |
| AC8 | 3, 5, 7, 8 | Active path checks, docs/model drift and exact-candidate gates |

Plan review authorizes only the selected execution method and local implementation;
external publication and Git actions retain the specified approval boundaries.

## Planning evidence

- `.agent/runtime/agent_cli/{governance,verify,security,cli}.py`: release gates,
  source/base binding, signed clearance and existing recording commands.
- `.agent/security/allowed_signers`: no enrolled keys at planning time.
- `docs/VERIFICATION.md`: documented process-local macOS SDK fix and test fixtures.
- [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners):
  native `ubuntu-24.04` and `ubuntu-24.04-arm` runners; availability/charges depend
  on repository settings, checked again before authorized dispatch.
- [Docker multi-platform CI](https://docs.docker.com/build/ci/github-actions/multi-platform/):
  native matrix builds and combined manifest publication.
- [Skopeo copy](https://github.com/podman-container-tools/skopeo/blob/main/docs/skopeo-copy.1.md):
  archive/registry transport and explicit digest preservation; smoke verifies
  loaded runtime identity separately from publication manifest identity.

## Local execution record (2026-10-02)

Implemented the image, chart, active Compose source paths, artifact validation and
manual publication workflow, scanner integration and operator/release docs. Local
verification uses an Apple Silicon host: Rust 1.96.1, Helm 4.1.3, Kind 0.33.0,
Kubernetes 1.36.4, Trivy 0.74.0 and Skopeo 1.24.1. This records local scope only;
the Linux native amd64/arm64 workflow has not been dispatched.

The full release Docker build succeeded after temporarily increasing Docker RAM
from 4 GiB to 12 GiB. The ARM64 image passed non-root/read-only/config-check/plugin
and SIGINT checks. An isolated Kind run passed SQL/password failure, verify-full
client TLS, real mount/root write rejection, backend outage without liveness
restarts, in-flight query drain, inline rollout/rollback, external Secret rollout,
malformed config and missing Secret checks. The SQL drain client runs in the
PostgreSQL fixture Pod so server Pod deletion cannot kill the client itself.

Final same-provider review confirmed and fixed the publication digest comparison
and missing chart OCI digest record. Regression checks verify exact native root
and runnable child digests, immutable digest inputs during manifest creation and
separate chart package/OCI digest recording. Receipt trust is unchanged from the
approved contract: the owner compares exported metadata against local evidence
and approves its hash; it is not independently authenticated remote clearance.
This local review does not satisfy the required cross-provider review gate.

Release blockers remain: clean committed candidate, independent provider review
with exact review-package approval, enrolled trusted signer and signed clearance,
full repository fixtures/gates, both native CI builds and protected GHCR setup.
The local host already has PostgreSQL on port 5432 from another workspace; it is
not used or modified for destructive upstream fixture setup. No Git commit,
push, merge, registry write or production access has occurred.
