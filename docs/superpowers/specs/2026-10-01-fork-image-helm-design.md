# Fork-owned container image and Helm chart

Date: 2026-10-01

Status: approved and implemented locally. The owner approved the GHCR image
and OCI chart direction, written specification, plan and native execution in chat
with `duyệt`. Local artifact verification is recorded in the implementation plan;
native multi-platform CI and formal release evidence remain pending. Publication
and Git actions retain their separate authorization gates.

## Outcome and scope

Build and distribute PgDog from this repository without consuming PgDog's
official container images or Helm chart. Keep all build, chart, validation and
release sources in `DevFun2026/fork-pgdog`.

The owner maintains releases; CI builds and validates artifacts; a Kubernetes
operator supplies backend configuration and Secrets; PostgreSQL clients connect
through the installed Service. The chart connects to existing PostgreSQL
backends and does not install or manage them.

Included: Docker build, amd64/arm64 packaging, repository-owned chart, manual
publishing workflows, active Compose examples, deployment documentation,
project-model updates, threat-model delta and meaningful verification.

Excluded: a new Rust dependency fork, offline builds, changes to proxy protocol
or routing behavior, managed PostgreSQL, EKS/Terraform provisioning, an LLM
agent, public ingress, automated production deployment, and automatic push/tag
publication. Imported upstream documents remain historical source material.
Git dependencies such as `pg_raw_parse` and `scram` remain upstream dependencies;
independence here applies to container and chart build/distribution.

## Approved architecture decision

Use GHCR for both artifact types:

- Container: `ghcr.io/devfun2026/fork-pgdog`.
- Chart source: `charts/fork-pgdog`.
- OCI chart: `oci://ghcr.io/devfun2026/charts/fork-pgdog`.

Use a self-contained multi-stage Dockerfile rather than requiring separately
published builder/runtime images. This removes the prerequisite package-base
run and its mutable `latest` dependencies. Build caching remains an optimization,
not a prerequisite for a clean build.

Alternatives considered: keep fork-owned builder/runtime packages (additional
releases and synchronization); serve charts on GitHub Pages (additional index
and publication state). GHCR OCI avoids an extra chart-serving website. The
architecture Pages workflow continues to serve architecture documentation.

## Container contract

1. `docker build -f applications/pgdog/Dockerfile -t fork-pgdog:local .`
   works from the repository root without any pre-existing fork or official
   PgDog base image. No runtime layer contains source, Git metadata or build
   credentials.
2. Builder/runtime bases use explicit versions and multi-platform digests
   selected and recorded during implementation. Use the workspace's Rust
   toolchain (`1.96` currently), Cargo.lock and `cargo build --locked`.
   OS package installation remains network-dependent; do not claim byte-for-byte
   reproducibility or complete independence from public registries.
3. Build dependencies include the existing clang/mold and native-library
   requirements. Preserve the `FEATURES` build argument and the existing
   `libpgdog_primary_only_tables.so` plugin. Include CA certificates and
   PostgreSQL 18 client tools, including `pg_dump`, in the runtime.
4. PgDog is PID 1, runs as a numeric non-root user, and retains working directory
   `/pgdog`, `RUST_LOG=info`, executable `/usr/local/bin/pgdog`, and
   `STOPSIGNAL SIGINT`. Keep CLI argument forwarding compatible with direct
   invocation. Mount configuration rather than bake credentials into images.
5. Docker context excludes private agent state, credential files, build
   outputs and unrelated documentation. Preserve only build-relevant Git
   metadata if needed for the existing version build script; never COPY it
   into the runtime stage. Record OCI source/revision/version labels.
6. Publish native `linux/amd64` and `linux/arm64` artifacts with a combined
   manifest, using GitHub-hosted runners rather than Blacksmith. Existing
   aarch64 `+lse` target requirements are retained and documented; no unsupported
   CPU compatibility guarantee is added.

## Chart interface and defaults

The first chart is an application chart without upstream chart dependencies.
Target Helm 3.8+ OCI support and Kubernetes 1.28+ stable APIs; CI must record
the exact Helm and Kubernetes versions it actually tests. These minimums are
an API target, not a claim of testing every version.

| Input | Contract |
| --- | --- |
| `image.repository` | Defaults to `ghcr.io/devfun2026/fork-pgdog` |
| `image.tag` | Explicit version or SHA; defaults to `Chart.appVersion` |
| `image.digest` | Optional validated `sha256:` digest; takes precedence over tag |
| `image.pullPolicy`, `imagePullSecrets` | Explicit pull policy and references to existing pull Secrets |
| `replicaCount` | Positive integer, default 1 |
| `service.type`, `service.port` | Default ClusterIP and 6432; explicit NodePort/LoadBalancer opt-in |
| `containerPort` | Default 6432; must match `general.port` in supplied TOML |
| `healthcheckPort` | Default 9090; must match `general.healthcheck_port` |
| `config.pgdogToml` | Complete non-secret TOML string, mounted via a chart-owned ConfigMap |
| `config.existingConfigMap` | Alternative existing ConfigMap containing `pgdog.toml` |
| `config.existingSecret` | Alternative existing Secret containing `pgdog.toml` for sensitive config |
| `users.existingSecret` | Required existing Secret containing `users.toml`; no inline password option |
| `tls.existingSecret` | Optional Secret mounted read-only at `/etc/pgdog/tls`; TOML refers to its file paths |
| `resources` | Default requests 100m/128Mi and limits 1 CPU/512Mi; operator tuning required |
| `nodeSelector`, `tolerations`, `affinity` | Standard scheduling overrides; non-Linux scheduling unsupported |
| `podAnnotations`, `podLabels` | Metadata additions; cannot change fixed selector identity |
| `terminationGracePeriodSeconds` | Default 150 seconds, positive integer |

Exactly one configuration source must be selected. Empty or conflicting sources,
missing users Secret name, invalid image digest, invalid ports or replica count
fail schema/template validation with an actionable error. A render can validate
Secret names, not the existence or contents of live Secrets. Missing live
objects cause Kubernetes mount failures and prevent startup.

Ship `values.schema.json`, a documented example values file with a synthetic
backend hostname, and NOTES that show Service connection instructions without
printing credentials. Default values have no real backend and no invented
Secret name; rendering/installing without required operator input must fail.

Render Deployment, Service, optional owned ConfigMap, and a dedicated
ServiceAccount with token automount disabled. Do not grant Kubernetes RBAC or
expose the admin database, metrics or health endpoint through a public Service
by default. Linux scheduling, non-root security context, dropped capabilities,
`allowPrivilegeEscalation: false`, RuntimeDefault seccomp and read-only root
filesystem are defaults. Provide a bounded writable `/tmp` emptyDir for tools.

Configuration and users files are separate read-only mounts, passed through
`--config` and `--users`. Run the same image's `configcheck` in an initContainer;
invalid TOML must fail before the main process serves connections. The operator
must match TOML listener/health ports to chart settings; Helm does not parse raw
TOML. Tests must verify this alignment in all shipped example configurations.

Inline ConfigMap changes alter a Pod-template checksum and trigger rolling
replacement. External ConfigMap/Secret rotation requires an explicit operator
rollout; do not promise automatic detection, atomic updates or hot reload.
Readiness rollout failures retain observable Kubernetes conditions and logs;
documentation uses bounded `helm upgrade --install --wait --timeout` commands.

## Probes, shutdown and storage

Startup and liveness use TCP on the proxy listener. Readiness uses HTTP `/` on
the configured health port. PgDog's current health handler returns 502 when all
configured pools are unhealthy, but also returns 200 when no pools exist. It
does not prove query execution or database completeness. Verification therefore
includes authenticated SQL through the Service, not just Pod readiness.

Keep `STOPSIGNAL SIGINT` and test that the Kubernetes runtime honors it and an
active query finishes during termination. SIGTERM currently exits immediately;
do not assume a generic preStop signal followed immediately by runtime SIGTERM
provides a drain. Avoid requiring Kubernetes alpha stop-signal fields. Operators
must configure PgDog shutdown timeouts so the total bounded drain fits inside
the Pod grace period; examples use 120s drain plus a 10s termination bound and
150s Pod grace. Runtimes ignoring the image stop signal are outside verified
drain compatibility and must be reported explicitly.

This Deployment chart initially supports stateless pooling/routing. It does not
provision durable per-replica 2PC WAL or claim crash recovery with ephemeral
volumes. Stateful WAL deployments require a separately designed storage/lifecycle
contract. The image retains existing application functionality.

## Versioning and publication states

Start chart version at `0.1.0`; record current application version `0.1.60` as
`appVersion`. Chart SemVer and application version evolve separately. Never
silently point the chart to official images or assume a version is already
published merely because it appears in Chart.yaml.

PR/manual validation has read-only permissions, builds locally and never logs
into a publishing registry. Existing repository policy keeps automatic push/tag
triggers disabled. Manual publication from main accepts a full source commit
SHA reachable from main, an application SemVer and a chart SemVer. Validate all
inputs before using them, checkout that exact SHA, and record it in artifact
metadata. Avoid checking out arbitrary refs with a write-capable job.

Publication states:

1. Validate source, versions, chart configuration, required gates and tests.
2. Build/test both architectures; failed legs block final manifest and chart.
3. Publish image digests and the combined manifest; sign/attest the exact image
   digest using the existing keyless image action with accurate source identity.
4. Package the chart with the requested chart version and application version;
   set its default image digest to the just-published combined manifest digest.
5. Publish the OCI chart only after the matching image is verified; record chart
   digest, image digest and source SHA in the release summary. Preserve package
   source/repository metadata so GHCR permissions associate with this fork.

Publish image SHA and exact SemVer tags; do not require mutable `latest`.
Reject attempts to overwrite existing release version tags. A partial failure
may leave unreferenced image digests; it never authorizes replacing a published
chart. Recovery reuses only digest-verified successful artifacts or uses new
release versions; retries never label missing attestation as successful.

The first publication needs GHCR package permissions and chosen visibility.
Private packages use documented registry login/imagePullSecrets; public
visibility changes require owner authorization. Authoring workflows does not
authorize dispatch, credential use, commit, push, merge or production rollout.
Do not silently remove independent review or release gates to make CI publish.
The implementation plan must resolve how manual publication consumes valid
gate evidence for the exact source SHA using existing runtime contracts.

## Threat-model delta and owners

The approved security profile remains `standard`.

| Change/threat | Required control and verification | Owner |
| --- | --- | --- |
| Source to image/chart to GHCR to cluster; tampered releases | Version/digest binding, pinned action revisions, restricted manual publish, provenance/signatures and registry pull-back checks | Repository owner and CI maintainer |
| CI publishing credentials and OIDC identity | Least privilege per job, no credentials in PR builds, checked-out source identity bound in attestations, no token logging | CI maintainer |
| Backend credentials/TLS files to Pod | Existing Secrets, read-only mounts, no plaintext values, no Secret contents in NOTES/evidence | Cluster operator |
| Proxy reachable through Service | ClusterIP default, explicit external exposure choice; operator controls client/backend TLS and network policy | Cluster operator |
| Container privileges and writable paths | Non-root, no capabilities/token, read-only root and bounded tmp; runtime smoke | Image/chart maintainer |
| Database outage and Pod termination | Distinct readiness/liveness, bounded drain and active-query termination test | Chart maintainer |
| OS/Rust/PostgreSQL/Actions supply chain | Recorded pins and scans, controlled upgrades, retain license notices; missing coverage remains unverified | Repository owner |

Residual risks: a compromised maintainer/registry can replace mutable tags;
Kubernetes Secrets require cluster access control and encryption policy;
external TLS/network controls are operator-owned; raw TOML may contain secrets
if the operator chooses ConfigMap incorrectly; package downloads remain
external; aarch64 CPU compatibility is limited by the current build flags.
Do not claim scanner coverage for containers or rendered Kubernetes resources
until the implementation has configured and actually run suitable checks.

## Migration, rollback and documentation

Replace upstream image references in the active main Compose demo and existing
PgDog Compose examples; local demos build the fork directly so first use does
not depend on GHCR publication. Update root README installation/build commands
to use the owned chart/image. No broad replacement of upstream attribution,
dependency URLs, license notices or imported historical documentation.

Retire or repurpose the obsolete package-base workflow/files so maintained
build instructions have one supported path. Keep unrelated binary release and
benchmark workflows outside this change unless a concrete incompatibility is
demonstrated.

Synchronize `.agent/project-model/` with registry/build/chart components,
artifact and Secret flows, and hosted/local Kubernetes environments. Update
`docs/architecture/containers.md`, focused deployment docs, verification docs
and `docs/security/threat-model.md`; rebuild generated architecture using
`./scripts/agent docs build` and verify with `./scripts/agent docs check`.

Existing official installations are not modified automatically. Migration is
an explicit operator installation using their backend/TLS configuration and
existing Secrets. Rollback uses the prior chart revision and recorded image
digest; external ConfigMaps and Secrets remain operator-owned and may need
separate restoration. Do not imply Helm rollback undoes external configuration
or database changes.

## Observable acceptance criteria

- AC1: A clean root-context image build succeeds without official PgDog image
  pulls; the runtime runs non-root, reports version, loads config/plugin and
  includes working `pg_dump` and trusted CA certificates.
- AC2: Both architecture images are built and smoke-tested; the combined
  manifest has the correct platforms and traceable immutable source SHA.
- AC3: Chart lint/template/package pass with valid examples; invalid required
  values fail as specified. Tests check mounts, selectors, digest precedence,
  security context, checksum rollout and absence of plaintext credentials.
- AC4: In an isolated disposable local cluster, install and upgrade succeed,
  an authenticated SQL query traverses Service to a synthetic PostgreSQL
  backend, wrong credentials fail, and backend outage does not induce liveness
  restart loops. No live production kube context is used.
- AC5: Terminating a Pod during an active query exercises SIGINT drain and
  completes within the configured grace period. Chart rollback is exercised.
- AC6: Validation workflows have no write/publish credentials; publication is
  manual only and cannot publish unvalidated refs, overwrite release versions,
  or publish a chart before its matching image succeeds.
- AC7: After authorized first publication, pull image/chart from GHCR, inspect
  their digests/platforms/source identity and install the pulled chart in the
  isolated cluster. Until then external distribution remains unverified.
- AC8: Active installation/Compose/build paths no longer consume official PgDog
  artifacts; synchronized model/docs pass checks and required quick/merge/release
  evidence is current. Missing tooling/review/permissions is reported separately
  from product defects and never counted as a passing gate.

Implement behavior tests first (intended RED, minimum implementation, GREEN).
The implementation plan must specify exact files, commands, fixtures, review
boundaries and evidence capture for these criteria. This spec is not a report
that the chart/image has been implemented or published.

## Evidence and external contracts

- `applications/pgdog/Dockerfile`: official builder/runtime defaults and SIGINT.
- `.github/workflows/package.yml` and `package-base.yml`: manual GHCR packaging,
  separate base releases and Blacksmith runners.
- `.github/actions/sign-and-attest-image/action.yml`: current keyless signature
  and workflow provenance; source checkout SHA/ref must remain accurate.
- `applications/pgdog/rust-toolchain.toml`, `.cargo/config.toml`, `Cargo.lock`,
  `pgdog/build.rs`: build toolchain, native linker and Git version requirements.
- `applications/pgdog/pgdog/src/main.rs`, `frontend/listener.rs`,
  `healthcheck.rs`, `cli.rs`: signals, probes, WAL and configcheck behavior.
- `.agent/config.toml`: standard security profile, independent review and
  required dependency/license/SAST scanners; container/IaC scanners unset.
- [Helm 3 OCI registries](https://helm.sh/docs/v3/topics/registries/): OCI
  version/name and push/install contracts.
- [Kubernetes Pod termination](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-termination):
  grace periods and runtime-dependent image stop-signal behavior.
