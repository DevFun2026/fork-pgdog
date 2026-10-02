# Residual Risks

- AI-generated and AI-reviewed changes may contain defects not detected by the
  selected evidence or reviewer.
- Local plaintext memory and review artifacts rely on operating-system account
  isolation and disk protections.
- Provider CLI behavior and privacy terms are outside this repository; approval
  confirms package contents, not provider guarantees.
- Optional ecosystem scanners can be unavailable. They are reported as not
  configured and become blocking when project policy marks them required.
- The template cannot validate an adopting project's production identity,
  network, data-retention, backup, or disaster-recovery controls.

Owners must reassess these risks when exposure, credentials, sensitive data,
trust boundaries, dependencies, infrastructure, or recovery design changes.

## Fork artifact delta

- Owner: release maintainer. Native amd64 CI, authorized GHCR pull-back/signature
  verification and first registry publication need current external evidence.
  Local arm64/Kind tests do not certify all supported Kubernetes/Helm versions.
- Owner: governance maintainer. The trusted signer file has no enrolled signer;
  no signed clearance/release receipt can pass until separate approved enrollment
  and independent review. Receipt checksum provides integrity, not independent
  authenticity; the owner must compare exported metadata to actual local evidence.
- Owner: registry administrator. Workflow serialization cannot prevent external
  writers racing or mutating tags. Ambiguous first-package/auth failures block;
  initialization, writer restrictions and visibility are explicit owner setup.
- Owner: deployment operator. External config/users/TLS changes require rollout
  and separate rollback/version management. Chart history does not back up them.
  Production TLS, ingress/NetworkPolicy and Secret/RBAC controls remain external.
- Owner: workload operator. Arm64 CPUs must support LSE. Default resource limits
  need measured sizing. Force deletion bypasses drain. Stateless Pods provide no
  durable per-replica 2PC WAL; dedicated storage/recovery design is required.
- Owner: supply-chain maintainer. OS package repositories remain dynamic; image
  digest pinning is not a hermetic build or full dependency-provenance assertion.
  FIPS feature runtime and full upstream language/TLS/COPY/fault matrices are
  separate verification scopes. Scanners can miss issues beyond selected rules.
