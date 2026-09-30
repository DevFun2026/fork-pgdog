# PgDog quality gate configuration

## Scope and authorization

The user requested configuration and execution of lint, tests, build, and independent
review for the PgDog import PR. Keep the existing standard security profile,
mandatory independent provider, trusted default-branch base, and exact manifest
approval before provider egress. Do not merge or waive a failed gate.

## Implementation sequence

1. Discover upstream Rust/toolchain/CI commands and establish environment baseline.
2. Configure `.agent/config.toml` for locked Cargo format, clippy, focused unit
   tests, full Rust/workflow tests, workspace build, and executable smoke check.
3. Add a positive CLI `verify --timeout` option, preserving the 60 second default.
   Regression tests must first fail without the option, then verify default,
   rejection of nonpositive values, and propagation to the gate runner.
4. Run tests against isolated PostgreSQL 18 fixtures and Toxiproxy. Full merge
   tests include the template runtime, workspace unit/doc tests, and Rust client
   integration tests. The separate upstream CI matrix exercises other clients,
   TLS, COPY, resharding, and fault scenarios; report its status separately.
5. Configure cargo-deny advisory/license scans and Semgrep Rust SAST. Findings
   and unavailable tools block clearance; no ignored advisories or fake results.
6. Adapt validation CI to GitHub-hosted runners; external upstream publishing and
   benchmark services require separate credentials and remain upstream-only.
7. Update the project model and generated docs; run quick, review and merge gates.
8. Prepare independent review using the complete trusted-base diff. Do not truncate
   an oversized import or approve its manifest on behalf of the user. Report
   package limits, provider availability and any approval still required.

## Acceptance and rollback

Retain exit codes/logs and identify passed, failed and blocked checks separately.
A local build is not an EKS/Vault deployment verification. Roll back the gate
configuration commit if necessary; leave upstream history intact. The existing
release gate additionally needs independently signed security clearance from a
signer trusted in the base revision; this task does not enroll a signer.
