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

## Authorized remediation follow-up

The user explicitly selected fixing discovered gate failures. Upgrade vulnerable
locked dependencies, use the pinned upstream jemalloc-ctl macro fix to remove
unmaintained paste, and preserve the released allocator sys crate. Add missing
workspace license metadata under the existing root license; retain explicit MIT
packages. Normalize only whitespace reported by the tracked-text check.

Reproduce then repair initialized-buffer handling on interrupted stream reads,
release-mode SIMD size/layout invariants, C hash length ABI/conversion, and the
two malformed backend message parsers identified during investigation. Replace
test environment mutation with child-process startup configuration. Record scoped
SAST dispositions only for reviewed compatibility/trusted-native-code boundaries.
Run focused regression tests, a fresh read-only candidate review, full gates and
hosted CI. Increase the JS suite's overall timeout from 60 to 300 seconds after
observing ongoing passing tests at the old deadline; retain per-test timeouts.
