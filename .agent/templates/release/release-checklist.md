# Release checklist

- Merge gate evidence matches the release revision and diff.
- Independent and cross-provider findings are adjudicated.
- Security review records scope, checks, unverified areas, and residual risks.
- Required threat-model delta is present.
- Required dependency, license, SAST, IaC, and container scanners passed.
- Optional unsupported scanners are explicitly recorded as not configured.
- Build and smoke tests passed from a clean checkout or release archive.
- Architecture and generated documentation have no drift.
- Release notes describe user-visible and operational changes.
- Migration, backup, compatibility, and rollback steps are verified.
- Residual risks have owners and explicit dispositions.
