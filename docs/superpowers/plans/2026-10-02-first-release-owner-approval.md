# First release owner approval implementation

Goal: publish the owner-approved 0.1.0 image/chart through an explicit bounded GitHub exception, with honest receipts and all existing validation controls.

Approved inputs: [spec](../specs/2026-10-02-first-release-owner-approval.md), owner comment 5948092075 and session continuation. Scope excludes canonical security gate changes and arbitrary release exceptions.

1. Add regression tests in tests/artifacts/test_owner_approval.py. Demonstrate RED: the existing receipt parser rejects the approved schema-2 record. Cover scope widening, tampering, actor/comment/reviewer mismatch, failed/skipped/wrong-source CI and protected revalidation.
2. Implement scripts/artifacts/owner_approval.py. Add schema-2 dispatch in release_receipt.py without weakening schema 1. Add an explicit owner-receipt command in scripts/verify-artifacts. Validate historical review packages against their real Git diff and genuine audit/findings, then bind live CI and owner metadata. Export only metadata and hashes.
3. Update package.yml to provide read-only Actions API permission in preflight and revalidate after environment approval before writes. Preserve native build/test/scan/transport/sign/chart jobs. Add workflow regression assertions before the change.
4. Update focused release, security and architecture docs plus canonical project model. Rebuild generated architecture and check adapters/docs. Run focused artifact tests, actionlint and the runtime unit suite.
5. Commit/push the candidate. Run exact-source full and native artifact CI. Preview the complete workflow-review package, obtain its exact manifest approval, run native AGY Gemini 3.8 Flash and adjudicate findings. No stale source review is reused for workflow changes.
6. Export schema-2 receipt from actual reviews and CI. Present its canonical hash. Merge the reviewed workflow candidate and, after exact receipt approval, dispatch main-only publication. Honor packages owner approval, retain digests and verify pulled artifacts.

Rollback: revert this explicit exception route while preserving schema-1 validation and existing packages. Failures produce no receipt/publication success claims.
