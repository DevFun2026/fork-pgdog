# PG12 publication evidence retention

This implements the release handoff already authorized by the approved PG12
specification and existing source-bound GitHub-owner release specification.
The user requested image and Helm chart 0.2.1 only after all required gates pass.
Source PR #12 merged at `3ae8a35536640eddf153c7724edc34d9ff568df8`; its reviewed
head is `2145a82bff7be333908061823d47d71c70fa5645`. The schema-3 workflow PR must
start at that exact source merge.

## Contract

The native build already requires strict-read Helm smoke for both PG18 and PG12.
Publication workflow must retain both fixed report files separately per
architecture. Keep the `fork-native` archive/metadata artifact unchanged, because
those two files are the closed publisher input inventory. Separate report
artifacts provide recoverable bounded build evidence without expanding that
trusted byte-copy input. Reports contain fixed synthetic fixture metadata.

Preserve the pinned upload action, bounded retention, source checkout, native
build command, permissions, required scans, protected packages environment,
receipt validation, immutable tag handling, signatures and pull-back checks.
A missing/failing smoke still fails the native build. Uploading a report grants
no publication authorization. Do not alter registry/function acceptance or
reader/writer behavior in this workflow PR.

## Verification and risk

Run existing artifact/workflow and closed-inventory contracts, generated-doc
checks, canonical quick/review/merge gates and both native CI architectures.
Independently review the exact workflow diff and retain all eight Standard
security lenses. Confirm the separate report artifact is not downloaded as
a native OCI publication input. No production database, Kubernetes context or
new credential is needed.

Native byte generation remains fresh at authorized publication. Review/CI
witnesses retain the original reviewed heads. Generate a fresh schema-3 receipt
after both exact PR merges; obtain approval of its concrete payload before
posting the owner comment. SSH waiver and canonical release gate status remain
reported as specified by the existing owner-release contract.

Rollback consists of reverting report retention only; it must not make a
failed PG12/PG18 build publishable. Without complete release evidence, keep the
new version unpublished and reader traffic denied/stopped.
