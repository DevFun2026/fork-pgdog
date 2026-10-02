# Fork artifact release

The image/chart sources are implemented. GHCR artifacts are not published by
local implementation or plan approval. Initial chart source is 0.1.0 with
appVersion 0.1.60. Exact production versions/digests are recorded only after a
successful authorized workflow and pull-back verification.

The owner subsequently approved **image 0.1.0 and chart 0.1.0** for the first
release in [PR #7 comment](https://github.com/DevFun2026/fork-pgdog/pull/7#issuecomment-5948092075).
Publication passes image version 0.1.0 to the source Dockerfile and packages
chart appVersion 0.1.0; this distribution version does not rewrite the upstream
Cargo package version. Artifact source remains the reviewed, merged
`09026eec63e0cb2da60389ef623e56ff1e4ba74b`.

Validation is pull-request/manual and read-only. The manual package workflow
accepts a full source SHA, exact new image/chart SemVer and an owner-approved
canonical receipt JSON/SHA256. Inputs enter scripts via environment/files and
argument arrays. Main-only dispatch, ancestry validation and a `packages`
environment with required reviewers guard write/OIDC capabilities. Configure
that protected environment separately; the workflow fails if reviewer protection
cannot be verified. Runner availability and repository billing remain owner settings.

Prepare a clean committed candidate before integration. Run current repository
review/release gates, required dependency/license/SAST/IaC/container scans,
independent provider review with exact manifest approval, signed security
clearance, threat-model delta, docs and clean-checkout smoke. The trusted signer
file currently has no enrolled signer. Enrollment is a separately approved
governance change; this feature does not add a key or manufacture clearance.

```sh
./scripts/agent release record --artifact release-notes --file docs/releases/fork-artifacts.md
./scripts/agent release record --artifact migration-rollback --file docs/operations/fork-artifact-rollback.md
./scripts/agent release record --artifact residual-risks --file docs/security/residual-risks.md
python3 scripts/verify-artifacts receipt --output .agent/.runs/artifacts/release-receipt.json
```

Receipt creation executes the existing release gate and exports metadata only
after a real pass. It binds exact source/base, clean diff, exact GateResult,
review/security/scanner/docs/release evidence hashes and native artifact checks.
It contains no prompt, private review text, Secret or host path. Review it against
local evidence and approve its exact canonical SHA256 before dispatch. The hash
protects integrity; the owner's approval supplies trust. It is not a remote
independent assessment or a detached signer replacement. After integration the
default branch may equal source, so retain the genuine pre-integration receipt
without forging an intermediate trusted base. Preserve the candidate SHA through
fast-forward; changed source needs new reviewed evidence.

## Explicit first-release owner exception

The approved schema-2 route is separate from the schema-1 signed release gate.
It does not enroll a signer, lower the Standard security profile, fabricate a
passed GateResult or call absent SSH clearance passed. Authorization explicitly
records `ssh_clearance: waived-by-owner` and `canonical_release_gate: not-claimed`.
The canonical security/runtime gates remain unchanged for other releases.

This route accepts only the exact PR #7 source, image 0.1.0 and chart 0.1.0.
Receipt metadata separately binds the publication workflow commit, both source
and workflow independent Gemini reviews, real source/workflow full-suite and
native CI run IDs/attempts, and security/threat/rollback/residual-risk hashes.
Every required job must be successful; skipped or failed jobs, wrong paths,
revisions or changed attempts block. Historical source review retains its real
pre-integration base; it does not pretend main still points to that base.

Create a receipt only after the workflow candidate is committed, reviewed and
its exact-source CI has passed:

```sh
python3 scripts/verify-artifacts owner-receipt \
  --source-review .agent/.runs/review-083a78d8-5c3a-4423-8925-e72850c8c974 \
  --workflow-review .agent/.runs/review-WORKFLOW-PACKAGE \
  --quality-run WORKFLOW_QUALITY_RUN_ID \
  --artifact-run WORKFLOW_NATIVE_RUN_ID \
  --output .agent/.runs/artifacts/first-release-receipt.json
```

Replace placeholders with actual completed evidence, compare the exported
metadata and approve its canonical checksum before main-only dispatch. Preflight
and the protected job before login re-read the exact owner comment, numeric
identity, current repository admin permission, packages owner reviewer,
main-only branch policy and all required CI jobs. Withdrawal or edit of the
comment blocks. The dispatch actor must be the approved owner and the dispatch
SHA must equal the reviewed workflow SHA in the receipt. Native jobs still build
and verify the exact selected artifact source and approved version.

In GitHub Actions, open **Publish fork image and OCI chart**, choose **Run
workflow**, branch main, and provide the source SHA, versions 0.1.0/0.1.0 and the
approved JSON/checksum. After preflight and both native builds, the owner reviews
the packages deployment and selects **Approve and deploy**. Registry tag absence,
byte-preserving copies, signing/attestation and chart pull-back are unchanged.
The pinned versions/source prevent this receipt from authorizing another
release. Partial publication remains a failure, and existing tags prevent replay.

Build jobs test amd64 and arm64 natively. BuildKit records max provenance;
the archive metadata binds actual image config/manifest, source label and checksum.
Skopeo imports the image and verifies config identity before runtime/Kind/scans.
Only fully tested archive bytes are transported to publish, with
`--all --preserve-digests`; no rebuild occurs after their tests. Actions, builder
image and downloaded validation tools are pinned. OS packages still resolve
against authenticated distribution repositories; package versions/tool identities
must be retained in release evidence. Pinning does not make a build hermetic.

The protected job rechecks authenticated tag absence, copies both archives,
verifies each copied root against its tested archive, creates the combined
manifest from immutable root digests, verifies both runnable child digests, and keylessly signs and
attests per-platform and combined digests. Source metadata explicitly identifies
the selected source SHA, even when dispatch SHA differs. The dispatch workflow
remains recorded separately. Hand-authored source metadata is not complete
dependency provenance; preserve BuildKit's actual Git resolution evidence where
available. Signature/attestation verification must pass before chart publication.

The chart is packaged from the selected source, pinned to the combined image
digest and exact versions, published last, and pulled back to verify identical
bytes. Record image/OCI chart manifest digests and package SHA256 in the release
record, then install the pulled chart/image in a new isolated smoke cluster.
No latest/moving compatibility tag is created. Existing SemVer/source/platform
tags block even if their digest matches. Only an authenticated MANIFEST_UNKNOWN
response permits new tags; authentication, repository-absence ambiguity, rate
limits and network/5xx failures block. First registry initialization may require
explicit owner administration if GHCR cannot confirm manifest absence.

Repository concurrency prevents two workflow publishes colliding, but cannot
prevent an external registry administrator changing tags between checks/writes.
Restrict external writers and enforce registry immutability through your process.
Partial image/signature/chart failures fail the job; they are recorded and
recovered under the [rollback runbook](../operations/fork-artifact-rollback.md).
