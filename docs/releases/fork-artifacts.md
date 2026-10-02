# Fork artifact release

The image/chart sources are implemented. GHCR artifacts are not published by
local implementation or plan approval. Initial chart source is 0.1.0 with
appVersion 0.1.60. Exact production versions/digests are recorded only after a
successful authorized workflow and pull-back verification.

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
