# GitHub owner release authorization

Approved by the owner in this session on 2026-10-12, following the reviewed release-approval proposal. This adds an opt-in publication receipt, not a weakening of canonical review, merge, SSH-security or signed-release validators.

## Scope

Support source `cd8d2a913e1077ca6d2c45f4975b0b9046857aba`, whose tree equals independently reviewed PR #9 head `59d4a1d793d8cfa7501a679564c37350ec45a772`, and a separately reviewed publication workflow revision. The mechanism is source/version-bound per receipt. The immutable 0.1.0 schema-2 exception and schema-1 signed-release path remain unchanged.

## Receipt contract

Schema 3 fields: `schema_version`, `repository`, `source_sha`, `workflow_sha`, `image_version`, `chart_version`, `created_at`, `authorization`, `provenance`, `reviews`, `ci_runs`, `evidence_sha256`.

Repository is DevFun2026/fork-pgdog. SHA/hash/timestamp/SemVer types are strict. Authorization has method `github-owner-reviewed-release`, owner actor ID 107181711 and login simonle251289, positive `comment_id`, `comment_body_sha256`, security profile standard, `ssh_clearance: waived-by-owner`, `canonical_release_gate: not-claimed`. Never manufacture a signed security gate result. Provenance has positive distinct source_pr/workflow_pr numbers. Each review retains the existing nine review-summary fields plus boolean `partitioned` and `audit_sha256`; author codex or claude, reviewer gemini, verdict/status pass. Gemini (AGY) is the independent reviewer and is never an accepted author (amended 2026-10-19 by owner decision; the schema-2 first-release exception remains codex-only). No review hash/head/base is rewritten after merge.

The owner approval body is a deterministic function of a canonical approval payload consisting of the entire receipt except authorization.comment_id and authorization.comment_body_sha256. This avoids a circular hash while binding versions, sources, reviews, CI witnesses, evidence and authorization mode. A draft may use comment_id zero locally; publication rejects drafts. The final dispatch receipt hash covers every field, including the real owner comment identity.

Evidence hashes: source-review-audit, workflow-review-audit, source-security-assessment, workflow-security-assessment, threat-model, release-notes, migration-rollback, residual-risks. Security assessments bind actual original reviewed head/base/diff/scope, Standard profile and all eight security lenses. Their status must not pretend absent SSH signatures passed. The owner approval supplies the explicitly chosen GitHub authorization.

## Historical evidence and live trust

Local exporter accepts only a clean committed workflow checkout. Validate complete ordinary review packages or complete runtime-validated partitions with successful integration; require real Git diff/scope/context/audit bindings and zero findings. Store original source and workflow review identities in the receipt. Retain all original evidence separately.

Publication must re-read live GitHub source/workflow PRs, Git commits/trees, current main ref, actor/admin permission, owner comment and protected packages environment. Both PRs must be merged in this repository into main. Their merge commits must have exactly two parents: the original reviewed base then original reviewed head. The reviewed head tree must equal the respective merge/source/workflow tree. Source must be an ancestor of workflow; dispatch SHA and current live main must equal workflow_sha. Reject squash/rebase, tree drift, arbitrary historical bases and stale workflow authority.

Require four genuine CI witnesses: source-quality/source-artifacts on the original source review head, workflow-quality/workflow-artifacts on the original workflow review head. Each has unique positive run ID, immutable attempt, expected workflow path, completed/success status and every expected full-suite/scanner or native job successful. Skips, changed attempts and incomplete job inventories fail. Retain existing required job names and checks from the historical first-release route.

The owner comment must have exact deterministic body/hash and owner identity, belong to the workflow PR's issue URL, and be unchanged. Require live admin permission and the packages environment's owner reviewer with exact main-only branch policy. Revalidate before registry login; withdrawal or main drift blocks publication.

## Artifact and deployment boundary

Keep native amd64/arm64 build, tested OCI bytes, paired strict-read Kubernetes smoke, five scanner categories, protected environment, immutable tag absence, signatures/attestations, digest-preserving copy and chart-last/pull-back unchanged. No cluster deployment or PKI generation is authorized by implementing this receipt. Operator preparation targets namespace database and the supplied PostgreSQL Service; real database/TLS/context inputs are still required.

## Acceptance

Demonstrate RED/GREEN for schema acceptance and each trust failure. Exercise schema-1/schema-2 regressions, tampered approval payload/comment, identity/revoked permissions/environment, wrong PR/merge/tree/main, source ancestry, failed/skipped/stale CI, incomplete partition, metadata drift, security profile/scope mismatch and no-overwrite export. A draft never reaches registry login. Run focused tests, complete artifact/runtime tests, canonical quick/merge gates, independent AGY review and exact owner receipt approval before publication.
