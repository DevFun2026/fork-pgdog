# First release through GitHub owner approval

Approved by the owner in [PR #7 comment](https://github.com/DevFun2026/fork-pgdog/pull/7#issuecomment-5948092075), confirmed in the interactive session. The comment approves image **0.1.0** and chart **0.1.0**, not the previously proposed image 0.1.60.

## Contract

Add an explicit schema-2 receipt for this first release only. Retain schema-1 signed-clearance receipts unchanged. Never manufacture a passed canonical release gate or SSH clearance. The approved Standard security profile remains unchanged.

The exception is restricted to repository DevFun2026/fork-pgdog, source 09026eec63e0cb2da60389ef623e56ff1e4ba74b (the reviewed and merged PR #7 source), image 0.1.0 and chart 0.1.0. Bind the executing main workflow revision separately from artifact source. Pin comment 5948092075, user ID 107181711, login simonle251289 and the exact approved comment body. Re-read that comment and the owner's repository permission during preflight and after protected-environment approval. Changed/deleted comments, wrong actors, refs, revisions, versions or missing API data block publication.

Receipt creation requires a clean committed workflow candidate, genuinely passed independent source and workflow reviews, historical source quality/native CI and current workflow quality/native CI. Validate job conclusions and native matrix names using the authenticated GitHub API. Every required job must be successful; rerun-attempt drift, skipped jobs, wrong revisions and wrong workflow paths fail closed. Reviews retain Git diff, manifest and findings hashes. Source review is historical evidence against its actual pre-integration base, not a forged current default-branch base.

The main-only workflow still uses the protected packages environment. Require its owner reviewer. Revalidate authorization and CI after approval before registry writes. Keep native amd64/arm64 build, container/Kind/scan tests, exact archive transport, tag absence checks, keyless signatures/attestations, digest-pinned chart-last publication and pull-back verification.

## Scope and operation

Change artifact receipt tooling, workflow preflight and focused documentation/model. Do not modify canonical security clearance validation, enroll keys, lower the security profile, modify AGY global settings, or enable automatic publication. Source code and distribution defaults remain at the already reviewed source; publication passes image version 0.1.0 as its explicit build argument and packages appVersion 0.1.0.

After tests and independent workflow review, export the honest schema-2 receipt and show its canonical hash for owner approval before dispatch. This authorization route is not general clearance and cannot authorize a different release. Existing immutable tags block reuse or recovery after partial publication.

## Threat model and rollback

The additional trust boundary is the authenticated owner comment and GitHub CI/environment API. Bind numeric identities, exact content, source and workflow SHAs; use argument arrays and never print token-bearing errors. A compromised owner account or GitHub runner remains a residual risk owned by the release maintainer. Require a separate current workflow review because main's publication code can differ from artifact source. Missing GitHub evidence blocks rather than falling back to local fabricated status.

Rollback removes schema-2 dispatch support; it does not delete packages or mutate existing tags. Partial publication uses the existing artifact rollback runbook and a separately authorized recovery decision.
