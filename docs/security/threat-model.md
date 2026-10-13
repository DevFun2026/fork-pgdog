# Threat Model

## Strict read endpoint delta

### PostgreSQL 12 compatibility delta

This change adds a separately captured, digest-pinned PG12 reference catalog and
fixed PG12 catalog SQL. It keeps the existing narrow SQL/function surface and
PgDog-owned READ ONLY transaction boundary. The registry is immutable and selected
from the actual protected backend identity for each snapshot; it is carried into
column checks, dependency checks and typed resolution. Unsupported versions,
malformed registry data and exact catalog mismatches deny.

| Threat | Required control and verification | Owner |
| --- | --- | --- |
| PG18 proof or resolver metadata reused on PG12 | Per-snapshot registry context and backend/transaction-bound proof; mixed-major isolation and stale identity negatives | Proxy maintainer |
| Missing PG12 catalog field silently treated as safe | Fixed version-specific SQL and complete real-row comparisons; live least-privilege PG12 query/closure tests | Proxy maintainer |
| Registry learned from compromised application schema | Offline pinned official reference, major/digest/provenance validation and complete dependency closure; generator negatives | Build maintainer |
| Supporting PG12 widens functions or hidden execution paths | Existing SQL admission/type/function/role/object denials retained; side-effect canaries and data/schema/sequence snapshots on both majors | Proxy maintainer |
| Release tested only on PG18 | Both strict profiles on PG12 and PG18 plus native paired Kind smoke before artifact publication | Release maintainer |

Actual managed PG12 catalog and application SQL are unverified until operator
staging checks pass. This proxy compatibility change does not extend upstream
PostgreSQL 12 maintenance or remove trust in the server binary/DBAs. Read traffic
must remain stopped or denied on a catalog mismatch; never bypass a proof or
route the read Service to the unrestricted writer. Controls authored here are
requirements, not assertions that tests or publication have passed.

Assets are database rows/schema/sequences, application credentials, query results,
the immutable read manifest and protected backend transactions. The attacker is an
authenticated DML-capable application using the read endpoint, including arbitrary
SQL and PostgreSQL wire messages. The read and unrestricted write processes are
separate trust boundaries. DBAs, the selected PostgreSQL 12/18 binary/built-ins and the drained,
reviewed schema epoch are trusted; native extension effects and malicious DBA
changes are outside this boundary.

| Threat | Control and verification scope | Owner |
| --- | --- | --- |
| Write hidden behind SELECT, CTE, batch or function | Closed recursive AST admission before any client forwarding; deny unknown nodes/functions and reject whole mixed batch; SQL denial/snapshot tests | Proxy maintainer |
| Planner, type input or index invokes unreviewed code | Same-backend catalog identity and exact pinned dependency metadata; ordinary-table/role checks and local typed proof before Parse/Bind; catalog negative fixtures | Proxy maintainer |
| SET/startup escape or parser grammar mismatch | Restricted startup, no SET or role changes, UTF8/standard_conforming_strings verification and acknowledged READ ONLY transaction | Proxy maintainer |
| Cached authorization or stale portal | Original SQL/type identity, private proofs, per-client generations and backend/database/role/manifest/transaction binding | Proxy maintainer |
| Flush/Sync/error/cancel recycles a writable or busy connection | Separate client/backend transaction states, reserved internal names, hidden housekeeping replies, discard uncertain backends; owned wire/failure tests | Proxy maintainer |
| Config reload or DNS alias bypass | Immutable process policy, config-publication checks, two distinct release selectors/Services and same init/runtime flags | Deployment operator |
| DDL races with proof | Drain/stop readers for controlled migration, review catalog/manifest revision, restart and smoke before resuming | Database operator |
| Query/credential leakage | Existing TLS/auth boundary, passthrough credentials, bounded reason codes, strict raw-SQL log rejection | Deployment operator |

These controls require the dedicated runtime/catalog/protocol and paired Service
checks. Authored tests are not passing evidence until executed. This delta does
not inherit the separate, source-specific image/chart 0.1.0 release exception.

## Fork container/chart delta

Assets: source-bound OCI image/chart bytes, release receipt, registry credentials,
database users/configuration/TLS secrets, running proxy and in-flight queries.
Actors: owner, release/deployment operators, CI contributor, registry writer and
compromised dependency. Boundaries: source-to-builder, read-only build-to-protected
publish, owner-approved receipt handoff, CI-to-GHCR, operator-to-cluster and
Secret-store-to-Pod. Implemented sources and local smoke are distinct from first
registry publication and production deployment.

| Threat | Control/evidence | Owner |
| --- | --- | --- |
| Official PgDog artifacts disappear/change | Fork-owned source build/chart; dependency/Compose tests | Build maintainer |
| Build leaks Git/credentials | Context exclusions, bounded uploads and no Git COPY; container contract tests | Build maintainer |
| Malformed config/privilege escalation/secret exposure | Closed schema, literal TOML, existing Secrets, configcheck and hardening; chart/Kind tests | Deployment operator |
| Backend outage restart loop or forced query loss | Separate TCP liveness/HTTP readiness, finite SIGINT grace; live outage/drain smoke | Workload operator |
| External Secret rollout/rollback confusion | Explicit rollout/version restoration runbook and live Secret rotation | Deployment operator |
| Receipt forgery/source mismatch | Genuine local release gate, owner-approved canonical hash, exact source/evidence checks and ancestry tests; no detached authenticity claim | Release owner |
| Untested/rebuilt bytes or wrong provenance | Native OCI archive/config/source checks, preserve-digests copy and explicit source vs dispatch SHA | Release maintainer |
| Existing-tag overwrite/partial publication | Authenticated MANIFEST_UNKNOWN only, serialized/repeated checks, signatures before chart-last push and pull-back | Registry administrator |
| External registry writer race | Restrict writers/immutability through registry process; residual risk remains | Registry administrator |

Required dependency/license/SAST/IaC/container scans preserve the standard profile;
High/Critical findings block. Missing independent provider review or actual
native/registry evidence blocks release. The normal signed route also requires
an enrolled signer and signed clearance; the bounded first-release exception
below explicitly waives that mechanism. TLS/network
policy, durable 2PC storage and production recovery remain outside this design.

## Scope

This model covers the template runtime, canonical policy and skills, local
Project Memory, generated documentation, review packages, provider CLI
processes, and CI wrappers. Product repositories created from the template must
replace or extend this model for their own assets and deployment.

## Assets and actors

Assets include repository source, Git history, configuration, provider prompts,
review evidence, canonical memory, private local memory, credentials available
to the host, and release artifacts. Actors include the project owner, coding
agents, independent reviewer providers, local provider CLIs, hosted CI runners,
dependencies, and an attacker able to contribute untrusted repository content.

## Trust boundaries and data flows

- The repository boundary separates versioned policy from the host filesystem.
- `.agent/.memory/` and `.agent/.runs/` are private local plaintext stores.
- Review packages cross from the local repository to a selected provider CLI
  only after a manifest preview and exact-hash approval.
- Provider output crosses back as untrusted structured data and is validated.
- CI runners execute the same repository runtime in a separate hosted boundary.

## Threats and controls

- Prompt injection in source or memory: content is treated as data; memory
  cannot override policy; review providers receive a fixed policy.
- Command injection: commands are argument arrays executed with `shell=False`.
- Path traversal and symlink escape: repository containment is checked before
  reads or writes.
- Secret leakage: deny rules, bounded packages, redaction, private blocks, and
  manifest approval run before provider invocation.
- Review-package tampering: the manifest binds diff, context, requirements,
  verification, policy, and schema; checksums are revalidated on resume.
- Hidden generated changes: deduplication compares regular-file modes and Git
  blobs at both base/head, only against a changed canonical source. Full scope
  and full-diff hash remain bound and projection is recomputed before execution
  and merge. Divergence, unsupported file modes, and unproven copies are reviewed.
- Context exhaustion: bounded ranked memory and estimated-token review caps
  reduce payloads; review overflow blocks rather than silently omitting changes.
  Token estimates exclude provider-internal prompts, repeated reads and output.
- Untrusted memory import: imported records remain candidates until reviewed.
- Supply-chain compromise: license, dependency, and provenance checks are
  release inputs, while unsupported checks remain explicitly unverified.

## Residual risks

### Antigravity migration delta

AGY can select Claude as well as Gemini: the Gemini adapter pins/validates a
Gemini model to preserve cross-provider identity. Its JSON parser requires a
successful terminal status and schema-validated findings, rejecting conflicting
response fields. Plan mode is advisory; the OS sandbox remains the read/write
boundary. A canonicalized disposable HOME fixes macOS temporary-path aliases
without granting new host directories. Only minimal API-key-mode settings are
created there; no host profile, plugin config or OAuth token store is imported.
The provider environment is reduced to `GEMINI_API_KEY` plus common runtime
variables. API-key backend/model compatibility still needs live verification.

Native migration deletes only unchanged manifest-owned retired outputs and
blocks path escapes/symlinks. AGY hooks consume only bounded invocation metadata,
never follow transcript paths, and inject memory as data. Stop does not restart
the agent or persist learning without review. Hook UI visibility is best effort.

Provider and scanner defects can miss vulnerabilities. Local plaintext depends
on host permissions and full-disk security. A compromised maintainer or CI
credential can bypass repository process. Real product runtime and deployment
remain outside this template-only assessment.
# First-release GitHub authorization delta (2026-10-02)

The owner explicitly waived SSH security signatures for image/chart 0.1.0 in PR
#7 comment 5948092075. The Standard profile and deterministic/independent reviews
are unchanged. Artifact source is fixed to 09026eec; publication workflow has a
separate immutable reviewed SHA. This is an alternate authorization decision,
not a passed canonical security clearance.

Assets: registry write/OIDC capabilities, exact image/chart bytes, review/CI
metadata and owner approval. Actor: GitHub user ID 107181711, current repository
admin and required packages reviewer. Entry points: bounded receipt JSON, owner
comment API, CI run/job API, manual main dispatch and protected deployment.

- Tampered, withdrawn or impersonated approval: pin comment ID, exact content,
  numeric owner identity and current admin permission; revalidate after approval.
- Workflow/source substitution: bind separate source/workflow SHAs and both
  independent reviews; dispatch SHA must match the receipt; validate ancestry.
- Forged/skipped/stale CI: fetch real run paths, SHAs, attempts and required job
  conclusions. Every required quality/scanner/native job must succeed.
- Broader releases/replay: pin image/chart 0.1.0 and original source; immutable tag
  absence checks block reuse, including partial-publication recovery.
- Credential exposure: argument-array gh API calls, token only in normal
  environment/keyring, generic errors without credential-bearing diagnostics.

Owner: release maintainer. Compromised GitHub administration/CI or external
registry writers remain residual risks. No complete security certification is
claimed. Tests cover owner, scope, CI and metadata failures; missing API evidence
always blocks publication. Rollback removes the schema-2 route without deleting
packages or modifying schema-1 signed clearance.

## Source-bound GitHub owner release delta

The owner approved an opt-in schema-3 route for the strict-read release. It retains
original source/workflow review heads and bases, including completed partitioned
review with integration. It does not reset remote refs or relabel historical
review as a review of a merge commit. Canonical review/merge/SSH validators and the
fixed first-release exception remain unchanged.

The new receipt binds exact source/workflow merge commits, versions, Standard
assessments, review/audit hashes and four CI run IDs/attempts. Its human-readable
owner body binds a canonical payload excluding only the comment ID/body hash to
avoid circular hashing; final receipt integrity covers those fields too. A draft
with comment ID zero cannot authorize publication. Actual original base/head and
merge configurations must all retain the approved Standard profile; other profiles
are rejected rather than lowered.

- Historical-base substitution: require real same-repository merged main PRs,
  exact original two-parent order and identical reviewed/merged Git trees. Compare
  live GitHub commit data with local Git; require source ancestry and live main
  equal to the exact dispatch workflow. Squash/rebase or tree drift blocks.
- Owner impersonation/replay: re-read exact workflow-PR comment, fixed numeric
  identity/login, current admin permission and owner/main-only packages protection.
  Modified/withdrawn comments and changed dispatch authority block before login.
- Forged evidence or profile downgrade: exporter checks complete ordinary or
  runtime-validated partition/integration evidence, actual Git diffs/contexts,
  all eight assessment lenses and committed profile configuration. Unknown fields,
  mismatched audit hashes, weaker assessments or incomplete CI fail closed.
- Stale CI/rebuild substitution: preserve required full-suite/scanner/native job
  names and immutable attempts. Existing native build/archive import, signature,
  digest-preserving publication and chart pull-back checks remain mandatory.

Owner: release maintainer. The new mode explicitly records SSH clearance waived
by owner and no claim of a canonical signed release gate. Compromised owner/CI,
host evidence tampering and external registry writers remain trust risks. It is
not an SSH key enrollment or a production-cluster authorization. See the
[approved contract](../superpowers/specs/2026-10-12-github-owner-release.md).
