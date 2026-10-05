# Partitioned independent review

Status: approved direction by the user on 2026-10-05: partition review while preserving quality.

## Contract

The existing single-package path remains compatible. Opt-in partitions retain
500,000 bytes / 96,000 estimated tokens per invocation, target at most 250,000
payload bytes, and impose 2,500,000 bytes / 800,000 estimated tokens across the
operation, including metadata, repeated requirements, context and integration.
The trusted remote-default ancestor must enable partition semantics before any
partition provider probe or egress. A feature-local configuration cannot grant it.
Local preview may prepare the proposed operation but must report this blocker.

A root manifest binds the existing complete Git projection manifest, full scope,
base/head, author/reviewer identities, verification, ordered child package hashes,
exact byte ranges and aggregate usage. Concatenating ordered child diff fragments
must reproduce every original projected byte; the existing full-Git projection
proof remains mandatory. Ordinary changed-file patches stay whole. Only the
pinned newly added PG18 registry may be split at complete JSON record boundaries;
fragment metadata identifies its file, table, record span and original offsets.
Unknown formats, oversized indivisible records or patches, gaps, overlaps,
symlinks, extra unlisted content, stale sources or checksums fail closed.

Every child sees complete change inventory, requirements and verification plus
its full assigned patches/records. No provider receives the oversized root.
Root approval is exact and required before even probing a provider. Author and
reviewer providers differ. Existing provider sandbox and output validation apply.
Child invocations cannot publish standalone global merge-clearance records.

An additional integration review is mandatory. It receives explicitly selected
immutable contracts/context, the complete inventory, all validated child outputs
and their audit bindings. Because outputs do not exist at initial preview,
integration has a second exact manifest approval before egress. No automatic
approval of derived provider text is inferred. Integration and child payloads
count towards the same aggregate limits; oversized outputs block further work.

All children and integration must complete with schema-valid pass verdicts and
no findings before automatic clearance. Any missing, malformed, stale, tampered,
failed or pending result prevents clearance. Findings require existing human
adjudication/fix workflows; integration cannot override incomplete children or
confirmed High/Critical findings. Gates reload all packages and results rather
than trusting summary status. Cross-package architecture, protocol state,
catalog assumptions, deployment boundaries and regression evidence are required
integration review questions, not optional recommendations.

## Migration and trust

This is a separate governance change. Its implementation must be reviewed under
the existing single-package limits and integrated into the trusted base before
it can clear the PgDog feature. This approval authorizes implementation and local
preview, not provider egress, commit, push, merge or release. Rollback disables
partition configuration; no existing single-package evidence is invalidated.
