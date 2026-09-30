# Observability

The template records deterministic command evidence, review manifests and checksums, provider audit events, documentation-impact decisions, security scope, adjudication dispositions, and release-gate results.

Operators should monitor:

- command exit codes, timeouts, tool versions, commit IDs, and worktree diff hashes;
- provider capability, authentication, review status, reviewer independence, and package checksum;
- memory health, stale records, rejected private content, and index rebuilds;
- documentation drift and architecture-model validation;
- required scanner status, unverified areas, and residual risks.

Local `.agent/.runs/` artifacts may be discarded and regenerated. Versioned source, canonical memory, architecture documents, and ADRs are durable project history.
