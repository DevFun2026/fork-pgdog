# Full-read review infrastructure implementation plan

Goal: review every byte of the eight v2 dependency profiles without weakening per-invocation or clearance controls.

Approved input: user approved the bounded full infrastructure proposal on 2026-10-14. Aggregate ceiling 30,000,000 bytes / 8,000,000 estimated tokens; per invocation 500,000 bytes / 96,000 estimated tokens; child target 250,000 bytes. Private icondo metadata stays local.

Scope: partition.py, focused partition/config tests, explicit project config and verification/security documentation. Historical registries remain supported; generic arbitrary JSON splitting is excluded. Default runtime caps remain unchanged for other projects. Feature runtime behavior is outside this infrastructure change.

## Tasks

1. Add RED config tests for approved aggregate limits and retained per-call caps; update only explicit project settings; run GREEN.
2. Add RED splitter tests for the eight exact profile paths and validated v2 provenance, selector and catalog shape. Implement catalog-record boundaries preserving the original patch bytes; verify full reconstruction, malformed envelopes, oversized records, modified-file boundaries and tampered partitions.
3. Run focused and full agent tests, Python lint, canonical quick, adapters/docs checks. Record any missing full legacy fixture separately.
4. Extract only infrastructure edits into an isolated checkout based on remote main. Keep fd34918d and original dirty checkout intact. Independently review infrastructure under existing trusted limits with exact manifest approval before AGY egress. Required Standard security/CI/merge gates remain in force.
5. After infrastructure enters trusted remote base, integrate it with the feature and build the complete partition root preview under the new trusted limits. Obtain exact root and later integration manifest approvals. Infrastructure review cannot clear feature review.

## Rollback and completion

Revert the infrastructure commit or disable partition_enabled; do not alter previously bound evidence. No external effect is implied by passing local tests. Missing, oversized, malformed or failed evidence blocks clearance. Completion requires independent review and normal merge gates, followed by separate full feature review.
