# Partitioned review implementation

Approved input: docs/superpowers/specs/2026-10-05-partitioned-cross-review.md and
user approval of the previously previewed partition design on 2026-10-05.

1. Add RED tests for exact reconstruction, complete registry-record boundaries,
   oversized atomic blocks, checksum/range/symlink/extra-file rejection, payload
   ceilings and root approval. Implement packaging in a separate module; preserve
   existing single-package loader and Git projection checks.
2. Add RED tests for zero provider probes before exact approval and trusted
   enablement, independent provider identity, all-child completion, malformed
   output and no child publication of merge clearance. Add opt-in orchestration.
3. Require second immutable integration package approval with validated child
   outputs and explicit cross-boundary context. Test partial/tampered results,
   aggregate overflow and inability to override failed child verdicts.
4. Add trusted-base configuration and CLI flags; default partitioning disabled
   when fields are absent. Test feature-local enablement cannot authorize egress.
5. Extend merge evidence loading for root-bound partition operations, preserving
   single-package validation and existing adjudication requirements.
6. Synchronize canonical policy/skills, project model and generated adapters/docs.
   Run runtime tests, quick checks, artifact checks and applicable security review.
7. Prepare a bounded governance-only immutable patch/preview for independent
   review under existing semantics. Do not select an artificial review base or
   bypass required trusted integration. Feature remains blocked until that step.

Ownership: smaller worker owns partition.py and its packaging tests. Primary owns
configuration, CLI, orchestration, evidence integration, documentation and final
verification. Preserve existing native-fixture changes and feature commit.
