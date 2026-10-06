# 0004: Quality-preserving partitioned independent review

Status: accepted design; runtime trust integration pending.
Decision owner: repository user, 2026-10-05, "duyệt chia gói cho review nhưng phải đảm bảo chất lượng".

The strict-read feature contains a pinned PostgreSQL catalog larger than the
existing single-review limits. Increasing one model context, dropping records,
changing the review base or truncating the patch would remove existing controls.

Keep the per-invocation limits and introduce a bounded aggregate operation with
complete byte reconstruction, complete registry records, provider independence
and two approval stages. Review each immutable shard, then require integration
review of the complete inventory, validated results and explicit cross-boundary
contracts. Missing evidence blocks; no shard independently clears merge.

Compared alternatives: retain the existing blocker; raise the single-context
limit; omit the registry; partition with only local shard verdicts. The selected
option preserves every reviewed byte and adds an integration check, at the cost
of repeated context, additional provider calls and an extra manifest approval.
Actual costs remain unknown until a concrete preview/provider choice exists.

Trusted-base enablement is a separate integration requirement. This accepted
design does not authorize egress, local commits, pushes or merge. The governance
implementation is reviewed through existing single-package semantics first.
Rollback disables partition_enabled; old single-package evidence remains valid.

Specification: ../superpowers/specs/2026-10-05-partitioned-cross-review.md.
Plan: ../superpowers/plans/2026-10-05-partitioned-cross-review.md.
Threat-model delta: ../security/partitioned-review-threat-model.md.
