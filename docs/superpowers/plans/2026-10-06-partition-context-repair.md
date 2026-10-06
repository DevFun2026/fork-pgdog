# Partition context sizing repair

Scope: repair the existing partition review's shared-context sizing and clarify
its package-reading instructions. The strict SQL policy, trusted byte/token
limits, at-most-once dispatch and independent-review gates remain the approved
contracts.

Evidence: the PR #9 preview at HEAD `961d6e6f`, with `resolve.rs` and `rows.rs` as
child context, failed with `partition sizing did not converge within its bounded
retries`. AGY also misread context-relative paths, child/root metadata and the
clean-worktree verification digest in the earlier immutable package. Preserve
that package, its native provider audits, and the bound adjudications.

1. Reproduce the sizing failure with a deterministic runtime regression and
   inspect actual context accounting. Fix the minimum cause in
   `.agent/runtime/agent_cli/review/partition.py`; do not increase limits or
   silently omit context.
2. Clarify `REVIEW_INSTRUCTIONS` in `review/package.py` and document the
   existing semantics in `docs/antigravity.md`.
3. Add a bounded, source-hash-verified registry/resolver/admission context
   excerpt and a drift regression, retaining the complete diff in all shards.
   Repair CI failure summaries for libtest, strict fixtures and unwrapped fatal
   phases with allowlisted labels, preserving exit codes and fixture cleanup.
4. Run focused partition/runtime regressions, adapter/doc checks, quick checks
   and fresh full review verification on the committed source.
5. Preview a source-bound registry/resolver/admission context package, check
   every child and the aggregate against trusted limits, and obtain exact
   manifest approval before native AGY egress. Retain any over-budget failure
   rather than converting it into clearance.
6. After complete independent review and CI evidence, run the merge gate and
   merge the already-authorized PR. Revert only these scoped repairs if they
   regress existing package validation.
