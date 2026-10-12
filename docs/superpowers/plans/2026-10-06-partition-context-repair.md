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

## Follow-up from the completed e4c93459 review

All eight native AGY calls completed with valid output: four pass and four fail
with five findings. Bound adjudication rejected the quoted-type network bypass
(admission denies it with 0A000), unsupported raw snapshot types (not an
allowlist), and unsorted parameters (stored in BTreeSet). The redundant internal
type-name reparsing and unreachable schema check are accepted maintenance
findings; simplify type_oid to the exact AST base identifier and retain the
namespace/scalar gates, with malformed-name and positive SQL controls.

GitHub test_full failed in both strict fixture phases. Reproduction with the
pinned PostgreSQL18 image and a runner-owned 0600 bootstrap showed permission
denied under the container postgres account. Docker Desktop bind ownership did
not reproduce the Linux inode behavior, so retain both observations. Stream SQL
to psql stdin in the recorded container after readiness; never widen private
file permissions. Verify failure cleanup and live isolated stdin bootstrap, then
run fresh committed-head full verification and CI. A changed-source review needs
a new exact manifest approval; preserve the e4c outputs and dispatch markers.
