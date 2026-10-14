# Terminal review retry implementation plan

**Goal:** A separately approved retry can complete one terminal-incomplete child without overwriting previous audits, dispatch markers or passing children.

**Approved input:** [Canonical contract](../specs/2026-10-14-terminal-review-retry.md). Human approval on 2026-10-14 of the local terminal-retry proposal for root `60e5252212433487a4fa147aaa349b028772edc9f52f467a8c29f8addc11fa32`. This approval authorizes implementation and infrastructure review, not provider egress for a new retry manifest.

**Scope:** Partition retry lifecycle, native process supervision, immutable receipts, transport-only inline instructions, CLI preview, tests and docs. No PgDog SQL policy or deployment change. Original feature HEAD/package stays immutable.

## Preflight
Original checkout has unrelated dirty/staged work. Reuse the clean infrastructure worktree on `codex/terminal-review-retry` from trusted main `97f50b30a81c92ee6f18e6cdc9c391774857863f`. Standard security profile, existing context ceilings and root operation lock remain enforced.

## Task 1: Supervised terminal evidence
Files: `.agent/runtime/agent_cli/providers/native_supervisor.py`, `.agent/tests/test_native_supervisor.py`, `scripts/native_partition_review.py`, `.agent/tests/test_native_partition_review.py`.
RED: confirmed invalid exit does not create eligible receipt; timeout/interrupt/live process group must not be eligible. GREEN: dedicated process group is reaped/cleaned, output files are private create-once, terminal receipt binds input/prompt/stdout/stderr/audit and launch identity. Native host remains explicitly opt-in and no permission bypass is added. Group supervision cannot establish that a malicious process did not escape its session; retain this native-exception risk.

## Task 2: Append-only retry state
Files: `.agent/runtime/agent_cli/review/partition_retry.py`, partition orchestrator, corresponding tests.
RED: separately approved terminal retry cannot currently proceed. GREEN: exact retry manifest approval precedes probe/launch; new package retains exact child input, old evidence stays byte-identical, attempts are bounded and included in aggregate accounting. Selection of a new receipt is validated in resume/integration/clearance. Unknown dispatches, changed inputs, fail verdicts, timeouts, running invocations and invalid terminal proofs remain pending/blocked.

## Task 3: CLI, docs and verification
Files: CLI, focused CLI tests, canonical skills/policy, project model, threat-model delta, docs. Preview is local only. Rebuild generated adapters/docs. Run targeted tests, all agent tests, artifact tests, quick and matching review gate; assess security with current source identities. Prepare independent infrastructure review package and request its exact hash only after all authorized local work is concrete. No provider call, feature retry or merge merely from design approval.

## Migration and rollback
Missing retry fields keep historical behavior. Legacy native audits lack supervised terminal receipts; do not retroactively mint proof from timestamps or reset markers. Recovery of the existing three empty-output attempts and one interrupted attempt remains a separate reconciliation decision/evidence task. Removal of new code returns those attempts to historical pending behavior without deleting artifacts.

## Final acceptance
All new invariants tested; no existing ambiguity test weakened; generated docs/adapters current; infrastructure independently reviewed before operational use. Feature clearance requires all 72 selected child receipts plus separately approved integration review. This plan does not grant release/security clearance.
