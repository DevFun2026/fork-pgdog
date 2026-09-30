# Context efficiency verification — 2026-09-22

Scope: approved memory retrieval, generated skill review deduplication, context
budgets, and planning tiers on branch `feat/context-efficiency`.

## Results

- Full suite: **159 tests passed**, including the clean-export smoke fixture and
  all six author/reviewer directions using mock providers. The inner clean
  export skips its own recursive smoke test by design.
- Command: `PATH="/Users/simon/.nvm/versions/node/v24.11.0/bin:$PATH" PYTHONPATH=.agent/runtime python3 -m unittest discover -s .agent/tests -q`.
- Adapter/doc drift, 21 skill contracts, eight declared source licenses and
  `git diff --check` passed. Shipped init answers render successfully.
- Independent read-only agent review found an ambiguity in legacy manifest
  handling. A regression test reproduced it; loading now rejects null/partial
  projection metadata. The reviewer rechecked the fix, scope validation and
  completed documentation and reported no remaining actionable findings.
- This was a separate agent review, not a live review by a different provider.

## Payload experiment

Deterministic fixture: one changed canonical skill and three matching native
copies, with all four requested as context.

| Measurement | Before | After |
| --- | ---: | ---: |
| Diff payload bytes | 4,920 | 1,227 |
| Context files | 4 | 1 |

The diff is 75.1% smaller in this fixture. The resulting package, including its
manifest and instructions, is estimated at 1,311 tokens by `utf8-div3-v1`.
These figures are payload measurements, not provider billing savings. Project
memory is intentionally empty until project-specific knowledge is promoted.

## Limits and environment

- The initially selected Homebrew Node 26.8.2 aborts in the existing provider
  sandbox: dyld cannot read `libnode.147.dylib`. The same Node fixture passes
  with the already-installed standalone Node 24.11.0. Only this test command's
  PATH was changed; no sandbox permission was broadened. Supporting dynamic
  Homebrew Node libraries remains a separate compatibility issue.
- `agent verify quick --json` reports `incomplete`: the reusable template has
  no product quick commands configured. This is not a merge/release clearance.
- No authenticated provider review, hosted CI run or measured token billing
  experiment was performed for this change.

See `docs/context-efficiency.md` for budgets, retrieval behavior, projection
proof, legacy manifest compatibility, and rollback limits.
