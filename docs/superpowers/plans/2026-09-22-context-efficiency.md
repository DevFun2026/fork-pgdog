# Context efficiency implementation

Approved by the user: improve memory retrieval, remove duplicate review content,
budget context, and scale workflow ceremony to task size. No new hosted service
or tokenizer dependency is required.

## Contract

- Memory uses deterministic weighted lexical ranking (Unicode words, partial
  query matches), bounded top-k results, fresh public/internal records, and a
  small startup selection of architecture/constraints/decisions/workflow.
- Generated skill diffs may be omitted only when the canonical file is changed
  and Git proves equal file modes and blobs in BOTH base and head. Full scope
  and full-diff digest remain bound. Mismatches/deletions without equivalence
  remain visible; loading and merge verification recompute the projection.
- Context profiles `light`, `standard`, `deep` bound memory and review payloads.
  Estimated tokens use a documented UTF-8 heuristic, not provider billing counts.
  Preview reports sizes before any provider execution; oversized reviews block
  rather than truncate. Resume must recheck current approved limits.
- Workflow tiers change planning/context effort, not mandatory merge/release
  checks. Small content-only edits need an inline plan; behavior changes need
  tests and a focused plan; architecture/security changes need the full workflow.

## Implementation and verification

1. `.agent/tests/test_memory_service.py`: RED for partial matching, ranking,
   startup selection, privacy, top-k, output limits, and repeated Git freshness
   work. Implement in `memory/service.py`, expose CLI controls and hook behavior.
2. `.agent/tests/test_review_package.py`: RED for duplicate skill changes,
   tampered/mode-changed copies, full-scope digest, and reload verification.
   Implement projection in `review/package.py`, manifest fields in `models.py`,
   preserve merge binding in `verify.py`.
3. Add context profiles/config validation and payload reporting. Test Unicode
   estimates, budget rejection before provider execution and resumed packages.
   Keep old config/init answers and old unprojected manifests readable.
4. Update AGENTS, policy, skills, workflow guidance, README, architecture and
   init template; regenerate native adapters and architecture output.
5. Run focused tests per change, full suite once integrated, generated-file
   checks, quick gate (report unconfigured project commands honestly), and
   independent read-only review. No authenticated provider call without exact
   package approval. No claim of measured billing savings without real usage.

## Rollback

Revert this change and regenerate adapters. Canonical memory formats remain
unchanged. New projected review packages must be recreated on older runtimes;
old manifests retain their previous full-diff semantics. No data migration.
