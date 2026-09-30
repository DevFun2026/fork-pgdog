---
name: memory-health-review
description: Use when project memory may be stale, duplicated, oversized, privacy-risky, weakly evidenced, or expensive to retrieve.
---

# Memory Health Review

Optimize for trustworthy retrieval, not maximum retention.

## When to use

- Periodic maintenance or retrieval symptoms suggest memory quality has degraded.

## Do not use

- Do not delete or rewrite canonical history without reviewed lineage and authorization.

## Inputs

- `./scripts/agent memory doctor --json`, index/search mode, record metadata, evidence freshness, retention policy, and retrieval measurements.

## Steps

1. Run memory doctor and verify owner-only local permissions, schema, and FTS/fallback mode.
2. Sample startup and task queries for relevant ranking, partial matches, top-k, privacy/freshness, character and estimated-token limits. Verify empty output is not caused by over-restrictive matching; retain whole records.
3. Identify stale, duplicate, orphaned, superseded, private, unsupported, or policy-like records.
4. Propose promotion, supersession, archival, forgetting, or index rebuild with impact and evidence.
5. Re-run health and retrieval checks after approved changes.

## Stop conditions

- Stop before destructive curation when target identity, lineage, or recovery path is unclear.

## Evidence

- Health report, sampled queries/IDs, freshness checks, permission state, and before/after retrieval results.

## Output

- Memory health assessment and bounded curation actions.

## Failure behavior

- Corrupt or unverifiable records are excluded from startup context until repaired or reviewed.
