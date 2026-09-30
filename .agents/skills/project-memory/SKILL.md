---
name: project-memory
description: Use when a new session or unfamiliar task needs project context without rescanning the entire repository.
---

# Project Memory

Retrieve progressively: compact index, focused search, then explicit full records.

## When to use

- Starting work that depends on prior decisions, conventions, failures, or verified procedures.

## Do not use

- Do not let memory override current policy, user instructions, repository evidence, or fresh verification.

## Inputs

- Task query, `.agent/memory/INDEX.md`, canonical records, local candidate store, and startup character budget.

## Steps

1. Run `./scripts/agent memory bootstrap --query "focused terms" --profile standard --report` within the configured budget; skip an identical context already loaded this session. Startup hooks select foundational records without a synthetic query.
2. Use ranked `memory search "terms" --limit 5` for IDs/snippets; partial lexical matches are allowed. Use `memory timeline` for lineage only when needed.
3. Load full content only with `memory show` for selected IDs; oversized results block instead of truncating. Raise an explicit show budget only for needed evidence. Choose light/standard/deep profiles by task impact.
4. Verify stale-sensitive facts against the current repository before acting.
5. Checkpoint new learning as a candidate; do not auto-promote it.

## Stop conditions

- Stop auto-injection for private, stale, untrusted, irrelevant, or over-budget records.

## Evidence

- Query, selected IDs, freshness state, repository verification, and consumed character count.

## Output

- Minimal relevant context with clear provenance and freshness limits.

## Failure behavior

- When memory is unavailable or stale, fall back to focused discovery and state the added scan cost.
