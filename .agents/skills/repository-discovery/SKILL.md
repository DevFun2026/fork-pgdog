---
name: repository-discovery
description: Use when a task depends on understanding an unfamiliar repository, its boundaries, commands, risks, or current state.
---

# Repository Discovery

Build an evidence-backed map before proposing changes.

## When to use

- The repository, subsystem, build path, ownership, or deployment topology is unfamiliar.

## Do not use

- Do not use as a reason to scan unrelated large files when focused evidence answers the task.

## Inputs

- User scope, repository status, `.agent/project-model/`, configuration, and relevant entry points.

## Steps

1. Read instructions and Git status; preserve unrelated and dirty work.
2. Query `./scripts/agent memory bootstrap --query "current work" --profile standard --report` with task-specific words; skip this if equivalent context was already loaded. Prefer architecture summary and canonical sources, excluding generated skill copies/HTML from broad searches.
3. Inspect the smallest set of manifests, entry points, tests, CI, deployment, and security boundaries needed.
4. Compare observed structure with `.agent/project-model/` and architecture documents.
5. Record facts, inferences, unknowns, and commands separately.

## Stop conditions

- Stop before mutation; discovery grants no permission to edit, install, publish, or contact external systems.

## Evidence

- Paths, symbols, exact commands, Git state, and unresolved verification gaps.

## Output

- Compact repository map and task-relevant risk/unknown list.

## Failure behavior

- If evidence is inaccessible, state the boundary and avoid guessing.
