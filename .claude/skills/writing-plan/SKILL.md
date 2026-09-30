---
name: writing-plan
description: Use when an approved specification requires a multi-step implementation sequence with exact files, tests, gates, and rollback boundaries.
---

# Writing an Implementation Plan

Make each step executable and independently verifiable.

## When to use

- Work spans multiple files, components, migrations, or quality gates.

## Do not use

- Do not plan before the behavioral specification and consequential decisions are approved.

## Inputs

- Approved spec/ADRs, repository map, interfaces, risk assessment, commands, and acceptance criteria.

## Steps

1. Choose planning effort using `agent workflow guide --task content|behavior|interface|architecture|security`. Small content-only edits use inline scope/checks; multi-step behavior and architecture/security changes use versioned plans. Interface guidance selects only the relevant design phase, not a lighter security gate. Decompose work into dependency-ordered tasks with exact paths and contracts.
2. For each behavior, place a failing test before implementation and name the expected failure.
3. Include focused verification, integration verification, docs/security impact, and commit boundaries.
4. Include safe rollback/migration handling and explicit approval gates for external effects.
5. Use `.agent/templates/plans/implementation-plan.md` and validate feasibility against the repository.

## Stop conditions

- Stop when a task depends on an unresolved interface, permission, or product decision.

## Evidence

- File inventory, dependency order, test commands, expected results, and cited requirements.

## Output

- An approved plan another agent can execute without rediscovering design intent.

## Failure behavior

- Mark uncertain steps as blocked decisions; do not hide them in implementation prose.
