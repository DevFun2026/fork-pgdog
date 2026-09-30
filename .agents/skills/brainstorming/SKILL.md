---
name: brainstorming
description: Use when product intent, behavior, constraints, or solution direction is ambiguous before implementation planning.
---

# Brainstorming

Turn an idea into an approved direction without prematurely writing code.

## When to use

- Multiple valid product or technical directions exist and tradeoffs matter.

## Do not use

- Do not use when the user supplied a complete approved design and only execution remains.

## Inputs

- User goal, repository discovery, constraints, non-goals, security profile, and relevant `.agent/memory/records/`.

## Steps

1. Restate the outcome and identify decisions that materially change scope.
2. Ask one focused question at a time only when repository evidence cannot resolve it.
3. Offer a small number of distinct approaches with costs, risks, and a recommendation.
4. Cover data flow, trust boundaries, failure behavior, testing, migration, and operations.
5. Capture the approved direction in a versioned spec; do not treat discussion as approval.

## Stop conditions

- Stop before implementation until the user approves the design direction.

## Evidence

- Decisions, alternatives, rationale, rejected options, and explicit approval.

## Output

- Coherent design direction suitable for `writing-spec`.

## Failure behavior

- Preserve unresolved choices as open questions rather than silently choosing.
