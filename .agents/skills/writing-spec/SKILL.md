---
name: writing-spec
description: Use when an approved idea needs a precise behavioral and system contract before an implementation plan is written.
---

# Writing a Specification

Specify observable outcomes and boundaries, not implementation theater.

## When to use

- A non-trivial feature, template, migration, or system change has an approved direction.

## Do not use

- Do not use to retroactively justify code that has not been reviewed against user intent.

## Inputs

- Approved design direction, repository evidence, `.agent/project-model/`, constraints, non-goals, and security/data classifications.

## Steps

1. Define goals, non-goals, actors, use cases, and observable acceptance criteria.
2. Specify interfaces, state transitions, data ownership, errors, timeouts, and compatibility.
3. Describe architecture impact, threat-model impact, operational impact, and migration/rollback.
4. Separate deterministic requirements from recommendations and assumptions.
5. Save the versioned spec under `docs/` and obtain approval before planning.

## Stop conditions

- Stop when a missing product choice would materially change behavior or scope.

## Evidence

- Source links, repository paths, approved decisions, and traceable acceptance criteria.

## Output

- Approved specification with no hidden implementation authorization.

## Failure behavior

- Mark unknowns and conflicting requirements explicitly; never fabricate a requirement.
