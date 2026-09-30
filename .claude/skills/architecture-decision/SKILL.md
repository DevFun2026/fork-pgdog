---
name: architecture-decision
description: Use when a consequential technical choice has alternatives, long-lived tradeoffs, or governance impact that future contributors need to understand.
---

# Architecture Decision

Record why a choice was made and how it can be revisited.

## When to use

- The choice changes boundaries, core technology, data ownership, security posture, or operational cost.

## Do not use

- Do not create an ADR for reversible routine implementation detail.

## Inputs

- Context, decision drivers, alternatives, evidence, risks, and approving authority.

## Steps

1. Copy `.agent/templates/decisions/adr.md` into the project's ADR directory.
2. Record context, drivers, viable options, decision, rationale, consequences, risks, and follow-up.
3. Link the spec, project model, threat model, and verification evidence.
4. Leave status proposed until an authorized human or governance process accepts it.
5. Supersede accepted ADRs with a new record instead of rewriting history.

## Stop conditions

- Stop before marking an ADR accepted without explicit authority.

## Evidence

- Compared options, decision owner, approval record, and linked artifacts.

## Output

- Immutable decision history with a clear status and follow-up.

## Failure behavior

- If no decision exists, keep the ADR proposed and the dependent work blocked.
