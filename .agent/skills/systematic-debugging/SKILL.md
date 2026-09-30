---
name: systematic-debugging
description: Use when a test, command, integration, or runtime behaves unexpectedly and the root cause is not yet demonstrated.
---

# Systematic Debugging

Prove the cause before changing behavior.

## When to use

- Failures are intermittent, surprising, multi-layered, or tempt speculative fixes.

## Do not use

- Do not apply a fix when the task requested diagnosis only.

## Inputs

- Exact failure, reproduction command, environment, recent diff, logs, and relevant `.agent/.runs/evidence/`.

## Steps

1. Reproduce with the smallest deterministic command and preserve raw symptoms safely.
2. Separate product failure from environment, permissions, network, credentials, or test-fixture failure.
3. Trace inputs and state backward to the first divergence; form one falsifiable hypothesis.
4. Change one variable or add targeted instrumentation to test that hypothesis.
5. After root-cause evidence, write a failing regression test and fix through the normal test-driven cycle.

## Stop conditions

- Stop after repeated identical blockers when no new safe evidence path remains and user input or external state is required.

## Evidence

- Reproduction, observations, falsified hypotheses, root cause, and regression proof.

## Output

- Root-cause explanation and, only when authorized, a verified minimal fix.

## Failure behavior

- If reproduction is impossible, report a bounded hypothesis and the missing evidence instead of claiming a cause.
