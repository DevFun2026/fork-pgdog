---
name: test-driven-development
description: Use when implementing a behavior change or defect fix before production code is written.
---

# Test-Driven Development

Evidence begins with a test that fails for the intended reason.

## When to use

- Any product or runtime behavior is added, changed, or repaired.

## Do not use

- Do not use for content-only edits where no executable behavior exists; validate the artifact contract instead.

## Inputs

- Approved behavior, current tests, smallest relevant interface, and configured commands in `.agent/config.toml`.

## Steps

1. Write one focused test expressing the next observable behavior.
2. Run it and confirm failure is caused by missing behavior, not syntax, fixture, or environment failure.
3. Implement the smallest production change that can satisfy the test.
4. Re-run the focused test, then related tests, then `./scripts/agent verify quick --json`.
5. Refactor only while tests stay green; record exact RED and GREEN commands.

## Stop conditions

- Stop and restart the cycle if production behavior was written before a meaningful failing test.

## Evidence

- Failing output, passing output, changed paths, and gate result tied to the current diff.

## Output

- Minimal verified behavior with regression coverage.

## Failure behavior

- An immediately passing test is not RED evidence; improve it before implementation.
