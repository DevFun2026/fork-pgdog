---
name: project-bootstrap
description: Use when starting a repository from this template or adopting the template into an existing project.
---

# Project Bootstrap

Establish the smallest reviewed configuration before product work begins.

## When to use

- A repository has no approved `.agent/config.toml` or project model.
- The project exposure, data, commands, and security profile are undecided.

## Do not use

- Do not use for routine feature setup after project governance is approved.

## Inputs

- Repository root, product intent, supported environments, data categories, and executable project commands.

## Steps

1. Inspect without mutating source and run `./scripts/agent doctor --json`.
2. Propose configuration, exposure, credentials, data categories, provider policy, and `baseline`, `standard`, or `high` security profile.
3. Obtain explicit human approval before recording governance choices.
4. Populate `.agent/config.toml`, `.agent/project-model/`, and focused architecture/security documents.
5. Run quick verification and report anything not configured.

## Stop conditions

- Stop before changing product source or lowering an approved security profile.

## Evidence

- Doctor output, approved choices, changed paths, and quick-gate result.

## Output

- Reviewed configuration and project model with explicit remaining decisions.

## Failure behavior

- Missing facts remain open decisions; unavailable checks never become passes.
