# Threat model: <project>

## Scope and version

Record the repository revision, change scope, approved security profile, and
the evidence reviewed.

## Assets

List code, credentials, user or business data, build artifacts, audit evidence,
and availability requirements.

## Actors and capabilities

Describe maintainers, users, CI workers, provider CLIs, dependencies, and
attackers without assuming that repository or model output is trustworthy.

## Trust boundaries and data flows

For each crossing, name source, destination, data categories, authorization,
validation, storage, retention, and possible egress.

## Abuse cases and mitigations

Cover prompt injection, command injection, path traversal, symlink escape,
credential exposure, untrusted imports, dependency compromise, artifact
tampering, privilege misuse, replay, races, and recovery failure.

## Delta for this change

State added, removed, or changed assets, actors, boundaries, and flows. If none
changed, provide evidence supporting that conclusion.

## Unverified areas and residual risks

Separate verified controls from assumptions and risks accepted by a human.
