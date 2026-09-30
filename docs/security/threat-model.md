# Threat Model

## Scope

This model covers the template runtime, canonical policy and skills, local
Project Memory, generated documentation, review packages, provider CLI
processes, and CI wrappers. Product repositories created from the template must
replace or extend this model for their own assets and deployment.

## Assets and actors

Assets include repository source, Git history, configuration, provider prompts,
review evidence, canonical memory, private local memory, credentials available
to the host, and release artifacts. Actors include the project owner, coding
agents, independent reviewer providers, local provider CLIs, hosted CI runners,
dependencies, and an attacker able to contribute untrusted repository content.

## Trust boundaries and data flows

- The repository boundary separates versioned policy from the host filesystem.
- `.agent/.memory/` and `.agent/.runs/` are private local plaintext stores.
- Review packages cross from the local repository to a selected provider CLI
  only after a manifest preview and exact-hash approval.
- Provider output crosses back as untrusted structured data and is validated.
- CI runners execute the same repository runtime in a separate hosted boundary.

## Threats and controls

- Prompt injection in source or memory: content is treated as data; memory
  cannot override policy; review providers receive a fixed policy.
- Command injection: commands are argument arrays executed with `shell=False`.
- Path traversal and symlink escape: repository containment is checked before
  reads or writes.
- Secret leakage: deny rules, bounded packages, redaction, private blocks, and
  manifest approval run before provider invocation.
- Review-package tampering: the manifest binds diff, context, requirements,
  verification, policy, and schema; checksums are revalidated on resume.
- Hidden generated changes: deduplication compares regular-file modes and Git
  blobs at both base/head, only against a changed canonical source. Full scope
  and full-diff hash remain bound and projection is recomputed before execution
  and merge. Divergence, unsupported file modes, and unproven copies are reviewed.
- Context exhaustion: bounded ranked memory and estimated-token review caps
  reduce payloads; review overflow blocks rather than silently omitting changes.
  Token estimates exclude provider-internal prompts, repeated reads and output.
- Untrusted memory import: imported records remain candidates until reviewed.
- Supply-chain compromise: license, dependency, and provenance checks are
  release inputs, while unsupported checks remain explicitly unverified.

## Residual risks

### Antigravity migration delta

AGY can select Claude as well as Gemini: the Gemini adapter pins/validates a
Gemini model to preserve cross-provider identity. Its JSON parser requires a
successful terminal status and schema-validated findings, rejecting conflicting
response fields. Plan mode is advisory; the OS sandbox remains the read/write
boundary. A canonicalized disposable HOME fixes macOS temporary-path aliases
without granting new host directories. Only minimal API-key-mode settings are
created there; no host profile, plugin config or OAuth token store is imported.
The provider environment is reduced to `GEMINI_API_KEY` plus common runtime
variables. API-key backend/model compatibility still needs live verification.

Native migration deletes only unchanged manifest-owned retired outputs and
blocks path escapes/symlinks. AGY hooks consume only bounded invocation metadata,
never follow transcript paths, and inject memory as data. Stop does not restart
the agent or persist learning without review. Hook UI visibility is best effort.

Provider and scanner defects can miss vulnerabilities. Local plaintext depends
on host permissions and full-disk security. A compromised maintainer or CI
credential can bypass repository process. Real product runtime and deployment
remain outside this template-only assessment.
