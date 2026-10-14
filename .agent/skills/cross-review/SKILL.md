---
name: cross-review
description: Use when a completed change requires review by an available model provider independent from the provider that authored it.
---

# Cross Review

Independence and exact manifest approval are mandatory.

## When to use

- Merge policy requires a reviewer provider different from the author provider.

## Do not use

- Do not use the author provider as reviewer or send repository content without exact package approval.

## Inputs

- Author identity, base/head refs, requirements, approved context paths, verification summary, and provider capability report.

## Steps

1. Fetch the remote default branch and ensure `refs/remotes/origin/HEAD` exists; the runtime must resolve it to a proper ancestor of `HEAD` and reject caller-selected `HEAD` or intermediate bases.
2. Optionally run `./scripts/agent doctor --providers --json` to inspect available independent reviewers; its capability probes must run without provider credentials or network access.
3. Run `./scripts/agent verify review --json`, then run `./scripts/agent review` without approval to build and preview a bounded `.agent/.runs/review-*` package without executing or probing a provider.
4. Inspect full scope, providers, trusted base SHA, bytes/estimated tokens, profile, omitted-generated mappings, verified-rename path tables, and manifest checksum; obtain exact approval. Generated copies require equal blobs/modes to the changed canonical source at BOTH revisions. Versioned rename tables require identical regular-file blobs/modes, source deletion and destination addition; they bind every mapping and a checksum recomputed from Git on load. Sensitive names may appear only as metadata for verified moves, never as context or changed content. The full-diff digest remains bound, and all content/mode changes stay visible or blocked by egress policy. Use light/standard/deep profiles; exceeding a budget blocks instead of truncating.
5. For opt-in `--partitioned`, require trusted-base enablement, full byte reconstruction, every child budget and the aggregate ceiling. Preview the root manifest and explicit `--integration-context` contracts; obtain its exact approval before child probes. After all children complete, preview the integration package containing their validated outputs/audit hashes and obtain its separate exact manifest approval. Child results cannot grant merge clearance, and integration cannot override a failed or incomplete child.
6. Confirm the host has `sandbox-exec` (macOS) or `bwrap` (Linux), then resume the same package with `--package` and `--approve-manifest`; only now may the runtime run its no-network/no-credential capability probe followed by the review.
7. Validate structured output, retain audit/findings, and route findings to `review-adjudication`.

## Stop conditions

- Stop before egress for secrets, denied paths, symlinks, oversized scope, provider identity conflict, missing/proposed/untrusted base, repository-contained provider executables or support files, caller-supplied host file/directory grants, inline interpreter commands, missing fresh verification, or checksum drift.

## Evidence

- Provider identities/versions, manifest, approval hash, audit record, structured findings, and status.

## Output

- Independent review result bound to immutable package contents.

## Failure behavior

- Missing CLI/OS sandbox, timeout, quota, invalid output, or mismatch is `review_pending`, never approval.

## Terminal child retries

An incomplete invocation is not a PASS. Never delete its marker or overwrite
its audit/output to make it dispatchable. An explicitly supervised invocation
that ended with exit 0 but without a valid verdict may produce a terminal
receipt. Preview a separate retry manifest binding that receipt, the original
child artifacts, complete input inventory, transport prompt/argv/executable/model
identities, attempt limit and root/base/head. Obtain its exact hash approval
before probing or dispatching the new attempt. The root operation lock protects
retry and normal dispatch alike.

Retain the original package and use a new clone and attempt record. Integration
and clearance reload the selected attempt, its approval/receipt and every prior
binding. Retry payloads count toward existing aggregate budgets; passing children
are retained unchanged. A valid fail verdict, timeout, interrupted/unknown
invocation, changed evidence or missing terminal receipt cannot use this retry
path. Historical native audits without process supervision stay pending. Native
host execution needs explicit human authorization and never implies OS isolation
or permission to enable provider tools.
