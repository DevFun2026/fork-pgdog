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
4. Inspect full scope, providers, trusted base SHA, bytes/estimated tokens, profile, omitted-generated mappings, and manifest checksum; obtain exact approval. The runtime omits only copies whose blobs/modes match the changed canonical source at BOTH revisions, and retains the full-diff digest. Drift remains visible. Use light/standard/deep profiles; exceeding a budget blocks instead of truncating.
5. Confirm the host has `sandbox-exec` (macOS) or `bwrap` (Linux), then resume the same package with `--package` and `--approve-manifest`; only now may the runtime run its no-network/no-credential capability probe followed by the review.
6. Validate structured output, retain audit/findings, and route findings to `review-adjudication`.

## Stop conditions

- Stop before egress for secrets, denied paths, symlinks, oversized scope, provider identity conflict, missing/proposed/untrusted base, repository-contained provider executables or support files, caller-supplied host file/directory grants, inline interpreter commands, missing fresh verification, or checksum drift.

## Evidence

- Provider identities/versions, manifest, approval hash, audit record, structured findings, and status.

## Output

- Independent review result bound to immutable package contents.

## Failure behavior

- Missing CLI/OS sandbox, timeout, quota, invalid output, or mismatch is `review_pending`, never approval.
