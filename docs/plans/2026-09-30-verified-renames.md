# Verified rename review projection

## Approved contract and impact

The repository owner approved metadata-only packaging of unchanged Git renames
on 2026-09-30. The existing 96,000-token limit, exact manifest approval,
independent reviewer and merge gates remain mandatory.

Only a regular file deleted at the source and added at the destination with
identical Git blob ID AND mode may have its rename-only patch omitted. Both
paths remain visible through a prefix-compressed path table in the manifest.
Groups with more than eight entries use nested directory keys and null file
leaves to avoid repeated prefixes; the table still enumerates every file.
The full scope uses prefix-to-suffix lists on disk and expands to the original
complete sorted tuple during validation; legacy manifests retain their encoding.
A SHA-256 over sorted `[source, destination, mode, blob]` JSON rows binds the
proof; the full Git diff digest and full destination scope remain bound too.
Loading a package independently recomputes every proof from the two commits.
All changed-content and changed-mode patches remain in full.

## Threat model and alternatives

Assets: complete review scope, approval binding and content confidentiality.
Untrusted input: branch files, filenames and package metadata. Trusted evidence:
Git commit trees at the independently resolved base and head. Provider egress
contains only approved package files; local proof computation reads no host files.

Threats include forged omission tables, secret-bearing changed files disguised
as renames, symlink/mode changes, path quoting and legacy-manifest downgrades.
Only verified regular-file renames may bypass the sensitive filename check for
metadata, never for explicitly requested context. Denied repository directories
and unsafe/control-character paths remain blocked. Changed sensitive files stay
blocked. Hashes are provenance metadata, not a replacement for reviewing changes.

Raising the budget alone cannot resolve denied paths. Sending all fixture contents
would expand egress unnecessarily. Skipping review or accepting unverified rename
claims would weaken the gate. Prefix grouping keeps the complete path mapping
reviewable within the current budget without omitting changed code.

## Implementation sequence

1. Add RED tests in `.agent/tests/test_review_package.py` for unchanged moves,
   sensitive metadata only, changed blob/mode, symlinks, explicit context,
   tampered proofs and backward compatibility.
2. Extend `review/models.py` and `review/package.py` with an optional versioned
   proof; use NUL-delimited Git metadata and exact tree equality, then recompute
   during load. Preserve old manifests and their budget/instruction binding.
3. Document the contract in cross-review policy/skill and canonical project model;
   regenerate adapters and architecture docs.
4. Run focused and full runtime tests, application verification and all scanners;
   inspect package size and complete scope. Obtain approval of the final manifest
   before native AGY egress, adjudicate findings, run merge gate and merge PR #4.

Rollback: revert the projection implementation and generated documentation. Older
packages retain their original behavior; new packages must fail closed on a
runtime that cannot verify this proof. No application data migration is involved.
