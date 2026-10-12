# Restore native AGY review authentication

Authority: user correction on 2026-10-06 explicitly requests AGY CLI review,
rather than requiring a Gemini API key. The previously approved governance
payload remains immutable; changing its provider identity or contents still
requires exact manifest approval.

## Contract and security impact

Keep `agy` and the explicit Gemini-only model selection. Do not synthesize
`modelProvider: gemini` settings that select a direct API backend. Retain the
disposable HOME, package read-only sandbox, output/schema validation and existing
environment allowlist. Do not mount host HOME, copy tokens, read credentials in
the assistant, or grant additional host file access. Native CLI authentication
may use its existing host keyring; actual readiness must be established by the
authorized invocation, not inferred from help/model-list output.

The correction removes an authentication-mode override. It does not add filesystem
grants or bypass the OS sandbox. The model slug remains the provider-independence
control. Unknown authentication, unavailable model, malformed output and timeout
remain pending. Native provider authentication is distinct from permission for
the reviewer agent to inspect private credential files.

Threat-model delta:

| Threat | Retained control / evidence |
| --- | --- |
| AGY selects a different model family | Explicit Gemini slug validation and no headless model fallback; inspect invocation/result metadata. |
| Native login exposes host profile files to model tools | Disposable HOME, no host HOME/token mounts, unchanged package-only file grants; native authentication is performed by the CLI. |
| Transport correction silently changes approved content | Reload the immutable package, reconstruct its Git projection and preserve its exact manifest; record runtime correction independently. |
| A capability probe is treated as a successful review | Only matching audit plus schema-valid findings can complete review; missing auth and timeout remain pending. |

Residual verification gap: host keyring access and actual native authentication
must be exercised under the existing sandbox. No new filesystem permissions are
inferred from model-list success, and no credential file is inspected by the agent.

## Sequence and evidence

1. Add focused RED tests for absence of forced API settings in macOS and Linux
   provider sandboxes; preserve disposable HOME and model checks.
2. Remove only synthetic API-mode setup; demonstrate GREEN on provider tests and
   retain any unrelated environment failures as separate blockers.
3. Correct `docs/antigravity.md`; lint, syntax and relevant governance checks.
4. Use the tested transport with the existing immutable governance package/root,
   record the corrected runtime digest separately, and invoke the exact approved
   Gemini manifest through AGY native. No source or approval hashes are changed.
5. Validate audit/schema/findings, adjudicate concrete findings, and retain the
   authentication correction as a separate source change with its normal
   verification and review. Primary owns integration, commit and publication.

Ownership: worker owns provider sandbox implementation, provider tests and AGY
documentation; primary owns integration, immutable package checks, review execution
and result adjudication. Preserve all existing feature/governance dirty work.

Rollback: revert the isolated authentication override removal; do not change
global AGY settings or erase existing reviews/approvals.

## Current execution result (2026-10-06)

Focused sandbox tests: 2/2 passed. Provider suite: 24/25 passed when run with the
native sandbox permitted; the existing Node dependency-bearing capability probe
failed. Documentation generation/check and `git diff --check` passed.
`verify quick` remains blocked by the Rust lint command (exit 101).

The exact approved manifest was first invoked inside the normal sandbox; AGY
requested OAuth and timed out after 60 seconds. The user then explicitly
authorized one native-host invocation to test the already logged-in CLI. That
invocation exited 0 and returned `SUCCESS`, schema-valid `pass`, and zero
findings. Independent checks matched its returned schema and structured result,
confirmed both repeated terminal JSON objects agreed, and verified the approved
package was unchanged. This is manual host-review evidence under a one-time
exception; it does not establish that OAuth works in the normal sandbox.

The original audit remains `review_pending`: the first response had explanatory
prose before two identical terminal JSON objects, which the adapter then
rejected. The parser now permits prose only before the first object and requires
every following terminal object to match the strict structured result; it
rejects conflicting or malformed objects and trailing content. The full
Antigravity suite passed 16/16, including the native sandbox sentinel. Adapter
and generated-document checks passed. Host login reuse within the default
sandbox remains unverified; the adapter does not force API-key mode.
