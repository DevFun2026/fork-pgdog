# Template final acceptance review

Date: 2026-09-22

Branch: `feat/agent-template-v1`

Evidence: `docs/evidence/template-acceptance.json`

## Outcome

The template is locally verified and ready for an independent branch review
before push. No acceptance criterion is known blocked. Fourteen criteria are
verified locally, five are partially verified, and one is unverified. Hosted CI,
real release clearance, dependency inventory, and provider authentication are
kept separate from deterministic local evidence.

## Criteria

1. **Partially verified — clean macOS and Linux doctor.** Clean-export doctor and smoke
   pass on macOS. The GitHub Actions matrix defines both `macos-latest` and
   `ubuntu-latest`, but the branch has not yet produced hosted results.
2. **Verified — init is tooling-only.** The end-to-end fixture runs `init`, then
   reaches merge-ready without modifying fixture product source.
3. **Verified — shared canonical policy and skills.** Canonical `.agent/`
   sources generate thin Claude, Gemini, and Codex adapters; native skill bodies
   are byte-compared to the canonical bodies.
4. **Verified — adapter drift.** `./scripts/agent adapters check` passes and
   mutation tests prove drift is detected.
5. **Verified — every mock cross-review direction.** Acceptance runs all six
   ordered author/reviewer pairs through the production adapters and immutable
   manifest approval flow.
6. **Verified — cross-review fails closed.** Tests cover same-provider review,
   missing CLI/OS sandbox, secrets, path escape, package limits/checksums,
   malformed output, exact Linux support-file mounts, macOS package-read and
   outside-file denial sentinels, unrelated environment-secret exclusion,
   repository-local executable/support rejection, pre-sandbox inline-command
   rejection, arbitrary host file/directory grant rejection, dependency-bearing
   Node CLI execution in the real sandbox, bounded provider output, zero provider
   probe before manifest approval, no-network/no-credential capability probing,
   and incomplete provider execution. Provider commands and package limits come
   from the trusted-base configuration.
7. **Verified — stale evidence rejection.** Commit, worktree diff, configured
   scanner set, scanner-output checksum, and changed memory-evidence tests reject
   stale or tampered evidence. Scanner identity changes when a path-based support
   script, flag-value support file, or explicitly declared recursively manifested
   support directory changes. Scan-target directories remain evidence inputs,
   not tool-identity inputs; timeout and exit-code semantics must agree.
8. **Partially verified — quick, merge, and release gates.** Passing, blocked,
   incomplete, missing-command, stale-artifact, adjudication, required-scanner,
   optional-scanner, runtime-derived scanner, strict scanner-output binding, and
   threat-model-delta logic is covered. A real configured project release with
   independent security clearance has not run.
9. **Verified — security boundaries.** Path, redaction, private memory,
   permissions, command argument, OS read sandbox, package, signed approval,
   profile, trusted remote-base anchoring, empty/intermediate-base rejection, and
   threat-boundary tests pass.
10. **Partially verified — governance artifacts.** Architecture, contracts,
    operations, security, ADR-0001, threat model, traceability, and bound runtime
    evidence are present. Independent security approval remains project-specific.
11. **Verified — deterministic generated files.** Determinism tests plus exact
    adapter and docs drift checks pass for `system.html`, `system-summary.md`,
    and provider outputs.
12. **Partially verified — source/license provenance.** Eight declared sources
    have pinned revision, license, and adaptation-boundary metadata. This audit
    does not claim a full dependency or transitive-license inventory.
13. **Unverified — hosted CI execution.** Contract tests prove GitHub Actions and
    GitLab CI call the same local runtime, materialize the remote default-branch
    anchor, and a shallow-clone integration test proves the gate fails before and
    succeeds after that anchor is fetched. Neither hosted pipeline result was
    available at the time of this report.
14. **Verified — canonical provider memory.** All provider adapters route memory
    startup through the same `.agent` runtime and canonical record store.
15. **Verified — focused session bootstrap.** Character-bounded bootstrap tests
    provide useful selected context without repository-wide scanning.
16. **Verified — progressive disclosure.** Search, timeline, and show have
    separate tested output boundaries.
17. **Verified — privacy.** Secret and `<no-memory>` tests prove excluded content
    does not reach SQLite, indexes, startup context, or exports; checksum-valid
    imported content is redacted again before persistence.
18. **Verified — memory governance.** Imports remain untrusted candidates,
    promotion requires evidence, stale records are excluded, and policy-like
    memory is rejected.
19. **Verified — complete README workflow.** README covers initialization,
    memory, architecture/HTML, immutable cross-review approval, CI, merge,
    release, and recovery.
20. **Partially verified — real-CLI boundary report.** Historical public-fixture
    runs found Claude unauthenticated, Gemini unauthenticated, and Codex capable
    of schema-valid read-only output. Current sandboxed capability probes pass
    for the installed Claude and Codex CLIs; Gemini is absent. Historical review
    executions are not counted as current passes. Repository source was not used
    for those smokes.

## Findings resolved during acceptance

- Merge and release evidence is now bound to the exact HEAD, diff, manifest,
  findings checksum, source checksum, and clean-worktree state where applicable.
- Review, cross-review, and security evidence must share the immutable fetched
  remote-default base SHA. `HEAD`, equal-head, and intermediate feature bases
  are rejected before package creation or security assessment. Provider commands,
  review limits, minimum security profile, and baseline required scanners cannot
  be weakened by the candidate branch.
- Provider review executes from an isolated allowlisted package inside a
  fail-closed macOS/Linux read sandbox; package/outside-path and environment
  sentinels prove the macOS boundary. Repository-contained executables/support
  files, caller-selected host file/directory grants, and inline interpreter/module
  commands are rejected before probing;
  dependency-bearing script bundles are mounted read-only, while broad bundle
  roots such as home, shared temporary, world-writable, and system roots are
  rejected; Linux command paths
  are rewritten to exact mounts with only explicit network-resolution files;
  and provider output is bounded before parsing. Package preview performs no
  provider execution; the post-approval capability probe has no proxy settings,
  network access, or provider credentials. Proxy values are included in output
  redaction for real reviews.
- Security assessment uses an explicit base/head diff and cannot become
  clearance without a strict, independent SSH signature over the complete
  assessment plus digest from a signer trusted by the base revision; release
  recomputes that assessment from Git/config.
- Required scanners come from reviewed command arrays and are executed by the
  runtime. Each result derives process status/tool identity and binds the exact
  HEAD, worktree diff, command checksum, an explicit configured version command,
  executable/direct/flag-value/declared-support checksums, strict non-boolean
  output types, consistent timeout/exit semantics, timestamp, and output checksum.
- Protected GitHub and GitLab gates fetch full default-branch history and set the
  immutable remote HEAD anchor before governance verification. GitHub uses an
  ephemeral job token for the protected fetch while checkout credential
  persistence remains disabled, including for private repositories.
- `verify review` now creates fresh lint/test/build evidence before package
  creation without depending on an expected-failing merge gate.
- Project Memory derives freshness from Git, validates promotion provenance,
  recursively redacts exports, and imports records transactionally.
- `init --answers` now provides deterministic reviewed initialization without
  modifying product source.
- `system.html` now embeds contracts, ADRs, security, operations, observability,
  recovery, and requirement traceability.

- Codex JSONL can contain progress messages before the terminal structured
  result. The adapter now selects exactly one schema-valid terminal result and
  has a regression test.
- Provider failure audits now retain a redacted diagnostic excerpt.
- Clean-export tests now force-track `.gitignore`, so user-level global ignore
  rules cannot invalidate the fixture.
- Workflow status now imports and returns the canonical `WorkflowState` rather
  than failing at runtime.

## Remaining verification

- Push the branch and require the GitHub Actions macOS/Linux matrix to pass.
- Run the GitLab pipeline when the template is mirrored or imported there.
- Authenticate/configure available providers, then run a non-sensitive complete
  review through the new OS sandbox before claiming any current real-CLI review
  pass. Current version/help capability probes alone are not review evidence.
- Exercise release readiness on a real configured project with independent
  security approval and required scanners.
