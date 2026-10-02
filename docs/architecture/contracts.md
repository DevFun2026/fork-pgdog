# Interfaces and contracts

- `.agent/config.toml` is the versioned project configuration. Commands are argument arrays and never shell strings.
- `.agent/project-model/*.toml` is the canonical architecture model used to generate the system views.
- `.agent/schemas/*.json` defines provider findings, evidence, memory, and documentation-impact payloads.
- `.agent/.runs/` contains local, commit-bound gate artifacts; it is evidence, not project source.
- Review packages contain only the approved diff, manifest, policy, requirements, verification summary, schema, and explicit context files.
- `.agent/memory/records/` contains reviewed, versioned memory. Private candidates and indexes remain local.
- Memory retrieval ranks partial Unicode lexical matches with title/component weights; startup selects architecture, constraints, decisions and workflow records. Default retrieval is top-5 and bounded by 4,000 characters / 1,200 estimated tokens, excluding private and stale records.
- Review manifests bind the full scope and full Git diff hash plus the projected diff. Only native skill copies equal in blob and mode to a changed canonical file at both endpoints are omitted. Every resume/merge recomputes proof; generated HTML and divergent copies remain visible.
- Context profiles light/standard/deep bound retrieval and review payload estimates; see `docs/context-efficiency.md`. Estimates are UTF-8 bytes divided by three, rounded up, not provider billing. Oversized reviews fail before provider execution.
- Planning tiers do not change merge/release gates or authorize state transitions. Content-only policy/security changes still require full impact review.
- `workflow guide --task interface` recommends the relevant UX/UI phase under standard context; it does not load every skill or change gates. Four provider-neutral UX/UI skills extend the 21 core skills. Their local references and artifact templates link evidence, journey/state IDs, design master/page deltas, implementation and review coverage. See `docs/ux-ui.md`.
- Adapted UX/UI documentation is pinned and attributed in `.agent/sources/UX_UI_AUDIT.md`; native projections retain local licenses. No upstream installer, binary, database, remote guideline loader or hook is part of this extension. Missing research or browser evidence stays unverified; local UX review never supplies cross-provider independence or accessibility certification.

All consumers fail closed on unknown configuration, malformed payloads, stale hashes, provider identity collisions, or artifacts bound to another Git state.

## Fork artifacts

The source Dockerfile builds binary/plugin with Cargo.lock, numeric UID/GID 10001,
SIGINT and explicit full source revision without shipping Git/private context.
The closed-schema chart requires one TOML source and existing users Secret,
uses one image for configcheck/main, and keeps fixed selectors, secret mounts,
TCP startup/liveness, HTTP readiness and bounded drain. External object updates
and restoration require explicit operator action; stateless 2PC WAL is not durable.

Artifact check/scanner inputs bind source tree and actual loaded image config.
Manual publish consumes a bounded owner-approved receipt of the genuine existing
pre-integration release gate. Native tested OCI archives are copied unchanged;
combined digest/signatures precede chart-last publication. Existing immutable
tags and ambiguous/auth/network registry failures block. See the operational and
release contracts in docs/operations/containers-and-helm.md and docs/releases/fork-artifacts.md.
