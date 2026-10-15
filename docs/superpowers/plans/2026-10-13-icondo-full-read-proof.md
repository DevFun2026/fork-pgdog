# Full-table strict-read implementation

**Goal:** Prove every one of the 282 ordinary icondo table shapes while retaining
all client-write and unproven-function denials.

**Approved inputs:** [Specification](../specs/2026-10-13-icondo-full-read-proof.md),
explicit user approval "Duyệt đặc tả và triển khai" on 2026-10-13.

**Scope:** Dependency-aware metadata proof, reviewed projection types, ordinary
inheritance and reviewed index/extension profiles on PG12 and PG18. No production
DDL, Secret reads, TLS downgrade, cluster installation or 0.2.1 tag overwrite.

## Preflight

Preserve the original checkout's dirty work. Work in the existing isolated source
clone on `codex/icondo-full-read-proof`, base `3d2f6b272e87f8a8ce1f0e723af73f038689f1a0`.
Use private metadata captures only for local diagnosis. Fixtures and externally
reviewed tests must use synthetic names/data. Maintain deep workflow classification
for this authorization boundary; review/security/merge gates are mandatory.

## Task 1: Structural expression dependencies

Owner: gpt-6-luna worker `fullread_nodes`, new `read_policy/node_tree.rs` only.
Primary owns module declaration and runtime integration.

Write failing tests for valid PG12/PG18 expression nodes before parser code, then
bounded structural parser GREEN. Return explicit OID dependencies and typed context;
never authorize their safety. Cover boolean tests, operators/scalar arrays, casts,
functions, constants, Coalesce and relabel shapes. Reject malformed/unknown nodes,
fields, duplicate/missing fields, invalid OIDs/Vars/constants and resource excess.
Run standalone module tests where feasible, then integrated Cargo tests. Bind
fixtures to actual version-specific node formats from owned pinned servers.

## Task 2: Type and enum proof

Owner: gpt-6-luna worker `fullread_types`, new `read_policy/type_proof.rs` only.
Primary owns existing rows, registry, resolver and SQL integration.

Demonstrate RED for exact enum I/O/data-only metadata proof and explicit array
element closure, then GREEN. Keep projection, input and operation capabilities
separate. Bind dynamic metadata to a canonical digest; reject domains, unknown
types, mutable ownership/schema rights, bad enum labels and incomplete I/O.
Do not trust arbitrary C/STABLE functions or generate trust from the lab capture.

## Task 3: Reference profiles and closed dependencies

Owner: primary initially, then reusable bounded worker assignment after Tasks 1/2.
Files: `scripts/read_policy_registry.py`, its tests, both versioned registry files,
owned fixture tooling and synthetic SQL fixtures.

Write RED for profile selection/closure and output types missing from baseline.
Capture exact required built-in and reviewed pg_trgm/btree_gist dependency rows
from owned immutable PG12/PG18 installations. Explicitly verify module provenance,
member normalization, text-search configuration chains, range metadata, AM handlers,
operator selectivity/planner support and family callbacks. Missing/extra/mutated
rows deny. Preserve permajor registry isolation and existing baseline behavior.

## Task 4: Runtime relation proof and lifetime

Owner: primary, existing `read_policy/mod.rs`, `rows.rs`, `resolve.rs`, catalog SQL,
frontend proof identity/portal integration as required.

Write RED for supported constraints/indexes, types and ordinary inheritance plus
negatives that fail before client Parse. Replace blanket gates only after full
closure is available. Prove all implicitly scanned descendants with exact manifest
coverage. Add snapshot/dependency digests and implement catalog stability using the
approved controlled DDL contract and explicit revalidation; never assume a READ
COMMITTED transaction or ACCESS SHARE alone freezes index metadata.

Run malicious false-IMMUTABLE CHECK/index/predicate canaries, unknown support
functions/types/overloads, hidden descendants, dependency drift and prepared/portal
reuse. Keep all existing client mutation and protocol denials.

## Task 5: Complete acceptance and documentation

Run every synthetic reproduction table through full proof and actual read endpoint
SELECT under an eligible nonowner writer-capable role. Report exactly 282 proven
and zero excluded before claiming full inventory support. Verify both majors and
pooling/protocol profiles, output formats, canary snapshots and writer behavior.
Record any unprovable real dependency as a blocker rather than granting it.

Update canonical project model, focused operations/threat/security docs and
generated docs. Run related Rust/Python tests, format, Clippy and canonical quick
and merge checks. Broaden testing only for changed integration paths or failures.
Review the integrated diff independently; primary inspects assertions and results.

## Final review and handoff

Prepare exact bounded native AGY review package only after local verification.
Request its new manifest hash approval before egress; use logged-in host CLI.
Validate output, adjudicate findings, and run required security/CI/merge gates.
No stale review or prior release payload applies to this new revision.

Keep publication/deployment separate. Prepare a new immutable version/digest and
fresh owner receipt only when authorized and all gates pass. Backend TLS, frontend
TLS, controlled schema epoch and eligible role are still operator requirements.
On failure stop/deny readers; preserve previous artifacts and never route the read
Service to the unrestricted writer. No runtime safety claim based only on worker
success or a coarse metadata screen.

## Post-integration verification repair — 2026-10-14

The full gate exposed stale source-bound review context and workspace proof tests
that require profile fixtures before the strict-read phases create them. Refresh
the canonical context hashes and semantic excerpts, keeping the source-byte
validator, then regenerate the architecture output.

Reuse the existing owned pinned profile producer around the entire workspace
nextest command in `scripts/workspace_read_tests.py`; update `scripts/verify-pgdog`
to invoke it. Keep generated references, matrices and variants temporary. Do not
commit raw captures or skip fixture-backed assertions. Demonstrate lifecycle tests
RED/GREEN in `.agent/tests/test_workspace_read_tests.py`: preparation precedes
Cargo, missing required files block it, ambient fixture paths are replaced,
failure exit codes survive, and temporary files are removed on every exit.

Run the real owned generator and workspace tests, then the complete canonical
review gate at the final commit. Preserve failed evidence and obtain a fresh
partition manifest approval; infrastructure clearance still does not clear the
feature. These repairs change verification orchestration and source context,
without changing SQL admission or granting additional function capabilities.
