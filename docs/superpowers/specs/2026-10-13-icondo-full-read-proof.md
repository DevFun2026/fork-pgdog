# Full-table strict-read support for icondo

Date: 2026-10-13
Status: Approved by the user on 2026-10-13: "Duyệt đặc tả và triển khai".
This records implementation authority, not a verification or release result.
Source baseline: `3d2f6b272e87f8a8ce1f0e723af73f038689f1a0`.
Implementation branch: `codex/icondo-full-read-proof`, isolated from the original
checkout's pre-existing changes.

## Requested outcome and correction

The user requests that the read endpoint can read every ordinary table in
`icondo`, while rejecting every client write and every function whose safety has
not been established. The earlier PG12 specification's qualification of "read
all" as only already-eligible tables does not satisfy this request. This document
supersedes that eligibility limitation; it preserves the strict-read protocol,
role, transaction, and credential-passthrough contract.

The read/write endpoints still target the same database and PostgreSQL server.
The write endpoint remains subject to PostgreSQL privileges. No automatic
replica routing, credentials embedded in configuration, or production DDL is
introduced by this fix.

## Diagnosis and evidence

Metadata-only inspection of the explicitly identified staging backend found
282 ordinary user tables on PostgreSQL 12.19. The current coarse screen excludes
208 and leaves 74 without a coarse blocker; the latter count is not a completed
application-role or query proof. The overlapping exclusion groups are:

| Current blanket gate | Tables excluded |
| --- | ---: |
| Foreign-key, CHECK, or exclusion constraint | 181 |
| Column types outside the scalar registry | 72 |
| Expression, partial, or non-default/non-btree index | 35 |
| Relation flags, including inheritance | 18 |

Removing the constraint ban alone leaves 82 tables excluded. The inventory has
JSONB, four array types and one application enum. It has 17 ordinary inheritance
edges, without declarative partitions, RLS, or rewrite rules. Index metadata
includes GIN, GiST and hash alongside btree, expression/partial indexes, built-in
text-search configurations and extension support from `pg_trgm` 1.4 and
`btree_gist` 1.5. Merely installing another extension does not authorize it.

Evidence is retained privately under `.agent/.runs/pg12/` as
`icondo-full-read-diagnosis.json`, `icondo-index-inheritance-diagnosis.json`,
`icondo-extension-constraint-diagnosis.json`, and the prior coarse screen.
These captures contain catalog metadata, not application rows. Raw schema names,
DDL and catalog captures must not be included in external review without a
separately previewed, explicitly approved package. Public fixtures use synthetic
names and data. No actual read endpoint installation has been performed.

Root-cause locations are `catalog-pg12.sql` and `catalog.sql`, which require
plain default btree indexes and reject constraints, and `rows.rs`, which rejects
inheritance and non-scalar column types. Resolver/output checks independently
restrict types, so relaxing catalog SQL alone is insufficient.

## Security boundary and alternatives

The selected direction replaces category bans with complete, bounded proofs of
the objects PostgreSQL can invoke when planning and executing an admitted read.
It expands the reviewed surface to the actual type/index families needed by this
inventory. It does not accept a function merely because it is named like a
built-in, is in `pg_catalog`, or is declared IMMUTABLE/STABLE.

An unconditional constraint/index bypass is rejected: PostgreSQL can simplify
CHECK expressions and index predicates/expressions during planning. A falsely
IMMUTABLE user function can run before execution or before an index is selected.
Forcing sequential scans, changing planner GUCs, or relying only on a READ ONLY
transaction therefore does not meet the function boundary. See PostgreSQL's
[volatility contract](https://www.postgresql.org/docs/12/xfunc-volatility.html)
and [planner constraint inspection](https://github.com/postgres/postgres/blob/REL_12_STABLE/src/backend/optimizer/util/plancat.c).

Changing or deleting the application's indexes/types/constraints to fit the old
allowlist would alter database semantics and requires a separate migration. It
is not part of this fix. A narrower FK-only patch cannot achieve full-table read.

Trusted PostgreSQL binaries, explicitly reviewed extension binaries, DBAs, and
controlled DDL remain assumptions. An application role must not own or be able
to change any proven object. Reviewable metadata cannot establish the integrity
of malicious server binaries. Vendor/version differences must be demonstrated
compatible, never learned automatically from the live database to silence a
denial.

## Required proof architecture

1. **Separate capabilities.** Distinguish projection/output type safety, input
   decoding, client SQL operations, planner expression evaluation and index
   support. An internal index callback profile does not automatically admit a
   client function call. Existing unknown stored-function denials stay intact.
2. **Versioned reference profiles.** Capture complete relevant catalog rows and
   dependency closure from owned, immutable PG12 and PG18 fixtures. Retain exact
   major-specific selection and provenance. Add JSONB and the needed array,
   range, text-search and index support explicitly; arrays recursively prove
   their element types. Check I/O, casts, operators, collations, access-method
   handlers, opclasses/families, `amop` and `amproc` support. Include planner
   support and operator selectivity callbacks, range subtype/canonical/subdiff
   metadata and cross-type family members. No broad C-language or STABLE-function
   permission is introduced.
3. **Data-only enum proof.** A database-local enum OID is not a new static
   trusted built-in. Validate complete type metadata, ownership/schema rights,
   exact reviewed core enum I/O, and all label OIDs/order/value metadata. Bind a
   canonical digest to the proof. Enum comparisons, ordering, grouping and
   parameters require their own proven capabilities; projection alone grants
   none of these implicitly. Unknown base types and domains still deny.
4. **Planner-visible expression proof.** Parse serialized catalog expression
   trees using strict, major-aware structural schemas. Extract explicit type,
   function, operator, cast and collation identities, and prove every node's
   admitted semantics and closure. Reject unknown nodes/fields, malformed input,
   inconsistent identities and exceeded resource limits. Bound input bytes,
   depth, nodes and list lengths; reject duplicate/missing fields, overflow,
   unsupported constant encodings and dangling/whole-row/system Vars. Bind root
   types and Vars to the specific CHECK, index key or predicate context. Do not
   evaluate the expression, run EXPLAIN, trust deparsed SQL, or use regex as the proof.
   `pg_depend` alone is insufficient because pinned built-ins can lack dependency
   edges. Use it as additional evidence, not as the complete expression graph.
5. **Complete relation closure.** Check all potentially planner-visible CHECK
   constraints, index expressions/predicates and exclusion support before
   forwarding a client Parse. Prove FK operator/reference-index support without
   assuming SELECT fires FK triggers. Support ordinary inheritance by recursively
   proving every implicitly scanned descendant against the exact reviewed table
   manifest. Detect cycles, missing children and closure growth past limits.
   Take required relation locks before catalog proof and recheck closure. Retain
   bans on RLS, rules, views, foreign tables and declarative partitioning until
   separately designed; the inspected target has none of these cases.
6. **Explicit extension profiles.** Admit only reviewed `pg_trgm` and `btree_gist`
   versions/members needed for these index paths, using complete normalized
   metadata and dependency identities from pinned reference installations.
   Extension-local OIDs are resolved and checked, not copied from icondo into an
   allowlist. Check membership, namespace, signatures, handler/support identity,
   library/procedure identity, reviewed binary provenance and ownership. Catalog
   metadata alone does not prove the integrity of an extension shared object.
   Unknown versions, altered members,
   missing support and custom callbacks deny. Text search additionally proves
   configuration, dictionary and template/lexize dependencies; a known
   `to_tsvector` function alone is insufficient.
7. **Proof lifetime.** Bind relation, inheritance, enum and dependency digests to
   backend/role identity, major, manifest, controlled schema epoch and transaction.
   No proof may authorize another connection, role, major or dependency state.
   Preserve the existing drain/epoch/restart requirement for controlled DDL;
   a READ COMMITTED transaction counter alone is not a catalog-stability proof.
   ACCESS SHARE alone does not freeze concurrent index creation or all dependency
   changes. Define and test the complete stabilization/invalidation contract;
   concurrent DDL is prohibited during admitted read traffic unless the new
   protocol demonstrably prevents every proof-to-planning race.
   Prepared/portal reuse must revalidate at the required boundary. Missing proof,
   metadata drift or inability to lock/revalidate denies before client planning.

The proof uses fixed, qualified, bound-parameter catalog queries. It reads no
function bodies or application rows merely to decide trust. Resource limits and
denial recovery must be deterministic, bounded and covered by tests. SQL errors
must not disclose sensitive catalog content to clients.

## Acceptance and verification

- In an owned schema-only reproduction using synthetic rows and the actual
  type/index/constraint/inheritance shapes, every one of the 282 inventory
  entries must pass full proof and supported `SELECT *` on the read endpoint
  under the same eligible DML-capable nonowner role used by the writer. This is
  an exhaustive table requirement, not a 74- or 200-table sample. Report exact
  proven/denied totals and reasons. Future tables require manifest/epoch review.
- Exercise text, numeric/date/int/text arrays, JSONB and enum text/binary output;
  joins and existing supported predicates/aggregates must remain compatible.
  Exercise inherited rows, partial/expression indexes, text search, GIN, GiST,
  hash and exclusion support. Run PG12 and PG18 with both existing strict
  protocol/pooling profiles and mixed-major isolation tests.
- Preserve every existing DML/DDL, modifying CTE, SELECT INTO, locking SELECT,
  COPY, sequence, unsafe startup/SET/role and protocol denial. Unknown functions
  deny, including IMMUTABLE/STABLE, SECURITY DEFINER, wrapped, overloaded and
  qualified user functions. Verify side-effect canaries and data/schema/sequence
  snapshots rather than trusting error text alone.
- Add malicious function canaries inside CHECK, unused index expressions and
  predicates, exclusion/operator support, enum/type I/O and text-search
  dictionaries. Demonstrate that unguarded planning can trigger an applicable
  canary, then show guarded Parse is rejected before it triggers. Include hidden
  unsafe inheritance children and missing/extra/tampered profile metadata.
- Test malformed expression nodes, missing pinned-object dependencies, extension
  version/member drift, graph bounds, changing enum labels, schema-epoch drift,
  parameter/result-format differences, preparation, suspended portals and pool
  reuse. A stale or incomplete proof must never become a successful query.
- Demonstrate relevant RED before production changes, then GREEN. Run matching
  canonical quick/merge checks, Standard security, CI, and independent native
  AGY review with a new exact manifest approval. Update project model, operations,
  threat delta and generated documentation; inspect primary integration evidence.

If the complete inventory contains a genuinely unproven dependency, the endpoint
must reject it. The release cannot be described as full-table support until all
282 actual shapes are proven. Such a conflict must be reported for a separately
reviewed profile or schema change, never silently bypassed.

## Release, deployment and rollback

Published 0.2.1 artifacts remain immutable. A subsequent release needs fresh
source-bound gates and release authority; this specification does not approve
reusing the 0.2.1 review package or owner payload. Prepare both endpoint values
against the new verified digest once available.

Actual staging deployment remains separate: backend SSL is currently off, while
the prepared configuration requires verified backend TLS and frontend TLS for
credential passthrough. No TLS downgrade, PKI mutation, database restart or Helm
installation is authorized by this guard fix. A controlled schema revision and
eligible application role are also required before live acceptance.

On any failed proof or compatibility check, leave read traffic stopped/denied.
Rollback stops/drains readers and restores the previous immutable image and
manifest/epoch; it does not claim the old image can read all tables. Never point
the read Service at the unrestricted writer as a workaround.
