# PostgreSQL 12 support for strict-read endpoints

Date: 2026-10-13
Status: Approved by the user on 2026-10-13, with explicit instruction to implement,
review through host AGY and publish 0.2.1 only if all required gates pass.
This document does not itself assert implementation or validation success.
Baseline inspected: `66832bfa7bf8800d8b3a806ab6ca0fb50d29f5f1`.

## Requested outcome

Extend the existing strict-read boundary to PostgreSQL 12, preserving PostgreSQL
18 support. The user explicitly requires rejecting every client data/schema/
sequence mutation and every function whose safety has not been established.
Build and publish a new image and Helm chart after the required gates pass.
The proposed new version is `0.2.1`; existing published `0.2.0` artifacts remain
immutable. Publication of a version already present in GHCR is forbidden.

Prepare separate read and write releases for database and alias `icondo`, backend
`staging-postgres.database.svc.cluster.local:5432`, namespace `database`.
Application credentials continue to pass through over mandatory TLS; the users
file remains empty. Actual cluster installation requires an identified context,
TLS material/backend CA, eligible-table inventory and controlled schema revision.
These are missing operator inputs, not prerequisites to implementing or testing
PG12 support in owned fixtures.

## Existing boundary and confirmed incompatibilities

This extends the approved [strict-read design](2026-10-05-strict-read-write-endpoints-design.md).
The existing AST/protocol admission, PgDog-owned acknowledged READ ONLY
transactions, same-backend catalog proof, immutable manifest and schema epoch,
application-role restrictions, bounded diagnostics and denial recovery remain
mandatory. The contract concerns client mutations, not PostgreSQL housekeeping
or temporary query work. PostgreSQL binaries/built-ins, DBAs and controlled DDL
remain trusted; arbitrary native extensions or a malicious DBA are outside it.

Current runtime embeds only `registry-pg18.json` and rejects other majors. Its
catalog SQL additionally references `pg_type.typsubscript` and
`pg_statistic_ext.stxexprs`, which are absent from PostgreSQL 12's catalog definitions:
[pg_type](https://www.postgresql.org/docs/12/catalog-pg-type.html),
[pg_statistic_ext](https://www.postgresql.org/docs/12/catalog-pg-statistic-ext.html).
This source inspection is not a live PG12 compatibility result.

## Selected architecture

1. Embed separately reviewed complete PG12 and PG18 catalog registries. Select
   one immutable registry context only after reading the actual backend version
   through the existing fixed identity query inside its protected transaction.
   Supported majors are exactly 12 and 18; every other major denies. A malformed
   or unavailable registry also denies.
2. Carry the selected context through catalog loading, column/type-I/O checks,
   dependency closure, type/cast/operator/aggregate resolution and proof identity.
   Selection is per backend snapshot, never a mutable process-global major.
   A proof from one backend/version/transaction must not authorize another.
3. Keep fixed, bound-parameter catalog SQL contracts for each supported major.
   PG12 must not reference absent fields or fabricate PG18 fields. Preserve full
   comparison of every real selected catalog row and exact expected row counts
   across all eleven catalogs. No field stripping or mismatch-as-success.
4. Preserve the existing dependency and candidate-set closure checks, including
   type I/O, casts, operators, aggregates, btree/hash support, overload/shadowing,
   schema mutability, role/ownership, relation and index checks. Represent absent
   PG12 facilities with reviewed version-specific checks, not an unchecked
   default. Do not add arbitrary SELECT functions or expand the SQL/object surface.
5. Generate PG12 metadata only from an owned official PostgreSQL 12 fixture pinned
   by immutable digest. Record exact version, platform, capture identity and
   reviewed selection. Offline tooling must enforce major, digest, complete table
   inventory, uniqueness and dependency closure. Never learn a new allowlist from
   `icondo` to suppress a denial. Retain PG18 registry bytes unless separately
   justified and reviewed.

The recommended approach extends the existing catalog-proof design. A version
check bypass cannot satisfy it. Replacing the endpoint boundary with database
roles alone would change the approved same-account read/write contract and is
outside this task.

## Observable acceptance criteria

- On actual pinned PG12 and PG18 fixtures, the same DML-capable, nonowner,
  nonprivileged application account can perform supported SELECTs on the read
  endpoint and DML on the unrestricted write endpoint. Exercise joins, subqueries,
  scalar casts/operators and count/sum/avg/min/max within the proven surface.
- On each version's strict-read endpoint, all existing DML/DDL, modifying CTE, SELECT INTO, locking SELECT,
  COPY, unsafe startup/SET/role/protocol and prepared-identity denials remain.
  Check backend data/schema/sequence snapshots for absence of client mutations.
- Unknown functions deny even if marked IMMUTABLE or wrapped in SELECT. Include
  user functions, overload/shadowing canaries, nextval and set_config; show that
  direct qualified controls can cause the tested side effect where applicable.
- Missing/changed/extra selected catalog metadata, unsupported types/objects,
  unsafe roles, incomplete dependency closure and unknown majors deny. A minor
  version or provider-specific catalog mismatch never silently widens acceptance.
- Mixed-major snapshot/resolver tests prove selection isolation. Stale proof,
  parameter I/O, named/unnamed preparation, suspended portals, transaction failure,
  cancellation and pool reuse retain the existing transaction/connection boundary.
- Run each major with the existing all/default profile and the protocol profile
  using transaction pooling, parser off and full prepared statements. Every fixed
  catalog query must execute successfully under the least-privilege fixture role.
  Add PG12 paired Helm/Kind smoke; retain PG18 coverage and test disjoint Services,
  mandatory TLS, passthrough, read denial and successful write/read visibility.
- Required quick/merge, Standard security, independent AGY review and release
  checks must bind the actual new revision. Missing or stale evidence does not pass.

## Release and deployment

Update focused operations/validation docs, project model and threat-model delta;
regenerate architecture docs. Extend fixture/CI pin selection without removing
PG18 coverage. The two releases use the same newly verified immutable image digest:

| Release | Policy | Endpoint |
| --- | --- | --- |
| pgdog-read | strict-read | pgdog-read-fork-pgdog.database.svc.cluster.local:6432 |
| pgdog-write | unrestricted | pgdog-write-fork-pgdog.database.svc.cluster.local:6432 |

Prepare PG12-aware operator inputs and values for icondo. "Read all" means the
exact inventory of currently eligible ordinary tables; it does not authorize
wildcards or automatically admit new tables. Existing unsupported views, custom
types, RLS, foreign/partitioned tables and constraint/index cases still deny;
report inventory exclusions before routing application traffic.

Use the existing release workflow for native amd64/arm64 builds, required tests
and scans, exact archive publication, signature/attestation verification and
digest-paired Helm chart pull-back. Independently verify anonymous image/chart
blob access before reporting public availability. New AGY content still requires
its exact manifest approval; new owner-release receipts require their exact
payload approval. Prior version-bound approvals are not relabeled. A waived SSH
clearance, if approved through the existing owner path, is never reported as a
normal signed canonical release gate pass.

## Rollback and residual limits

Stop/drain read traffic around schema/role/catalog changes; restart with the
reviewed manifest and epoch. On mismatch, keep the read endpoint denying or stop
it. Never repoint the read Service to the unrestricted writer or roll back to
0.2.0 while claiming it supports PG12. Preserve manifests, values, evidence and
artifact digests independently of Helm history. Write access remains governed
by PostgreSQL grants and reachability of the write/backend paths.

Actual icondo catalog/provider compatibility and driver SQL remain unverified
until tested against the identified staging environment. This feature does not
change PostgreSQL 12's upstream support lifecycle or certify the database server.
