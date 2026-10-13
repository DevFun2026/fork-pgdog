# Full-read local verification — 2026-10-14

Status: local behavioral verification passed; independent AGY, Standard security,
CI and merge/release clearance are still pending. No image/chart was published
and no Kubernetes deployment was changed for this feature.

## Reproduction and scope

The private schema-only inventory contains 282 ordinary table shapes, 4,670
columns, 1,013 indexes, 670 source constraints and 17 inheritance edges.
The owned fixtures use synthetic names and data with an eligible nonowner,
writer-capable application role. Source metadata and private fixtures remain
local; this report includes no application rows, SQL literals or credentials.
These tests do not certify the live icondo application's role, ACLs or TLS.

The final full structural proof admitted 282 and denied zero. All 67 stored
expression roots matched canonical owned PostgreSQL trees on both PG12 and PG18,
with zero mismatches. Type, modifier/rank, index, constraint and inheritance
metadata were separately checked against the owned reproduction on both majors.

## Final local results

| Check | Result |
| --- | --- |
| PG12 transaction endpoint, final rebuilt binary | 282/282 reads; 4,670 columns |
| PG18 session endpoint, final rebuilt binary | 282/282 reads; 4,670 columns |
| Complementary PG12 session / PG18 transaction runs | 282/282 reads each, before the final mechanical API/style cleanup |
| Text and binary output | Nonempty JSONB, text/numeric/date/int arrays and enum values passed on both majors |
| Negative endpoint cases | 9/9 denied per major; DML, DDL, unknown function and unsafe CHECK/index/predicate callbacks |
| Side effects and writer | Zero advisory-lock canaries; authorized writer DML passed |
| Source shape / canonical expression tests after refactor | 2/2 explicitly run ignored local helpers passed |
| PG18 canonical fixture, final binary | 2 baseline + 19 protocol + 172 core passed; 3 private diagnostic helpers ignored |
| PG12 transaction, query-parser off, prepared-statements full | 19/19 protocol passed |
| Related Python suites | 56 profile/compiler tests + 18 fixture-isolation tests passed |
| Canonical quick | format, all-workspace/all-target Clippy with `-D warnings`, configured changed tests passed |
| Generated docs / adapters | Current |

The 3 ignored core helpers are local diagnostics, not counted as passing core
tests. The structural and canonical helpers were explicitly run separately;
the fixed-table diagnostic was not a required acceptance gate. Owned endpoint
runs used a 30-second fixture query timeout; they are correctness checks, not a
production latency or default-timeout guarantee. Final exhaustive runs took
approximately 433 seconds on PG12 and 472 seconds on PG18 on the local host.

## Remaining gates

Eight new immutable profile files total 12,150,542 bytes. The trusted review
policy currently permits 2,500,000 aggregate bytes and its atom splitter supports
only the historical registry envelopes. No AGY package was sent and no review
clearance was fabricated. A bounded review-infrastructure proposal is pending
user design approval before this larger full-scope package can be prepared.

The canonical merge/security/CI/release gates have not passed for this revision.
Keep the controlled schema-epoch drain/restart requirement: ACCESS SHARE and
recapture do not freeze concurrent DBA or native-library changes. Eligible role,
backend/frontend TLS, and operator configuration remain deployment prerequisites.
Published 0.2.1 artifacts are unchanged and cannot claim this new behavior.
