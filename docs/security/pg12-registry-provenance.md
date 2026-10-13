# PostgreSQL 12 strict-read reference

The candidate registry was seeded offline from a complete catalog capture of an
owned official PostgreSQL 12.22/bookworm container. No icondo or shared database
was queried. The reference container had no published ports and `--network none`;
its private initialization credential was not included in the capture. The owned
container was removed after capture.

| Identity | Captured value |
| --- | --- |
| Official image index | `postgres:12.22-bookworm@sha256:2f2a8c2a7d10862e7fba2602e304523554f9df8244c632dafe2628ccb398fb5c` |
| Actual server | `12.22 (Debian 12.22-1.pgdg120+1)` |
| Actual version number | `120022` |
| Capture platform | `linux/arm64` |
| Full reference capture SHA-256 | `fa5c43772da7ed9368046d2a845f6f61612aa1a3b8030390674c76252b4d6a3c` |
| Selected registry SHA-256 | `4e6474a721a9e4302c41439b06a6cad5f0f26ab38129edc72f189db1d84eef31` |
| Retained PG18 registry SHA-256 | `acf8a44a1dc1da47607cb4ca7ddff2959e1fab0917b95c1d31bfce87df1e837b` |

Capture UUID and actual server/platform are embedded in the candidate registry.
Local reference JSON, image index and capture helper are retained under ignored
`.agent/.runs/pg12/`; those private operational files are not CI prerequisites.

All eleven complete tables were captured with `to_jsonb` and the same explicit
OID/regproc/text representations used by the fixed runtime catalog query. PG12's
absent `typsubscript` field was not fabricated. Candidate generation selects the
existing scalar gate, scalar casts, candidate aggregate/operator overloads,
btree/hash classes/families/support members and transitive I/O/support dependencies.
Missing dependency rows deny generation. Selected rows are not permission for
arbitrary functions/types; the local resolver still enforces the narrow SQL gate.

| Catalog | Full capture rows | Selected closure rows |
| --- | ---: | ---: |
| pg_type | 406 | 24 |
| pg_proc | 2960 | 939 |
| pg_operator | 770 | 530 |
| pg_aggregate | 136 | 44 |
| pg_cast | 216 | 62 |
| pg_am | 7 | 2 |
| pg_collation | 813 | 3 |
| pg_opclass | 128 | 42 |
| pg_opfamily | 107 | 30 |
| pg_amop | 715 | 210 |
| pg_amproc | 447 | 108 |

Offline regeneration from this full reference is:

```sh
python3 scripts/read_policy_registry.py --postgres-major 12 \
  --seed-reference .agent/.runs/pg12/reference-pg12.json --output /tmp/registry-pg12.json
```

The capture establishes provenance of the reference data. It does not establish
passing runtime, protocol, managed-provider, minor-version or deployment tests.
Those require their own fresh evidence. Never refresh a registry from application
catalog rows merely to make a policy denial disappear.
