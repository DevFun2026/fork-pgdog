#!/usr/bin/env python3
"""Refresh strict-read's pinned PG18 metadata from an owned fixture capture.

The capture must come from the repository's locally pinned PostgreSQL image.
This tool is offline: it reads one capture artifact, validates complete OID
closure against the existing reviewed selection, and atomically writes the
registry consumed by the strict-read resolver.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "applications/pgdog/pgdog/src/backend/schema/read_policy/registry-pg18.json"
PIN_SOURCE = ROOT / "tests/artifacts/kubernetes/postgres.yaml"
TABLES = (
    "pg_type", "pg_proc", "pg_operator", "pg_aggregate", "pg_cast", "pg_am",
    "pg_collation", "pg_opclass", "pg_opfamily", "pg_amop", "pg_amproc",
)
CANDIDATE_FUNCTION_NAMES = {"count", "sum", "avg", "min", "max"}
CANDIDATE_OPERATOR_NAMES = {
    "=", "<>", "<", "<=", ">", ">=", "+", "-", "*", "/", "%", "^",
    "||", "~~", "!~~", "~~*", "!~~*",
}


def pinned_image() -> str:
    content = PIN_SOURCE.read_text(encoding="utf-8")
    match = re.search(r"image:\s*(postgres:18@sha256:[0-9a-f]{64})\b", content)
    if not match:
        raise ValueError("repository PostgreSQL 18 image pin is missing or malformed")
    return match.group(1)


def oid_key(table: str) -> str:
    return "aggfnoid" if table == "pg_aggregate" else "oid"


def row_oids(table: str, rows: list[dict]) -> list[int]:
    key = oid_key(table)
    try:
        values = [int(row[key]) for row in rows]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"capture contains malformed {table} OID metadata") from error
    if any(value <= 0 or value > 0xFFFFFFFF for value in values):
        raise ValueError(f"capture contains invalid {table} OID")
    if len(values) != len(set(values)):
        raise ValueError(f"capture contains duplicate {table} OIDs")
    return values


def refresh(capture_path: Path, output_path: Path) -> None:
    expected = json.loads(REGISTRY.read_text(encoding="utf-8"))
    captured = json.loads(capture_path.read_text(encoding="utf-8"))
    if captured.get("postgres_major") != expected.get("postgres_major"):
        raise ValueError("capture PostgreSQL major does not match the pinned registry")
    image = pinned_image()
    if captured.get("source_image") != image or expected.get("source_image") != image:
        raise ValueError("capture provenance does not match the repository image digest")
    tables = captured.get("tables")
    if not isinstance(tables, dict) or set(tables) != set(TABLES):
        raise ValueError("capture must include exactly the reviewed catalog tables")

    for table in TABLES:
        rows = tables[table]
        old_rows = expected.get("tables", {}).get(table)
        if not isinstance(rows, list) or not isinstance(old_rows, list):
            raise ValueError(f"missing {table} catalog rows")
        if sorted(row_oids(table, rows)) != sorted(row_oids(table, old_rows)):
            raise ValueError(f"capture {table} OID closure differs from reviewed selection")
        rows.sort(key=lambda row: int(row[oid_key(table)]))

    expected["tables"] = tables
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output_path.parent,
                                     prefix=f".{output_path.name}.", delete=False) as handle:
        temp_path = Path(handle.name)
        json.dump(expected, handle, separators=(",", ":"), sort_keys=True)
        handle.write("\n")
    temp_path.replace(output_path)


def seed_candidates(reference_path: Path, output_path: Path) -> None:
    expected = json.loads(REGISTRY.read_text(encoding="utf-8"))
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    image = pinned_image()
    if reference.get("postgres_major") != expected.get("postgres_major"):
        raise ValueError("reference PostgreSQL major does not match the pinned registry")
    if reference.get("source_image") != image or expected.get("source_image") != image:
        raise ValueError("reference provenance does not match the repository image digest")
    source_tables = reference.get("tables")
    if not isinstance(source_tables, dict):
        raise ValueError("reference catalog is missing table rows")

    by_oid = {name: {int(row[oid_key(name)]): row for row in rows}
              for name, rows in source_tables.items()}
    scalar_types = {16, 17, 20, 21, 23, 25, 700, 701, 1042, 1043, 1082, 1083,
                    1114, 1184, 1186, 1266, 1700, 2950}
    operator_symbols = set(CANDIDATE_OPERATOR_NAMES)
    names = set(CANDIDATE_FUNCTION_NAMES)

    def integer(row: dict, field: str) -> int:
        return int(row.get(field, 0))

    def rows(table_name: str, oids: set[int]) -> list[dict]:
        return [by_oid[table_name][oid] for oid in sorted(oids) if oid in by_oid[table_name]]

    selected: dict[str, list[dict]] = {name: [] for name in TABLES}
    selected["pg_type"] = rows("pg_type", scalar_types)
    selected["pg_cast"] = [row for row in source_tables["pg_cast"]
                            if integer(row, "castsource") in scalar_types
                            and integer(row, "casttarget") in scalar_types]
    selected["pg_opclass"] = [row for row in source_tables["pg_opclass"]
                               if integer(row, "opcintype") in scalar_types
                               and integer(row, "opcmethod") in {403, 405}]
    family_ids = {integer(row, "opcfamily") for row in selected["pg_opclass"]}
    selected["pg_opfamily"] = [row for row in source_tables["pg_opfamily"]
                                if integer(row, "oid") in family_ids]
    selected["pg_amop"] = [row for row in source_tables["pg_amop"]
                            if integer(row, "amopfamily") in family_ids]
    selected["pg_amproc"] = [row for row in source_tables["pg_amproc"]
                             if integer(row, "amprocfamily") in family_ids]
    methods = {integer(row, "opcmethod") for row in selected["pg_opclass"]}
    selected["pg_am"] = [row for row in source_tables["pg_am"] if integer(row, "oid") in methods]
    selected["pg_collation"] = [row for row in source_tables["pg_collation"]
                                 if integer(row, "oid") in {100, 950, 951}]

    candidate_procs = {integer(row, "oid") for row in source_tables["pg_proc"]
                       if row.get("proname") in names}
    selected["pg_proc"] = rows("pg_proc", candidate_procs)
    agg_ids = {integer(row, "oid") for row in selected["pg_proc"]
               if row.get("prokind") == "a"
               and all(int(oid) in scalar_types | {2276}
                       for oid in row.get("proargtypes", "").split())}
    selected["pg_aggregate"] = [row for row in source_tables["pg_aggregate"]
                                if integer(row, "aggfnoid") in agg_ids]
    operator_ids = {integer(row, "oid") for row in source_tables["pg_operator"]
                    if row.get("oprname") in operator_symbols}
    operator_ids.update(integer(row, "amopopr") for row in selected["pg_amop"])
    operator_ids.update(integer(row, "aggsortop") for row in selected["pg_aggregate"])
    while True:
        before = set(operator_ids)
        for oid in before - {0}:
            row = by_oid["pg_operator"].get(oid)
            if row is not None:
                operator_ids.update((integer(row, "oprcom"), integer(row, "oprnegate")))
        if before == operator_ids:
            break
    selected["pg_operator"] = rows("pg_operator", operator_ids - {0})

    function_ids = set(candidate_procs)
    for table_name, fields in (
        ("pg_type", ("typinput", "typoutput", "typreceive", "typsend", "typmodin",
                      "typmodout", "typanalyze", "typsubscript")),
        ("pg_operator", ("oprcode", "oprrest", "oprjoin")),
        ("pg_cast", ("castfunc",)),
        ("pg_aggregate", ("aggtransfn", "aggfinalfn", "aggcombinefn", "aggserialfn",
                           "aggdeserialfn", "aggmtransfn", "aggminvtransfn", "aggmfinalfn")),
        ("pg_am", ("amhandler",)),
        ("pg_amproc", ("amproc",)),
    ):
        for row in selected[table_name]:
            function_ids.update(integer(row, field) for field in fields)
    while True:
        before = set(function_ids)
        for oid in before - {0}:
            row = by_oid["pg_proc"].get(oid)
            if row is not None:
                function_ids.add(integer(row, "prosupport"))
        function_ids.discard(0)
        if before == function_ids:
            break
    selected["pg_proc"] = rows("pg_proc", function_ids)

    # Include transition, opclass, and operator input/result types required by
    # the selected dependency rows, plus scalar public types and their arrays.
    type_ids = set(scalar_types)
    for table_name, fields in (
        ("pg_opclass", ("opcintype", "opckeytype")),
        ("pg_amop", ("amoplefttype", "amoprighttype")),
        ("pg_aggregate", ("aggtranstype", "aggmtranstype")),
    ):
        for row in selected[table_name]:
            type_ids.update(integer(row, field) for field in fields)
    type_ids.discard(0)
    type_ids.update(integer(row, "typelem") for row in rows("pg_type", type_ids) if integer(row, "typelem"))
    selected["pg_type"] = rows("pg_type", type_ids)

    # Expand type I/O after selecting closure types; every such function row is
    # compared at runtime even when the type is only an aggregate transition.
    for row in selected["pg_type"]:
        for field in ("typinput", "typoutput", "typreceive", "typsend", "typmodin",
                      "typmodout", "typanalyze", "typsubscript"):
            function_ids.add(integer(row, field))
    function_ids.discard(0)
    while True:
        before = set(function_ids)
        for oid in before:
            row = by_oid["pg_proc"].get(oid)
            if row is not None:
                function_ids.add(integer(row, "prosupport"))
        function_ids.discard(0)
        if before == function_ids:
            break
    selected["pg_proc"] = rows("pg_proc", function_ids)
    # Include all source-proven cast candidates and complete hash/btree planner
    # support closures. Row records are refreshed from a live pinned fixture.
    expected["tables"] = {name: selected[name] for name in TABLES}

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output_path.parent,
                                     prefix=f".{output_path.name}.", delete=False) as handle:
        temp_path = Path(handle.name)
        json.dump(expected, handle, separators=(",", ":"), sort_keys=True)
        handle.write("\n")
    temp_path.replace(output_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, nargs="?", help="owned local fixture catalog capture JSON")
    parser.add_argument("--seed-reference", type=Path,
                        help="offline pinned full-catalog JSON used to add candidate OIDs before capture")
    parser.add_argument("--output", type=Path, default=REGISTRY)
    args = parser.parse_args()
    try:
        output = args.output.expanduser().resolve()
        if args.seed_reference is not None:
            seed_candidates(args.seed_reference.expanduser().resolve(), output)
            print(f"Seeded candidate OIDs from pinned reference: {output}")
        elif args.capture is not None:
            refresh(args.capture.expanduser().resolve(), output)
            print(f"Updated complete strict-read registry: {output}")
        else:
            parser.error("provide a capture or --seed-reference")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
