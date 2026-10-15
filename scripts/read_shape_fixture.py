"""Compile a private relation capture into a synthetic, incomplete DDL skeleton.

This module is deliberately offline. It never connects to PostgreSQL and never
copies captured identifiers, enum labels, or expression text into generated SQL.
The returned lineage maps are intended for a separate, proof-aware expression
remapper; pending constraints and indexes are retained rather than implied safe.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


class ShapeError(ValueError):
    """The input is incomplete, ambiguous, or outside the reviewed type subset."""


MAX_RELATIONS = 1000
MAX_ATTRIBUTES = 50000
MAX_ENUM_LABELS = 256
MAX_HEAP_ATTRIBUTE_NUMBER = 1600

# OIDs are intentionally the reviewed core scalar and array output set only.
BUILTIN_TYPES = {
    16: ("bool", "pg_catalog.bool"),
    17: ("bytea", "pg_catalog.bytea"),
    20: ("int8", "pg_catalog.int8"),
    21: ("int2", "pg_catalog.int2"),
    23: ("int4", "pg_catalog.int4"),
    25: ("text", "pg_catalog.text"),
    700: ("float4", "pg_catalog.float4"),
    701: ("float8", "pg_catalog.float8"),
    1042: ("bpchar", "pg_catalog.bpchar"),
    1043: ("varchar", "pg_catalog.varchar"),
    1082: ("date", "pg_catalog.date"),
    1083: ("time", "pg_catalog.time"),
    1114: ("timestamp", "pg_catalog.timestamp"),
    1184: ("timestamptz", "pg_catalog.timestamptz"),
    1186: ("interval", "pg_catalog.interval"),
    1266: ("timetz", "pg_catalog.timetz"),
    1700: ("numeric", "pg_catalog.numeric"),
    2950: ("uuid", "pg_catalog.uuid"),
    3802: ("jsonb", "pg_catalog.jsonb"),
    1007: ("_int4", "pg_catalog.int4[]"),
    1009: ("_text", "pg_catalog.text[]"),
    1182: ("_date", "pg_catalog.date[]"),
    1231: ("_numeric", "pg_catalog.numeric[]"),
}

_OID_RE = re.compile(r"^[0-9]+$")
_OPERATOR_TOKEN_RE = re.compile(r"^[~!@#%^&|`?+*/<>=-]{1,63}$")


def _oid(value: Any, label: str, *, zero: bool = False) -> int:
    if type(value) is int:
        result = value
    elif isinstance(value, str) and _OID_RE.fullmatch(value):
        result = int(value)
    else:
        raise ShapeError(f"invalid {label}")
    if result < (0 if zero else 1) or result > 0xFFFFFFFF:
        raise ShapeError(f"out-of-range {label}")
    return result


def _int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is int:
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"-?(0|[1-9][0-9]*)", value):
        parsed = int(value)
    else:
        raise ShapeError(f"invalid {label}")
    if not minimum <= parsed <= maximum:
        raise ShapeError(f"invalid {label}")
    return parsed


def _rows(capture: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = capture.get(key)
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ShapeError(f"missing or malformed {key}")
    return value


def _truth(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ShapeError(f"invalid {label}")
    return value


def _enum_label_count(labels: list[dict[str, Any]]) -> int:
    if not labels or len(labels) > MAX_ENUM_LABELS:
        raise ShapeError("unsupported enum label count")
    seen_oids: set[int] = set()
    orders: set[float] = set()
    for row in labels:
        seen_oids.add(_oid(row.get("oid"), "enum label OID"))
        order = row.get("enumsortorder")
        if type(order) not in (int, float) or not float("-inf") < float(order) < float("inf"):
            raise ShapeError("invalid enum order")
        if order in orders:
            raise ShapeError("duplicate enum order")
        orders.add(order)
        if not isinstance(row.get("enumlabel"), str):
            raise ShapeError("invalid enum label metadata")
    if len(seen_oids) != len(labels):
        raise ShapeError("duplicate enum label OID")
    return len(labels)


def _synthetic_labels(count: int) -> list[str]:
    if count > MAX_ENUM_LABELS:
        raise ShapeError("unsupported enum label count")
    return (["alpha", "beta"] +
            [f"label_{index:03d}" for index in range(3, count + 1)])[:count]


def _numeric_modifier(typmod: int) -> str:
    if typmod < 0:
        return "numeric"
    packed = typmod - 4
    precision = (packed >> 16) & 0xFFFF
    scale = packed & 0x7FF
    if scale & 0x400:
        scale -= 0x800
    if not 1 <= precision <= 1000 or not -1000 <= scale <= 1000:
        raise ShapeError("unsupported numeric typmod")
    return f"numeric({precision},{scale})"


def _interval_modifier(typmod: int) -> str:
    if typmod < 0:
        return "pg_catalog.interval"
    # PostgreSQL's INTERVAL_RANGE is the upper 16-bit portion and
    # INTERVAL_PRECISION is the lower 16-bit portion (utils/timestamp.h).
    fields = (typmod >> 16) & 0x7FFF
    precision = typmod & 0xFFFF
    ranges = {
        0x0002: "YEAR",
        0x0004: "MONTH",
        0x0006: "YEAR TO MONTH",
        0x0008: "DAY",
        0x0010: "HOUR",
        0x0020: "MINUTE",
        0x0040: "SECOND",
        0x0018: "DAY TO HOUR",
        0x0038: "DAY TO MINUTE",
        0x0078: "DAY TO SECOND",
        0x0030: "HOUR TO MINUTE",
        0x0070: "HOUR TO SECOND",
        0x0060: "MINUTE TO SECOND",
        0x7FFF: "",
    }
    if fields not in ranges:
        raise ShapeError("unsupported interval typmod")
    range_text = ranges[fields]
    if precision != 0xFFFF:
        if precision > 6 or (fields != 0x7FFF and "SECOND" not in range_text):
            raise ShapeError("unsupported interval precision")
        if range_text:
            range_text += f"({precision})"
        else:
            return f"interval({precision})"
    return "interval" + (f" {range_text}" if range_text else "")


def _type_sql(type_oid: int, typmod: int, dimensions: int,
              types: dict[int, dict[str, Any]], enum_names: dict[int, str]) -> str:
    if type_oid not in types:
        raise ShapeError("attribute type metadata is missing")
    if type_oid in enum_names:
        if typmod != -1 or dimensions != 0:
            raise ShapeError("enum typmod/dimensions unsupported")
        sql = enum_names[type_oid]
    elif type_oid in BUILTIN_TYPES and type_oid not in (1007, 1009, 1182, 1231):
        if dimensions != 0:
            raise ShapeError("scalar type has array dimensions")
        sql = BUILTIN_TYPES[type_oid][1]
        if type_oid == 1700:
            sql = _numeric_modifier(typmod)
        elif type_oid in (1042, 1043) and typmod >= 0:
            length = typmod - 4
            if not 1 <= length <= 10485760:
                raise ShapeError("unsupported character typmod")
            sql = f"{sql}({length})"
        elif type_oid == 1083 and typmod >= 0:
            if typmod > 6:
                raise ShapeError("unsupported time typmod")
            sql = f"pg_catalog.time({typmod})"
        elif type_oid == 1266 and typmod >= 0:
            if typmod > 6:
                raise ShapeError("unsupported time typmod")
            sql = f"pg_catalog.timetz({typmod})"
        elif type_oid in (1114, 1184) and typmod >= 0:
            if typmod > 6:
                raise ShapeError("unsupported timestamp typmod")
            if type_oid == 1184:
                sql = f"pg_catalog.timestamptz({typmod})"
            else:
                sql = f"pg_catalog.timestamp({typmod})"
        elif type_oid == 1186 and typmod >= 0:
            sql = _interval_modifier(typmod)
    elif type_oid in BUILTIN_TYPES and type_oid in (1007, 1009, 1182, 1231):
        sql = BUILTIN_TYPES[type_oid][1]
        expected_element = {1007: 23, 1009: 25, 1182: 1082, 1231: 1700}[type_oid]
        row = types.get(type_oid)
        if row is None or _oid(row.get("typelem"), "array element OID", zero=True) != expected_element:
            raise ShapeError("array type metadata mismatch")
        dimensions = max(1, dimensions)
        if dimensions > 6:
            raise ShapeError("unsupported array dimensions")
        sql = BUILTIN_TYPES[expected_element][1] + "[]" * dimensions
        if expected_element == 1700:
            sql = _numeric_modifier(typmod) + "[]" * dimensions
    else:
        # Domains, pseudo-types, unknown built-ins and unreviewed arrays deny.
        raise ShapeError("unreviewed attribute type")
    if type_oid in types:
        meta = types[type_oid]
        if meta.get("typtype") == "d":
            raise ShapeError("domain attribute type denied")
        if meta.get("typtype") == "p":
            raise ShapeError("pseudo-type attribute denied")
    return sql


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ShapeError("value cannot be canonically encoded") from error


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ShapeError(f"invalid {label}")
    return '"' + value.replace('"', '""') + '"'


def _qualified_identifier(value: Any, label: str) -> str:
    if not isinstance(value, list) or len(value) != 2:
        raise ShapeError(f"invalid {label}")
    return ".".join(_identifier(part, label) for part in value)


def _operator_reference(value: Any) -> str:
    if not isinstance(value, list) or len(value) != 2:
        raise ShapeError("invalid exclusion operator identity")
    schema = _identifier(value[0], "exclusion operator schema")
    token = value[1]
    if (not isinstance(token, str) or not _OPERATOR_TOKEN_RE.fullmatch(token)
            or "--" in token or "/*" in token or "*/" in token
            or (token.endswith(("+", "-")) and not re.search(r"[~!@#%^&|`?]", token))):
        raise ShapeError("invalid exclusion operator token")
    return f"OPERATOR({schema}.{token})"


def _proof_oid_map(rows: list[dict[str, Any]], key: str, label: str) -> dict[int, dict[str, Any]]:
    result = {}
    for row in rows:
        oid = _oid(row.get(key), label)
        if oid in result:
            raise ShapeError(f"duplicate {label}")
        result[oid] = row
    return result


_CONSTRAINT_PROOF_FIELDS = (
    "contype", "conrelid", "confrelid", "conkey", "confkey", "conpfeqop", "conppeqop",
    "conffeqop", "confmatchtype", "confupdtype", "confdeltype", "condeferrable",
    "condeferred", "convalidated", "conislocal", "coninhcount", "connoinherit",
    "conindid", "conparentid",
)
_OPTIONAL_CONSTRAINT_PROOF_FIELDS = ("confdelsetcols", "conperiod", "conexclop")
_SUPPORTED_INDEX_METHODS = {"btree", "gin", "gist", "hash"}


def _verified_expression_map(capture: dict[str, Any], proof: dict[str, Any]) -> dict[tuple[str, int], list[str]]:
    expected: dict[tuple[str, int], dict[str, Any]] = {}
    for row in capture["constraints"]:
        oid = _oid(row.get("oid"), "constraint OID")
        source = row.get("conbin")
        if source:
            if not isinstance(source, str):
                raise ShapeError("constraint expression source is malformed")
            expected[("pg_constraint.conbin", oid)] = {
                "relation_oid": _oid(row.get("conrelid"), "constraint relation OID"),
                "digest": hashlib.sha256(source.encode("utf-8")).hexdigest(),
                "count": 1,
            }
    for row in capture["indexes"]:
        oid = _oid(row.get("indexrelid"), "index OID")
        relid = _oid(row.get("indrelid"), "index relation OID")
        for field in ("indexprs", "indpred"):
            source = row.get(field)
            if source:
                if not isinstance(source, str):
                    raise ShapeError("index expression source is malformed")
                count = 1
                if field == "indexprs":
                    keys = row.get("indkey")
                    if not isinstance(keys, list):
                        raise ShapeError("index key vector is malformed")
                    count = sum(_int(attnum, "index attribute number", 0,
                                     MAX_HEAP_ATTRIBUTE_NUMBER) == 0 for attnum in keys)
                    if count == 0:
                        raise ShapeError("index expression has no expression key")
                expected[(f"pg_index.{field}", oid)] = {
                    "relation_oid": relid,
                    "digest": hashlib.sha256(source.encode("utf-8")).hexdigest(),
                    "count": count,
                }

    entries = proof.get("expressions")
    if not isinstance(entries, list) or len(entries) != sum(item["count"] for item in expected.values()):
        raise ShapeError("expression proof inventory mismatch")
    actual: dict[tuple[str, int], list[tuple[int, str]]] = defaultdict(list)
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
                "catalog", "source_field", "object_oid", "relation_oid", "source_sha256",
                "source_ordinal", "sql"}:
            raise ShapeError("malformed expression proof")
        catalog = entry.get("catalog")
        field = entry.get("source_field")
        if catalog not in ("pg_constraint", "pg_index") or not isinstance(field, str):
            raise ShapeError("unsupported expression proof source")
        key = (f"{catalog}.{field}", _oid(entry.get("object_oid"), "expression object OID"))
        if key not in expected:
            raise ShapeError("unexpected expression proof")
        source = expected[key]
        if (_oid(entry.get("relation_oid"), "expression relation OID") != source["relation_oid"]
                or entry.get("source_sha256") != source["digest"]
                or type(entry.get("source_ordinal")) is not int
                or not isinstance(entry.get("sql"), str) or not entry["sql"]):
            raise ShapeError("expression proof binding mismatch")
        actual[key].append((entry["source_ordinal"], entry["sql"]))

    result = {}
    for key, source in expected.items():
        items = actual.get(key, [])
        if len(items) != source["count"]:
            raise ShapeError("expression proof count mismatch")
        ordinals = [ordinal for ordinal, _ in items]
        if sorted(ordinals) != list(range(source["count"])):
            raise ShapeError("expression proof ordinal mismatch")
        result[key] = [sql for _, sql in sorted(items)]
    return result


def _verified_index_support(capture: dict[str, Any], proof: dict[str, Any]) -> dict[int, dict[str, Any]]:
    raw_rows = capture["indexes"]
    support = proof.get("index_support")
    if not isinstance(support, dict):
        raise ShapeError("index proof inventory is missing")
    raw_by_oid = _proof_oid_map(raw_rows, "indexrelid", "index OID")
    if set(support) != {str(oid) for oid in raw_by_oid}:
        raise ShapeError("index proof inventory mismatch")
    class_rows = _proof_oid_map(_rows(capture, "index_relations"), "oid", "index relation OID")
    if set(class_rows) != set(raw_by_oid):
        raise ShapeError("index relation inventory mismatch")
    method_oids = {"btree": 403, "hash": 405, "gist": 783, "gin": 2742}
    result = {}
    for oid, row in raw_by_oid.items():
        item = support[str(oid)]
        if not isinstance(item, dict) or set(item) != {
                "source_metadata", "relation_metadata", "method", "opclasses", "collations",
                "exclusion_operators"}:
            raise ShapeError("malformed index proof")
        if item["source_metadata"] != row:
            raise ShapeError("index proof source metadata mismatch")
        relation_metadata = item["relation_metadata"]
        relation_row = class_rows[oid]
        if relation_metadata != relation_row:
            raise ShapeError("index relation metadata mismatch")
        method = item.get("method")
        if not isinstance(method, str) or method not in _SUPPORTED_INDEX_METHODS:
            raise ShapeError("unsupported index access method")
        if (_oid(relation_row.get("oid"), "index relation OID") != oid
                or _oid(relation_row.get("relam"), "index access method OID") != method_oids[method]
                or relation_row.get("relkind") != "i"
                or relation_row.get("relpersistence") != "p"
                or relation_row.get("relispartition") is not False
                or relation_row.get("reloptions") not in (None, [])
                or _oid(relation_row.get("reltablespace"), "index tablespace OID", zero=True) != 0):
            raise ShapeError("unsupported index relation metadata")
        natts = _int(row.get("indnatts"), "index attribute count", 1, MAX_HEAP_ATTRIBUTE_NUMBER)
        nkeys = _int(row.get("indnkeyatts"), "index key count", 1, natts)
        keys = row.get("indkey")
        classes = item.get("opclasses")
        collations = item.get("collations")
        operators = item.get("exclusion_operators")
        options = row.get("indoption")
        raw_classes = row.get("indclass")
        raw_collations = row.get("indcollation")
        if (natts != nkeys or not isinstance(keys, list) or len(keys) != natts
                or not isinstance(classes, list) or len(classes) != nkeys
                or not isinstance(collations, list) or len(collations) != nkeys
                or not isinstance(options, list) or len(options) != nkeys
                or not isinstance(raw_classes, list) or len(raw_classes) != nkeys
                or not isinstance(raw_collations, list) or len(raw_collations) != nkeys
                or not isinstance(operators, list)):
            raise ShapeError("unsupported index key shape")
        if any(_int(value, "index option", 0, 0xFFFF) > 3 for value in options):
            raise ShapeError("unsupported index ordering option")
        if bool(row.get("indisexclusion")) != bool(operators):
            raise ShapeError("exclusion operator proof mismatch")
        if operators and len(operators) != nkeys:
            raise ShapeError("exclusion operator count mismatch")
        rendered_classes = [_qualified_identifier(value, "index opclass") for value in classes]
        rendered_collations = [None if value is None else
                               _qualified_identifier(value, "index collation") for value in collations]
        rendered_operators = [_operator_reference(value) for value in operators]
        result[oid] = {
            "method": method,
            "opclasses": rendered_classes,
            "collations": rendered_collations,
            "exclusion_operators": rendered_operators,
        }
    return result


def _constraint_deferrability(row: dict[str, Any]) -> str:
    if type(row.get("condeferrable")) is not bool or type(row.get("condeferred")) is not bool:
        raise ShapeError("invalid constraint deferrability metadata")
    if row["condeferrable"]:
        return " DEFERRABLE" + (" INITIALLY DEFERRED" if row["condeferred"] else " INITIALLY IMMEDIATE")
    if row["condeferred"]:
        raise ShapeError("non-deferrable constraint is initially deferred")
    return " NOT DEFERRABLE"


def _constraint_key_sql(relid: int, values: Any, shape: dict[str, Any], label: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise ShapeError(f"invalid {label} key vector")
    relation = shape["relations"].get(str(relid))
    if relation is None:
        raise ShapeError(f"{label} relation is outside capture")
    result = []
    for value in values:
        attnum = _int(value, f"{label} attribute number", 1, MAX_HEAP_ATTRIBUTE_NUMBER)
        mapping = relation["source_attnums"].get(str(attnum))
        if mapping is None:
            raise ShapeError(f"{label} attribute is missing")
        result.append(_identifier(mapping["column"], "synthetic column"))
    return result


def _verified_constraint_support(capture: dict[str, Any], proof: dict[str, Any]) -> dict[int, dict[str, Any]]:
    support = proof.get("constraint_support")
    if not isinstance(support, dict):
        raise ShapeError("constraint proof inventory is missing")
    rows = _proof_oid_map(capture["constraints"], "oid", "constraint OID")
    index_rows = _proof_oid_map(capture["indexes"], "indexrelid", "index OID")
    if set(support) != {str(oid) for oid in rows}:
        raise ShapeError("constraint proof inventory mismatch")
    result = {}
    for oid, row in rows.items():
        item = support[str(oid)]
        if not isinstance(item, dict) or set(item) != {"source_metadata"}:
            raise ShapeError("malformed constraint proof")
        metadata = item["source_metadata"]
        if not isinstance(metadata, dict):
            raise ShapeError("malformed constraint source metadata")
        expected_fields = set(_CONSTRAINT_PROOF_FIELDS)
        expected_fields.update(field for field in _OPTIONAL_CONSTRAINT_PROOF_FIELDS if field in row)
        if set(metadata) != expected_fields:
            raise ShapeError("constraint proof fields mismatch")
        for field in expected_fields:
            if metadata[field] != row.get(field):
                raise ShapeError("constraint proof binding mismatch")
        if row.get("contype") not in {"c", "f", "p", "u", "x"}:
            raise ShapeError("unsupported constraint kind")
        for flag in ("convalidated", "condeferrable", "condeferred", "conislocal", "connoinherit"):
            if type(row.get(flag)) is not bool:
                raise ShapeError("invalid constraint flag")
        _int(row.get("coninhcount"), "constraint inheritance count", 0, MAX_RELATIONS)
        if row.get("conparentid") not in (0, "0") or row.get("conislocal") is not True or row.get("coninhcount") != 0:
            raise ShapeError("inherited constraint is unsupported")
        if row.get("condeferred") and not row.get("condeferrable"):
            raise ShapeError("invalid constraint deferrability")
        if type(row.get("connoinherit")) is not bool:
            raise ShapeError("invalid constraint inheritance flag")
        if row.get("contype") in {"p", "u"} and row.get("convalidated") is not True:
            raise ShapeError("unvalidated key constraint is unsupported")
        if row.get("contype") == "x" and row.get("convalidated") is not True:
            raise ShapeError("unvalidated exclusion constraint is unsupported")
        if row.get("conperiod") is True:
            raise ShapeError("temporal constraint syntax is unsupported")
        if row.get("contype") in {"p", "u"} and row.get("conindid") in (0, "0"):
            raise ShapeError("key constraint has no backing index")
        if row.get("contype") == "x" and row.get("conindid") in (0, "0"):
            raise ShapeError("exclusion constraint has no backing index")
        if row.get("contype") == "c" and row.get("conindid") not in (0, "0"):
            raise ShapeError("check constraint has an unexpected backing index")
        if row.get("contype") == "f":
            referenced_index_oid = _oid(row.get("conindid"), "foreign key referenced index OID")
            referenced_index = index_rows.get(referenced_index_oid)
            if referenced_index is None:
                raise ShapeError("foreign key referenced index is outside capture")
            referenced_relation_oid = _oid(row.get("confrelid"), "foreign key referenced relation OID")
            if _oid(referenced_index.get("indrelid"), "referenced index relation OID") != referenced_relation_oid:
                raise ShapeError("foreign key referenced index relation mismatch")
            if (referenced_index.get("indisunique") is not True
                    or referenced_index.get("indisexclusion") is True
                    or referenced_index.get("indisready") is not True
                    or referenced_index.get("indisvalid") is not True
                    or referenced_index.get("indislive") is not True
                    or referenced_index.get("indcheckxmin") is not False
                    or referenced_index.get("indpred") not in (None, "")
                    or referenced_index.get("indexprs") not in (None, "")):
                raise ShapeError("foreign key referenced index is not a usable unique index")
            local = row.get("conkey")
            referenced = row.get("confkey")
            operator_vectors = [row.get(field) for field in ("conpfeqop", "conppeqop", "conffeqop")]
            if (not isinstance(local, list) or not isinstance(referenced, list) or not local
                    or len(local) != len(referenced)
                    or any(not isinstance(vector, list) or len(vector) != len(local)
                           for vector in operator_vectors)):
                raise ShapeError("foreign key operator/key vectors are malformed")
            index_keys = referenced_index.get("indkey")
            key_count = _int(referenced_index.get("indnkeyatts"), "referenced index key count",
                             1, MAX_HEAP_ATTRIBUTE_NUMBER)
            natts = _int(referenced_index.get("indnatts"), "referenced index attribute count",
                         key_count, MAX_HEAP_ATTRIBUTE_NUMBER)
            if (key_count != len(referenced) or not isinstance(index_keys, list)
                    or len(index_keys) != natts):
                raise ShapeError("foreign key referenced index key count mismatch")
            normalized_index_keys = [_int(value, "referenced index key", 1,
                                           MAX_HEAP_ATTRIBUTE_NUMBER)
                                     for value in index_keys[:key_count]]
            normalized_referenced_keys = [_int(value, "foreign key referenced key", 1,
                                               MAX_HEAP_ATTRIBUTE_NUMBER)
                                          for value in referenced]
            if normalized_index_keys != normalized_referenced_keys:
                raise ShapeError("foreign key referenced index key mismatch")
            for vector in operator_vectors:
                for operator_oid in vector:
                    _oid(operator_oid, "foreign key operator OID")
        if row.get("contype") == "x":
            operators = row.get("conexclop")
            if not isinstance(operators, list) or not operators:
                raise ShapeError("exclusion operator vector is malformed")
            for operator_oid in operators:
                _oid(operator_oid, "exclusion operator OID")
        result[oid] = row
    return result


def compile_read_shape(capture: dict[str, Any], proof_export: dict[str, Any]) -> dict[str, Any]:
    """Compile a synthetic read-shape fixture only from a full proof-bound export.

    The root exporter is responsible for PostgreSQL semantic proofs. This
    offline compiler independently binds the export to the exact capture and
    skeleton digest, checks complete index/constraint inventory coverage, and
    uses only synthetic relation/type/column names in generated DDL.
    """
    if not isinstance(proof_export, dict) or proof_export.get("format") != "pgdog-owned-read-proof/v1":
        raise ShapeError("unsupported read proof format")
    if set(proof_export) != {
            "format", "capture_sha256", "relation_shape_sha256", "source_read_proof_complete",
            "expressions", "index_support", "constraint_support"}:
        raise ShapeError("unexpected read proof fields")
    if proof_export.get("source_read_proof_complete") is not True:
        raise ShapeError("source read proof is incomplete")
    if proof_export.get("capture_sha256") != _digest(capture):
        raise ShapeError("proof capture digest mismatch")
    skeleton = compile_shape(capture)
    if proof_export.get("relation_shape_sha256") != _digest(skeleton):
        raise ShapeError("proof relation-shape digest mismatch")

    expressions = _verified_expression_map(capture, proof_export)
    index_support = _verified_index_support(capture, proof_export)
    constraint_rows = _verified_constraint_support(capture, proof_export)
    table_names = {int(oid): row["synthetic_name"]
                   for oid, row in skeleton["relations"].items()}
    index_names = {row["source_oid"]: row["id"] for row in skeleton["pending"]["index_inventory"]}
    constraint_names = {row["source_oid"]: row["id"]
                        for row in skeleton["pending"]["constraint_inventory"]}

    constraints_by_index: dict[int, dict[str, Any]] = {}
    for oid, row in constraint_rows.items():
        if row["contype"] in {"p", "u", "x"}:
            index_oid = _oid(row.get("conindid"), "constraint backing index OID")
            if index_oid not in index_names or index_oid in constraints_by_index:
                raise ShapeError("constraint backing index mapping is ambiguous")
            constraints_by_index[index_oid] = row

    ddl = list(skeleton["ddl"])
    result_index_rows = []
    expression_consumers = set()
    raw_indexes = _proof_oid_map(capture["indexes"], "indexrelid", "index OID")
    for index_oid in sorted(raw_indexes):
        row = raw_indexes[index_oid]
        relid = _oid(row.get("indrelid"), "index relation OID")
        if relid not in table_names:
            raise ShapeError("index relation is outside capture")
        flags = ("indisunique", "indisprimary", "indisexclusion", "indisready", "indisvalid",
                 "indislive", "indcheckxmin", "indisclustered", "indisreplident")
        if any(type(row.get(flag)) is not bool for flag in flags):
            raise ShapeError("index flag metadata is incomplete")
        if not (row["indisready"] and row["indisvalid"] and row["indislive"]):
            raise ShapeError("unready or invalid index is unsupported")
        if row["indcheckxmin"] or row["indisclustered"] or row["indisreplident"]:
            raise ShapeError("unsupported index state")
        if row["indisprimary"] and not row["indisunique"]:
            raise ShapeError("primary index is not unique")
        if row["indisexclusion"] and row["indisunique"]:
            raise ShapeError("exclusion index is marked unique")
        if "indnullsnotdistinct" in row and type(row["indnullsnotdistinct"]) is not bool:
            raise ShapeError("invalid unique null semantics")
        keys = row["indkey"]
        natts = _int(row["indnatts"], "index key count", 1, MAX_HEAP_ATTRIBUTE_NUMBER)
        if len(keys) != natts:
            raise ShapeError("index key count mismatch")
        support = index_support[index_oid]
        method = support["method"]
        exprs = expressions.get(("pg_index.indexprs", index_oid), [])
        expr_position = 0
        rendered_keys = []
        for position, value in enumerate(keys):
            attnum = _int(value, "index attribute number", 0, MAX_HEAP_ATTRIBUTE_NUMBER)
            if attnum == 0:
                if expr_position >= len(exprs):
                    raise ShapeError("index expression key is missing")
                key_sql = f"({exprs[expr_position]})"
                expr_position += 1
            else:
                mapped = skeleton["relations"][str(relid)]["source_attnums"].get(str(attnum))
                if mapped is None:
                    raise ShapeError("index attribute is missing")
                key_sql = _identifier(mapped["column"], "synthetic column")
            collation = support["collations"][position]
            if collation is not None:
                key_sql += f" COLLATE {collation}"
            key_sql += f" {support['opclasses'][position]}"
            option = _int(row["indoption"][position], "index option", 0, 3)
            if method == "btree":
                if option & 1:
                    key_sql += " DESC"
                if option & 2:
                    key_sql += " NULLS FIRST"
                elif option & 1:
                    key_sql += " NULLS LAST"
            elif option != 0:
                raise ShapeError("non-btree index ordering option")
            rendered_keys.append(key_sql)
        if expr_position != len(exprs):
            raise ShapeError("unused index expression proof")
        predicate = expressions.get(("pg_index.indpred", index_oid), [])
        if len(predicate) > 1:
            raise ShapeError("multiple index predicates")
        if predicate:
            expression_consumers.add(("pg_index.indpred", index_oid))
        if exprs:
            expression_consumers.add(("pg_index.indexprs", index_oid))

        backing_constraint = constraints_by_index.get(index_oid)
        if backing_constraint:
            if ((backing_constraint["contype"] == "p") != row["indisprimary"]
                    or (backing_constraint["contype"] in {"p", "u"}) != row["indisunique"]
                    or (backing_constraint["contype"] == "x") != row["indisexclusion"]):
                raise ShapeError("constraint/index flags disagree")
            if _oid(backing_constraint.get("conrelid"), "constraint relation OID") != relid:
                raise ShapeError("constraint/index relation mismatch")
            if backing_constraint["contype"] in {"p", "u"}:
                constraint_keys = backing_constraint.get("conkey")
                index_keys = row.get("indkey")
                if not isinstance(constraint_keys, list) or not isinstance(index_keys, list):
                    raise ShapeError("constraint/index key vectors are missing")
                index_attnums = [_int(value, "index key attribute", 1,
                                      MAX_HEAP_ATTRIBUTE_NUMBER) for value in index_keys]
                constraint_attnums = [_int(value, "constraint key attribute", 1,
                                           MAX_HEAP_ATTRIBUTE_NUMBER) for value in constraint_keys]
                if index_attnums != constraint_attnums:
                    raise ShapeError("constraint/index key order mismatch")
                if row.get("indpred") or row.get("indexprs"):
                    raise ShapeError("constraint backing index is partial or expression-based")
                if backing_constraint["contype"] == "p":
                    for attnum in constraint_attnums:
                        column = skeleton["relations"][str(relid)]["source_attnums"].get(str(attnum))
                        if column is None or column["not_null"] is not True:
                            raise ShapeError("primary key column is nullable")
            elif backing_constraint["contype"] == "x":
                constraint_keys = backing_constraint.get("conkey")
                index_keys = row.get("indkey")
                if not isinstance(constraint_keys, list) or not isinstance(index_keys, list):
                    raise ShapeError("exclusion constraint/index key vectors are missing")
                if ([_int(value, "constraint key attribute", 0, MAX_HEAP_ATTRIBUTE_NUMBER)
                     for value in constraint_keys] !=
                        [_int(value, "index key attribute", 0, MAX_HEAP_ATTRIBUTE_NUMBER)
                         for value in index_keys]):
                    raise ShapeError("exclusion constraint/index key order mismatch")
        elif row["indisprimary"] or row["indisexclusion"]:
            raise ShapeError("constraint index has no matching constraint")
        index_sql = "CREATE " + ("UNIQUE " if row["indisunique"] else "")
        if row.get("indnullsnotdistinct") and (not row["indisunique"] or row["indisprimary"]):
            raise ShapeError("unsupported NULLS NOT DISTINCT index flags")
        index_sql += f"INDEX {_identifier(index_names[index_oid], 'synthetic index')} ON "
        index_sql += f"{_identifier(table_names[relid], 'synthetic relation')} USING {method} "
        index_sql += "(" + ", ".join(rendered_keys) + ")"
        if row.get("indnullsnotdistinct"):
            index_sql += " NULLS NOT DISTINCT"
        if predicate:
            index_sql += f" WHERE {predicate[0]}"
        index_sql += ";"
        if not (backing_constraint and backing_constraint["contype"] == "x"):
            ddl.append(index_sql)
        result_index_rows.append({
            "id": index_names[index_oid], "source_oid": index_oid,
            "relation": table_names[relid], "method": method,
            "keys": rendered_keys, "predicate_present": bool(predicate),
            "constraint_backing": (constraint_names[_oid(backing_constraint["oid"], "constraint OID")]
                                   if backing_constraint else None),
            "complete": True,
        })

    result_constraint_rows = []
    constraint_expression_consumers = set()
    for oid in sorted(constraint_rows):
        row = constraint_rows[oid]
        kind = row["contype"]
        relid = _oid(row.get("conrelid"), "constraint relation OID")
        name = _identifier(constraint_names[oid], "synthetic constraint")
        table = _identifier(table_names[relid], "synthetic relation")
        deferrability = _constraint_deferrability(row)
        validated = "" if row["convalidated"] else " NOT VALID"
        if kind == "c":
            sqls = expressions.get(("pg_constraint.conbin", oid), [])
            if len(sqls) != 1:
                raise ShapeError("check constraint expression proof is missing")
            constraint_expression_consumers.add(("pg_constraint.conbin", oid))
            ddl.append(f"ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({sqls[0]})" +
                       (" NO INHERIT" if row["connoinherit"] else "") + validated + ";")
        elif kind == "f":
            local_keys = _constraint_key_sql(relid, row.get("conkey"), skeleton, "foreign key")
            ref_relid = _oid(row.get("confrelid"), "referenced relation OID")
            if ref_relid not in table_names:
                raise ShapeError("foreign key target is outside capture")
            ref_keys = _constraint_key_sql(ref_relid, row.get("confkey"), skeleton,
                                           "referenced foreign key")
            if len(local_keys) != len(ref_keys):
                raise ShapeError("foreign key key count mismatch")
            match = {"s": "SIMPLE", "f": "FULL", "p": "PARTIAL"}.get(row["confmatchtype"])
            action = {"a": "NO ACTION", "r": "RESTRICT", "c": "CASCADE",
                      "n": "SET NULL", "d": "SET DEFAULT"}
            if (match is None or match == "PARTIAL" or row["confupdtype"] not in action
                    or row["confdeltype"] not in action):
                raise ShapeError("unsupported foreign key action")
            set_columns = row.get("confdelsetcols")
            if set_columns:
                if row["confdeltype"] not in {"n", "d"}:
                    raise ShapeError("foreign key set-column list has no set action")
                delete_set_sql = " (" + ", ".join(_constraint_key_sql(
                    relid, set_columns, skeleton, "foreign key delete set")) + ")"
            else:
                delete_set_sql = ""
            delete_action = action[row["confdeltype"]] + delete_set_sql
            sql = (f"ALTER TABLE {table} ADD CONSTRAINT {name} FOREIGN KEY (" +
                   ", ".join(local_keys) + ") REFERENCES " +
                   _identifier(table_names[ref_relid], "referenced relation") + " (" +
                   ", ".join(ref_keys) + f") MATCH {match} ON UPDATE {action[row['confupdtype']]}" +
                   f" ON DELETE {delete_action}" + deferrability + validated + ";")
            ddl.append(sql)
        elif kind in {"p", "u"}:
            index_oid = _oid(row.get("conindid"), "constraint backing index OID")
            if index_oid not in index_names:
                raise ShapeError("constraint backing index is missing")
            constraint_kind = "PRIMARY KEY" if kind == "p" else "UNIQUE"
            ddl.append(f"ALTER TABLE {table} ADD CONSTRAINT {name} {constraint_kind} USING INDEX " +
                       _identifier(index_names[index_oid], "synthetic index") + deferrability + ";")
            ddl.append(f"ALTER INDEX {name} RENAME TO " +
                       _identifier(index_names[index_oid], "synthetic index") + ";")
        elif kind == "x":
            index_oid = _oid(row.get("conindid"), "constraint backing index OID")
            index_row = raw_indexes.get(index_oid)
            support = index_support.get(index_oid)
            if index_row is None or support is None or not index_row["indisexclusion"]:
                raise ShapeError("exclusion backing index proof is missing")
            if not isinstance(row.get("conexclop"), list):
                raise ShapeError("exclusion source operator vector is missing")
            if (len(row["conexclop"]) != len(support["exclusion_operators"])
                    or len(row["conexclop"]) != len(index_row["indkey"])):
                raise ShapeError("exclusion operator proof count mismatch")
            keys = index_row["indkey"]
            terms = []
            exprs = expressions.get(("pg_index.indexprs", index_oid), [])
            expression_position = 0
            for position, value in enumerate(keys):
                attnum = _int(value, "exclusion attribute number", 0, MAX_HEAP_ATTRIBUTE_NUMBER)
                if attnum == 0:
                    if expression_position >= len(exprs):
                        raise ShapeError("exclusion expression key is missing")
                    term = f"({exprs[expression_position]})"
                    expression_position += 1
                else:
                    mapped = skeleton["relations"][str(relid)]["source_attnums"].get(str(attnum))
                    if mapped is None:
                        raise ShapeError("exclusion attribute is missing")
                    term = _identifier(mapped["column"], "synthetic column")
                collation = support["collations"][position]
                if collation is not None:
                    term += f" COLLATE {collation}"
                term += (f" {support['opclasses'][position]} WITH " +
                         support["exclusion_operators"][position])
                terms.append(term)
            if expression_position != len(exprs):
                raise ShapeError("unused exclusion expression proof")
            if exprs:
                expression_consumers.add(("pg_index.indexprs", index_oid))
            predicate = expressions.get(("pg_index.indpred", index_oid), [])
            if len(predicate) > 1:
                raise ShapeError("multiple exclusion predicates")
            if predicate:
                expression_consumers.add(("pg_index.indpred", index_oid))
            ddl.append(f"ALTER TABLE {table} ADD CONSTRAINT {name} EXCLUDE USING {support['method']} (" +
                       ", ".join(terms) + ")" +
                       (f" WHERE ({predicate[0]})" if predicate else "") +
                       deferrability + validated + ";")
            ddl.append(f"ALTER INDEX {name} RENAME TO " +
                       _identifier(index_names[index_oid], "synthetic index") + ";")
        result_constraint_rows.append({
            "id": constraint_names[oid], "source_oid": oid, "relation": table_names[relid],
            "kind": kind, "complete": True,
        })

    if set(expressions) != expression_consumers | constraint_expression_consumers:
        raise ShapeError("unconsumed expression proof")
    result = dict(skeleton)
    result["ddl"] = ddl
    result["source_read_proof_complete"] = True
    result["writer_equivalence"] = False
    result["read_shape_digest"] = proof_export["relation_shape_sha256"]
    result["pending"] = dict(skeleton["pending"])
    result["pending"].update({
        "constraints": [], "constraint_inventory": result_constraint_rows,
        "check_constraints": [], "foreign_keys": [], "exclusion_constraints": [],
        "indexes": [], "index_inventory": result_index_rows,
        "index_expressions": [], "index_predicates": [],
        "inventory_complete": True,
    })
    result["limitations"] = [
        "read indexes and constraints are emitted from a verified private proof export",
        "defaults and triggers are intentionally omitted; this is not writer equivalence",
        "generated DDL uses synthetic relation, column, enum, constraint, and index identifiers",
    ]
    return result


@dataclass
class _UnionFind:
    parent: dict[tuple[int, int], tuple[int, int]]

    def find(self, value: tuple[int, int]) -> tuple[int, int]:
        root = self.parent[value]
        if root != value:
            self.parent[value] = self.find(root)
        return self.parent[value]

    def union(self, left: tuple[int, int], right: tuple[int, int]) -> None:
        a, b = self.find(left), self.find(right)
        if a != b:
            self.parent[max(a, b)] = min(a, b)


def compile_shape(capture: dict[str, Any]) -> dict[str, Any]:
    """Return deterministic synthetic DDL, lineage and explicit pending inventory.

    The result is a schema skeleton only. It is never a proof that the original
    constraints, expressions, indexes, defaults, triggers, or dependencies have
    been recreated or validated.
    """
    if not isinstance(capture, dict):
        raise ShapeError("capture must be an object")
    major = capture.get("postgres_major")
    if type(major) is not int or major not in (12, 18):
        raise ShapeError("unsupported PostgreSQL major")
    inheritance_status = capture.get("inheritance_status")
    if inheritance_status is not None and not isinstance(inheritance_status, dict):
        raise ShapeError("malformed inheritance status")
    if inheritance_status is not None and inheritance_status.get("complete") is not True:
        raise ShapeError("inheritance capture is incomplete")

    relations = _rows(capture, "relations")
    attributes = _rows(capture, "attributes")
    types_rows = _rows(capture, "types")
    enums = _rows(capture, "enums")
    constraints = _rows(capture, "constraints")
    indexes = _rows(capture, "indexes")
    edges = _rows(capture, "inheritance_edges")
    if not relations or len(relations) > MAX_RELATIONS or len(attributes) > MAX_ATTRIBUTES:
        raise ShapeError("relation/attribute capture exceeds bounds")
    if len(constraints) > 20000 or len(indexes) > 20000:
        raise ShapeError("constraint/index capture exceeds bounds")
    if (inheritance_status is not None
            and (inheritance_status.get("relation_count") != len(relations)
                 or inheritance_status.get("edge_count") != len(edges))):
        raise ShapeError("inheritance inventory count mismatch")

    rel_by_oid: dict[int, dict[str, Any]] = {}
    for relation in relations:
        oid = _oid(relation.get("oid"), "relation OID")
        if oid in rel_by_oid:
            raise ShapeError("duplicate relation OID")
        if relation.get("relkind") != "r" or relation.get("relispartition") is True:
            raise ShapeError("unsupported relation kind")
        rel_by_oid[oid] = relation
    if capture.get("roots") is not None:
        if not isinstance(capture["roots"], list):
            raise ShapeError("malformed root manifest")
        roots = {_oid(value, "root OID") for value in capture["roots"]}
        if roots != set(rel_by_oid):
            raise ShapeError("root manifest mismatch")

    types: dict[int, dict[str, Any]] = {}
    for row in types_rows:
        oid = _oid(row.get("oid"), "type OID")
        if oid in types:
            raise ShapeError("duplicate type OID")
        if oid in BUILTIN_TYPES:
            expected_name, _ = BUILTIN_TYPES[oid]
            if (_oid(row.get("typnamespace"), "type namespace OID") != 11
                    or row.get("typname") != expected_name
                    or row.get("typtype") != "b"):
                raise ShapeError("reviewed built-in type metadata mismatch")
        types[oid] = row

    enum_labels: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for label in enums:
        type_oid = _oid(label.get("enumtypid"), "enum type OID")
        if type_oid not in types or types[type_oid].get("typtype") != "e":
            raise ShapeError("enum label has no captured enum type")
        enum_labels[type_oid].append(label)
    enum_names: dict[int, str] = {}
    enum_label_counts: dict[int, int] = {}
    for type_oid, row in sorted(types.items()):
        if row.get("typtype") == "e":
            enum_names[type_oid] = f"e{len(enum_names) + 1:04d}"
            enum_label_counts[type_oid] = _enum_label_count(enum_labels.get(type_oid, []))
    if set(enum_labels) != set(enum_names):
        raise ShapeError("unexpected enum metadata")

    attrs_by_relation: dict[int, list[dict[str, Any]]] = defaultdict(list)
    attr_by_key: dict[tuple[int, int], dict[str, Any]] = {}
    for attribute in attributes:
        relid = _oid(attribute.get("attrelid"), "attribute relation OID")
        attnum = _int(attribute.get("attnum"), "attribute number", 1, MAX_HEAP_ATTRIBUTE_NUMBER)
        if relid not in rel_by_oid:
            raise ShapeError("attribute relation is outside the relation manifest")
        key = (relid, attnum)
        if key in attr_by_key:
            raise ShapeError("duplicate source attribute identity")
        if attribute.get("attisdropped") is not False:
            raise ShapeError("dropped or malformed relation attribute")
        if attribute.get("attgenerated") not in ("", None) or attribute.get("attidentity") not in ("", None):
            raise ShapeError("generated/identity attribute unsupported in skeleton")
        _truth(attribute.get("attnotnull"), "attribute nullability")
        _int(attribute.get("attinhcount"), "inheritance count", 0, MAX_RELATIONS)
        _truth(attribute.get("attislocal"), "attribute local flag")
        type_oid = _oid(attribute.get("atttypid"), "attribute type OID")
        collation_oid = _oid(attribute.get("attcollation"), "attribute collation OID", zero=True)
        if collation_oid not in (0, 100):
            raise ShapeError("unreviewed attribute collation")
        typmod = attribute.get("atttypmod")
        dimensions = attribute.get("attndims")
        if type(typmod) is not int or not -1 <= typmod <= 0x7FFFFFFF:
            raise ShapeError("invalid attribute typmod")
        typmod_types = {1042, 1043, 1083, 1114, 1184, 1186, 1266, 1700, 1231}
        if typmod != -1 and type_oid not in typmod_types:
            raise ShapeError("unexpected typmod for reviewed type")
        _int(dimensions, "array dimensions", 0, 6)
        _type_sql(type_oid, typmod, dimensions, types, enum_names)
        if not isinstance(attribute.get("attname"), str):
            raise ShapeError("missing attribute identity")
        attr_by_key[key] = attribute
        attrs_by_relation[relid].append(attribute)

    for relid, relation in rel_by_oid.items():
        attrs = attrs_by_relation.get(relid, [])
        if len(attrs) != _int(relation.get("relnatts"), "relation attribute count", 0, MAX_ATTRIBUTES):
            raise ShapeError("relation attribute inventory mismatch")
        names = [row["attname"] for row in attrs]
        if len(set(names)) != len(names):
            raise ShapeError("duplicate logical column name")
        attrs.sort(key=lambda row: row["attnum"])

    parents: dict[int, list[int]] = defaultdict(list)
    children: dict[int, list[tuple[int, int]]] = defaultdict(list)
    edge_seen: set[tuple[int, int, int]] = set()
    sequences_by_child: dict[int, set[int]] = defaultdict(set)
    for edge in edges:
        parent = _oid(edge.get("parent"), "inheritance parent OID")
        child = _oid(edge.get("child"), "inheritance child OID")
        sequence = _int(edge.get("sequence"), "inheritance sequence", 1, MAX_RELATIONS)
        if parent not in rel_by_oid or child not in rel_by_oid or parent == child:
            raise ShapeError("inheritance edge leaves relation manifest")
        token = (parent, child, sequence)
        if token in edge_seen:
            raise ShapeError("duplicate inheritance edge")
        if sequence in sequences_by_child[child]:
            raise ShapeError("ambiguous inheritance sequence")
        edge_seen.add(token)
        sequences_by_child[child].add(sequence)
        parents[child].append(parent)
        children[parent].append((sequence, child))
    for child, values in parents.items():
        if len(values) != len(set(values)):
            raise ShapeError("duplicate inheritance parent")
    if any(not attrs_by_relation.get(relid) and relid not in parents for relid in rel_by_oid):
        raise ShapeError("empty root relation is unsupported")

    # Topological order also detects cycles and makes inherited-column closure finite.
    ordered: list[int] = []
    state: dict[int, int] = {}

    def visit(oid: int) -> None:
        marker = state.get(oid, 0)
        if marker == 1:
            raise ShapeError("inheritance cycle")
        if marker == 2:
            return
        state[oid] = 1
        for parent in sorted(parents.get(oid, [])):
            visit(parent)
        state[oid] = 2
        ordered.append(oid)

    for oid in sorted(rel_by_oid):
        visit(oid)

    union = _UnionFind({key: key for key in attr_by_key})
    inherited_dimension_overrides: list[dict[str, Any]] = []
    for child in ordered:
        parent_ids = parents.get(child, [])
        for attribute in attrs_by_relation.get(child, []):
            child_key = (child, attribute["attnum"])
            if attribute["attinhcount"] == 0:
                continue
            candidates: list[tuple[int, int]] = []
            for parent in parent_ids:
                match = next((row for row in attrs_by_relation.get(parent, [])
                              if row["attname"] == attribute["attname"]), None)
                if match is not None:
                    if (match["atttypid"], match["atttypmod"], match["attcollation"]) != (
                            attribute["atttypid"], attribute["atttypmod"], attribute["attcollation"]):
                        raise ShapeError("inherited column metadata mismatch")
                    if match["attndims"] != attribute["attndims"]:
                        inherited_dimension_overrides.append({
                            "relation_oid": child,
                            "attnum": attribute["attnum"],
                            "parent_relation_oid": parent,
                            "parent_attnum": match["attnum"],
                            "source_dimensions": attribute["attndims"],
                            "inherited_dimensions": match["attndims"],
                            "source_is_local": attribute["attislocal"],
                            "applied_by_local_declaration": attribute["attislocal"],
                            "complete": attribute["attislocal"],
                        })
                    candidates.append((parent, match["attnum"]))
            if len(candidates) != attribute["attinhcount"] or not candidates:
                raise ShapeError("inherited column parent count mismatch")
            representative = candidates[0]
            for candidate in candidates[1:]:
                union.union(representative, candidate)
            union.union(child_key, representative)

    # Assign stable synthetic names by the smallest source identity in each inherited group.
    groups: dict[tuple[int, int], list[tuple[int, int]]] = defaultdict(list)
    for key in attr_by_key:
        groups[union.find(key)].append(key)
    logical_roots = sorted(min(group) for group in groups.values())
    column_name = {root: f"c{index:04d}" for index, root in enumerate(logical_roots, 1)}
    source_column: dict[tuple[int, int], str] = {
        key: column_name[min(groups[union.find(key)])] for key in attr_by_key
    }

    table_name = {oid: f"t{index:04d}" for index, oid in enumerate(sorted(rel_by_oid), 1)}
    target_orders: dict[int, list[str]] = {}
    source_attnums: dict[int, dict[str, dict[str, Any]]] = {}
    local_declarations: dict[int, list[tuple[dict[str, Any], str]]] = {}
    for relid in ordered:
        inherited: list[str] = []
        for parent in sorted(parents.get(relid, []), key=lambda oid: (min(
                (seq for seq, child in children[oid] if child == relid), default=0), oid)):
            for column in target_orders[parent]:
                if column not in inherited:
                    inherited.append(column)
        # A local duplicate of an inherited PostgreSQL column is declared again
        # to retain attislocal=true, but it does not add a second target column.
        local_attrs = [row for row in attrs_by_relation.get(relid, []) if row["attislocal"]]
        new_local_attrs = [row for row in local_attrs if row["attinhcount"] == 0]
        local_columns = [source_column[(relid, row["attnum"])] for row in new_local_attrs]
        if len(set(local_columns)) != len(local_columns) or set(local_columns) & set(inherited):
            raise ShapeError("local/inherited column collision")
        target_order = inherited + local_columns
        target_orders[relid] = target_order
        positions = {name: index for index, name in enumerate(target_order, 1)}
        source_attnums[relid] = {}
        for row in attrs_by_relation.get(relid, []):
            name = source_column[(relid, row["attnum"])]
            source_attnums[relid][str(row["attnum"])] = {
                "column": name,
                "target_attnum": positions[name],
                "source_relation_oid": relid,
                "source_attnum": row["attnum"],
                "source_type_oid": row["atttypid"],
                "source_collation_oid": _oid(row["attcollation"], "attribute collation OID", zero=True),
                "typmod": row["atttypmod"],
                "array_dimensions": row["attndims"],
                "not_null": row["attnotnull"],
                "inheritance_count": row["attinhcount"],
                "is_local": row["attislocal"],
            }
        local_declarations[relid] = [(row, source_column[(relid, row["attnum"])]) for row in local_attrs]

    ddl: list[str] = []
    for type_oid, name in sorted(enum_names.items(), key=lambda item: item[1]):
        safe_labels = _synthetic_labels(enum_label_counts[type_oid])
        labels = ", ".join(f"'{label}'" for label in safe_labels)
        ddl.append(f"CREATE TYPE {name} AS ENUM ({labels});")
    for relid in ordered:
        declarations = []
        for row, name in local_declarations[relid]:
            sql_type = _type_sql(_oid(row["atttypid"], "attribute type OID"),
                                 row["atttypmod"], row["attndims"], types, enum_names)
            nullability = " NOT NULL" if row["attnotnull"] else ""
            declarations.append(f"    {name} {sql_type}{nullability}")
        parents_sql = ""
        parent_ids = sorted(parents.get(relid, []), key=lambda oid: (
            next(sequence for sequence, child in children[oid] if child == relid), oid))
        if parent_ids:
            parents_sql = " INHERITS (" + ", ".join(table_name[parent] for parent in parent_ids) + ")"
        body = " (\n" + ",\n".join(declarations) + "\n)" if declarations else " ()"
        ddl.append(f"CREATE TABLE {table_name[relid]}{body}{parents_sql};")
        # A locally strengthened NOT NULL flag on an inherited attribute needs a
        # child-only constraint because inherited columns are not redeclared.
        for row in attrs_by_relation.get(relid, []):
            if row["attinhcount"] > 0 and row["attnotnull"]:
                parent_notnull = any(
                    match["attnotnull"]
                    for parent in parent_ids
                    for match in attrs_by_relation.get(parent, [])
                    if match["attname"] == row["attname"]
                )
                if not parent_notnull:
                    ddl.append(f"ALTER TABLE {table_name[relid]} ALTER COLUMN "
                               f"{source_column[(relid, row['attnum'])]} SET NOT NULL;")

    result_constraints = []
    for index, row in enumerate(sorted(constraints, key=lambda item: _oid(item.get("oid"), "constraint OID")), 1):
        relid_value = row.get("conrelid")
        relid = _oid(relid_value, "constraint relation OID", zero=True)
        if row.get("contype") not in {"c", "f", "p", "u", "x", "t"}:
            raise ShapeError("unsupported constraint kind")
        source_keys_raw = row.get("conkey")
        source_keys = source_keys_raw if isinstance(source_keys_raw, list) else None
        mapped_keys = []
        for source_attnum in source_keys or []:
            source_attnum = _int(source_attnum, "constraint attribute number", 0,
                                 MAX_HEAP_ATTRIBUTE_NUMBER)
            mapped_keys.append(None if source_attnum == 0 else
                               source_attnums.get(relid, {}).get(str(source_attnum)))
        result_constraints.append({
            "id": f"k{index:04d}",
            "source_oid": _oid(row.get("oid"), "constraint OID"),
            "relation": table_name.get(relid),
            "source_relation_oid": relid,
            "kind": row.get("contype"),
            "validated": row.get("convalidated"),
            "deferrable": row.get("condeferrable"),
            "initially_deferred": row.get("condeferred"),
            "is_local": row.get("conislocal"),
            "inheritance_count": row.get("coninhcount"),
            "no_inherit": row.get("connoinherit"),
            "parent_constraint_oid": _oid(row.get("conparentid"), "parent constraint OID", zero=True),
            "expression_present": bool(row.get("conbin")),
            "source_attnums": source_keys,
            "mapped_keys": mapped_keys if source_keys is not None else None,
            "referenced_relation_oid": _oid(row.get("confrelid"), "referenced relation OID", zero=True),
            "referenced_relation": table_name.get(_oid(row.get("confrelid"), "referenced relation OID", zero=True)),
            "referenced_attnums": row.get("confkey") if isinstance(row.get("confkey"), list) else None,
            "complete": False,
        })
    result_indexes = []
    for index, row in enumerate(sorted(indexes, key=lambda item: _oid(item.get("indexrelid"), "index OID")), 1):
        relid = _oid(row.get("indrelid"), "index relation OID", zero=True)
        source_keys = row.get("indkey") if isinstance(row.get("indkey"), list) else None
        result_indexes.append({
            "id": f"i{index:04d}",
            "source_oid": _oid(row.get("indexrelid"), "index OID"),
            "relation": table_name.get(relid),
            "source_relation_oid": relid,
            "source_key_attnums": source_keys if isinstance(source_keys, list) else None,
            "key_count": row.get("indnatts"),
            "key_attribute_count": row.get("indnkeyatts"),
            "unique": row.get("indisunique"),
            "primary": row.get("indisprimary"),
            "exclusion": row.get("indisexclusion"),
            "ready": row.get("indisready"),
            "valid": row.get("indisvalid"),
            "expression_present": bool(row.get("indexprs")),
            "predicate_present": bool(row.get("indpred")),
            "complete": False,
        })
    return {
        "format": "pgdog-read-shape-skeleton/v1",
        "postgres_major": major,
        "complete": False,
        "ddl": ddl,
        "relations": {
            str(relid): {
                "synthetic_name": table_name[relid],
                "source_oid": relid,
                "parents": [table_name[parent] for parent in sorted(parents.get(relid, []))],
                "column_order": target_orders[relid],
                "source_attnums": source_attnums[relid],
            }
            for relid in sorted(rel_by_oid)
        },
        "columns": {
            column_name[root]: {
                "source_identities": [
                    {"relation_oid": relid, "attnum": attnum}
                    for relid, attnum in sorted(groups[union.find(root)])
                ]
            }
            for root in logical_roots
        },
        "types": {
            str(type_oid): {
                "synthetic_name": name,
                "label_count": enum_label_counts[type_oid],
                "labels": [
                    {"source_label_oid": _oid(label["oid"], "enum label OID"),
                     "synthetic_label": synthetic}
                    for label, synthetic in zip(
                        sorted(enum_labels[type_oid], key=lambda row: row["enumsortorder"]),
                        _synthetic_labels(enum_label_counts[type_oid]),
                    )
                ],
            }
            for type_oid, name in sorted(enum_names.items())
        },
        "pending": {
            "constraints": [row["id"] for row in result_constraints],
            "constraint_inventory": result_constraints,
            "check_constraints": [row["id"] for row in result_constraints if row["kind"] == "c"],
            "foreign_keys": [row["id"] for row in result_constraints if row["kind"] == "f"],
            "exclusion_constraints": [row["id"] for row in result_constraints if row["kind"] == "x"],
            "indexes": [row["id"] for row in result_indexes],
            "index_inventory": result_indexes,
            "index_expressions": [row["id"] for row in result_indexes if row["expression_present"]],
            "index_predicates": [row["id"] for row in result_indexes if row["predicate_present"]],
            "defaults": [
                {"relation_oid": relid, "attnum": row["attnum"]}
                for relid, rows in attrs_by_relation.items()
                for row in rows if row.get("atthasdef") is True
            ],
            "triggers": [
                {"relation_oid": relid}
                for relid, row in rel_by_oid.items() if row.get("relhastriggers") is True
            ],
            "inherited_array_dimension_adjustments": inherited_dimension_overrides,
            "inherited_array_dimension_overrides": [
                row for row in inherited_dimension_overrides if not row["complete"]
            ],
            "inventory_complete": False,
        },
        "limitations": [
            "constraints, indexes, defaults, triggers and expression trees are pending",
            "inherited array dimension differences are recorded; local redeclarations apply their dimensions",
            "target attnums describe generated synthetic tables, not source attnums",
            "schema skeleton is not a complete shape reproduction or proof",
        ],
    }
