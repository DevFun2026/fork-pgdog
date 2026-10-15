import copy
import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import read_shape_fixture as shape


def fixture():
    return {
        "postgres_major": 12,
        "relations": [
            {"oid": 100, "relkind": "r", "relnatts": 2},
            {"oid": 200, "relkind": "r", "relnatts": 3},
        ],
        "attributes": [
            {"attrelid": 100, "attnum": 1, "attname": "private_parent_id", "atttypid": 23,
             "attcollation": 0, "atttypmod": -1, "attndims": 0, "attnotnull": True, "attinhcount": 0,
             "attislocal": True, "attisdropped": False, "attgenerated": "", "attidentity": ""},
            {"attrelid": 100, "attnum": 2, "attname": "private_parent_value", "atttypid": 25,
             "attcollation": 100, "atttypmod": -1, "attndims": 0, "attnotnull": False, "attinhcount": 0,
             "attislocal": True, "attisdropped": False, "attgenerated": "", "attidentity": ""},
            {"attrelid": 200, "attnum": 1, "attname": "private_child_local", "atttypid": 23,
             "attcollation": 0, "atttypmod": -1, "attndims": 0, "attnotnull": False, "attinhcount": 0,
             "attislocal": True, "attisdropped": False, "attgenerated": "", "attidentity": ""},
            {"attrelid": 200, "attnum": 2, "attname": "private_parent_id", "atttypid": 23,
             "attcollation": 0, "atttypmod": -1, "attndims": 0, "attnotnull": True, "attinhcount": 1,
             "attislocal": False, "attisdropped": False, "attgenerated": "", "attidentity": ""},
            {"attrelid": 200, "attnum": 3, "attname": "private_parent_value", "atttypid": 25,
             "attcollation": 100, "atttypmod": -1, "attndims": 0, "attnotnull": False, "attinhcount": 1,
             "attislocal": False, "attisdropped": False, "attgenerated": "", "attidentity": ""},
        ],
        "inheritance_edges": [{"parent": 100, "child": 200, "sequence": 1}],
        "types": [
            {"oid": 23, "typname": "int4", "typnamespace": 11, "typtype": "b", "typelem": 0,
             "typbasetype": 0, "typcategory": "N"},
            {"oid": 25, "typname": "text", "typnamespace": 11, "typtype": "b", "typelem": 0,
             "typbasetype": 0, "typcategory": "S"},
        ],
        "enums": [],
        "constraints": [{"oid": 900, "conrelid": 100, "contype": "c", "conparentid": 0,
                         "confrelid": 0, "confkey": [], "conkey": [], "convalidated": True,
                         "condeferrable": False, "condeferred": False, "conislocal": True,
                         "coninhcount": 0, "connoinherit": False}],
        "indexes": [{"indexrelid": 800, "indrelid": 100}],
    }


def _canonical_digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def proof_export(capture, check_sql=None):
    class_by_oid = {row["oid"]: row for row in capture.get("index_relations", [])}
    index_oids = {row["indexrelid"] for row in capture["indexes"]}
    for oid in index_oids - set(class_by_oid):
        class_by_oid[oid] = {
            "oid": oid, "relam": 403, "relkind": "i", "relpersistence": "p",
            "relispartition": False, "reloptions": None, "reltablespace": 0,
        }
    capture["index_relations"] = [class_by_oid[oid] for oid in sorted(index_oids)]
    expressions = []
    if check_sql is not None:
        source = next(row["conbin"] for row in capture["constraints"] if row.get("conbin"))
        expressions.append({
            "catalog": "pg_constraint", "source_field": "conbin", "object_oid": 900,
            "relation_oid": 100, "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "source_ordinal": 0, "sql": check_sql,
        })
    for row in capture["indexes"]:
        oid = row["indexrelid"]
        relid = row["indrelid"]
        for field in ("indexprs", "indpred"):
            source = row.get(field)
            if not source:
                continue
            count = (sum(int(value) == 0 for value in row["indkey"])
                     if field == "indexprs" else 1)
            for ordinal in range(count):
                expressions.append({
                    "catalog": "pg_index", "source_field": field, "object_oid": oid,
                    "relation_oid": relid,
                    "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                    "source_ordinal": ordinal,
                    "sql": "c0001" if field == "indexprs" else "c0001 > 0",
                })
    constraints = {}
    for row in capture["constraints"]:
        fields = (
            "contype", "conrelid", "confrelid", "conkey", "confkey", "conpfeqop", "conppeqop",
            "conffeqop", "confmatchtype", "confupdtype", "confdeltype", "condeferrable",
            "condeferred", "convalidated", "conislocal", "coninhcount", "connoinherit",
            "conindid", "conparentid",
        ) + tuple(field for field in ("confdelsetcols", "conperiod", "conexclop") if field in row)
        constraints[str(row["oid"])] = {
            "source_metadata": {field: row.get(field) for field in fields}
        }
    base = shape.compile_shape(capture)
    index_support = {
        str(row["indexrelid"]): {
            "source_metadata": row,
            "relation_metadata": next(item for item in capture["index_relations"]
                                       if item["oid"] == row["indexrelid"]),
            "method": "btree", "opclasses": [["pg_catalog", "int4_ops"]],
            "collations": [None], "exclusion_operators": [],
        }
        for row in capture["indexes"]
    }
    return {
        "format": "pgdog-owned-read-proof/v1",
        "capture_sha256": _canonical_digest(capture),
        "relation_shape_sha256": _canonical_digest(base),
        "source_read_proof_complete": True,
        "expressions": expressions,
        "index_support": index_support,
        "constraint_support": constraints,
    }


class ReadShapeFixtureTests(unittest.TestCase):
    def test_multiple_parent_order_uses_inheritance_sequence(self):
        source = fixture()
        source["relations"] = [
            {"oid": 100, "relkind": "r", "relnatts": 1},
            {"oid": 200, "relkind": "r", "relnatts": 1},
            {"oid": 300, "relkind": "r", "relnatts": 1},
        ]
        source["attributes"] = [
            {"attrelid": oid, "attnum": 1, "attname": "private_id", "atttypid": 23,
             "attcollation": 0, "atttypmod": -1, "attndims": 0, "attnotnull": False,
             "attinhcount": 0 if oid != 300 else 2, "attislocal": oid != 300,
             "attisdropped": False, "attgenerated": "", "attidentity": ""}
            for oid in (100, 200, 300)
        ]
        source["inheritance_edges"] = [
            {"parent": 100, "child": 300, "sequence": 2},
            {"parent": 200, "child": 300, "sequence": 1},
        ]
        source["constraints"] = []
        source["indexes"] = []

        result = shape.compile_shape(source)

        child_ddl = next(sql for sql in result["ddl"] if sql.startswith("CREATE TABLE t0003"))
        self.assertIn("INHERITS (t0002, t0001)", child_ddl)

    def test_inheritance_and_source_attnums_map_to_synthetic_target_layout(self):
        result = shape.compile_shape(fixture())
        parent = result["relations"]["100"]
        child = result["relations"]["200"]
        source_parent_id = parent["source_attnums"]["1"]["column"]
        self.assertEqual(source_parent_id, child["source_attnums"]["2"]["column"])
        self.assertEqual(parent["source_attnums"]["1"]["target_attnum"],
                         child["source_attnums"]["2"]["target_attnum"])
        self.assertNotEqual(child["source_attnums"]["1"]["column"],
                            child["source_attnums"]["2"]["column"])
        self.assertEqual(child["source_attnums"]["1"]["target_attnum"], 3)
        self.assertTrue(any("INHERITS" in statement for statement in result["ddl"]))

    def test_nontrivial_objects_remain_explicitly_pending(self):
        result = shape.compile_shape(fixture())
        self.assertEqual(result["pending"]["constraints"], ["k0001"])
        self.assertEqual(result["pending"]["indexes"], ["i0001"])
        self.assertFalse(result["complete"])

    def test_enum_labels_are_synthetic_and_unknown_base_types_fail_closed(self):
        source = fixture()
        source["types"].append({"oid": 500, "typname": "private_enum", "typnamespace": 9000,
                                "typtype": "e", "typelem": 0, "typbasetype": 0,
                                "typcategory": "E"})
        source["enums"] = [
            {"oid": 501, "enumtypid": 500, "enumlabel": "private_label_a", "enumsortorder": 1},
            {"oid": 502, "enumtypid": 500, "enumlabel": "private_label_b", "enumsortorder": 2},
        ]
        source["attributes"][0]["atttypid"] = 500
        source["attributes"][3]["atttypid"] = 500
        result = shape.compile_shape(source)
        self.assertIn("'alpha'", " ".join(result["ddl"]))
        self.assertNotIn("private_label_a", " ".join(result["ddl"]))
        enum = next(iter(result["types"].values()))
        self.assertEqual([item["synthetic_label"] for item in enum["labels"]], ["alpha", "beta"])
        self.assertNotIn("private_label_a", repr(result))

        unknown = fixture()
        unknown["attributes"][0]["atttypid"] = 99999
        with self.assertRaises(shape.ShapeError):
            shape.compile_shape(unknown)

    def test_column_order_and_type_must_agree_across_inheritance(self):
        source = fixture()
        source["attributes"][3]["atttypid"] = 25
        with self.assertRaises(shape.ShapeError):
            shape.compile_shape(source)

    def test_inherited_collation_must_match_parent(self):
        source = fixture()
        source["attributes"][3]["attcollation"] = 100
        with self.assertRaises(shape.ShapeError):
            shape.compile_shape(source)

    def test_builtin_arrays_are_qualified_and_keep_dimensions(self):
        source = fixture()
        source["types"].append({"oid": 1009, "typname": "_text", "typnamespace": 11,
                                "typtype": "b", "typelem": 25})
        source["attributes"][0].update({"atttypid": 1009, "attndims": 2, "attcollation": 100})
        source["attributes"][3].update({"atttypid": 1009, "attndims": 2, "attcollation": 100})
        result = shape.compile_shape(source)
        self.assertIn("pg_catalog.text[][]", " ".join(result["ddl"]))

        scalar_dimensions = fixture()
        scalar_dimensions["attributes"][0]["attndims"] = 1
        with self.assertRaises(shape.ShapeError):
            shape.compile_shape(scalar_dimensions)

        scalar_dimensions = fixture()
        scalar_dimensions["attributes"][0]["attndims"] = 1
        with self.assertRaises(shape.ShapeError):
            shape.compile_shape(scalar_dimensions)

    def test_output_is_deterministic_and_does_not_copy_source_identifiers(self):
        source = fixture()
        forward = shape.compile_shape(source)
        shuffled = copy.deepcopy(source)
        for key in ("relations", "attributes", "constraints", "indexes", "inheritance_edges", "types"):
            shuffled[key].reverse()
        backward = shape.compile_shape(shuffled)
        self.assertEqual(forward, backward)
        rendered = repr(forward)
        for private_token in ("private_parent_id", "private_parent_value", "private_child_local"):
            self.assertNotIn(private_token, rendered)

    def test_attribute_number_above_catalog_limit_is_rejected(self):
        source = fixture()
        source["attributes"][0]["attnum"] = 1601
        with self.assertRaises(shape.ShapeError):
            shape.compile_shape(source)

    def test_empty_relation_fails_with_shape_error(self):
        source = fixture()
        source["relations"].append({"oid": 300, "relkind": "r", "relnatts": 0})
        with self.assertRaises(shape.ShapeError):
            shape.compile_shape(source)

    def test_interval_range_and_precision_use_postgres_typmod_bit_layout(self):
        source = fixture()
        source["types"].append({"oid": 1186, "typname": "interval", "typnamespace": 11,
                                "typtype": "b", "typelem": 0})
        interval_typmod = (0x0006 << 16) | 0xFFFF
        source["attributes"][0].update({"atttypid": 1186, "atttypmod": interval_typmod})
        source["attributes"][3].update({"atttypid": 1186, "atttypmod": interval_typmod})
        result = shape.compile_shape(source)
        self.assertIn("c0001 interval YEAR TO MONTH", " ".join(result["ddl"]))

    def test_qualified_temporal_typmod_uses_unambiguous_builtin_spelling(self):
        source = fixture()
        source["types"].append({"oid": 1083, "typname": "time", "typnamespace": 11,
                                "typtype": "b", "typelem": 0})
        source["attributes"][0].update({"atttypid": 1083, "atttypmod": 3})
        source["attributes"][3].update({"atttypid": 1083, "atttypmod": 3})
        result = shape.compile_shape(source)
        self.assertIn("pg_catalog.time(3)", " ".join(result["ddl"]))
        self.assertNotIn("without time zone", " ".join(result["ddl"]))

    def test_inherited_table_with_no_local_columns_emits_empty_column_list(self):
        source = fixture()
        source["relations"][1]["relnatts"] = 2
        source["attributes"] = [row for row in source["attributes"]
                                if not (row["attrelid"] == 200 and row["attnum"] == 1)]
        result = shape.compile_shape(source)
        child_ddl = next(statement for statement in result["ddl"]
                         if statement.startswith("CREATE TABLE t0002"))
        self.assertRegex(child_ddl, re.compile(r"^CREATE TABLE t0002 \(\) INHERITS \(t0001\);$"))

    def test_local_duplicate_of_inherited_column_is_declared_to_preserve_local_flag(self):
        source = fixture()
        source["attributes"][3]["attislocal"] = True
        result = shape.compile_shape(source)
        child_ddl = next(statement for statement in result["ddl"]
                         if statement.startswith("CREATE TABLE t0002"))
        self.assertIn("c0001 pg_catalog.int4", child_ddl)
        self.assertIn("INHERITS (t0001)", child_ddl)

    def test_proof_compiler_emits_verified_index_and_check_constraint(self):
        source = fixture()
        source["constraints"] = [{
            "oid": 900, "conrelid": 100, "contype": "c", "conparentid": 0,
            "confrelid": 0, "confkey": [], "conkey": [1], "convalidated": True,
            "condeferrable": False, "condeferred": False, "conislocal": True,
            "coninhcount": 0, "connoinherit": True, "conbin": "tree-check",
            "conpfeqop": [], "conppeqop": [], "conffeqop": [], "confmatchtype": "s",
            "confupdtype": "a", "confdeltype": "a", "conindid": 0,
        }]
        source["indexes"] = [{
            "indexrelid": 800, "indrelid": 100, "indkey": [1], "indnatts": 1,
            "indnkeyatts": 1, "indisunique": True, "indisprimary": False,
            "indisexclusion": False, "indisready": True, "indisvalid": True,
            "indislive": True, "indcheckxmin": False, "indisclustered": False,
            "indisreplident": False, "indoption": [0], "indclass": [1978],
            "indcollation": [0], "indpred": None, "indexprs": None,
        }]
        export = proof_export(source, check_sql="c0001 > 0")
        export["index_support"]["800"] = {
            "source_metadata": source["indexes"][0],
            "relation_metadata": source["index_relations"][0],
            "method": "btree", "opclasses": [["pg_catalog", "int4_ops"]],
            "collations": [None], "exclusion_operators": [],
        }

        result = shape.compile_read_shape(source, export)

        self.assertTrue(result["source_read_proof_complete"])
        self.assertTrue(any('CREATE UNIQUE INDEX "i0001"' in sql for sql in result["ddl"]))
        self.assertTrue(any('ADD CONSTRAINT "k0001" CHECK (c0001 > 0)' in sql
                            for sql in result["ddl"]))
        self.assertTrue(any("NO INHERIT" in sql for sql in result["ddl"]))
        self.assertEqual(result["pending"]["indexes"], [])
        self.assertEqual(result["pending"]["constraints"], [])
        self.assertFalse(result["writer_equivalence"])

    def test_proof_compiler_rejects_missing_or_tampered_index_coverage(self):
        source = fixture()
        source["indexes"] = [{
            "indexrelid": 800, "indrelid": 100, "indkey": [1], "indnatts": 1,
            "indnkeyatts": 1, "indisunique": False, "indisprimary": False,
            "indisexclusion": False, "indisready": True, "indisvalid": True,
            "indislive": True, "indcheckxmin": False, "indisclustered": False,
            "indisreplident": False, "indoption": [0], "indclass": [1978],
            "indcollation": [0], "indpred": None, "indexprs": None,
        }]
        export = proof_export(source)
        del export["index_support"]["800"]
        with self.assertRaises(shape.ShapeError):
            shape.compile_read_shape(source, export)
        export = proof_export(source)
        export["index_support"]["800"]["method"] = "unknown"
        with self.assertRaises(shape.ShapeError):
            shape.compile_read_shape(source, export)

    def test_proof_compiler_requires_exact_capture_and_constraint_bindings(self):
        source = fixture()
        source["constraints"][0]["conbin"] = "opaque-check-tree"
        export = proof_export(source, check_sql="c0001 > 0")
        export["source_read_proof_complete"] = False
        with self.assertRaises(shape.ShapeError):
            shape.compile_read_shape(source, export)

        export = proof_export(source, check_sql="c0001 > 0")
        export["constraint_support"]["900"]["source_metadata"]["convalidated"] = False
        with self.assertRaises(shape.ShapeError):
            shape.compile_read_shape(source, export)

        export = proof_export(source, check_sql="c0001 > 0")
        source["constraints"][0]["convalidated"] = False
        with self.assertRaises(shape.ShapeError):
            shape.compile_read_shape(source, export)

    def test_proof_compiler_preserves_fk_actions_deferrability_and_not_valid(self):
        source = fixture()
        source["constraints"] = [{
            "oid": 901, "conrelid": 100, "contype": "f", "conparentid": 0,
            "confrelid": 200, "conkey": [1], "confkey": [2], "convalidated": False,
            "condeferrable": True, "condeferred": True, "conislocal": True,
            "coninhcount": 0, "connoinherit": False, "conindid": 800,
            "conpfeqop": [96], "conppeqop": [96], "conffeqop": [96],
            "confmatchtype": "f", "confupdtype": "c", "confdeltype": "n",
            "confdelsetcols": [1],
        }]
        source["indexes"] = [{
            "indexrelid": 800, "indrelid": 200, "indkey": [2], "indnatts": 1,
            "indnkeyatts": 1, "indisunique": True, "indisprimary": False,
            "indisexclusion": False, "indisready": True, "indisvalid": True,
            "indislive": True, "indcheckxmin": False, "indisclustered": False,
            "indisreplident": False, "indoption": [0], "indclass": [1978],
            "indcollation": [0], "indpred": None, "indexprs": None,
        }]
        export = proof_export(source)

        result = shape.compile_read_shape(source, export)

        sql = next(statement for statement in result["ddl"] if "FOREIGN KEY" in statement)
        self.assertIn('FOREIGN KEY ("c0001")', sql)
        self.assertIn('REFERENCES "t0002" ("c0001") MATCH FULL', sql)
        self.assertIn('ON UPDATE CASCADE ON DELETE SET NULL ("c0001")', sql)
        self.assertIn("DEFERRABLE INITIALLY DEFERRED NOT VALID", sql)

        source["constraints"][0]["convalidated"] = True
        with self.assertRaises(shape.ShapeError):
            shape.compile_read_shape(source, export)

    def test_proof_compiler_attaches_primary_constraint_to_its_verified_index(self):
        source = fixture()
        source["constraints"] = [{
            "oid": 902, "conrelid": 100, "contype": "p", "conparentid": 0,
            "confrelid": 0, "conkey": [1], "confkey": [], "convalidated": True,
            "condeferrable": False, "condeferred": False, "conislocal": True,
            "coninhcount": 0, "connoinherit": False, "conindid": 800,
            "conpfeqop": [], "conppeqop": [], "conffeqop": [], "confmatchtype": "s",
            "confupdtype": "a", "confdeltype": "a",
        }]
        source["indexes"] = [{
            "indexrelid": 800, "indrelid": 100, "indkey": [1], "indnatts": 1,
            "indnkeyatts": 1, "indisunique": True, "indisprimary": True,
            "indisexclusion": False, "indisready": True, "indisvalid": True,
            "indislive": True, "indcheckxmin": False, "indisclustered": False,
            "indisreplident": False, "indoption": [0], "indclass": [1978],
            "indcollation": [0], "indpred": None, "indexprs": None,
        }]
        source["index_relations"] = [{
            "oid": 800, "relam": 403, "relkind": "i", "relpersistence": "p",
            "relispartition": False, "reloptions": None, "reltablespace": 0,
        }]
        export = proof_export(source)

        result = shape.compile_read_shape(source, export)

        self.assertEqual(sum('CREATE UNIQUE INDEX "i0001"' in sql for sql in result["ddl"]), 1)
        self.assertTrue(any('PRIMARY KEY USING INDEX "i0001"' in sql
                            for sql in result["ddl"]))
        self.assertTrue(any('ALTER INDEX "k0001" RENAME TO "i0001"' in sql
                            for sql in result["ddl"]))
        self.assertFalse(result["pending"]["constraints"])

    def test_proof_compiler_preserves_exclusion_method_opclass_and_operator(self):
        source = fixture()
        source["constraints"] = [{
            "oid": 903, "conrelid": 100, "contype": "x", "conparentid": 0,
            "confrelid": 0, "conkey": [1, 0], "confkey": [], "convalidated": True,
            "condeferrable": False, "condeferred": False, "conislocal": True,
            "coninhcount": 0, "connoinherit": False, "conindid": 800,
            "conpfeqop": [], "conppeqop": [], "conffeqop": [], "confmatchtype": "s",
            "confupdtype": "a", "confdeltype": "a", "conexclop": [3888, 3888],
        }]
        source["indexes"] = [{
            "indexrelid": 800, "indrelid": 100, "indkey": [1, 0], "indnatts": 2,
            "indnkeyatts": 2, "indisunique": False, "indisprimary": False,
            "indisexclusion": True, "indisready": True, "indisvalid": True,
            "indislive": True, "indcheckxmin": False, "indisclustered": False,
            "indisreplident": False, "indoption": [0, 0], "indclass": [10078, 10078],
            "indcollation": [0, 0], "indpred": "opaque-exclusion-predicate",
            "indexprs": "opaque-exclusion-expression",
        }]
        source["index_relations"] = [{
            "oid": 800, "relam": 783, "relkind": "i", "relpersistence": "p",
            "relispartition": False, "reloptions": None, "reltablespace": 0,
        }]
        export = proof_export(source)
        export["index_support"]["800"].update({
            "method": "gist", "opclasses": [["pg_catalog", "range_ops"],
                                                ["pg_catalog", "range_ops"]],
            "collations": [None, None],
            "exclusion_operators": [["pg_catalog", "&&"], ["pg_catalog", "&&"]],
        })

        result = shape.compile_read_shape(source, export)

        exclusion = next(statement for statement in result["ddl"] if " EXCLUDE USING " in statement)
        self.assertIn('EXCLUDE USING gist ("c0001" "pg_catalog"."range_ops" WITH '
                      'OPERATOR("pg_catalog".&&), (c0001) "pg_catalog"."range_ops" WITH '
                      'OPERATOR("pg_catalog".&&)) WHERE (c0001 > 0)', exclusion)
        self.assertEqual(sum('CREATE INDEX "i0001"' in sql for sql in result["ddl"]), 0)
        self.assertTrue(any('ALTER INDEX "k0001" RENAME TO "i0001"' in sql
                            for sql in result["ddl"]))

    def test_proof_compiler_rejects_non_operator_tokens(self):
        source = fixture()
        source["constraints"] = [{
            "oid": 903, "conrelid": 100, "contype": "x", "conparentid": 0,
            "confrelid": 0, "conkey": [1], "confkey": [], "convalidated": True,
            "condeferrable": False, "condeferred": False, "conislocal": True,
            "coninhcount": 0, "connoinherit": False, "conindid": 800,
            "conpfeqop": [], "conppeqop": [], "conffeqop": [], "confmatchtype": "s",
            "confupdtype": "a", "confdeltype": "a", "conexclop": [96],
        }]
        source["indexes"] = [{
            "indexrelid": 800, "indrelid": 100, "indkey": [1], "indnatts": 1,
            "indnkeyatts": 1, "indisunique": False, "indisprimary": False,
            "indisexclusion": True, "indisready": True, "indisvalid": True,
            "indislive": True, "indcheckxmin": False, "indisclustered": False,
            "indisreplident": False, "indoption": [0], "indclass": [10078],
            "indcollation": [0], "indpred": None, "indexprs": None,
        }]
        export = proof_export(source)
        export["index_support"]["800"].update({
            "method": "gist", "opclasses": [["public", "gist_int4_ops"]],
            "collations": [None],
            "exclusion_operators": [["pg_catalog", "=); DROP TABLE t0001; --"]],
        })

        with self.assertRaises(shape.ShapeError):
            shape.compile_read_shape(source, export)

    def test_proof_compiler_uses_only_bound_index_expression_sql(self):
        source = fixture()
        source["constraints"] = []
        source["indexes"] = [{
            "indexrelid": 800, "indrelid": 100, "indkey": [0], "indnatts": 1,
            "indnkeyatts": 1, "indisunique": False, "indisprimary": False,
            "indisexclusion": False, "indisready": True, "indisvalid": True,
            "indislive": True, "indcheckxmin": False, "indisclustered": False,
            "indisreplident": False, "indoption": [0], "indclass": [1978],
            "indcollation": [0], "indpred": None, "indexprs": "opaque-private-tree",
        }]
        export = proof_export(source)

        result = shape.compile_read_shape(source, export)

        index_sql = next(statement for statement in result["ddl"] if statement.startswith("CREATE INDEX"))
        self.assertIn('((c0001) "pg_catalog"."int4_ops")', index_sql)
        self.assertNotIn("opaque-private-tree", " ".join(result["ddl"]))

        export["expressions"][0]["source_sha256"] = "0" * 64
        with self.assertRaises(shape.ShapeError):
            shape.compile_read_shape(source, export)

    def test_proof_compiler_preserves_nulls_not_distinct_index_semantics(self):
        source = fixture()
        source["constraints"] = []
        source["indexes"] = [{
            "indexrelid": 800, "indrelid": 100, "indkey": [1], "indnatts": 1,
            "indnkeyatts": 1, "indisunique": True, "indisprimary": False,
            "indisexclusion": False, "indisready": True, "indisvalid": True,
            "indislive": True, "indcheckxmin": False, "indisclustered": False,
            "indisreplident": False, "indoption": [0], "indclass": [1978],
            "indcollation": [0], "indpred": None, "indexprs": None,
            "indnullsnotdistinct": True,
        }]

        result = shape.compile_read_shape(source, proof_export(source))

        sql = next(statement for statement in result["ddl"] if statement.startswith("CREATE UNIQUE INDEX"))
        self.assertTrue(sql.endswith(") NULLS NOT DISTINCT;"))

    def test_proof_compiler_accepts_fk_bound_to_referenced_unique_index(self):
        source = fixture()
        source["constraints"] = [{
            "oid": 901, "conrelid": 200, "contype": "f", "conparentid": 0,
            "confrelid": 100, "conkey": [2], "confkey": [1], "convalidated": True,
            "condeferrable": False, "condeferred": False, "conislocal": True,
            "coninhcount": 0, "connoinherit": False, "conindid": 800,
            "conpfeqop": [96], "conppeqop": [96], "conffeqop": [96],
            "confmatchtype": "s", "confupdtype": "a", "confdeltype": "a",
        }]
        source["indexes"] = [{
            "indexrelid": 800, "indrelid": 100, "indkey": [1], "indnatts": 1,
            "indnkeyatts": 1, "indisunique": True, "indisprimary": False,
            "indisexclusion": False, "indisready": True, "indisvalid": True,
            "indislive": True, "indcheckxmin": False, "indisclustered": False,
            "indisreplident": False, "indoption": [0], "indclass": [1978],
            "indcollation": [0], "indpred": None, "indexprs": None,
        }]
        export = proof_export(source)

        result = shape.compile_read_shape(source, export)

        self.assertTrue(any("FOREIGN KEY" in sql and 'REFERENCES "t0001"' in sql
                            for sql in result["ddl"]))

    def test_proof_compiler_rejects_fk_with_unbound_or_wrong_referenced_index(self):
        source = fixture()
        source["constraints"] = [{
            "oid": 901, "conrelid": 200, "contype": "f", "conparentid": 0,
            "confrelid": 100, "conkey": [2], "confkey": [1], "convalidated": True,
            "condeferrable": False, "condeferred": False, "conislocal": True,
            "coninhcount": 0, "connoinherit": False, "conindid": 0,
            "conpfeqop": [96], "conppeqop": [96], "conffeqop": [96],
            "confmatchtype": "s", "confupdtype": "a", "confdeltype": "a",
        }]
        source["indexes"] = [{
            "indexrelid": 800, "indrelid": 200, "indkey": [2], "indnatts": 1,
            "indnkeyatts": 1, "indisunique": True, "indisprimary": False,
            "indisexclusion": False, "indisready": True, "indisvalid": True,
            "indislive": True, "indcheckxmin": False, "indisclustered": False,
            "indisreplident": False, "indoption": [0], "indclass": [1978],
            "indcollation": [0], "indpred": None, "indexprs": None,
        }]

        with self.assertRaises(shape.ShapeError):
            shape.compile_read_shape(source, proof_export(source))

    def test_proof_compiler_rejects_fk_index_target_relation_and_key_mismatch(self):
        base = fixture()
        base["constraints"] = [{
            "oid": 901, "conrelid": 200, "contype": "f", "conparentid": 0,
            "confrelid": 100, "conkey": [2], "confkey": [1], "convalidated": True,
            "condeferrable": False, "condeferred": False, "conislocal": True,
            "coninhcount": 0, "connoinherit": False, "conindid": 800,
            "conpfeqop": [96], "conppeqop": [96], "conffeqop": [96],
            "confmatchtype": "s", "confupdtype": "a", "confdeltype": "a",
        }]
        base["indexes"] = [{
            "indexrelid": 800, "indrelid": 100, "indkey": [1], "indnatts": 1,
            "indnkeyatts": 1, "indisunique": True, "indisprimary": False,
            "indisexclusion": False, "indisready": True, "indisvalid": True,
            "indislive": True, "indcheckxmin": False, "indisclustered": False,
            "indisreplident": False, "indoption": [0], "indclass": [1978],
            "indcollation": [0], "indpred": None, "indexprs": None,
        }]

        for mutation in ("relation", "key", "partial", "not_unique"):
            with self.subTest(mutation=mutation):
                source = copy.deepcopy(base)
                if mutation == "relation":
                    source["indexes"][0]["indrelid"] = 200
                elif mutation == "key":
                    source["constraints"][0]["confkey"] = [2]
                elif mutation == "partial":
                    source["indexes"][0]["indpred"] = "opaque partial tree"
                else:
                    source["indexes"][0]["indisunique"] = False
                with self.assertRaises(shape.ShapeError):
                    shape.compile_read_shape(source, proof_export(source))

if __name__ == "__main__":
    unittest.main()
