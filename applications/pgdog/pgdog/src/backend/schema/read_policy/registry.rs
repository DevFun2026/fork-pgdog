//! Strict-read's separately pinned PostgreSQL catalog registries.

use serde_json::Value;
use std::sync::OnceLock;

static REGISTRY_PG12: OnceLock<Option<Value>> = OnceLock::new();
static REGISTRY_PG18: OnceLock<Option<Value>> = OnceLock::new();
const REGISTRY_PG12_JSON: &str = include_str!("registry-pg12.json");
const REGISTRY_PG18_JSON: &str = include_str!("registry-pg18.json");
pub(crate) const CATALOG_TABLES: &[&str] = &[
    "pg_type",
    "pg_proc",
    "pg_operator",
    "pg_aggregate",
    "pg_cast",
    "pg_am",
    "pg_collation",
    "pg_opclass",
    "pg_opfamily",
    "pg_amop",
    "pg_amproc",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadRegistry {
    major: u32,
    data: &'static Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TypeIo {
    pub(crate) input: u32,
    pub(crate) output: u32,
    pub(crate) receive: u32,
    pub(crate) send: u32,
}

impl ReadRegistry {
    /// Select after the actual backend identity query. Each immutable context
    /// belongs to one backend catalog snapshot; there is no active global major.
    pub(crate) fn for_major(major: u32) -> Option<Self> {
        let data = match major {
            12 => REGISTRY_PG12
                .get_or_init(|| serde_json::from_str(REGISTRY_PG12_JSON).ok())
                .as_ref()?,
            18 => REGISTRY_PG18
                .get_or_init(|| serde_json::from_str(REGISTRY_PG18_JSON).ok())
                .as_ref()?,
            _ => return None,
        };
        let registry = Self { major, data };
        registry.is_complete().then_some(registry)
    }

    pub(crate) fn major(&self) -> u32 {
        self.major
    }

    fn is_complete(&self) -> bool {
        self.data.get("postgres_major").and_then(Value::as_u64) == Some(self.major.into())
            && self
                .data
                .get("source_image")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            && CATALOG_TABLES.iter().all(|name| {
                self.data
                    .get("tables")
                    .and_then(|t| t.get(name))
                    .and_then(Value::as_array)
                    .is_some_and(|rows| !rows.is_empty())
            })
    }

    fn table(&self, name: &str) -> Option<&'static [Value]> {
        self.data
            .get("tables")?
            .get(name)?
            .as_array()
            .map(Vec::as_slice)
    }

    fn row_by_oid(&self, table_name: &str, oid: u32) -> Option<&'static Value> {
        let key = if table_name == "pg_aggregate" {
            "aggfnoid"
        } else {
            "oid"
        };
        self.table(table_name)?
            .iter()
            .find(|row| field_number(row, key) == Some(oid))
    }

    pub(crate) fn expected_count(&self, name: &str) -> Option<usize> {
        Some(self.table(name)?.len())
    }

    pub(crate) fn expected_oids_csv(&self, name: &str) -> Option<String> {
        let key = if name == "pg_aggregate" {
            "aggfnoid"
        } else {
            "oid"
        };
        Some(
            self.table(name)?
                .iter()
                .map(|row| field_number(row, key).map(|oid| oid.to_string()))
                .collect::<Option<Vec<_>>>()?
                .join(","),
        )
    }

    pub(crate) fn expected_opclass_oids_csv(&self) -> Option<String> {
        self.expected_oids_csv("pg_opclass")
    }

    pub(crate) fn candidate_oids_csv(
        &self,
        table_name: &str,
        names: &std::collections::BTreeSet<String>,
    ) -> Option<String> {
        let name_field = match table_name {
            "pg_proc" => "proname",
            "pg_operator" => "oprname",
            _ => return None,
        };
        let wanted = names
            .iter()
            .filter_map(|name| name.rsplit('.').next())
            .map(|name| name.trim_matches('"'))
            .collect::<std::collections::BTreeSet<_>>();
        Some(
            self.table(table_name)?
                .iter()
                .filter(|row| {
                    row.get(name_field)
                        .and_then(Value::as_str)
                        .is_some_and(|name| wanted.contains(name))
                })
                .map(|row| field_number(row, "oid").map(|oid| oid.to_string()))
                .collect::<Option<Vec<_>>>()?
                .join(","),
        )
    }

    pub(crate) fn scalar_oids_csv(&self) -> String {
        [
            16u32, 17, 20, 21, 23, 25, 700, 701, 1042, 1043, 1082, 1083, 1114, 1184, 1186, 1266,
            1700, 2950,
        ]
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
    }

    pub(crate) fn exact_catalog_record(&self, table_name: &str, oid: u32, actual: &Value) -> bool {
        self.row_by_oid(table_name, oid)
            .is_some_and(|expected| normalize(expected) == normalize(actual))
    }

    #[cfg(test)]
    pub(crate) fn catalog_record_mismatch_fields(
        &self,
        table_name: &str,
        oid: u32,
        actual: &Value,
    ) -> Vec<String> {
        let Some(expected) = self.row_by_oid(table_name, oid) else {
            return vec!["<missing-expected-row>".into()];
        };
        let (Some(expected), Some(actual)) = (expected.as_object(), actual.as_object()) else {
            return vec!["<non-object-row>".into()];
        };
        expected
            .keys()
            .chain(actual.keys())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter(|key| {
                expected.get(key.as_str()).map(normalize)
                    != actual.get(key.as_str()).map(normalize)
            })
            .map(|key| key.to_string())
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn source_image(&self) -> Option<&'static str> {
        self.data.get("source_image")?.as_str()
    }

    pub(crate) fn scalar_type(&self, oid: u32) -> bool {
        const PUBLIC_SCALARS: &[u32] = &[
            16, 17, 20, 21, 23, 25, 700, 701, 1042, 1043, 1082, 1083, 1114, 1184, 1186, 1266, 1700,
            2950,
        ];
        PUBLIC_SCALARS.contains(&oid)
            && self.row_by_oid("pg_type", oid).is_some_and(|row| {
                field_number(row, "typnamespace") == Some(11)
                    && row.get("typtype").and_then(Value::as_str) == Some("b")
                    && field_number(row, "typbasetype") == Some(0)
            })
    }

    pub(crate) fn trusted_type_io(&self, oid: u32, name: &str, io: TypeIo, collation: u32) -> bool {
        self.scalar_type(oid)
            && self.row_by_oid("pg_type", oid).is_some_and(|row| {
                row.get("typname").and_then(Value::as_str) == Some(name)
                    && field_number(row, "typinput") == Some(io.input)
                    && field_number(row, "typoutput") == Some(io.output)
                    && field_number(row, "typreceive") == Some(io.receive)
                    && field_number(row, "typsend") == Some(io.send)
                    && field_number(row, "typcollation") == Some(collation)
            })
    }

    pub(crate) fn type_oid(&self, name: &str) -> Option<u32> {
        self.table("pg_type")?
            .iter()
            .find(|row| {
                row.get("typname").and_then(Value::as_str) == Some(name)
                    && field_number(row, "typnamespace") == Some(11)
                    && field_number(row, "oid").is_some_and(|oid| self.scalar_type(oid))
            })
            .and_then(|row| field_number(row, "oid"))
    }

    fn trusted_proc(&self, oid: u32) -> bool {
        self.row_by_oid("pg_proc", oid).is_some_and(|proc| {
            field_number(proc, "pronamespace") == Some(11)
                && matches!(field_number(proc, "prolang"), Some(12 | 14))
                && proc.get("prokind").and_then(Value::as_str) == Some("f")
                && proc.get("provolatile").and_then(Value::as_str) == Some("i")
                && proc.get("prosecdef").and_then(Value::as_bool) == Some(false)
                && proc.get("proretset").and_then(Value::as_bool) == Some(false)
                && proc.get("proconfig").is_some_and(Value::is_null)
        })
    }

    pub(crate) fn operator_result(
        &self,
        symbol: &str,
        left: Option<u32>,
        right: u32,
    ) -> Option<u32> {
        let left = left.unwrap_or(0);
        self.table("pg_operator")?.iter().find_map(|op| {
            (field_number(op, "oprnamespace") == Some(11)
                && op.get("oprname").and_then(Value::as_str) == Some(symbol)
                && field_number(op, "oprleft") == Some(left)
                && field_number(op, "oprright") == Some(right)
                && field_number(op, "oid")
                    .and_then(|oid| self.row_by_oid("pg_operator", oid).map(|_| oid))
                    .is_some()
                && field_number(op, "oprcode").is_some_and(|oid| self.trusted_proc(oid)))
            .then(|| field_number(op, "oprresult"))?
        })
    }

    pub(crate) fn aggregate_result(&self, name: &str, args: &[u32], star: bool) -> Option<u32> {
        let aggregate = self.table("pg_aggregate")?.iter().find(|aggregate| {
            let Some(oid) = field_number(aggregate, "aggfnoid") else {
                return false;
            };
            let Some(proc) = self.row_by_oid("pg_proc", oid) else {
                return false;
            };
            let expected = proc
                .get("proargtypes")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .split_whitespace()
                .filter_map(|v| v.parse::<u32>().ok())
                .collect::<Vec<_>>();
            let args_match = if star {
                args.is_empty() && expected.is_empty()
            } else if expected == [2276] {
                args.len() == 1 && self.scalar_type(args[0])
            } else {
                expected == args
            };
            field_number(proc, "pronamespace") == Some(11)
                && proc.get("proname").and_then(Value::as_str) == Some(name)
                && args_match
                && [
                    "aggtransfn",
                    "aggfinalfn",
                    "aggcombinefn",
                    "aggserialfn",
                    "aggdeserialfn",
                    "aggmtransfn",
                    "aggminvtransfn",
                    "aggmfinalfn",
                ]
                .iter()
                .filter_map(|key| field_number(aggregate, key))
                .all(|oid| oid == 0 || self.trusted_proc(oid))
        })?;
        field_number(aggregate, "aggfnoid")
            .and_then(|oid| self.row_by_oid("pg_proc", oid))
            .and_then(|proc| field_number(proc, "prorettype"))
    }

    pub(crate) fn cast_allowed(&self, source: u32, target: u32, implicit: bool) -> bool {
        self.table("pg_cast").is_some_and(|casts| {
            casts.iter().any(|cast| {
                field_number(cast, "castsource") == Some(source)
                    && field_number(cast, "casttarget") == Some(target)
                    && (!implicit || cast.get("castcontext").and_then(Value::as_str) == Some("i"))
                    && match field_number(cast, "castfunc") {
                        Some(0) => cast.get("castmethod").and_then(Value::as_str) == Some("b"),
                        Some(oid) => self.trusted_proc(oid),
                        None => false,
                    }
            })
        })
    }
}

fn number(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .or_else(|| value.as_str()?.parse().ok())
}

fn field_number(row: &Value, name: &str) -> Option<u32> {
    number(row.get(name)?)
}

fn normalize(value: &Value) -> Value {
    match value {
        Value::Number(value) => Value::String(value.to_string()),
        Value::Array(values) => Value::Array(values.iter().map(normalize).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), normalize(value)))
                .collect(),
        ),
        value => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_selection_is_explicit_and_isolated_per_backend_major() {
        let pg12 = ReadRegistry::for_major(12).expect("PG12 registry is reviewed and embedded");
        let pg18 = ReadRegistry::for_major(18).expect("PG18 registry remains supported");

        assert_eq!(pg12.major(), 12);
        assert_eq!(pg18.major(), 18);
        assert_ne!(
            pg12.expected_count("pg_type"),
            pg18.expected_count("pg_type"),
            "each backend must use its own catalog snapshot"
        );
        let pg12_int4 = pg12.row_by_oid("pg_type", 23).unwrap();
        let pg18_int4 = pg18.row_by_oid("pg_type", 23).unwrap();
        assert!(pg12.exact_catalog_record("pg_type", 23, pg12_int4));
        assert!(pg18.exact_catalog_record("pg_type", 23, pg18_int4));
        assert!(!pg12.exact_catalog_record("pg_type", 23, pg18_int4));
        assert!(!pg18.exact_catalog_record("pg_type", 23, pg12_int4));
        assert!(ReadRegistry::for_major(13).is_none());
        assert!(ReadRegistry::for_major(17).is_none());
        assert!(ReadRegistry::for_major(19).is_none());
    }

    #[test]
    fn pinned_registry_has_only_expected_scalar_type_identity() {
        let registry = ReadRegistry::for_major(18).unwrap();
        assert!(registry.scalar_type(23));
        assert!(!registry.scalar_type(50_001));
        assert_eq!(registry.type_oid("int4"), Some(23));
        assert_eq!(registry.type_oid("pg_catalog.int4"), None);
        assert_eq!(registry.type_oid("\"pg_catalog.int4\""), None);
        assert_eq!(registry.type_oid("\"pg_catalog\".\"int4\""), None);
        assert_eq!(registry.type_oid("\"int4\""), None);
        assert_eq!(registry.type_oid("public.int4"), None);
    }

    #[test]
    fn every_type_io_slot_must_match_for_each_supported_major() {
        for major in [12, 18] {
            let registry = ReadRegistry::for_major(major).unwrap();
            let row = registry.row_by_oid("pg_type", 23).unwrap();
            let io = TypeIo {
                input: field_number(row, "typinput").unwrap(),
                output: field_number(row, "typoutput").unwrap(),
                receive: field_number(row, "typreceive").unwrap(),
                send: field_number(row, "typsend").unwrap(),
            };
            let collation = field_number(row, "typcollation").unwrap();
            assert!(registry.trusted_type_io(23, "int4", io, collation));

            for mutate_io in [
                |io: &mut TypeIo| io.input += 1,
                |io: &mut TypeIo| io.output += 1,
                |io: &mut TypeIo| io.receive += 1,
                |io: &mut TypeIo| io.send += 1,
            ] as [fn(&mut TypeIo); 4]
            {
                let mut changed = io;
                mutate_io(&mut changed);
                assert!(
                    !registry.trusted_type_io(23, "int4", changed, collation),
                    "PG{major} accepted a changed type I/O OID: {changed:?}"
                );
            }
        }
    }

    #[test]
    fn operator_aggregate_and_cast_resolution_uses_full_reviewed_signatures() {
        let registry = ReadRegistry::for_major(18).unwrap();
        assert_eq!(registry.operator_result("=", Some(23), 23), Some(16));
        assert_eq!(registry.operator_result("=", Some(23), 25), None);
        assert_eq!(registry.aggregate_result("sum", &[23], false), Some(20));
        assert_eq!(registry.aggregate_result("sum", &[25], false), None);
        assert_eq!(registry.aggregate_result("count", &[], true), Some(20));
        assert!(registry.cast_allowed(23, 20, true));
        assert!(!registry.cast_allowed(25, 20, true));
    }
}
