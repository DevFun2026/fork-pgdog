//! Strict-read v1's pinned PostgreSQL 18 catalog registry.
//!
//! `registry-pg18.json` was derived from the pinned official PG18 reference
//! catalog and contains full rows for the supported scalar, operator,
//! aggregate, cast and btree dependency closure. Runtime catalog rows must be
//! compared against these complete records before these lookups can authorize.

use serde_json::Value;
use std::sync::OnceLock;

static REGISTRY: OnceLock<Option<Value>> = OnceLock::new();
const REGISTRY_JSON: &str = include_str!("registry-pg18.json");
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

fn registry() -> Option<&'static Value> {
    REGISTRY
        .get_or_init(|| serde_json::from_str(REGISTRY_JSON).ok())
        .as_ref()
}

fn table(name: &str) -> Option<&'static [Value]> {
    registry()?
        .get("tables")?
        .get(name)?
        .as_array()
        .map(Vec::as_slice)
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

fn row_by_oid(table_name: &str, oid: u32) -> Option<&'static Value> {
    let key = if table_name == "pg_aggregate" {
        "aggfnoid"
    } else {
        "oid"
    };
    table(table_name)?
        .iter()
        .find(|row| field_number(row, key) == Some(oid))
}

pub(crate) fn expected_count(table_name: &str) -> Option<usize> {
    Some(table(table_name)?.len())
}

pub(crate) fn expected_oids_csv(table_name: &str) -> Option<String> {
    let records = table(table_name)?;
    let key = if table_name == "pg_aggregate" {
        "aggfnoid"
    } else {
        "oid"
    };
    Some(
        records
            .iter()
            .map(|row| field_number(row, key).map(|oid| oid.to_string()))
            .collect::<Option<Vec<_>>>()?
            .join(","),
    )
}

pub(crate) fn expected_opclass_oids_csv() -> Option<String> {
    expected_oids_csv("pg_opclass")
}

pub(crate) fn candidate_oids_csv(
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
    let key = if table_name == "pg_aggregate" {
        "aggfnoid"
    } else {
        "oid"
    };
    let rows = table(table_name)?
        .iter()
        .filter(|row| {
            row.get(name_field)
                .and_then(Value::as_str)
                .is_some_and(|name| wanted.contains(name))
        })
        .map(|row| field_number(row, key).map(|oid| oid.to_string()))
        .collect::<Option<Vec<_>>>()?;
    Some(rows.join(","))
}

pub(crate) fn scalar_oids_csv() -> String {
    [
        16u32, 17, 20, 21, 23, 25, 700, 701, 1042, 1043, 1082, 1083, 1114, 1184, 1186, 1266, 1700,
        2950,
    ]
    .iter()
    .map(u32::to_string)
    .collect::<Vec<_>>()
    .join(",")
}

pub(crate) fn server_major() -> Option<u32> {
    registry()?
        .get("postgres_major")?
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
}

#[cfg(test)]
pub(crate) fn source_image() -> Option<&'static str> {
    registry()?.get("source_image")?.as_str()
}

/// Compare a complete catalog row (normally `to_jsonb(catalog_row)`) with the
/// pinned source record. Numeric JSON representations are normalized because
/// the reference extractor serializes OID fields as decimal strings.
pub(crate) fn exact_catalog_record(table_name: &str, oid: u32, actual: &Value) -> bool {
    let Some(expected) = row_by_oid(table_name, oid) else {
        return false;
    };
    normalize(expected) == normalize(actual)
}

#[cfg(test)]
pub(crate) fn catalog_record_mismatch_fields(
    table_name: &str,
    oid: u32,
    actual: &Value,
) -> Vec<String> {
    let Some(expected) = row_by_oid(table_name, oid) else {
        return vec!["<missing-expected-row>".into()];
    };
    let (Some(expected), Some(actual)) = (expected.as_object(), actual.as_object()) else {
        return vec!["<non-object-row>".into()];
    };
    let keys = expected
        .keys()
        .chain(actual.keys())
        .collect::<std::collections::BTreeSet<_>>();
    keys.into_iter()
        .filter_map(|key| {
            let expected_value = expected.get(key.as_str());
            let actual_value = actual.get(key.as_str());
            (expected_value.map(normalize) != actual_value.map(normalize)).then(|| key.to_string())
        })
        .collect()
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

pub(crate) fn scalar_type(oid: u32) -> bool {
    const PUBLIC_SCALARS: &[u32] = &[
        16, 17, 20, 21, 23, 25, 700, 701, 1042, 1043, 1082, 1083, 1114, 1184, 1186, 1266, 1700,
        2950,
    ];
    PUBLIC_SCALARS.contains(&oid)
        && row_by_oid("pg_type", oid).is_some_and(|row| {
            field_number(row, "typnamespace") == Some(11)
                && row.get("typtype").and_then(Value::as_str) == Some("b")
                && field_number(row, "typbasetype") == Some(0)
        })
}

pub(crate) fn trusted_type_io(
    oid: u32,
    name: &str,
    input: u32,
    output: u32,
    receive: u32,
    send: u32,
    collation: u32,
) -> bool {
    scalar_type(oid)
        && row_by_oid("pg_type", oid).is_some_and(|row| {
            row.get("typname").and_then(Value::as_str) == Some(name)
                && field_number(row, "typinput") == Some(input)
                && field_number(row, "typoutput") == Some(output)
                && field_number(row, "typreceive") == Some(receive)
                && field_number(row, "typsend") == Some(send)
                && field_number(row, "typcollation") == Some(collation)
        })
}

pub(crate) fn type_oid(name: &str) -> Option<u32> {
    let mut parts = name.split('.').map(|part| part.trim_matches('"'));
    let (schema, name) = match (parts.next()?, parts.next(), parts.next()) {
        (name, None, None) => ("pg_catalog", name),
        ("pg_catalog", Some(name), None) => ("pg_catalog", name),
        _ => return None,
    };
    if schema != "pg_catalog" {
        return None;
    }
    table("pg_type")?
        .iter()
        .find(|row| {
            row.get("typname").and_then(Value::as_str) == Some(name)
                && field_number(row, "typnamespace") == Some(11)
                && field_number(row, "oid").is_some_and(scalar_type)
        })
        .and_then(|row| field_number(row, "oid"))
}

fn trusted_proc(oid: u32) -> bool {
    let Some(proc) = row_by_oid("pg_proc", oid) else {
        return false;
    };
    field_number(proc, "pronamespace") == Some(11)
        && matches!(field_number(proc, "prolang"), Some(12 | 14))
        && proc.get("prokind").and_then(Value::as_str) == Some("f")
        && proc.get("provolatile").and_then(Value::as_str) == Some("i")
        && proc.get("prosecdef").and_then(Value::as_bool) == Some(false)
        && proc.get("proretset").and_then(Value::as_bool) == Some(false)
        && proc.get("proconfig").is_some_and(Value::is_null)
}

pub(crate) fn operator_result(symbol: &str, left: Option<u32>, right: u32) -> Option<u32> {
    let left = left.unwrap_or(0);
    table("pg_operator")?.iter().find_map(|op| {
        (field_number(op, "oprnamespace") == Some(11)
            && op.get("oprname").and_then(Value::as_str) == Some(symbol)
            && field_number(op, "oprleft") == Some(left)
            && field_number(op, "oprright") == Some(right)
            && field_number(op, "oid")
                .and_then(|oid| row_by_oid("pg_operator", oid).map(|_| oid))
                .is_some()
            && field_number(op, "oprcode").is_some_and(trusted_proc))
        .then(|| field_number(op, "oprresult"))?
    })
}

pub(crate) fn aggregate_result(name: &str, args: &[u32], star: bool) -> Option<u32> {
    let aggregate = table("pg_aggregate")?.iter().find(|aggregate| {
        let oid = field_number(aggregate, "aggfnoid");
        let Some(oid) = oid else {
            return false;
        };
        let Some(proc) = row_by_oid("pg_proc", oid) else {
            return false;
        };
        let expected_args = proc
            .get("proargtypes")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .split_whitespace()
            .filter_map(|v| v.parse::<u32>().ok())
            .collect::<Vec<_>>();
        let arg_match = if star {
            args.is_empty() && expected_args.is_empty()
        } else if expected_args == [2276] {
            args.len() == 1 && scalar_type(args[0])
        } else {
            expected_args == args
        };
        int_field(proc, "pronamespace") == Some(11)
            && proc.get("proname").and_then(Value::as_str) == Some(name)
            && arg_match
            && aggregate_dependencies_safe(aggregate)
    })?;
    field_number(aggregate, "aggfnoid")
        .and_then(|oid| row_by_oid("pg_proc", oid))
        .and_then(|proc| field_number(proc, "prorettype"))
}

fn int_field(row: &Value, key: &str) -> Option<u32> {
    field_number(row, key)
}

fn aggregate_dependencies_safe(aggregate: &Value) -> bool {
    [
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
    .all(|oid| oid == 0 || trusted_proc(oid))
}

pub(crate) fn cast_allowed(source: u32, target: u32, implicit: bool) -> bool {
    table("pg_cast").is_some_and(|casts| {
        casts.iter().any(|cast| {
            field_number(cast, "castsource") == Some(source)
                && field_number(cast, "casttarget") == Some(target)
                && (!implicit || cast.get("castcontext").and_then(Value::as_str) == Some("i"))
                && match field_number(cast, "castfunc") {
                    Some(0) => cast.get("castmethod").and_then(Value::as_str) == Some("b"),
                    Some(oid) => trusted_proc(oid),
                    None => false,
                }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_registry_has_only_expected_scalar_type_identity() {
        assert_eq!(server_major(), Some(18));
        assert!(scalar_type(23));
        assert!(!scalar_type(50_001));
        assert_eq!(type_oid("pg_catalog.int4"), Some(23));
        assert_eq!(type_oid("\"pg_catalog\".\"int4\""), Some(23));
        assert_eq!(type_oid("public.int4"), None);
    }

    #[test]
    fn operator_aggregate_and_cast_resolution_uses_full_reviewed_signatures() {
        assert_eq!(operator_result("=", Some(23), 23), Some(16));
        assert_eq!(operator_result("=", Some(23), 25), None);
        assert_eq!(aggregate_result("sum", &[23], false), Some(20));
        assert_eq!(aggregate_result("sum", &[25], false), None);
        assert_eq!(aggregate_result("count", &[], true), Some(20));
        assert!(cast_allowed(23, 20, true));
        assert!(!cast_allowed(25, 20, true));
    }
}
