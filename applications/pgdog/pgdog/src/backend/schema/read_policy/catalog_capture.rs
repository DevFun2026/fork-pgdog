//! Bounded live catalog capture for dependency-profile equality checks.
//!
//! Queries are fixed per catalog and PostgreSQL major. Every OID/name list is
//! passed as a text bind parameter. Extension C-language membership is checked
//! before a query can return full `pg_proc` rows; source fields are returned
//! only as SHA-256 fingerprints.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::{
    backend::{Server, server::ServerRequest},
    frontend::read_policy::PolicyError,
    net::{DataRow, messages::bind::Parameter as BindParameter},
};

use super::dependency_profile::ValidatedDependencyProfile;

const CATALOGS: &[&str] = &[
    "pg_aggregate",
    "pg_am",
    "pg_amop",
    "pg_amproc",
    "pg_cast",
    "pg_collation",
    "pg_enum",
    "pg_extension",
    "pg_namespace",
    "pg_opclass",
    "pg_operator",
    "pg_opfamily",
    "pg_proc",
    "pg_range",
    "pg_ts_config",
    "pg_ts_config_map",
    "pg_ts_dict",
    "pg_ts_parser",
    "pg_ts_template",
    "pg_type",
];
const MAX_ROWS: usize = 20_000;
const MAX_ROW_BYTES: usize = 1_048_576;
const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

const SERVER_VERSION_SQL: &str = "SELECT pg_catalog.jsonb_build_object( \
    'server_version', pg_catalog.current_setting('server_version'), \
    'server_version_num', pg_catalog.current_setting('server_version_num')::pg_catalog.int4, \
    'postgres_major', pg_catalog.current_setting('server_version_num')::pg_catalog.int4 / 10000 \
)::pg_catalog.text";

const EXTENSION_MEMBERS_SQL: &str = "SELECT pg_catalog.jsonb_build_object( \
    'catalog', c.relname, 'extname', e.extname, 'objid', d.objid::pg_catalog.text, \
    'objsubid', d.objsubid::pg_catalog.text)::pg_catalog.text \
FROM pg_catalog.pg_depend AS d \
JOIN pg_catalog.pg_extension AS e ON e.oid = d.refobjid \
JOIN pg_catalog.pg_class AS c ON c.oid = d.classid \
WHERE d.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass \
  AND d.deptype = 'e' \
  AND e.extname = ANY(pg_catalog.string_to_array($1, ',')) \
ORDER BY e.extname, c.relname, d.objid, d.objsubid LIMIT 20001";

// This query intentionally tests only language metadata. Do not add a full
// pg_proc row or prosrc access here: the C-language gate must run first.
const EXTENSION_PROC_PREFLIGHT_SQL: &str = "SELECT EXISTS ( \
    SELECT 1 FROM pg_catalog.pg_depend AS d \
    JOIN pg_catalog.pg_extension AS e ON e.oid = d.refobjid \
    LEFT JOIN pg_catalog.pg_proc AS p ON p.oid = d.objid \
    LEFT JOIN pg_catalog.pg_language AS l ON l.oid = p.prolang \
    WHERE d.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass \
      AND d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass \
      AND d.deptype = 'e' \
      AND e.extname = ANY(pg_catalog.string_to_array($1, ',')) \
      AND (p.oid IS NULL OR l.lanname IS DISTINCT FROM 'c'))::pg_catalog.text";

const EXTENSION_ROWS_SQL: &str = "SELECT pg_catalog.to_jsonb(e)::pg_catalog.text \
FROM pg_catalog.pg_extension AS e \
WHERE e.extname = ANY(pg_catalog.string_to_array($1, ',')) \
ORDER BY e.extname LIMIT 20001";

/// Raw capture plus namespace authority facts. The dependency-profile validator
/// checks `catalog`; the caller must independently enforce `namespace_security`.
#[derive(Debug, Clone)]
pub(crate) struct CatalogCapture {
    pub(crate) raw: Value,
    pub(crate) namespace_security: Value,
}

fn capture_failure(stage: &str) -> PolicyError {
    #[cfg(test)]
    eprintln!("catalog_capture_failure stage={stage}");
    let _ = stage;
    PolicyError::unsupported()
}

fn capture_diagnostic(stage: &str, detail: &str) {
    #[cfg(test)]
    eprintln!("catalog_capture_diagnostic stage={stage} detail={detail}");
    let _ = (stage, detail);
}

#[derive(Debug)]
struct JsonText(String);

impl From<DataRow> for JsonText {
    fn from(row: DataRow) -> Self {
        Self(row.get_text(0).unwrap_or_default())
    }
}

/// Capture the complete reviewed static dependency closure from one protected
/// backend connection. All failures are intentionally collapsed to unsupported
/// so callers cannot accidentally continue with a partial snapshot.
pub(crate) async fn capture(
    server: &mut Server,
    profile: &ValidatedDependencyProfile,
) -> Result<CatalogCapture, PolicyError> {
    if !server.in_transaction() {
        return Err(capture_failure("transaction_preflight"));
    }
    server
        .enable_strict_protocol()
        .map_err(|_| capture_failure("strict_protocol_preflight"))?;
    let read_only = server
        .fetch_all::<String>(ServerRequest::strict_internal(
            "SHOW transaction_read_only",
            &[],
        ))
        .await
        .map_err(|_| capture_failure("read_only_query"))?;
    if read_only.as_slice() != ["on"] {
        return Err(capture_failure("read_only_result"));
    }

    let version = query_one_json(server, SERVER_VERSION_SQL, &[])
        .await
        .map_err(|_| capture_failure("server_version_query"))?;
    let major = version
        .get("postgres_major")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| capture_failure("server_version_major"))?;
    let version_num = version
        .get("server_version_num")
        .and_then(Value::as_u64)
        .ok_or_else(|| capture_failure("server_version_num"))?;
    let version_text = version
        .get("server_version")
        .and_then(Value::as_str)
        .ok_or_else(|| capture_failure("server_version_text"))?;
    if major != profile.major()
        || version_num / 10_000 != u64::from(major)
        || version_text.is_empty()
    {
        return Err(capture_failure("server_version_profile_match"));
    }

    let enabled_extensions = profile.enabled_extensions();
    let extension_filter =
        extension_filter(&enabled_extensions).map_err(|_| capture_failure("extension_filter"))?;
    let extension_members = if enabled_extensions.is_empty() {
        Vec::new()
    } else {
        query_json_rows(
            server,
            EXTENSION_MEMBERS_SQL,
            &[BindParameter::new(extension_filter.as_bytes())],
        )
        .await
        .map_err(|_| capture_failure("extension_members_query"))?
    };
    if extension_members.len() > MAX_ROWS {
        return Err(capture_failure("extension_members_limit"));
    }
    let members = parse_extension_members(&extension_members)
        .map_err(|_| capture_failure("extension_members_parse"))?;
    let extension_rows = if enabled_extensions.is_empty() {
        Vec::new()
    } else {
        query_json_rows(
            server,
            EXTENSION_ROWS_SQL,
            &[BindParameter::new(extension_filter.as_bytes())],
        )
        .await
        .map_err(|_| capture_failure("extension_rows_query"))?
    };
    if extension_rows.len() != enabled_extensions.len() {
        return Err(capture_failure("extension_rows_count"));
    }
    let extension_namespace_oids = extension_rows
        .iter()
        .map(|row| {
            oid_from_row(row, "extnamespace")
                .map_err(|_| capture_failure("extension_namespace_oid"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let function_member_oids = member_oids(&members, "pg_proc");
    if !enabled_extensions.is_empty() && !function_member_oids.is_empty() {
        let invalid_language = query_one_text(
            server,
            EXTENSION_PROC_PREFLIGHT_SQL,
            &[BindParameter::new(extension_filter.as_bytes())],
        )
        .await
        .map_err(|_| capture_failure("extension_proc_language_query"))?;
        if invalid_language != "false" {
            return Err(capture_failure("extension_proc_language_result"));
        }
    }

    let mut tables = Map::new();
    let mut total_rows = extension_members.len() + extension_rows.len();
    let mut total_bytes = serialized_size(&extension_members)
        .map_err(|_| capture_failure("extension_members_size"))?
        .checked_add(
            serialized_size(&extension_rows).map_err(|_| capture_failure("extension_rows_size"))?,
        )
        .ok_or_else(|| capture_failure("extension_metadata_size_overflow"))?;
    for table in CATALOGS {
        let rows = if *table == "pg_enum" {
            Vec::new()
        } else if *table == "pg_extension" {
            extension_rows.clone()
        } else {
            let rows = fetch_table(
                server,
                profile,
                &members,
                table,
                major,
                &extension_namespace_oids,
            )
            .await
            .map_err(|_| capture_failure(&format!("catalog_query:{table}")))?;
            if *table == "pg_proc" && !function_member_oids.is_empty() {
                // The C-language preflight above is a hard sequencing gate for
                // this first access to complete extension pg_proc rows.
                let captured_proc_oids = rows
                    .iter()
                    .map(|row| {
                        oid_from_row(row, "oid").map_err(|_| capture_failure("pg_proc_oid_parse"))
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?;
                if !function_member_oids.is_subset(&captured_proc_oids) {
                    return Err(capture_failure("pg_proc_extension_member_coverage"));
                }
            }
            rows
        };
        total_rows = total_rows
            .checked_add(rows.len())
            .ok_or_else(|| capture_failure("catalog_row_count_overflow"))?;
        if total_rows > MAX_ROWS {
            return Err(capture_failure("catalog_total_row_limit"));
        }
        total_bytes = total_bytes
            .checked_add(
                serialized_size(&rows)
                    .map_err(|_| capture_failure(&format!("catalog_size:{table}")))?,
            )
            .ok_or_else(|| capture_failure("catalog_total_byte_count_overflow"))?;
        if total_bytes > MAX_CAPTURE_BYTES {
            return Err(capture_failure("catalog_total_byte_limit"));
        }
        tables.insert((*table).to_owned(), Value::Array(rows));
    }

    let namespace_security = fetch_namespace_security(
        server,
        &profile.core_oids_for_catalog("pg_namespace"),
        &extension_namespace_oids,
    )
    .await
    .map_err(|_| capture_failure("namespace_security_query"))?;
    total_bytes = total_bytes
        .checked_add(namespace_security.to_string().len())
        .ok_or_else(|| capture_failure("namespace_security_size_overflow"))?;
    if total_bytes > MAX_CAPTURE_BYTES {
        return Err(capture_failure("namespace_security_byte_limit"));
    }
    let mut raw = Map::new();
    raw.insert("postgres_major".into(), Value::from(major));
    raw.insert(
        "server_version".into(),
        Value::String(version_text.to_owned()),
    );
    raw.insert("server_version_num".into(), Value::from(version_num));
    raw.insert("capture_id".into(), Value::String(next_capture_id()));
    raw.insert("tables".into(), Value::Object(tables));
    raw.insert("extension_members".into(), Value::Array(extension_members));
    raw.insert("namespace_security".into(), namespace_security.clone());
    Ok(CatalogCapture {
        raw: Value::Object(raw),
        namespace_security,
    })
}

async fn fetch_table(
    server: &mut Server,
    profile: &ValidatedDependencyProfile,
    members: &[Value],
    table: &str,
    major: u32,
    extension_namespaces: &[u32],
) -> Result<Vec<Value>, PolicyError> {
    let mut ids = profile.core_oids_for_catalog(table);
    ids.extend(member_oids(members, table));
    ids.sort_unstable();
    ids.dedup();
    let builtin_rows = fetch_named_builtin_rows(server, profile, table, major).await?;

    let mut params = Vec::new();
    let sql = match table {
        "pg_extension" | "pg_enum" => return Ok(builtin_rows),
        "pg_ts_config_map" => {
            let cfg = profile.core_oids_for_catalog("pg_ts_config");
            let config_names = builtin_names(profile, "pg_ts_config")?;
            if cfg.is_empty() && config_names.is_empty() {
                return Ok(builtin_rows);
            }
            params.push(BindParameter::new(oid_csv(cfg)?.as_bytes()));
            params.push(BindParameter::new(names_csv(config_names).as_bytes()));
            catalog_sql(table, major, QueryShape::MapClosure)
        }
        "pg_amop" => {
            let families = family_oids(profile, members);
            if families.is_empty() {
                return Ok(builtin_rows);
            }
            params.push(BindParameter::new(oid_csv(families)?.as_bytes()));
            catalog_sql(table, major, QueryShape::OneOid)
        }
        "pg_amproc" => {
            let families = family_oids(profile, members);
            if families.is_empty() {
                return Ok(builtin_rows);
            }
            params.push(BindParameter::new(oid_csv(families)?.as_bytes()));
            catalog_sql(table, major, QueryShape::OneOid)
        }
        "pg_type" => {
            let ext_types = member_oids(members, "pg_type");
            if ids.is_empty() && ext_types.is_empty() {
                return Ok(builtin_rows);
            }
            params.push(BindParameter::new(oid_csv(ids)?.as_bytes()));
            params.push(BindParameter::new(oid_csv(ext_types)?.as_bytes()));
            catalog_sql(table, major, QueryShape::TypeClosure)
        }
        "pg_range" => {
            if ids.is_empty() {
                return Ok(builtin_rows);
            }
            params.push(BindParameter::new(oid_csv(ids)?.as_bytes()));
            catalog_sql(table, major, QueryShape::OneOid)
        }
        "pg_aggregate" => {
            if ids.is_empty() {
                return Ok(builtin_rows);
            }
            params.push(BindParameter::new(oid_csv(ids)?.as_bytes()));
            catalog_sql(table, major, QueryShape::OneOid)
        }
        "pg_namespace" => {
            ids.extend_from_slice(extension_namespaces);
            ids.sort_unstable();
            ids.dedup();
            if ids.is_empty() {
                return Ok(builtin_rows);
            }
            params.push(BindParameter::new(oid_csv(ids)?.as_bytes()));
            catalog_sql(table, major, QueryShape::OneOid)
        }
        _ => {
            if ids.is_empty() {
                return Ok(builtin_rows);
            }
            params.push(BindParameter::new(oid_csv(ids)?.as_bytes()));
            catalog_sql(table, major, QueryShape::OneOid)
        }
    }
    .ok_or_else(PolicyError::unsupported)?;
    let sql_stage = format!("catalog_sql_fetch:{table}");
    let mut rows = query_json_rows_with_stage(server, sql, &params, &sql_stage).await?;
    rows.extend(builtin_rows);
    let mut seen = BTreeSet::new();
    for row in &rows {
        let key = match row_sort_key(table, row) {
            Ok(key) => key,
            Err(error) => {
                if table == "pg_aggregate" {
                    let keys = row
                        .as_object()
                        .map(|object| {
                            object
                                .keys()
                                .map(String::as_str)
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_else(|| "<non_object>".to_owned());
                    capture_diagnostic("row_sort_key:pg_aggregate", &format!("row_keys={keys}"));
                }
                return Err(error);
            }
        };
        if !seen.insert(key) {
            capture_diagnostic(&format!("row_duplicate:{table}"), "duplicate_identity");
            return Err(PolicyError::unsupported());
        }
    }
    rows.sort_by_key(|row| row_sort_key(table, row).unwrap_or_default());
    Ok(rows)
}

fn row_sort_key(table: &str, row: &Value) -> Result<String, PolicyError> {
    if table == "pg_ts_config_map" {
        let cfg = oid_from_row(row, "mapcfg")?;
        let token = oid_from_row(row, "maptokentype")?;
        let seq = oid_from_row(row, "mapseqno")?;
        return Ok(format!("{cfg:010}:{token:010}:{seq:010}"));
    }
    let key = match table {
        "pg_aggregate" => "aggfnoid",
        "pg_range" => "rngtypid",
        _ => "oid",
    };
    Ok(format!("{:010}", oid_from_row(row, key)?))
}

async fn fetch_named_builtin_rows(
    server: &mut Server,
    profile: &ValidatedDependencyProfile,
    table: &str,
    major: u32,
) -> Result<Vec<Value>, PolicyError> {
    let expected = profile.expected_named_builtin_rows(table);
    if expected.is_empty() {
        return Ok(Vec::new());
    }
    let names = builtin_names_from_expected(table, &expected)?;
    let sql =
        catalog_sql(table, major, QueryShape::BuiltinName).ok_or_else(PolicyError::unsupported)?;
    let stage = format!("named_builtin_fetch:{table}");
    let rows = query_json_rows_with_stage(
        server,
        sql,
        &[BindParameter::new(names_csv(names.clone()).as_bytes())],
        &stage,
    )
    .await?;
    if check_builtin_candidate_counts(table, &expected, &rows).is_err() {
        capture_diagnostic(
            &format!("named_builtin_candidates:{table}"),
            "candidate_count_mismatch",
        );
        return Err(PolicyError::unsupported());
    }
    Ok(rows)
}

fn builtin_names(
    profile: &ValidatedDependencyProfile,
    table: &str,
) -> Result<Vec<String>, PolicyError> {
    let expected = profile.expected_named_builtin_rows(table);
    builtin_names_from_expected(table, &expected)
}

fn builtin_names_from_expected(
    table: &str,
    expected: &[(String, Value)],
) -> Result<Vec<String>, PolicyError> {
    let allowlist: &[&str] = match table {
        "pg_proc" => &["dsnowball_init", "dsnowball_lexize"],
        "pg_ts_config" => &["simple", "english"],
        "pg_ts_dict" => &["simple", "english_stem"],
        "pg_ts_template" => &["simple", "snowball"],
        _ => return Ok(Vec::new()),
    };
    let prefix = format!("$builtin:{table}:pg_catalog.");
    let mut names = BTreeSet::new();
    for (identity, _) in expected {
        let suffix = identity
            .strip_prefix(&prefix)
            .ok_or_else(PolicyError::unsupported)?;
        let name = suffix.split('(').next().unwrap_or_default();
        if !allowlist.contains(&name) || !names.insert(name.to_owned()) {
            return Err(PolicyError::unsupported());
        }
    }
    Ok(names.into_iter().collect())
}

fn check_builtin_candidate_counts(
    table: &str,
    expected: &[(String, Value)],
    rows: &[Value],
) -> Result<(), PolicyError> {
    let mut expected_counts = BTreeMap::<String, usize>::new();
    for (identity, _) in expected {
        let prefix = format!("$builtin:{table}:pg_catalog.");
        let suffix = identity
            .strip_prefix(&prefix)
            .ok_or_else(PolicyError::unsupported)?;
        let name = suffix.split('(').next().unwrap_or_default();
        *expected_counts.entry(name.to_owned()).or_default() += 1;
    }
    let name_field = match table {
        "pg_proc" => "proname",
        "pg_ts_config" => "cfgname",
        "pg_ts_dict" => "dictname",
        "pg_ts_template" => "tmplname",
        _ => return Err(PolicyError::unsupported()),
    };
    let mut actual_counts = BTreeMap::<String, usize>::new();
    for row in rows {
        let name = row
            .get(name_field)
            .and_then(Value::as_str)
            .ok_or_else(PolicyError::unsupported)?;
        *actual_counts.entry(name.to_owned()).or_default() += 1;
    }
    if actual_counts != expected_counts {
        return Err(PolicyError::unsupported());
    }
    Ok(())
}

fn names_csv(names: Vec<String>) -> String {
    names.join(",")
}

async fn fetch_namespace_security(
    server: &mut Server,
    core_namespace_oids: &[u32],
    extension_namespace_oids: &[u32],
) -> Result<Value, PolicyError> {
    let mut ids = core_namespace_oids.to_vec();
    ids.extend_from_slice(extension_namespace_oids);
    let ids = oid_csv(ids)?;
    if ids.is_empty() {
        return Err(PolicyError::unsupported());
    }
    let sql = "SELECT pg_catalog.jsonb_build_object( \
        'oid', n.oid::pg_catalog.text, 'nspname', n.nspname, \
        'nspowner', n.nspowner::pg_catalog.text, 'nspacl', n.nspacl, \
        'has_create', pg_catalog.has_schema_privilege(current_user, n.oid, 'CREATE'), \
        'has_usage', pg_catalog.has_schema_privilege(current_user, n.oid, 'USAGE'), \
        'actor_oid', (SELECT r.oid::pg_catalog.text FROM pg_catalog.pg_roles AS r \
            WHERE r.rolname = current_user))::pg_catalog.text \
        FROM pg_catalog.pg_namespace AS n \
        WHERE n.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
        ORDER BY n.oid LIMIT 20001";
    let rows = query_json_rows(server, sql, &[BindParameter::new(ids.as_bytes())]).await?;
    if rows.len() > MAX_ROWS {
        return Err(PolicyError::unsupported());
    }
    Ok(Value::Array(rows))
}

#[derive(Debug, Clone, Copy)]
enum QueryShape {
    OneOid,
    TypeClosure,
    MapClosure,
    BuiltinName,
}

macro_rules! row_by_oid_sql {
    ($table:literal, $alias:literal) => {
        concat!(
            "SELECT pg_catalog.to_jsonb(",
            $alias,
            ")::pg_catalog.text FROM pg_catalog.",
            $table,
            " AS ",
            $alias,
            " WHERE ",
            $alias,
            ".oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) ORDER BY ",
            $alias,
            ".oid LIMIT 20001"
        )
    };
}

fn catalog_sql(table: &str, major: u32, shape: QueryShape) -> Option<&'static str> {
    if !matches!(major, 12 | 18) {
        return None;
    }
    match (table, shape) {
        ("pg_proc", QueryShape::BuiltinName) if major == 12 => Some(
            "SELECT ((pg_catalog.to_jsonb(p) - 'prosrc') || pg_catalog.jsonb_build_object( \
                'prosrc', pg_catalog.jsonb_build_object('sha256_utf8', \
                    pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc, 'UTF8')), 'hex')), \
                'prosupport', p.prosupport::pg_catalog.oid::pg_catalog.text, \
                'proargtypes', p.proargtypes::pg_catalog.text, \
                'proallargtypes', p.proallargtypes::pg_catalog.text, \
                'proargmodes', p.proargmodes::pg_catalog.text, \
                'proconfig', p.proconfig::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_proc AS p \
             WHERE p.pronamespace = (SELECT n.oid FROM pg_catalog.pg_namespace AS n WHERE n.nspname = 'pg_catalog') \
               AND p.proname = ANY(pg_catalog.string_to_array($1, ',')) \
             ORDER BY p.proname, p.oid LIMIT 20001",
        ),
        ("pg_proc", QueryShape::BuiltinName) => Some(
            "SELECT ((pg_catalog.to_jsonb(p) - 'prosrc' - 'prosqlbody') || pg_catalog.jsonb_build_object( \
                'prosrc', pg_catalog.jsonb_build_object('sha256_utf8', \
                    pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc, 'UTF8')), 'hex')), \
                'prosqlbody', CASE WHEN p.prosqlbody IS NULL THEN 'null'::pg_catalog.jsonb \
                    ELSE pg_catalog.jsonb_build_object('sha256_utf8', \
                        pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosqlbody::pg_catalog.text, 'UTF8')), 'hex')) END, \
                'prosupport', p.prosupport::pg_catalog.oid::pg_catalog.text, \
                'proargtypes', p.proargtypes::pg_catalog.text, \
                'proallargtypes', p.proallargtypes::pg_catalog.text, \
                'proargmodes', p.proargmodes::pg_catalog.text, \
                'proconfig', p.proconfig::pg_catalog.text, \
                'protrftypes', p.protrftypes::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_proc AS p \
             WHERE p.pronamespace = (SELECT n.oid FROM pg_catalog.pg_namespace AS n WHERE n.nspname = 'pg_catalog') \
               AND p.proname = ANY(pg_catalog.string_to_array($1, ',')) \
             ORDER BY p.proname, p.oid LIMIT 20001",
        ),
        ("pg_ts_config", QueryShape::BuiltinName) => Some(
            "SELECT pg_catalog.to_jsonb(c)::pg_catalog.text FROM pg_catalog.pg_ts_config AS c \
             JOIN pg_catalog.pg_namespace AS n ON n.oid = c.cfgnamespace \
             WHERE n.nspname = 'pg_catalog' AND c.cfgname = ANY(pg_catalog.string_to_array($1, ',')) \
             ORDER BY c.cfgname, c.oid LIMIT 20001",
        ),
        ("pg_ts_dict", QueryShape::BuiltinName) => Some(
            "SELECT pg_catalog.to_jsonb(d)::pg_catalog.text FROM pg_catalog.pg_ts_dict AS d \
             JOIN pg_catalog.pg_namespace AS n ON n.oid = d.dictnamespace \
             WHERE n.nspname = 'pg_catalog' AND d.dictname = ANY(pg_catalog.string_to_array($1, ',')) \
             ORDER BY d.dictname, d.oid LIMIT 20001",
        ),
        ("pg_ts_template", QueryShape::BuiltinName) => Some(
            "SELECT (pg_catalog.to_jsonb(t) || pg_catalog.jsonb_build_object( \
                'tmplinit', t.tmplinit::pg_catalog.oid::pg_catalog.text, \
                'tmpllexize', t.tmpllexize::pg_catalog.oid::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_ts_template AS t \
             JOIN pg_catalog.pg_namespace AS n ON n.oid = t.tmplnamespace \
             WHERE n.nspname = 'pg_catalog' AND t.tmplname = ANY(pg_catalog.string_to_array($1, ',')) \
             ORDER BY t.tmplname, t.oid LIMIT 20001",
        ),
        ("pg_ts_config_map", QueryShape::MapClosure) => Some(
            "SELECT pg_catalog.to_jsonb(m)::pg_catalog.text FROM pg_catalog.pg_ts_config_map AS m \
             WHERE m.mapcfg = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
                OR m.mapcfg IN (SELECT c.oid FROM pg_catalog.pg_ts_config AS c \
                                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.cfgnamespace \
                                WHERE n.nspname = 'pg_catalog' \
                                  AND c.cfgname = ANY(pg_catalog.string_to_array($2, ','))) \
             ORDER BY m.mapcfg, m.maptokentype, m.mapseqno LIMIT 20001",
        ),
        ("pg_type", QueryShape::TypeClosure) if major == 12 => Some(
            "SELECT (pg_catalog.to_jsonb(t) || pg_catalog.jsonb_build_object( \
                'typinput', t.typinput::pg_catalog.oid::pg_catalog.text, 'typoutput', t.typoutput::pg_catalog.oid::pg_catalog.text, \
                'typreceive', t.typreceive::pg_catalog.oid::pg_catalog.text, 'typsend', t.typsend::pg_catalog.oid::pg_catalog.text, \
                'typmodin', t.typmodin::pg_catalog.oid::pg_catalog.text, 'typmodout', t.typmodout::pg_catalog.oid::pg_catalog.text, \
                'typanalyze', t.typanalyze::pg_catalog.oid::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_type AS t \
             WHERE t.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
                OR t.typelem = ANY(pg_catalog.string_to_array($2, ',')::pg_catalog.oid[]) \
             ORDER BY t.oid LIMIT 20001",
        ),
        ("pg_type", QueryShape::TypeClosure) => Some(
            "SELECT (pg_catalog.to_jsonb(t) || pg_catalog.jsonb_build_object( \
                'typinput', t.typinput::pg_catalog.oid::pg_catalog.text, 'typoutput', t.typoutput::pg_catalog.oid::pg_catalog.text, \
                'typreceive', t.typreceive::pg_catalog.oid::pg_catalog.text, 'typsend', t.typsend::pg_catalog.oid::pg_catalog.text, \
                'typmodin', t.typmodin::pg_catalog.oid::pg_catalog.text, 'typmodout', t.typmodout::pg_catalog.oid::pg_catalog.text, \
                'typanalyze', t.typanalyze::pg_catalog.oid::pg_catalog.text, 'typsubscript', t.typsubscript::pg_catalog.oid::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_type AS t \
             WHERE t.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
                OR t.typelem = ANY(pg_catalog.string_to_array($2, ',')::pg_catalog.oid[]) \
             ORDER BY t.oid LIMIT 20001",
        ),
        ("pg_proc", QueryShape::OneOid) if major == 12 => Some(
            "SELECT ((pg_catalog.to_jsonb(p) - 'prosrc') || pg_catalog.jsonb_build_object( \
                'prosrc', pg_catalog.jsonb_build_object('sha256_utf8', \
                    pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc, 'UTF8')), 'hex')), \
                'prosupport', p.prosupport::pg_catalog.oid::pg_catalog.text, \
                'proargtypes', p.proargtypes::pg_catalog.text, \
                'proallargtypes', p.proallargtypes::pg_catalog.text, \
                'proargmodes', p.proargmodes::pg_catalog.text, \
                'proconfig', p.proconfig::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_proc AS p \
             WHERE p.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
             ORDER BY p.oid LIMIT 20001",
        ),
        ("pg_proc", QueryShape::OneOid) => Some(
            "SELECT ((pg_catalog.to_jsonb(p) - 'prosrc' - 'prosqlbody') || pg_catalog.jsonb_build_object( \
                'prosrc', pg_catalog.jsonb_build_object('sha256_utf8', \
                    pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc, 'UTF8')), 'hex')), \
                'prosqlbody', CASE WHEN p.prosqlbody IS NULL THEN 'null'::pg_catalog.jsonb \
                    ELSE pg_catalog.jsonb_build_object('sha256_utf8', \
                        pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosqlbody::pg_catalog.text, 'UTF8')), 'hex')) END, \
                'prosupport', p.prosupport::pg_catalog.oid::pg_catalog.text, \
                'proargtypes', p.proargtypes::pg_catalog.text, \
                'proallargtypes', p.proallargtypes::pg_catalog.text, \
                'proargmodes', p.proargmodes::pg_catalog.text, \
                'proconfig', p.proconfig::pg_catalog.text, \
                'protrftypes', p.protrftypes::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_proc AS p \
             WHERE p.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
             ORDER BY p.oid LIMIT 20001",
        ),
        ("pg_aggregate", QueryShape::OneOid) => Some(
            "SELECT (pg_catalog.to_jsonb(a) || pg_catalog.jsonb_build_object( \
                'aggfnoid', a.aggfnoid::pg_catalog.oid::pg_catalog.text, \
                'aggtransfn', a.aggtransfn::pg_catalog.oid::pg_catalog.text, \
                'aggfinalfn', a.aggfinalfn::pg_catalog.oid::pg_catalog.text, \
                'aggcombinefn', a.aggcombinefn::pg_catalog.oid::pg_catalog.text, \
                'aggserialfn', a.aggserialfn::pg_catalog.oid::pg_catalog.text, \
                'aggdeserialfn', a.aggdeserialfn::pg_catalog.oid::pg_catalog.text, \
                'aggmtransfn', a.aggmtransfn::pg_catalog.oid::pg_catalog.text, \
                'aggminvtransfn', a.aggminvtransfn::pg_catalog.oid::pg_catalog.text, \
                'aggmfinalfn', a.aggmfinalfn::pg_catalog.oid::pg_catalog.text, \
                'aggsortop', a.aggsortop::pg_catalog.oid::pg_catalog.text, \
                'aggtranstype', a.aggtranstype::pg_catalog.oid::pg_catalog.text, \
                'aggmtranstype', a.aggmtranstype::pg_catalog.oid::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_aggregate AS a \
             WHERE a.aggfnoid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
             ORDER BY a.aggfnoid LIMIT 20001",
        ),
        ("pg_range", QueryShape::OneOid) => Some(
            "SELECT (pg_catalog.to_jsonb(r) || pg_catalog.jsonb_build_object( \
                'rngcanonical', r.rngcanonical::pg_catalog.oid::pg_catalog.text, \
                'rngsubdiff', r.rngsubdiff::pg_catalog.oid::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_range AS r \
             WHERE r.rngtypid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
             ORDER BY r.rngtypid LIMIT 20001",
        ),
        ("pg_ts_config_map", QueryShape::OneOid) => Some(
            "SELECT pg_catalog.to_jsonb(m)::pg_catalog.text FROM pg_catalog.pg_ts_config_map AS m \
             WHERE m.mapcfg = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
             ORDER BY m.mapcfg, m.maptokentype, m.mapseqno LIMIT 20001",
        ),
        ("pg_amop", QueryShape::OneOid) => Some(
            "SELECT pg_catalog.to_jsonb(o)::pg_catalog.text FROM pg_catalog.pg_amop AS o \
             WHERE o.amopfamily = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
             ORDER BY o.oid LIMIT 20001",
        ),
        ("pg_amproc", QueryShape::OneOid) => Some(
            "SELECT (pg_catalog.to_jsonb(o) || pg_catalog.jsonb_build_object( \
                'amproc', o.amproc::pg_catalog.oid::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_amproc AS o \
             WHERE o.amprocfamily = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
             ORDER BY o.oid LIMIT 20001",
        ),
        ("pg_aggregate", _) | ("pg_range", _) | ("pg_amop", _) | ("pg_amproc", _) => None,
        ("pg_proc", _) | ("pg_type", _) | ("pg_ts_config_map", _) => None,
        ("pg_enum", _) | ("pg_extension", _) => None,
        ("pg_am", QueryShape::OneOid) => Some(
            "SELECT (pg_catalog.to_jsonb(r) || pg_catalog.jsonb_build_object( \
                'amhandler', r.amhandler::pg_catalog.oid::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_am AS r WHERE r.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
             ORDER BY r.oid LIMIT 20001",
        ),
        ("pg_cast", QueryShape::OneOid) => Some(
            "SELECT (pg_catalog.to_jsonb(r) || pg_catalog.jsonb_build_object( \
                'castfunc', r.castfunc::pg_catalog.oid::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_cast AS r WHERE r.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
             ORDER BY r.oid LIMIT 20001",
        ),
        ("pg_collation", QueryShape::OneOid) => Some(row_by_oid_sql!("pg_collation", "r")),
        ("pg_namespace", QueryShape::OneOid) => Some(row_by_oid_sql!("pg_namespace", "r")),
        ("pg_opclass", QueryShape::OneOid) => Some(row_by_oid_sql!("pg_opclass", "r")),
        ("pg_operator", QueryShape::OneOid) => Some(
            "SELECT (pg_catalog.to_jsonb(r) || pg_catalog.jsonb_build_object( \
                'oprcode', r.oprcode::pg_catalog.oid::pg_catalog.text, \
                'oprrest', r.oprrest::pg_catalog.oid::pg_catalog.text, \
                'oprjoin', r.oprjoin::pg_catalog.oid::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_operator AS r WHERE r.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
             ORDER BY r.oid LIMIT 20001",
        ),
        ("pg_opfamily", QueryShape::OneOid) => Some(row_by_oid_sql!("pg_opfamily", "r")),
        ("pg_ts_config", QueryShape::OneOid) => Some(row_by_oid_sql!("pg_ts_config", "r")),
        ("pg_ts_dict", QueryShape::OneOid) => Some(row_by_oid_sql!("pg_ts_dict", "r")),
        ("pg_ts_parser", QueryShape::OneOid) => Some(
            "SELECT (pg_catalog.to_jsonb(r) || pg_catalog.jsonb_build_object( \
                'prsstart', r.prsstart::pg_catalog.oid::pg_catalog.text, \
                'prstoken', r.prstoken::pg_catalog.oid::pg_catalog.text, \
                'prsend', r.prsend::pg_catalog.oid::pg_catalog.text, \
                'prsheadline', r.prsheadline::pg_catalog.oid::pg_catalog.text, \
                'prslextype', r.prslextype::pg_catalog.oid::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_ts_parser AS r WHERE r.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
             ORDER BY r.oid LIMIT 20001",
        ),
        ("pg_ts_template", QueryShape::OneOid) => Some(
            "SELECT (pg_catalog.to_jsonb(r) || pg_catalog.jsonb_build_object( \
                'tmplinit', r.tmplinit::pg_catalog.oid::pg_catalog.text, \
                'tmpllexize', r.tmpllexize::pg_catalog.oid::pg_catalog.text))::pg_catalog.text \
             FROM pg_catalog.pg_ts_template AS r WHERE r.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
             ORDER BY r.oid LIMIT 20001",
        ),
        _ => None,
    }
}

fn member_oids(members: &[Value], table: &str) -> BTreeSet<u32> {
    members
        .iter()
        .filter(|row| row.get("catalog").and_then(Value::as_str) == Some(table))
        .filter_map(|row| row.get("objid").and_then(parse_oid_value))
        .collect()
}

fn family_oids(profile: &ValidatedDependencyProfile, members: &[Value]) -> BTreeSet<u32> {
    let mut ids = profile
        .core_oids_for_catalog("pg_opfamily")
        .into_iter()
        .collect::<BTreeSet<_>>();
    ids.extend(member_oids(members, "pg_opfamily"));
    ids
}

fn parse_extension_members(rows: &[Value]) -> Result<Vec<Value>, PolicyError> {
    if rows.len() > MAX_ROWS {
        return Err(PolicyError::unsupported());
    }
    for row in rows {
        let Some(catalog) = row.get("catalog").and_then(Value::as_str) else {
            return Err(PolicyError::unsupported());
        };
        let Some(extname) = row.get("extname").and_then(Value::as_str) else {
            return Err(PolicyError::unsupported());
        };
        if !CATALOGS.contains(&catalog) || !matches!(extname, "pg_trgm" | "btree_gist") {
            return Err(PolicyError::unsupported());
        }
        let objid = row
            .get("objid")
            .and_then(parse_oid_value)
            .ok_or_else(PolicyError::unsupported)?;
        let objsubid = row
            .get("objsubid")
            .and_then(parse_oid_value)
            .ok_or_else(PolicyError::unsupported)?;
        if objid == 0 || objsubid != 0 {
            return Err(PolicyError::unsupported());
        }
    }
    Ok(rows.to_vec())
}

fn extension_filter(names: &[String]) -> Result<String, PolicyError> {
    if names.len() > 2
        || names.windows(2).any(|pair| pair[0] >= pair[1])
        || names
            .iter()
            .any(|name| !matches!(name.as_str(), "btree_gist" | "pg_trgm"))
    {
        return Err(PolicyError::unsupported());
    }
    Ok(names.join(","))
}

fn parse_oid_value(value: &Value) -> Option<u32> {
    match value {
        Value::Number(number) => u32::try_from(number.as_u64()?).ok(),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn oid_from_row(row: &Value, field: &str) -> Result<u32, PolicyError> {
    row.get(field)
        .and_then(parse_oid_value)
        .filter(|oid| *oid != 0)
        .ok_or_else(PolicyError::unsupported)
}

fn oid_csv(values: impl IntoIterator<Item = u32>) -> Result<String, PolicyError> {
    let values = values.into_iter().collect::<BTreeSet<_>>();
    if values.contains(&0) || values.len() > MAX_ROWS {
        return Err(PolicyError::unsupported());
    }
    let output = values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    Ok(output)
}

fn serialized_size(values: &[Value]) -> Result<usize, PolicyError> {
    values.iter().try_fold(0usize, |total, value| {
        total
            .checked_add(value.to_string().len())
            .ok_or_else(PolicyError::unsupported)
    })
}

fn next_capture_id() -> String {
    format!("pgdog-live-catalog-{}", uuid::Uuid::new_v4())
}

async fn query_json_rows(
    server: &mut Server,
    sql: &str,
    params: &[BindParameter],
) -> Result<Vec<Value>, PolicyError> {
    query_json_rows_with_stage(server, sql, params, "query_json_rows").await
}

async fn query_json_rows_with_stage(
    server: &mut Server,
    sql: &str,
    params: &[BindParameter],
    stage: &str,
) -> Result<Vec<Value>, PolicyError> {
    let rows = match server
        .fetch_all::<JsonText>(ServerRequest::strict_internal(sql, params))
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            if stage == "catalog_sql_fetch:pg_aggregate" {
                if let crate::backend::Error::ExecutionError(response) = &error {
                    let message = response
                        .message
                        .chars()
                        .filter(|ch| ch.is_ascii_graphic() || *ch == ' ')
                        .take(200)
                        .collect::<String>();
                    capture_diagnostic(
                        stage,
                        &format!("sqlstate={} message={message}", response.code),
                    );
                } else {
                    capture_diagnostic(stage, "backend_error_non_execution");
                }
            }
            return Err(PolicyError::unsupported());
        }
    };
    if rows.len() > MAX_ROWS {
        capture_diagnostic(stage, "row_limit");
        return Err(PolicyError::unsupported());
    }
    decode_json_rows_with_stage(rows, stage)
}

#[cfg(test)]
fn decode_json_rows(rows: Vec<JsonText>) -> Result<Vec<Value>, PolicyError> {
    decode_json_rows_with_stage(rows, "json_decode")
}

fn decode_json_rows_with_stage(
    rows: Vec<JsonText>,
    stage: &str,
) -> Result<Vec<Value>, PolicyError> {
    if rows.len() > MAX_ROWS {
        capture_diagnostic(stage, "decode_row_limit");
        return Err(PolicyError::unsupported());
    }
    let mut total_bytes = 0usize;
    rows.into_iter()
        .enumerate()
        .map(|(index, row)| {
            if row.0.is_empty() || row.0.len() > MAX_ROW_BYTES {
                capture_diagnostic(stage, &format!("decode_row_bounds row_index={index}"));
                return Err(PolicyError::unsupported());
            }
            total_bytes = total_bytes.checked_add(row.0.len()).ok_or_else(|| {
                capture_diagnostic(stage, "decode_byte_count_overflow");
                PolicyError::unsupported()
            })?;
            if total_bytes > MAX_CAPTURE_BYTES {
                capture_diagnostic(stage, "decode_byte_limit");
                return Err(PolicyError::unsupported());
            }
            serde_json::from_str(&row.0).map_err(|_| {
                capture_diagnostic(stage, &format!("decode_json_syntax row_index={index}"));
                PolicyError::unsupported()
            })
        })
        .collect()
}

async fn query_one_json(
    server: &mut Server,
    sql: &str,
    params: &[BindParameter],
) -> Result<Value, PolicyError> {
    let mut rows = query_json_rows(server, sql, params).await?;
    if rows.len() != 1 {
        return Err(PolicyError::unsupported());
    }
    Ok(rows.remove(0))
}

async fn query_one_text(
    server: &mut Server,
    sql: &str,
    params: &[BindParameter],
) -> Result<String, PolicyError> {
    let rows = server
        .fetch_all::<String>(ServerRequest::strict_internal(sql, params))
        .await
        .map_err(|_| PolicyError::unsupported())?;
    if rows.len() != 1 {
        return Err(PolicyError::unsupported());
    }
    Ok(rows[0].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_query_is_selected_from_a_fixed_whitelist() {
        assert!(catalog_sql("pg_type", 18, QueryShape::TypeClosure).is_some());
        assert!(catalog_sql("pg_proc", 12, QueryShape::OneOid).is_some());
        assert!(catalog_sql("pg_namespace; select pg_sleep(1)", 18, QueryShape::OneOid).is_none());
        assert!(catalog_sql("pg_type", 17, QueryShape::TypeClosure).is_none());
        assert!(EXTENSION_MEMBERS_SQL.contains("text FROM pg_catalog.pg_depend"));
        assert!(EXTENSION_MEMBERS_SQL.contains("AS d JOIN pg_catalog.pg_extension"));
    }

    #[test]
    fn aggregate_oid_aliases_are_serialized_as_numeric_oid_text() {
        let sql = catalog_sql("pg_aggregate", 12, QueryShape::OneOid).unwrap();
        assert!(
            sql.starts_with("SELECT (pg_catalog.to_jsonb(a) || pg_catalog.jsonb_build_object(")
        );
        assert!(sql.contains("'aggfnoid', a.aggfnoid::pg_catalog.oid::pg_catalog.text"));
        assert!(sql.contains("'aggtransfn', a.aggtransfn::pg_catalog.oid::pg_catalog.text"));
    }

    #[test]
    fn amproc_function_oid_is_serialized_as_numeric_oid_text() {
        let sql = catalog_sql("pg_amproc", 12, QueryShape::OneOid).unwrap();
        assert!(sql.contains("'amproc', o.amproc::pg_catalog.oid::pg_catalog.text"));
    }

    #[test]
    fn producer_numeric_callback_fields_cover_all_capture_shapes() {
        for major in [12, 18] {
            for shape in [QueryShape::OneOid, QueryShape::BuiltinName] {
                let sql = catalog_sql("pg_ts_template", major, shape).unwrap();
                let alias = if matches!(shape, QueryShape::OneOid) {
                    "r"
                } else {
                    "t"
                };
                for field in ["tmplinit", "tmpllexize"] {
                    assert!(
                        sql.contains(&format!(
                            "'{field}', {alias}.{field}::pg_catalog.oid::pg_catalog.text"
                        )),
                        "pg_ts_template {shape:?} major {major} must normalize {field}"
                    );
                }
            }
            let cast = catalog_sql("pg_cast", major, QueryShape::OneOid).unwrap();
            assert!(cast.contains("'castfunc', r.castfunc::pg_catalog.oid::pg_catalog.text"));
        }
    }

    #[test]
    fn regproc_catalog_fields_are_normalized_to_numeric_oid_text() {
        let cases: &[(&str, u32, &[&str])] = &[
            (
                "pg_aggregate",
                12,
                &[
                    "aggfnoid",
                    "aggtransfn",
                    "aggfinalfn",
                    "aggcombinefn",
                    "aggmtransfn",
                ],
            ),
            ("pg_am", 12, &["amhandler"]),
            ("pg_operator", 12, &["oprcode", "oprrest", "oprjoin"]),
            ("pg_range", 12, &["rngcanonical", "rngsubdiff"]),
            (
                "pg_ts_parser",
                12,
                &[
                    "prsstart",
                    "prstoken",
                    "prsend",
                    "prsheadline",
                    "prslextype",
                ],
            ),
            ("pg_ts_template", 12, &["tmplinit", "tmpllexize"]),
        ];
        for (table, major, fields) in cases {
            let sql = catalog_sql(table, *major, QueryShape::OneOid).unwrap();
            for field in *fields {
                assert!(
                    sql.contains(&format!("{field}::pg_catalog.oid::pg_catalog.text")),
                    "{table}.{field} must serialize its OID, not regproc display text"
                );
            }
        }
        for major in [12, 18] {
            let sql = catalog_sql("pg_type", major, QueryShape::TypeClosure).unwrap();
            for field in [
                "typinput",
                "typoutput",
                "typreceive",
                "typsend",
                "typmodin",
                "typmodout",
                "typanalyze",
            ] {
                assert!(sql.contains(&format!("{field}::pg_catalog.oid::pg_catalog.text")));
            }
            assert_eq!(sql.contains("typsubscript"), major >= 14);
        }
        for major in [12, 18] {
            for shape in [QueryShape::OneOid, QueryShape::BuiltinName] {
                let sql = catalog_sql("pg_proc", major, shape).unwrap();
                assert!(sql.contains("prosupport::pg_catalog.oid::pg_catalog.text"));
            }
        }
    }

    #[test]
    fn extension_filter_is_exact_sorted_subset_and_allows_core_only() {
        assert_eq!(extension_filter(&[]).unwrap(), "");
        assert_eq!(
            extension_filter(&["pg_trgm".to_owned()]).unwrap(),
            "pg_trgm"
        );
        assert_eq!(
            extension_filter(&["btree_gist".to_owned(), "pg_trgm".to_owned()]).unwrap(),
            "btree_gist,pg_trgm"
        );
        assert!(extension_filter(&["pg_trgm".to_owned(), "btree_gist".to_owned()]).is_err());
        assert!(extension_filter(&["unreviewed".to_owned()]).is_err());
    }

    #[test]
    fn extension_preflight_never_reads_procedure_source() {
        assert!(
            !EXTENSION_PROC_PREFLIGHT_SQL
                .to_ascii_lowercase()
                .contains("prosrc")
        );
        assert!(EXTENSION_PROC_PREFLIGHT_SQL.contains("lanname IS DISTINCT FROM 'c'"));
        let proc_sql = catalog_sql("pg_proc", 18, QueryShape::OneOid).unwrap();
        assert!(proc_sql.contains("prosrc"));
        assert!(proc_sql.contains("string_to_array($1"));
    }

    #[test]
    fn oid_csv_is_numeric_bounded_and_deterministic() {
        assert_eq!(oid_csv([42, 1, 42]).unwrap(), "1,42");
        assert_eq!(oid_csv([]).unwrap(), "");
        assert!(oid_csv([0]).is_err());
        assert!(oid_csv(std::iter::repeat_n(1, MAX_ROWS + 1)).is_ok());
        assert!(oid_csv(1..=(MAX_ROWS as u32 + 1)).is_err());
    }

    #[test]
    fn json_query_rows_are_bounded_by_total_bytes_before_decoding() {
        let row_len = MAX_ROW_BYTES - 100;
        let rows = (0..19)
            .map(|_| JsonText(format!("\"{}\"", "a".repeat(row_len))))
            .collect();
        assert!(decode_json_rows(rows).is_err());
    }

    #[test]
    fn capture_provenance_does_not_claim_offline_image_or_binary_hashes() {
        let capture = CatalogCapture {
            raw: Value::Object(Map::new()),
            namespace_security: Value::Array(Vec::new()),
        };
        assert!(capture.raw.get("source_image").is_none());
        assert!(capture.raw.get("module_sha256").is_none());
        assert!(capture.raw.get("platform").is_none());
    }

    #[test]
    fn vector_queries_are_major_specific_and_fixed() {
        assert!(
            catalog_sql("pg_proc", 12, QueryShape::OneOid)
                .unwrap()
                .contains("proargmodes")
        );
        assert!(
            !catalog_sql("pg_proc", 12, QueryShape::OneOid)
                .unwrap()
                .contains("protrftypes")
        );
        assert!(
            catalog_sql("pg_proc", 18, QueryShape::OneOid)
                .unwrap()
                .contains("protrftypes")
        );
    }

    #[test]
    fn function_rows_replace_source_bodies_with_hash_markers() {
        for major in [12, 18] {
            let sql = catalog_sql("pg_proc", major, QueryShape::OneOid).unwrap();
            assert!(sql.contains("'sha256_utf8'"));
            assert!(sql.contains("'prosrc'"));
            assert!(sql.contains("to_jsonb(p) - 'prosrc'"));
            assert!(!sql.contains("to_jsonb(p)::pg_catalog.text"));
        }
        let pg18 = catalog_sql("pg_proc", 18, QueryShape::OneOid).unwrap();
        assert!(pg18.contains("'prosqlbody'"));
        assert!(
            !catalog_sql("pg_proc", 12, QueryShape::OneOid)
                .unwrap()
                .contains("prosqlbody")
        );
        assert!(
            catalog_sql("pg_proc", 18, QueryShape::BuiltinName)
                .unwrap()
                .contains("pronamespace = (SELECT n.oid")
        );
        assert!(
            catalog_sql("pg_proc", 12, QueryShape::BuiltinName)
                .unwrap()
                .contains("'sha256_utf8'")
        );
    }

    #[test]
    fn named_builtin_capture_is_fixed_and_requires_all_candidates() {
        let expected = vec![(
            "$builtin:pg_proc:pg_catalog.dsnowball_init(pg_catalog.internal)->pg_catalog.internal/f"
                .to_owned(),
            Value::Null,
        )];
        assert_eq!(
            builtin_names_from_expected("pg_proc", &expected).unwrap(),
            ["dsnowball_init"]
        );
        let good = vec![serde_json::json!({"proname":"dsnowball_init","oid":"13232"})];
        assert!(check_builtin_candidate_counts("pg_proc", &expected, &good).is_ok());
        let extra = vec![
            serde_json::json!({"proname":"dsnowball_init","oid":"13232"}),
            serde_json::json!({"proname":"dsnowball_init","oid":"13233"}),
        ];
        assert!(check_builtin_candidate_counts("pg_proc", &expected, &extra).is_err());
        let injected = vec![(
            "$builtin:pg_proc:pg_catalog.dsnowball_init);select 1--".into(),
            Value::Null,
        )];
        assert!(builtin_names_from_expected("pg_proc", &injected).is_err());
    }
}
