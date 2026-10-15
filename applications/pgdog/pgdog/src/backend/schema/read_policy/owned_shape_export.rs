//! Private test fixture export; never used by runtime authorization.
use super::{dependency_profile::DependencyProof, full_catalog::ProvenCatalog, owned_expression};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn digest(value: &Value) -> Result<String, ()> {
    let bytes = serde_json::to_vec(value).map_err(|_| ())?;
    Ok(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}
fn oid(value: &Value) -> Result<u32, ()> {
    let id = if let Some(s) = value.as_str() {
        s.parse::<u32>().map_err(|_| ())?
    } else {
        u32::try_from(value.as_u64().ok_or(())?).map_err(|_| ())?
    };
    if id == 0 { Err(()) } else { Ok(id) }
}
fn rows<'a>(raw: &'a Value, key: &str) -> Result<&'a Vec<Value>, ()> {
    raw.get(key).and_then(Value::as_array).ok_or(())
}
fn symbol(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn qualified(
    deps: &DependencyProof,
    catalog: &str,
    id: u32,
    namespace: &str,
    name: &str,
) -> Result<Value, ()> {
    let identity = deps.identity_for_runtime_oid(catalog, id).ok_or(())?;
    let fields = &deps.row(catalog, identity).ok_or(())?["fields"];
    let ns = oid(&fields[namespace])?;
    let ns_identity = deps
        .identity_for_runtime_oid("pg_namespace", ns)
        .ok_or(())?;
    let schema = deps.row("pg_namespace", ns_identity).ok_or(())?["fields"]["nspname"]
        .as_str()
        .ok_or(())?;
    let name = fields[name].as_str().ok_or(())?;
    if !matches!(schema, "pg_catalog" | "public") {
        return Err(());
    }
    Ok(json!([schema, name]))
}

pub(super) fn export(
    raw: &Value,
    shape: &Value,
    deparsed: &Value,
    deps: &DependencyProof,
    proven: &ProvenCatalog,
) -> Result<Value, ()> {
    let mut stable = raw.clone();
    stable.as_object_mut().ok_or(())?.remove("capture_id");
    if proven.metadata["capture"] != stable
        || proven.metadata["dependency_digest"] != json!(deps.digest())
        || proven.metadata["reviewed_profile_digest"] != json!(deps.profile_digest())
    {
        return Err(());
    }
    let mapped = shape["relations"].as_object().ok_or(())?;
    if mapped.len() != proven.relations.len() {
        return Err(());
    }
    let mut columns = BTreeMap::<u32, BTreeMap<String, String>>::new();
    for (&relation, (_, source_columns)) in &proven.relations {
        let mapping = mapped.get(&relation.to_string()).ok_or(())?;
        let target = mapping["synthetic_name"].as_str().ok_or(())?;
        if !symbol(target) {
            return Err(());
        }
        let attrs = mapping["source_attnums"].as_object().ok_or(())?;
        if attrs.len() != source_columns.len() {
            return Err(());
        }
        let mut names = BTreeMap::new();
        for column in source_columns {
            let number = column.attribute_number().ok_or(())?;
            let attr = attrs.get(&number.to_string()).ok_or(())?;
            if oid(&attr["source_relation_oid"])? != relation
                || attr["source_attnum"] != json!(number)
                || oid(&attr["source_type_oid"])? != column.type_oid
            {
                return Err(());
            }
            let name = attr["column"].as_str().ok_or(())?;
            if !symbol(name) || names.insert(column.name.clone(), name.to_owned()).is_some() {
                return Err(());
            }
        }
        columns.insert(relation, names);
    }
    let namespaces = rows(raw, "namespaces")?
        .iter()
        .map(|row| {
            Ok((
                oid(&row["oid"])?,
                row["nspname"].as_str().ok_or(())?.to_owned(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, ()>>()?;
    let mut type_names = BTreeMap::new();
    for ty in rows(raw, "types")? {
        if ty["typtype"] != "e" {
            continue;
        }
        let id = oid(&ty["oid"])?;
        let name = ty["typname"].as_str().ok_or(())?;
        let ns = namespaces.get(&oid(&ty["typnamespace"])?).ok_or(())?;
        let target = shape["types"][id.to_string()]["synthetic_name"]
            .as_str()
            .ok_or(())?;
        if !symbol(target) {
            return Err(());
        }
        type_names.insert(
            vec![ns.clone(), name.to_owned()],
            vec!["public".into(), target.into()],
        );
        type_names.insert(vec![name.to_owned()], vec!["public".into(), target.into()]);
    }
    let mut expressions = Vec::new();
    for entry in rows(deparsed, "sources")? {
        let relation = oid(&entry["relation_oid"])?;
        let object = oid(&entry["object_oid"])?;
        let catalog = entry["catalog"].as_str().ok_or(())?;
        let field = entry["source_field"].as_str().ok_or(())?;
        let (table, id_field, rel_field) = match (catalog, field) {
            ("pg_index", "indexprs" | "indpred") => ("indexes", "indexrelid", "indrelid"),
            ("pg_constraint", "conbin") => ("constraints", "oid", "conrelid"),
            _ => return Err(()),
        };
        let matches = rows(raw, table)?
            .iter()
            .filter(|row| oid(&row[id_field]).ok() == Some(object))
            .collect::<Vec<_>>();
        if matches.len() != 1 || oid(&matches[0][rel_field])? != relation {
            return Err(());
        }
        let source = matches[0][field].as_str().ok_or(())?;
        let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, source.as_bytes())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if entry["source_sha256"].as_str() != Some(&hash) {
            return Err(());
        }
        // This inventory has a single target in each expression index.
        if field == "indexprs"
            && matches[0]["indkey"]
                .as_array()
                .ok_or(())?
                .iter()
                .filter(|v| **v == json!(0))
                .count()
                != 1
        {
            return Err(());
        }
        let sql = owned_expression::remap(
            entry["sql"].as_str().ok_or(())?,
            columns.get(&relation).ok_or(())?,
            &type_names,
        )
        .map_err(|_| ())?;
        expressions.push(json!({"catalog":catalog,"source_field":field,"object_oid":object,"relation_oid":relation,
            "source_sha256":hash,"source_ordinal":0,"sql":sql}));
    }
    let classes = rows(raw, "index_relations")?
        .iter()
        .map(|row| Ok((oid(&row["oid"])?, row)))
        .collect::<Result<BTreeMap<_, _>, ()>>()?;
    let constraints = rows(raw, "constraints")?;
    let mut support = serde_json::Map::new();
    for index in rows(raw, "indexes")? {
        let id = oid(&index["indexrelid"])?;
        let class = *classes.get(&id).ok_or(())?;
        let method_id = oid(&class["relam"])?;
        let method_identity = deps
            .identity_for_runtime_oid("pg_am", method_id)
            .ok_or(())?;
        let method = deps.row("pg_am", method_identity).ok_or(())?["fields"]["amname"]
            .as_str()
            .ok_or(())?;
        let opclasses = index["indclass"]
            .as_array()
            .ok_or(())?
            .iter()
            .map(|v| qualified(deps, "pg_opclass", oid(v)?, "opcnamespace", "opcname"))
            .collect::<Result<Vec<_>, _>>()?;
        let collations = index["indcollation"]
            .as_array()
            .ok_or(())?
            .iter()
            .map(|v| {
                if *v == json!(0) || *v == json!("0") {
                    Ok(Value::Null)
                } else {
                    qualified(deps, "pg_collation", oid(v)?, "collnamespace", "collname")
                }
            })
            .collect::<Result<Vec<_>, ()>>()?;
        let operators = if index["indisexclusion"] == true {
            let owners = constraints
                .iter()
                .filter(|row| row["contype"] == "x" && oid(&row["conindid"]).ok() == Some(id))
                .collect::<Vec<_>>();
            if owners.len() != 1 {
                return Err(());
            }
            owners[0]["conexclop"]
                .as_array()
                .ok_or(())?
                .iter()
                .map(|v| qualified(deps, "pg_operator", oid(v)?, "oprnamespace", "oprname"))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        support.insert(id.to_string(),json!({"source_metadata":index,"relation_metadata":class,
            "method":method,"opclasses":opclasses,"collations":collations,"exclusion_operators":operators}));
    }
    const CONSTRAINT_FIELDS: &[&str] = &[
        "contype",
        "conrelid",
        "confrelid",
        "conkey",
        "confkey",
        "conpfeqop",
        "conppeqop",
        "conffeqop",
        "confmatchtype",
        "confupdtype",
        "confdeltype",
        "condeferrable",
        "condeferred",
        "convalidated",
        "conislocal",
        "coninhcount",
        "connoinherit",
        "conindid",
        "conparentid",
    ];
    let constraints = constraints
        .iter()
        .map(|row| {
            let mut metadata = serde_json::Map::new();
            for field in CONSTRAINT_FIELDS {
                metadata.insert((*field).to_owned(), row.get(*field).ok_or(())?.clone());
            }
            for field in ["confdelsetcols", "conperiod", "conexclop"] {
                if let Some(value) = row.get(field) {
                    metadata.insert(field.to_owned(), value.clone());
                }
            }
            Ok((
                oid(&row["oid"])?.to_string(),
                json!({"source_metadata":metadata}),
            ))
        })
        .collect::<Result<serde_json::Map<_, _>, ()>>()?;
    Ok(
        json!({"format":"pgdog-owned-read-proof/v1","source_read_proof_complete":true,
        "capture_sha256":digest(raw)?,"relation_shape_sha256":digest(shape)?,
        "expressions":expressions,"index_support":support,"constraint_support":constraints}),
    )
}
