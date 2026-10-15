//! Private owned-server expression comparison; never endpoint acceptance.
use super::{
    dependency_profile::{DependencyProof, ValidatedDependencyProfile},
    expression_proof,
    namespace_authority::{self, NamespaceAuthorityProof},
    node_tree::{self, Context, ExpressionLineage},
    owned_shape_export, regconfig_name, reviewed_profiles,
    rows::{ColumnRow, RoleRow},
    type_catalog,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const MODULES: &[&str] = &["btree_gist", "pg_trgm"];

fn read_json(path: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("private fixture file must be readable"))
        .expect("private fixture JSON must be valid")
}

fn oid(value: &Value) -> Result<u32, ()> {
    let parsed = if let Some(text) = value.as_str() {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(());
        }
        text.parse::<u32>().map_err(|_| ())?
    } else {
        u32::try_from(value.as_u64().ok_or(())?).map_err(|_| ())?
    };
    if parsed == 0 { Err(()) } else { Ok(parsed) }
}

fn rows<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], ()> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(())
}

fn role() -> RoleRow {
    RoleRow {
        valid: true,
        oid: 20_001,
        superuser: false,
        create_role: false,
        create_database: false,
        replication: false,
        bypass_rls: false,
        inherit: true,
        has_memberships: false,
    }
}

fn authority_for_capture(capture: &Value, role: &RoleRow) -> Result<NamespaceAuthorityProof, ()> {
    let source = rows(capture.get("tables").ok_or(())?, "pg_namespace")?;
    if source.is_empty() || source.len() > 64 {
        return Err(());
    }
    let mut expected = BTreeMap::new();
    let mut facts = Vec::with_capacity(source.len());
    for row in source {
        let id = oid(row.get("oid").ok_or(())?)?;
        let name = row.get("nspname").and_then(Value::as_str).ok_or(())?;
        if expected.insert(id, name.to_owned()).is_some() {
            return Err(());
        }
        facts.push(json!({
            "oid": row["oid"], "nspname": name, "nspowner": row["nspowner"],
            "nspacl": row["nspacl"], "has_create": false, "actor_oid": role.oid.to_string(),
            "has_usage": true,
        }));
    }
    namespace_authority::prove(role, &expected, &Value::Array(facts))
}

fn selected_capture(mut capture: Value) -> Value {
    let extensions = MODULES.iter().copied().collect::<BTreeSet<_>>();
    if let Some(rows) = capture["tables"]["pg_extension"].as_array_mut() {
        rows.retain(|row| {
            row["extname"]
                .as_str()
                .is_some_and(|name| extensions.contains(name))
        });
    }
    if let Some(rows) = capture["extension_members"].as_array_mut() {
        rows.retain(|row| {
            row["extname"]
                .as_str()
                .is_some_and(|name| name == "plpgsql" || extensions.contains(name))
        });
    }
    if let Some(rows) = capture
        .get_mut("module_sha256")
        .and_then(Value::as_array_mut)
    {
        rows.retain(|row| {
            row.as_str().is_some_and(|hash| {
                extensions
                    .iter()
                    .any(|name| hash.contains(&format!("/{name}.so")))
            })
        });
    }
    capture
}

fn dependency_proof(
    profile: &'static ValidatedDependencyProfile,
    capture: &Value,
    major: u32,
    authority: &NamespaceAuthorityProof,
) -> DependencyProof {
    profile
        .validate_live_authorized(capture, major, authority)
        .expect("private dependency capture must match the immutable reviewed profile")
}

fn namespace_name(dependencies: &DependencyProof, oid: u32) -> Result<String, ()> {
    let identity = dependencies
        .identity_for_runtime_oid("pg_namespace", oid)
        .ok_or(())?;
    dependencies
        .row("pg_namespace", identity)
        .and_then(|row| row.get("fields"))
        .and_then(|row| row.get("nspname"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(())
}

fn field_oid(row: &Value, key: &str) -> Result<u32, ()> {
    oid(row.get(key).ok_or(())?)
}

fn make_column(
    attribute: &Value,
    ty: &Value,
    dependencies: &DependencyProof,
) -> Result<ColumnRow, ()> {
    let schema = namespace_name(dependencies, field_oid(ty, "typnamespace")?)?;
    ColumnRow::from_catalog_metadata(attribute, ty, &schema)
}

fn source_columns(
    capture: &Value,
    dependencies: &DependencyProof,
) -> Result<BTreeMap<u32, Vec<ColumnRow>>, ()> {
    let types = rows(capture, "types")?
        .iter()
        .map(|row| Ok((field_oid(row, "oid")?, row)))
        .collect::<Result<BTreeMap<_, _>, ()>>()?;
    let mut result = BTreeMap::<u32, Vec<ColumnRow>>::new();
    for attribute in rows(capture, "attributes")? {
        if attribute.get("attisdropped").and_then(Value::as_bool) != Some(false) {
            continue;
        }
        let relation = field_oid(attribute, "attrelid")?;
        let type_id = field_oid(attribute, "atttypid")?;
        let ty = types.get(&type_id).ok_or(())?;
        result
            .entry(relation)
            .or_default()
            .push(make_column(attribute, ty, dependencies)?);
    }
    Ok(result)
}

fn target_type_rows(owned: &Value, dependencies: &DependencyProof) -> Result<Vec<Value>, ()> {
    let mut requested = BTreeSet::new();
    for attribute in rows(owned, "attribute_rows")? {
        requested.insert(field_oid(attribute, "type_oid")?);
    }
    let dynamic = rows(owned, "enum_types")?
        .iter()
        .map(|row| Ok((field_oid(row, "oid")?, row.clone())))
        .collect::<Result<BTreeMap<_, _>, ()>>()?;
    requested
        .into_iter()
        .map(|type_id| {
            if let Some(row) = dynamic.get(&type_id) {
                return Ok(row.clone());
            }
            let identity = dependencies
                .identity_for_runtime_oid("pg_type", type_id)
                .ok_or(())?;
            let row = dependencies
                .row("pg_type", identity)
                .and_then(|row| row.get("fields"))
                .ok_or(())?;
            Ok(row.clone())
        })
        .collect()
}

fn target_columns(
    owned: &Value,
    type_rows: &[Value],
    dependencies: &DependencyProof,
) -> Result<BTreeMap<u32, Vec<ColumnRow>>, ()> {
    let types = type_rows
        .iter()
        .map(|row| Ok((field_oid(row, "oid")?, row)))
        .collect::<Result<BTreeMap<_, _>, ()>>()?;
    let mut result = BTreeMap::<u32, Vec<ColumnRow>>::new();
    for row in rows(owned, "attribute_rows")? {
        if row.get("dropped").and_then(Value::as_bool) != Some(false) {
            return Err(());
        }
        let attribute = json!({
            "attrelid": row["relation_oid"], "attnum": row["attnum"], "attname": row["name"],
            "atttypid": row["type_oid"], "atttypmod": row["typmod"], "attndims": row["dimensions"],
            "attcollation": row["collation_oid"], "attnotnull": row["not_null"],
            "attgenerated": "", "attidentity": "", "attisdropped": false,
        });
        let relation = field_oid(row, "relation_oid")?;
        let ty = types.get(&field_oid(row, "type_oid")?).ok_or(())?;
        result
            .entry(relation)
            .or_default()
            .push(make_column(&attribute, ty, dependencies)?);
    }
    for columns in result.values_mut() {
        columns.sort_by_key(ColumnRow::attribute_number);
    }
    Ok(result)
}

fn tree_context(catalog: &str, field: &str, relation_oid: u32) -> Result<Context, ()> {
    match (catalog, field) {
        ("pg_index", "indexprs") => Ok(Context::index(relation_oid)),
        ("pg_index", "indpred") => Ok(Context::predicate(relation_oid)),
        ("pg_constraint", "conbin") => Ok(Context::check(relation_oid)),
        _ => Err(()),
    }
}

fn matching_config(
    sql: &str,
    dependencies: &DependencyProof,
) -> Result<(Option<u32>, Option<String>), ()> {
    let name = regconfig_name::builtin_name(sql).ok();
    let Some(name) = name else {
        return Ok((None, None));
    };
    let row = dependencies
        .rows("pg_ts_config")
        .ok_or(())?
        .find(|row| {
            row.get("fields")
                .and_then(|fields| fields.get("cfgname"))
                .and_then(Value::as_str)
                == Some(name)
        })
        .ok_or(())?;
    let identity = row
        .get("identity")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            row.get("identity")
                .and_then(Value::as_u64)
                .map(|id| id.to_string())
        })
        .ok_or(())?;
    let oid = dependencies
        .runtime_oid_for_identity("pg_ts_config", &identity)
        .ok_or(())?;
    Ok((Some(oid), Some(identity)))
}

fn lineage(shape: &Value, owned: &Value) -> Result<(ExpressionLineage, ExpressionLineage), ()> {
    let mut source = ExpressionLineage::default();
    let mut target = ExpressionLineage::default();
    let target_relations = owned
        .get("relations")
        .and_then(Value::as_object)
        .ok_or(())?;
    for (source_id, relation) in shape
        .get("relations")
        .and_then(Value::as_object)
        .ok_or(())?
    {
        let source_oid = source_id.parse::<u32>().map_err(|_| ())?;
        let target_relation = target_relations.get(source_id).ok_or(())?;
        let target_oid = field_oid(target_relation, "owned_oid")?;
        let identity = relation
            .get("synthetic_name")
            .and_then(Value::as_str)
            .ok_or(())?
            .to_owned();
        source.relations.insert(source_oid, identity.clone());
        target.relations.insert(target_oid, identity);
        let columns = relation
            .get("source_attnums")
            .and_then(Value::as_object)
            .ok_or(())?;
        for (attnum, column) in columns {
            let source_attnum = attnum.parse::<i32>().map_err(|_| ())?;
            let target_attnum = i32::try_from(
                column
                    .get("target_attnum")
                    .and_then(Value::as_i64)
                    .ok_or(())?,
            )
            .map_err(|_| ())?;
            let identity = column
                .get("column")
                .and_then(Value::as_str)
                .ok_or(())?
                .to_owned();
            source
                .columns
                .insert((source_oid, source_attnum), identity.clone());
            target.columns.insert((target_oid, target_attnum), identity);
        }
    }
    for (source_type, details) in shape.get("types").and_then(Value::as_object).ok_or(())? {
        let source_oid = source_type.parse::<u32>().map_err(|_| ())?;
        let identity = format!(
            "public.{}",
            details
                .get("synthetic_name")
                .and_then(Value::as_str)
                .ok_or(())?
        );
        source.enum_types.insert(source_oid, identity.clone());
        let target_oid = owned
            .get("enums")
            .and_then(Value::as_array)
            .ok_or(())?
            .iter()
            .find(|row| field_oid(row, "source_type_oid").ok() == Some(source_oid))
            .map(|row| field_oid(row, "owned_type_oid"))
            .transpose()?
            .ok_or(())?;
        target.enum_types.insert(target_oid, identity);
    }
    Ok((source, target))
}

fn source_expression_rows<'a>(capture: &'a Value, entry: &Value) -> Result<&'a Value, ()> {
    let catalog = entry.get("catalog").and_then(Value::as_str).ok_or(())?;
    let field = entry
        .get("source_field")
        .and_then(Value::as_str)
        .ok_or(())?;
    let object = field_oid(entry, "object_oid")?;
    let relation = field_oid(entry, "relation_oid")?;
    let (table, id_field, relation_field) = match (catalog, field) {
        ("pg_index", "indexprs" | "indpred") => ("indexes", "indexrelid", "indrelid"),
        ("pg_constraint", "conbin") => ("constraints", "oid", "conrelid"),
        _ => return Err(()),
    };
    let matches = rows(capture, table)?
        .iter()
        .filter(|row| {
            field_oid(row, id_field).ok() == Some(object)
                && field_oid(row, relation_field).ok() == Some(relation)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(());
    }
    let raw = matches[0].get(field).and_then(Value::as_str).ok_or(())?;
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, raw.as_bytes());
    let hex = hash
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if entry.get("source_sha256").and_then(Value::as_str) != Some(hex.as_str())
        || entry.get("source_node_tree").and_then(Value::as_str) != Some(raw)
    {
        return Err(());
    }
    Ok(matches[0])
}

fn owned_expression_row<'a>(owned: &'a Value, entry: &Value) -> Result<&'a Value, ()> {
    let catalog = entry.get("catalog").and_then(Value::as_str).ok_or(())?;
    let field = entry
        .get("source_field")
        .and_then(Value::as_str)
        .ok_or(())?;
    let object = field_oid(entry, "object_oid")?;
    let key = match catalog {
        "pg_index" => ("indexes", "source_indexrelid"),
        "pg_constraint" => ("constraints", "source_constraint_oid"),
        _ => return Err(()),
    };
    let matches = rows(owned, key.0)?
        .iter()
        .filter(|row| field_oid(row, key.1).ok() == Some(object))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(());
    }
    let expected_field = match field {
        "indexprs" | "indpred" | "conbin" => field,
        _ => return Err(()),
    };
    matches[0]
        .get(expected_field)
        .filter(|value| !value.is_null())
        .ok_or(())
        .map(|_| matches[0])
}

struct ExpressionProofContext<'a> {
    columns: &'a [ColumnRow],
    enums: &'a BTreeMap<u32, super::type_proof::EnumTypeProof>,
    dependencies: &'a DependencyProof,
    lineage: &'a ExpressionLineage,
}

fn prove_and_canonicalize(
    raw_tree: &str,
    major: u32,
    context: Context,
    proof_context: ExpressionProofContext<'_>,
    deparsed_sql: &str,
    expected_ordinal: usize,
) -> Result<[u8; 32], String> {
    let trees =
        node_tree::parse_and_extract_all(raw_tree, major, context).map_err(|_| "tree_parse")?;
    if trees.len() != 1 {
        return Err("tree_ordinal_count".into());
    }
    let tree = &trees[0];
    if tree.source_ordinal() != expected_ordinal {
        return Err("source_ordinal".into());
    }
    let checked = expression_proof::precheck(
        tree,
        proof_context.dependencies,
        proof_context.columns,
        proof_context.enums,
    )
    .map_err(|_| "typed_precheck")?;
    let (config_oid, config_identity) = if checked.requires_regconfig() {
        matching_config(deparsed_sql, proof_context.dependencies)
            .map_err(|_| "regconfig_resolution")?
    } else {
        if regconfig_name::builtin_name(deparsed_sql).is_ok() {
            return Err("unexpected_regconfig_deparse".into());
        }
        (None, None)
    };
    let proof = checked.finish(config_oid).map_err(|_| "proof_finish")?;
    let mut scoped_lineage = ExpressionLineage::default();
    let relation_identity = proof_context
        .lineage
        .relations
        .get(&tree.relation_oid)
        .ok_or("missing_relation_lineage")?;
    scoped_lineage
        .relations
        .insert(tree.relation_oid, relation_identity.clone());
    for var in &tree.vars {
        if var.relation_oid != tree.relation_oid {
            return Err("var_relation_lineage".into());
        }
        let key = (var.relation_oid, var.attno);
        let identity = proof_context
            .lineage
            .columns
            .get(&key)
            .ok_or("missing_column_lineage")?;
        scoped_lineage.columns.insert(key, identity.clone());
    }
    scoped_lineage.enum_types = proof_context.lineage.enum_types.clone();
    let canonical = node_tree::canonical_expression(
        tree,
        &proof,
        proof_context.dependencies,
        &scoped_lineage,
        config_identity.as_deref(),
    )
    .map_err(|_| "canonicalize")?;
    Ok(*canonical.digest())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_dir() -> PathBuf {
        PathBuf::from(
            std::env::var_os("PGDOG_PRIVATE_INVENTORY_DIR")
                .expect("private owned fixture directory is required"),
        )
    }

    #[test]
    #[ignore = "private owned PG12/PG18 expression comparison; not endpoint acceptance"]
    fn private_owned_source_expressions_match_canonical_postgres_trees() {
        let directory = fixture_dir();
        let source_relations = read_json(&directory.join("icondo-private-full-relations.json"));
        let source_global = read_json(&directory.join("icondo-private-full-dependencies.json"));
        let source_shape = read_json(&directory.join("private-owned-shape.json"));
        let shape = read_json(&directory.join("private-owned-complete-shape.json"));
        let source_export = read_json(&directory.join("private-owned-read-proof.json"));
        let digest_file = |name: &str| {
            aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA256,
                &std::fs::read(directory.join(name))
                    .expect("private fixture file must be readable"),
            )
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
        };
        assert_eq!(source_export["format"], "pgdog-owned-read-proof/v1");
        assert_eq!(source_export["source_read_proof_complete"], true);
        assert_eq!(
            source_export["capture_sha256"],
            owned_shape_export::digest(&source_relations)
                .expect("source capture binding must hash")
        );
        assert_eq!(
            source_export["relation_shape_sha256"],
            owned_shape_export::digest(&source_shape["shape"])
                .expect("source lineage shape binding must hash")
        );
        assert_eq!(
            shape["read_shape_digest"],
            owned_shape_export::digest(&source_shape["shape"])
                .expect("completed shape binding must hash")
        );
        let source_global = selected_capture(source_global);
        let role = role();
        let source_authority = authority_for_capture(&source_global, &role)
            .expect("source actor-authority facts must be shaped");
        let source_profile = reviewed_profiles::for_modules(12, MODULES)
            .expect("immutable source profile must be available");
        let source_dependencies =
            dependency_proof(source_profile, &source_global, 12, &source_authority);
        let source_type_proofs = type_catalog::prove(
            &rows(&source_relations, "attributes")
                .unwrap()
                .iter()
                .filter(|row| row.get("attisdropped").and_then(Value::as_bool) == Some(false))
                .map(|row| field_oid(row, "atttypid").unwrap())
                .collect::<BTreeSet<_>>(),
            rows(&source_relations, "types").unwrap(),
            rows(&source_relations, "enums").unwrap(),
            &source_dependencies,
            &role,
            &source_authority,
        )
        .expect("source type I/O and enum proofs must hold");
        let source_columns_by_relation = source_columns(&source_relations, &source_dependencies)
            .expect("source relation columns must decode");

        for major in [12, 18] {
            let expression_artifact =
                read_json(&directory.join(format!("owned-expression-pg{major}.json")));
            let dependency_artifact =
                read_json(&directory.join(format!("owned-dependencies-pg{major}.json")));
            assert_eq!(
                expression_artifact["comparison_status"],
                "pending canonical comparison"
            );
            assert_eq!(
                dependency_artifact["comparison_status"],
                "pending canonical comparison"
            );
            assert_eq!(
                expression_artifact["format"],
                "pgdog-owned-expression-context/v1"
            );
            assert_eq!(
                dependency_artifact["format"],
                "pgdog-owned-dependency-capture/v1"
            );
            assert_eq!(expression_artifact["postgres_major"], major);
            assert_eq!(dependency_artifact["postgres_major"], major);
            assert_eq!(
                expression_artifact["source_capture_sha256"],
                digest_file("icondo-private-full-relations.json")
            );
            assert_eq!(
                expression_artifact["source_read_proof_sha256"],
                digest_file("private-owned-read-proof.json")
            );
            assert_eq!(
                expression_artifact["shape_sha256"],
                digest_file("private-owned-complete-shape.json")
            );
            assert_eq!(
                dependency_artifact["capture_sha256"],
                owned_shape_export::digest(&dependency_artifact["actual_capture"])
                    .expect("capture binding must hash")
            );
            assert_eq!(
                dependency_artifact["normalized_profile_sha256"],
                owned_shape_export::digest(&dependency_artifact["normalized_profile"])
                    .expect("normalized profile binding must hash")
            );
            let target_global = selected_capture(dependency_artifact["actual_capture"].clone());
            let target_authority = authority_for_capture(&target_global, &role)
                .expect("owned actor-authority facts must be shaped");
            let target_profile = reviewed_profiles::for_modules(major, MODULES)
                .expect("immutable target profile must be available");
            let target_dependencies =
                dependency_proof(target_profile, &target_global, major, &target_authority);
            let owned = expression_artifact
                .get("owned")
                .ok_or(())
                .expect("owned context exists");
            let target_types = target_type_rows(owned, &target_dependencies)
                .expect("owned attribute type rows must be complete");
            let target_labels = rows(owned, "enum_labels").expect("owned enum labels are captured");
            let target_requested = rows(owned, "attribute_rows")
                .unwrap()
                .iter()
                .map(|row| field_oid(row, "type_oid").unwrap())
                .collect::<BTreeSet<_>>();
            let target_type_proofs = type_catalog::prove(
                &target_requested,
                &target_types,
                target_labels,
                &target_dependencies,
                &role,
                &target_authority,
            )
            .expect("owned target type I/O and enum proofs must hold");
            let target_columns = target_columns(owned, &target_types, &target_dependencies)
                .expect("owned relation columns must decode");
            let (source_lineage, target_lineage) = lineage(&shape, owned)
                .expect("source-to-owned relation/column/type lineage must be complete");
            let expression_entries = rows(&expression_artifact, "source_expressions").unwrap();
            assert_eq!(
                expression_entries.len(),
                67,
                "source expression inventory changed"
            );
            let proof_entries = rows(&source_export, "expressions").unwrap();
            assert_eq!(
                proof_entries.len(),
                expression_entries.len(),
                "proof export inventory changed"
            );
            let mut compared = 0usize;

            for entry in expression_entries {
                let _source_row = source_expression_rows(&source_relations, entry)
                    .expect("source expression source digest and OID bindings must match");
                let owned_tree = owned_expression_row(owned, entry)
                    .expect("owned expression tree must map to exactly one source object");
                let catalog = entry["catalog"].as_str().unwrap();
                let field = entry["source_field"].as_str().unwrap();
                let source_relation = field_oid(entry, "relation_oid").unwrap();
                let owned_object = if catalog == "pg_index" {
                    owned["indexes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|row| {
                            field_oid(row, "source_indexrelid").ok()
                                == field_oid(entry, "object_oid").ok()
                        })
                        .and_then(|row| field_oid(row, "indrelid").ok())
                        .expect("owned index relation is bound")
                } else {
                    field_oid(owned_tree, "conrelid").expect("owned constraint relation is bound")
                };
                let owned_relation_expected = field_oid(
                    &owned["relations"][source_relation.to_string()],
                    "owned_oid",
                )
                .expect("lineage binds the same owned relation");
                assert_eq!(
                    owned_object, owned_relation_expected,
                    "relation binding mismatch field=relation_oid"
                );
                let context = tree_context(catalog, field, source_relation)
                    .expect("source expression context is approved");
                let owned_context = tree_context(catalog, field, owned_object)
                    .expect("owned expression context is approved");
                let source_tree_text = entry["source_node_tree"]
                    .as_str()
                    .ok_or(())
                    .expect("source node tree captured");
                let target_tree_text = owned_tree
                    .get(field)
                    .and_then(Value::as_str)
                    .ok_or(())
                    .expect("owned node tree captured");
                let source_columns = source_columns_by_relation
                    .get(&source_relation)
                    .ok_or(())
                    .expect("source relation columns exist");
                let target_columns = target_columns
                    .get(&owned_object)
                    .ok_or(())
                    .expect("owned relation columns exist");
                let expected_ordinal = entry["source_ordinal"]
                    .as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .expect("source ordinal is bounded integer");
                let proof_entry = proof_entries
                    .iter()
                    .find(|candidate| {
                        candidate["catalog"] == entry["catalog"]
                            && candidate["source_field"] == entry["source_field"]
                            && candidate["object_oid"] == entry["object_oid"]
                            && candidate["relation_oid"] == entry["relation_oid"]
                    })
                    .expect("source proof export has exactly one object binding");
                assert_eq!(
                    expected_ordinal,
                    proof_entry["source_ordinal"]
                        .as_u64()
                        .and_then(|n| usize::try_from(n).ok())
                        .expect("proof ordinal is bounded integer"),
                    "source proof binding mismatch field=source_ordinal"
                );
                assert!(
                    entry["source_sha256"] == proof_entry["source_sha256"],
                    "source proof binding mismatch field=source_sha256"
                );
                assert!(
                    entry["sql"] == proof_entry["sql"],
                    "source proof binding mismatch field=sql_receipt"
                );
                let source_digest = prove_and_canonicalize(
                    source_tree_text,
                    12,
                    context,
                    ExpressionProofContext {
                        columns: source_columns,
                        enums: &source_type_proofs.enums,
                        dependencies: &source_dependencies,
                        lineage: &source_lineage,
                    },
                    entry["sql"]
                        .as_str()
                        .ok_or(())
                        .expect("source deparse receipt exists"),
                    expected_ordinal,
                )
                .unwrap_or_else(|field| panic!("source proof failed field={field}"));
                let target_digest = prove_and_canonicalize(
                    target_tree_text,
                    major,
                    owned_context,
                    ExpressionProofContext {
                        columns: target_columns,
                        enums: &target_type_proofs.enums,
                        dependencies: &target_dependencies,
                        lineage: &target_lineage,
                    },
                    entry["sql"]
                        .as_str()
                        .ok_or(())
                        .expect("source deparse receipt exists"),
                    expected_ordinal,
                )
                .unwrap_or_else(|field| panic!("owned proof failed field={field}"));
                assert_eq!(
                    source_digest, target_digest,
                    "canonical mismatch field=digest"
                );
                compared += 1;
            }
            assert_eq!(
                compared, 67,
                "canonical expression comparison count mismatch"
            );
            eprintln!(
                "private canonical expression comparison: major={major} compared={compared} mismatch_fields=0"
            );
        }
    }
}
