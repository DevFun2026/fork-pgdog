//! Full relation proof: metadata alone never grants client SQL capabilities.
use super::*;
use serde_json::Value;
use std::collections::BTreeSet;

fn stage<T, E>(result: Result<T, E>, label: &str) -> Result<T, ()> {
    result.map_err(|_| {
        #[cfg(test)]
        eprintln!("full catalog denied at {label}");
        #[cfg(not(test))]
        let _ = label;
    })
}

fn typed_stage<T, E: std::fmt::Debug>(result: Result<T, E>, label: &str) -> Result<T, ()> {
    result.map_err(|error| {
        #[cfg(test)]
        eprintln!("full proof stage={label} reason={error:?}");
        #[cfg(not(test))]
        let _ = (label, error);
    })
}

fn oid(raw: &Value, key: &str) -> Result<u32, ()> {
    let value = raw.get(key).ok_or(())?;
    let parsed = if let Some(text) = value.as_str() {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(());
        }
        text.parse::<u32>().map_err(|_| ())?
    } else {
        u32::try_from(value.as_u64().ok_or(())?).map_err(|_| ())?
    };
    if parsed == 0 { Err(()) } else { Ok(parsed) }
}
fn text<'a>(raw: &'a Value, key: &str) -> Result<&'a str, ()> {
    raw.get(key).and_then(Value::as_str).ok_or(())
}
fn boolean(raw: &Value, key: &str) -> Result<bool, ()> {
    raw.get(key).and_then(Value::as_bool).ok_or(())
}
fn relation_row(
    raw: &Value,
    names: &BTreeMap<u32, String>,
    inherited: bool,
    role: &RoleRow,
    authority: &namespace_authority::NamespaceAuthorityProof,
    deps: &dependency_profile::DependencyProof,
) -> Result<RelationRow, ()> {
    let namespace = oid(raw, "relnamespace")?;
    let am = oid(raw, "relam")?;
    let identity = deps.identity_for_runtime_oid("pg_am", am).ok_or(())?;
    let fields = &deps.row("pg_am", identity).ok_or(())?["fields"];
    if fields["amname"] != "heap"
        || fields["amtype"] != "t"
        || !authority.covers(namespace, role.oid)
        || !role.is_safe_application_role()
    {
        return Err(());
    }
    let row = RelationRow {
        valid: true,
        oid: oid(raw, "oid")?,
        schema: names.get(&namespace).ok_or(())?.clone(),
        name: text(raw, "relname")?.into(),
        kind: text(raw, "relkind")?.into(),
        persistence: text(raw, "relpersistence")?.into(),
        owner_oid: oid(raw, "relowner")?,
        row_security: boolean(raw, "relrowsecurity")?,
        force_row_security: boolean(raw, "relforcerowsecurity")?,
        has_rules: boolean(raw, "relhasrules")?,
        is_partition: boolean(raw, "relispartition")?,
        has_inheritance: inherited,
        namespace_can_create: false,
        access_method: "heap".into(),
    };
    let mut shape = row.clone();
    shape.has_inheritance = false;
    if !shape.is_supported_base_table()
        || row.owner_oid == role.oid
        || row.name.len() > 63
        || row.name.contains('\0')
    {
        return Err(());
    }
    Ok(row)
}

pub(super) struct ProvenCatalog {
    pub(super) relations: BTreeMap<u32, (RelationRow, Vec<ColumnRow>)>,
    pub(super) capabilities: BTreeMap<u32, type_proof::TypeCapabilities>,
    pub(super) metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(super) struct RelationProof {
    relation: RelationRow,
    columns: Vec<ColumnRow>,
    dependency_digest: [u8; 32],
}
impl RelationProof {
    pub(super) fn matches(&self, relation: &RelationRow, columns: &[ColumnRow]) -> bool {
        &self.relation == relation && self.columns == columns
    }
    pub(super) fn matches_metadata(&self, metadata: &Value) -> bool {
        let Ok(encoded) = serde_json::to_vec(metadata) else {
            return false;
        };
        if encoded.len() > 16 * 1024 * 1024 {
            return false;
        }
        let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &encoded);
        hash.as_ref() == self.dependency_digest
    }
}
impl ProvenCatalog {
    pub(super) fn proofs(&self) -> BTreeMap<u32, RelationProof> {
        let encoded =
            serde_json::to_vec(&self.metadata).expect("validated bounded catalog serializes");
        let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &encoded);
        let mut digest = [0; 32];
        digest.copy_from_slice(hash.as_ref());
        self.relations
            .iter()
            .map(|(&id, (relation, columns))| {
                (
                    id,
                    RelationProof {
                        relation: relation.clone(),
                        columns: columns.clone(),
                        dependency_digest: digest,
                    },
                )
            })
            .collect()
    }
}

/// Capture and prove on the exact protected backend. The caller still performs
/// client syntax/overload proof and binds this result to its policy identity.
pub(super) async fn load(
    server: &mut Server,
    roots: &[u32],
    role: &RoleRow,
    major: u32,
    allowed: &BTreeSet<(String, String)>,
) -> Result<ProvenCatalog, PolicyError> {
    async fn inner(
        server: &mut Server,
        roots: &[u32],
        role: &RoleRow,
        major: u32,
        allowed: &BTreeSet<(String, String)>,
    ) -> Result<ProvenCatalog, ()> {
        let modules=server.fetch_all::<String>(ServerRequest::strict_internal(
            "SELECT extname::pg_catalog.text FROM pg_catalog.pg_extension WHERE extname IN ('btree_gist','pg_trgm') ORDER BY extname",&[]))
            .await.map_err(|_| ())?;
        let selected = modules.iter().map(String::as_str).collect::<Vec<_>>();
        let profile = reviewed_profiles::for_modules(major, &selected).ok_or(())?;
        let global = stage(
            catalog_capture::capture(server, profile).await,
            "dependency capture",
        )?;
        let static_names = namespace_names(global.namespace_security.as_array().ok_or(())?)?;
        let static_authority = stage(
            namespace_authority::prove(role, &static_names, &global.namespace_security),
            "dependency namespace authority",
        )?;
        let deps = stage(
            profile.validate_live_authorized(&global.raw, major, &static_authority),
            "dependency profile",
        )?;
        let initial = stage(
            relation_capture::capture(server, roots, major).await,
            "relation capture",
        )?;
        for target in lock_targets(&initial)? {
            let query = format!("LOCK TABLE ONLY {target} IN ACCESS SHARE MODE NOWAIT");
            stage(
                server
                    .execute_checked(ServerRequest::strict_internal(&query, &[]))
                    .await,
                "relation lock",
            )?;
        }
        let raw = stage(
            relation_capture::capture(server, roots, major).await,
            "locked relation capture",
        )?;
        if !stable_capture_equal(&initial, &raw) {
            return Err(());
        }
        let mut namespaces = inventory(rows(&raw, "namespaces")?.iter(), "oid")?
            .into_iter()
            .map(|(id, row)| (id, row.clone()))
            .collect::<BTreeMap<_, _>>();
        for row in global.namespace_security.as_array().ok_or(())? {
            if let Some(previous) = namespaces.insert(oid(row, "oid")?, row.clone())
                && previous != *row
            {
                return Err(());
            }
        }
        let namespaces = namespaces.into_values().collect::<Vec<_>>();
        let names = namespace_names(&namespaces)?;
        let authority = namespace_authority::prove(role, &names, &Value::Array(namespaces))?;
        // Types, I/O, Vars and every call in a tree are proved before invoking
        // pg_get_expr. Unknown constant output functions cannot be deparsed.
        let attrs = attributes(&raw)?;
        let requested = attrs
            .values()
            .flatten()
            .map(|row| oid(row, "atttypid"))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let types = stage(
            type_catalog::prove(
                &requested,
                rows(&raw, "types")?,
                rows(&raw, "enums")?,
                &deps,
                role,
                &authority,
            ),
            "projection types",
        )?;
        let type_rows = inventory(rows(&raw, "types")?.iter(), "oid")?;
        let columns = attrs
            .iter()
            .map(|(&id, attrs)| {
                let columns = attrs
                    .iter()
                    .map(|attribute| {
                        let ty = *type_rows.get(&oid(attribute, "atttypid")?).ok_or(())?;
                        ColumnRow::from_catalog_metadata(
                            attribute,
                            ty,
                            names.get(&oid(ty, "typnamespace")?).ok_or(())?,
                        )
                    })
                    .collect::<Result<Vec<_>, ()>>()?;
                Ok((id, columns))
            })
            .collect::<Result<BTreeMap<_, _>, ()>>()?;
        let mut configs = BTreeMap::new();
        for (key, catalog, source_field, rel_field, context_kind) in [
            ("indexes", "pg_index", "indexprs", "indrelid", 0),
            ("indexes", "pg_index", "indpred", "indrelid", 1),
            ("dependency_indexes", "pg_index", "indexprs", "indrelid", 0),
            ("dependency_indexes", "pg_index", "indpred", "indrelid", 1),
            ("constraints", "pg_constraint", "conbin", "conrelid", 2),
        ] {
            for row in rows(&raw, key)? {
                let Some(source) = row.get(source_field).and_then(Value::as_str) else {
                    if row.get(source_field) != Some(&Value::Null) {
                        return Err(());
                    }
                    continue;
                };
                let relation = oid(row, rel_field)?;
                let context = match context_kind {
                    0 => node_tree::Context::index(relation),
                    1 => node_tree::Context::predicate(relation),
                    _ => node_tree::Context::check(relation),
                };
                let trees =
                    node_tree::parse_and_extract_all(source, major, context).map_err(|_| ())?;
                for tree in &trees {
                    let checked = expression_proof::precheck(
                        tree,
                        &deps,
                        columns.get(&relation).ok_or(())?,
                        &types.enums,
                    )
                    .map_err(|_| ())?;
                    if !checked.requires_regconfig() {
                        continue;
                    }
                    let id_field = if catalog == "pg_index" {
                        "indexrelid"
                    } else {
                        "oid"
                    };
                    let object = oid(row, id_field)?.to_string();
                    let relation = relation.to_string();
                    // Every identifier here comes from the fixed tuple above;
                    // no SQL identifier or expression text is interpolated.
                    let query = format!(
                        "SELECT pg_catalog.pg_get_expr({source_field},{rel_field})::pg_catalog.text FROM pg_catalog.{catalog} WHERE {id_field}=$1::pg_catalog.oid AND {source_field}::pg_catalog.text=$2::pg_catalog.text AND {rel_field}=$3::pg_catalog.oid"
                    );
                    let deparsed = server
                        .fetch_all::<String>(ServerRequest::strict_internal(
                            &query,
                            &[
                                BindParameter::new(object.as_bytes()),
                                BindParameter::new(source.as_bytes()),
                                BindParameter::new(relation.as_bytes()),
                            ],
                        ))
                        .await
                        .map_err(|_| ())?;
                    if deparsed.len() != 1 {
                        return Err(());
                    }
                    let name = regconfig_name::builtin_name(&deparsed[0])?;
                    let config = deps
                        .rows("pg_ts_config")
                        .ok_or(())?
                        .find(|row| row["fields"]["cfgname"].as_str() == Some(name))
                        .ok_or(())?;
                    let identity = config["identity"]
                        .as_str()
                        .map(str::to_owned)
                        .or_else(|| config["identity"].as_u64().map(|id| id.to_string()))
                        .ok_or(())?;
                    let config_oid = deps
                        .runtime_oid_for_identity("pg_ts_config", &identity)
                        .ok_or(())?;
                    checked.finish(Some(config_oid)).map_err(|_| ())?;
                    if let Some(previous) = configs.insert(*tree.source_digest(), config_oid)
                        && previous != config_oid
                    {
                        return Err(());
                    }
                }
            }
        }
        let proven = stage(
            prove(&raw, &deps, role, &authority, &names, allowed, &configs),
            "full relation proof",
        )?;
        // Detect drift throughout capture/deparse/proof. These checks complement
        // the controlled DDL epoch; ACCESS SHARE does not freeze index creation
        // or dependency implementations and is not a concurrent-DBA sandbox.
        let final_relations = stage(
            relation_capture::capture(server, roots, major).await,
            "final relation capture",
        )?;
        let final_global = stage(
            catalog_capture::capture(server, profile).await,
            "final dependency capture",
        )?;
        if !stable_capture_equal(&raw, &final_relations)
            || !stable_capture_equal(&global.raw, &final_global.raw)
        {
            return Err(());
        }
        Ok(proven)
    }
    inner(server, roots, role, major, allowed)
        .await
        .map_err(|_| PolicyError::unsupported())
}

// Names are captured catalog data, never SQL fragments. ONLY avoids implicit
// inheritance expansion before the complete captured closure has been locked.
fn lock_targets(raw: &Value) -> Result<Vec<String>, ()> {
    fn quoted(name: &str) -> Result<String, ()> {
        if name.is_empty() || name.len() > 63 || name.contains('\0') {
            return Err(());
        }
        Ok(format!("\"{}\"", name.replace('"', "\"\"")))
    }
    let namespaces = inventory(rows(raw, "namespaces")?.iter(), "oid")?;
    let relations = inventory(
        rows(raw, "relations")?
            .iter()
            .chain(rows(raw, "relation_dependencies")?),
        "oid",
    )?;
    if relations.is_empty() || relations.len() > 4096 {
        return Err(());
    }
    relations
        .values()
        .map(|row| {
            if text(row, "relkind")? != "r" {
                return Err(());
            }
            let namespace = namespaces.get(&oid(row, "relnamespace")?).ok_or(())?;
            Ok(format!(
                "{}.{}",
                quoted(text(namespace, "nspname")?)?,
                quoted(text(row, "relname")?)?
            ))
        })
        .collect()
}

fn stable_capture_equal(first: &Value, second: &Value) -> bool {
    let (Some(first), Some(second)) = (first.as_object(), second.as_object()) else {
        return false;
    };
    let mut first = first.clone();
    let mut second = second.clone();
    first.remove("capture_id");
    second.remove("capture_id");
    first == second
}

fn namespace_names(rows: &[Value]) -> Result<BTreeMap<u32, String>, ()> {
    rows.iter()
        .map(|row| Ok((oid(row, "oid")?, text(row, "nspname")?.to_owned())))
        .collect()
}

fn rows<'a>(raw: &'a Value, key: &str) -> Result<&'a [Value], ()> {
    let rows = raw.get(key).and_then(Value::as_array).ok_or(())?;
    if rows.len() > 20000 {
        return Err(());
    }
    Ok(rows)
}
fn inventory<'a>(
    rows: impl Iterator<Item = &'a Value>,
    key: &str,
) -> Result<BTreeMap<u32, &'a Value>, ()> {
    let mut output = BTreeMap::new();
    for row in rows {
        let id = oid(row, key)?;
        if let Some(previous) = output.insert(id, row) {
            // A FK may reference an index already captured for a scanned table.
            if previous != row {
                return Err(());
            }
        }
    }
    Ok(output)
}
fn constraint_inventory(raw: &Value) -> Result<BTreeMap<u32, &Value>, ()> {
    let roots = rows(raw, "constraints")?;
    let referenced = roots
        .iter()
        .filter(|row| row["contype"] == "f")
        .map(|row| Ok((oid(row, "conindid")?, oid(row, "confrelid")?)))
        .collect::<Result<BTreeSet<_>, ()>>()?;
    let indexes = inventory(rows(raw, "dependency_indexes")?.iter(), "indexrelid")?;
    let supporting = match raw.get("dependency_constraints") {
        Some(_) => rows(raw, "dependency_constraints")?,
        // Historical private captures lack this field; with no added support
        // authority the ordinary outgoing-dependency check still fails closed.
        None => &[],
    };
    for row in supporting {
        let index = oid(row, "conindid")?;
        let table = oid(row, "conrelid")?;
        if !matches!(row["contype"].as_str(), Some("p" | "u"))
            || !referenced.contains(&(index, table))
            || oid(indexes.get(&index).ok_or(())?, "indrelid")? != table
        {
            return Err(());
        }
    }
    inventory(roots.iter().chain(supporting), "oid")
}
fn attributes(raw: &Value) -> Result<BTreeMap<u32, Vec<&Value>>, ()> {
    let mut output = BTreeMap::<u32, Vec<&Value>>::new();
    let mut seen = BTreeMap::new();
    for row in rows(raw, "attributes")?
        .iter()
        .chain(rows(raw, "dependency_attributes")?)
    {
        let relation = oid(row, "attrelid")?;
        let number = oid(row, "attnum")?;
        if number > 1600 {
            return Err(());
        }
        if let Some(previous) = seen.insert((relation, number), row) {
            if previous != row {
                return Err(());
            }
            continue;
        }
        if !boolean(row, "attisdropped")? {
            output.entry(relation).or_default().push(row);
        }
    }
    for columns in output.values_mut() {
        columns.sort_by_key(|row| oid(row, "attnum").unwrap_or(0));
    }
    Ok(output)
}
fn expression(
    raw: &str,
    context: node_tree::Context,
    columns: &[ColumnRow],
    deps: &dependency_profile::DependencyProof,
    enums: &BTreeMap<u32, type_proof::EnumTypeProof>,
    configs: &BTreeMap<[u8; 32], u32>,
) -> Result<Vec<expression_proof::ExpressionProof>, ()> {
    node_tree::parse_and_extract_all(raw, deps.major(), context)
        .map_err(|_| ())?
        .iter()
        .map(|tree| {
            let checked = expression_proof::precheck(tree, deps, columns, enums).map_err(|_| ())?;
            let config = if checked.requires_regconfig() {
                Some(*configs.get(tree.source_digest()).ok_or(())?)
            } else {
                None
            };
            checked.finish(config).map_err(|_| ())
        })
        .collect()
}
fn prove(
    raw: &Value,
    deps: &dependency_profile::DependencyProof,
    role: &RoleRow,
    authority: &namespace_authority::NamespaceAuthorityProof,
    names: &BTreeMap<u32, String>,
    allowed: &BTreeSet<(String, String)>,
    configs: &BTreeMap<[u8; 32], u32>,
) -> Result<ProvenCatalog, ()> {
    if !role.is_safe_application_role()
        || serde_json::to_vec(raw).map_err(|_| ())?.len() > 16 * 1024 * 1024
    {
        return Err(());
    }
    match raw.get("expression_statistics") {
        Some(Value::Array(statistics)) if statistics.is_empty() => {}
        None if deps.major() == 12 => {} // PG12 cannot have expression statistics.
        _ => return Err(()),
    }
    let edges = rows(raw, "inheritance_edges")?
        .iter()
        .map(|row| Ok((oid(row, "parent")?, oid(row, "child")?)))
        .collect::<Result<Vec<_>, ()>>()?;
    let touched = edges
        .iter()
        .flat_map(|(p, c)| [*p, *c])
        .collect::<BTreeSet<_>>();
    let classes = inventory(
        rows(raw, "relations")?
            .iter()
            .chain(rows(raw, "relation_dependencies")?),
        "oid",
    )?;
    let relation_rows = classes
        .iter()
        .map(|(id, row)| {
            Ok((
                *id,
                relation_row(row, names, touched.contains(id), role, authority, deps)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, ()>>()?;
    let roots = raw.get("roots").and_then(Value::as_array).ok_or(())?;
    if roots.is_empty() || roots.len() > 4096 {
        return Err(());
    }
    let mut scanned = BTreeSet::new();
    for root in roots {
        let root = oid(&serde_json::json!({"oid":root}), "oid")?;
        scanned.extend(typed_stage(
            inheritance::prove_closure(root, &relation_rows, &edges, allowed, role.oid),
            "inheritance closure",
        )?);
    }
    // Every captured scan relation must belong to the proven closure.
    if rows(raw, "relations")?
        .iter()
        .any(|row| !oid(row, "oid").is_ok_and(|id| scanned.contains(&id)))
    {
        return Err(());
    }
    let attributes = attributes(raw)?;
    let requested = attributes
        .values()
        .flatten()
        .map(|row| oid(row, "atttypid"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let types = stage(
        type_catalog::prove(
            &requested,
            rows(raw, "types")?,
            rows(raw, "enums")?,
            deps,
            role,
            authority,
        ),
        "projection types",
    )?;
    let raw_types = inventory(rows(raw, "types")?.iter(), "oid")?;
    let mut columns = BTreeMap::new();
    for (&id, attrs) in &attributes {
        if !classes.contains_key(&id) {
            return Err(());
        }
        let decoded = attrs
            .iter()
            .map(|attribute| {
                let ty = *raw_types.get(&oid(attribute, "atttypid")?).ok_or(())?;
                let schema = names.get(&oid(ty, "typnamespace")?).ok_or(())?;
                let column = ColumnRow::from_catalog_metadata(attribute, ty, schema)?;
                if !column.generated.is_empty()
                    || !column.identity.is_empty()
                    || !types.capabilities.contains_key(&column.type_oid)
                {
                    return Err(());
                }
                Ok(column)
            })
            .collect::<Result<Vec<_>, ()>>()?;
        columns.insert(id, decoded);
    }
    let index_classes = inventory(
        rows(raw, "index_relations")?
            .iter()
            .chain(rows(raw, "dependency_index_relations")?),
        "oid",
    )?;
    let indexes = inventory(
        rows(raw, "indexes")?
            .iter()
            .chain(rows(raw, "dependency_indexes")?),
        "indexrelid",
    )?;
    let mut index_attributes = BTreeMap::<u32, BTreeMap<u32, &Value>>::new();
    for attribute in rows(raw, "index_attributes")?
        .iter()
        .chain(rows(raw, "dependency_index_attributes")?)
    {
        let id = oid(attribute, "attrelid")?;
        let number = oid(attribute, "attnum")?;
        if let Some(previous) = index_attributes
            .entry(id)
            .or_default()
            .insert(number, attribute)
            && previous != attribute
        {
            return Err(());
        }
    }
    let mut index_proofs = BTreeMap::new();
    let mut attribute_digests = BTreeMap::new();
    for (&id, index) in &indexes {
        let table = oid(index, "indrelid")?;
        let cols = columns.get(&table).ok_or(())?;
        let expressions = match index.get("indexprs").ok_or(())? {
            Value::Null => vec![],
            Value::String(source) => expression(
                source,
                node_tree::Context::index(table),
                cols,
                deps,
                &types.enums,
                configs,
            )?,
            _ => return Err(()),
        };
        let predicate = match index.get("indpred").ok_or(())? {
            Value::Null => None,
            Value::String(source) => {
                let mut proofs = expression(
                    source,
                    node_tree::Context::predicate(table),
                    cols,
                    deps,
                    &types.enums,
                    configs,
                )?;
                if proofs.len() != 1 {
                    return Err(());
                }
                proofs.pop()
            }
            _ => return Err(()),
        };
        let options = index_attributes
            .get(&id)
            .ok_or(())?
            .iter()
            .enumerate()
            .map(|(offset, (&number, row))| {
                if number != u32::try_from(offset + 1).map_err(|_| ())?
                    || boolean(row, "attisdropped")?
                {
                    return Err(());
                }
                match row.get("attoptions").ok_or(())? {
                    Value::Null => Ok(None),
                    Value::Array(values) => Ok(Some(
                        values
                            .iter()
                            .map(|v| v.as_str().map(str::to_owned).ok_or(()))
                            .collect::<Result<Vec<_>, _>>()?,
                    )),
                    _ => Err(()),
                }
            })
            .collect::<Result<Vec<_>, ()>>()?;
        let proof = typed_stage(
            index_proof::prove(
                index,
                index_classes.get(&id).ok_or(())?,
                index_proof::ProofContext {
                    columns: cols,
                    expression_proofs: &expressions,
                    predicate: predicate.as_ref(),
                    dependencies: deps,
                    enums: &types.enums,
                    role_oid: role.oid,
                    authority,
                    index_attribute_options: &options,
                },
            ),
            "typed index dependency proof",
        )?;
        let attributes = index_attributes[&id]
            .values()
            .map(|row| (*row).clone())
            .collect::<Vec<_>>();
        let attribute_digest = typed_stage(
            index_proof::validate_attributes(&proof, index, &attributes, cols, deps, &types.enums),
            "index physical attributes",
        )?;
        attribute_digests.insert(id, attribute_digest);
        index_proofs.insert(id, proof);
    }
    if rows(raw, "constraints")?
        .iter()
        .any(|row| !oid(row, "conrelid").is_ok_and(|id| scanned.contains(&id)))
    {
        return Err(());
    }
    let mut constraint_digests = BTreeMap::new();
    for (id, constraint) in constraint_inventory(raw)? {
        let table = oid(constraint, "conrelid")?;
        if !classes.contains_key(&table)
            || oid(constraint, "connamespace")? != oid(classes[&table], "relnamespace")?
        {
            return Err(());
        }
        if !scanned.contains(&table) && !matches!(constraint["contype"].as_str(), Some("p" | "u")) {
            return Err(());
        }
        let cols = columns.get(&table).ok_or(())?;
        let check = match constraint.get("conbin").ok_or(())? {
            Value::Null => None,
            Value::String(source) => {
                let mut proofs = expression(
                    source,
                    node_tree::Context::check(table),
                    cols,
                    deps,
                    &types.enums,
                    configs,
                )?;
                if proofs.len() != 1 {
                    return Err(());
                }
                proofs.pop()
            }
            _ => return Err(()),
        };
        let proof = typed_stage(
            constraint_proof::prove(
                constraint,
                table,
                cols,
                &columns,
                &index_proofs,
                check.as_ref(),
                deps,
                &types.enums,
            ),
            "constraint dependency proof",
        )?;
        if constraint_digests.insert(id, *proof.digest()).is_some() {
            return Err(());
        }
    }
    // Outgoing catalog dependencies are checked in addition to structural OID
    // fields. Pinned built-ins may have no pg_depend rows at all.
    for dependency in rows(raw, "dependencies")? {
        let reference = oid(dependency, "refobjid")?;
        let catalog = oid(dependency, "refclassid")?;
        let accepted = match catalog {
            1259 => classes.contains_key(&reference) || index_proofs.contains_key(&reference),
            2615 => authority.covers(reference, role.oid),
            2606 => constraint_digests.contains_key(&reference),
            1247 => {
                types.enums.contains_key(&reference)
                    || deps
                        .identity_for_runtime_oid("pg_type", reference)
                        .is_some()
                    || classes
                        .values()
                        .any(|row| oid(row, "reltype").ok() == Some(reference))
            }
            1255 => deps
                .identity_for_runtime_oid("pg_proc", reference)
                .is_some(),
            2617 => deps
                .identity_for_runtime_oid("pg_operator", reference)
                .is_some(),
            2616 => deps
                .identity_for_runtime_oid("pg_opclass", reference)
                .is_some(),
            3456 => deps
                .identity_for_runtime_oid("pg_collation", reference)
                .is_some(),
            // The exact profiled storage type must be a direct member of this
            // extension. A known extension name alone never proves membership.
            3079 => {
                oid(dependency, "classid").ok() == Some(1247)
                    && dependency["deptype"] == "e"
                    && dependency["objsubid"] == 0
                    && dependency["refobjsubid"] == 0
                    && oid(dependency, "objid").is_ok_and(|object| {
                        raw_types
                            .get(&object)
                            .is_some_and(|row| deps.matches_type_row(row))
                            && deps.has_direct_extension_member(reference, "pg_type", object)
                    })
            }
            // A regconfig edge must refer to a configuration whose complete
            // expression/dictionary/parser closure was finished above.
            3602 => {
                dependency["deptype"] == "n"
                    && dependency["objsubid"] == 0
                    && dependency["refobjsubid"] == 0
                    && configs.values().any(|config| *config == reference)
                    && deps
                        .identity_for_runtime_oid("pg_ts_config", reference)
                        .is_some()
                    && oid(dependency, "objid").is_ok_and(|object| {
                        match oid(dependency, "classid") {
                            Ok(1259) => index_proofs.contains_key(&object),
                            Ok(2606) => constraint_digests.contains_key(&object),
                            _ => false,
                        }
                    })
            }
            _ => false,
        };
        if !accepted {
            #[cfg(test)]
            eprintln!(
                "full proof denied outgoing dependency catalog={catalog} source_catalog={} dependency_kind={}",
                dependency["classid"], dependency["deptype"]
            );
            return Err(());
        }
    }
    let output = scanned
        .iter()
        .map(|id| {
            Ok((
                *id,
                (
                    relation_rows[id].clone(),
                    columns.get(id).ok_or(())?.clone(),
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, ()>>()?;
    let mut stable = raw.clone();
    stable.as_object_mut().ok_or(())?.remove("capture_id");
    let index_digests = index_proofs
        .iter()
        .map(|(id, proof)| (*id, *proof.digest()))
        .collect::<BTreeMap<_, _>>();
    Ok(ProvenCatalog {
        relations: output,
        capabilities: types.capabilities,
        metadata: serde_json::json!({"capture":stable,"dependency_digest":deps.digest(),"reviewed_profile_digest":deps.profile_digest(),"authority_digest":authority.digest(),
            "index_digests":index_digests,"attribute_digests":attribute_digests,"constraint_digests":constraint_digests}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reviewed_direct_extension_edges_bind_exact_runtime_member() {
        let root = std::path::PathBuf::from(
            std::env::var_os("PGDOG_PROFILE_TEST_FIXTURE_DIR").expect("owned fixtures required"),
        );
        for major in [12, 18] {
            let profile: Value = serde_json::from_slice(
                &std::fs::read(root.join(format!(
                    "variants/read-dependency-profile-pg{major}-both.json"
                )))
                .unwrap(),
            )
            .unwrap();
            let mut capture: Value = serde_json::from_slice(
                &std::fs::read(root.join(format!("reference-extended-pg{major}.json"))).unwrap(),
            )
            .unwrap();
            capture["extension_members"]
                .as_array_mut()
                .unwrap()
                .retain(|row| {
                    matches!(
                        row["extname"].as_str(),
                        Some("plpgsql" | "pg_trgm" | "btree_gist")
                    )
                });
            capture["tables"]["pg_extension"]
                .as_array_mut()
                .unwrap()
                .retain(|row| matches!(row["extname"].as_str(), Some("pg_trgm" | "btree_gist")));
            let deps = dependency_profile::DependencyProof::from_test_values(
                &profile,
                &capture,
                major,
                profile["provenance"]["source_image"].as_str().unwrap(),
            )
            .unwrap();
            let extension = oid(
                capture["tables"]["pg_extension"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["extname"] == "btree_gist")
                    .unwrap(),
                "oid",
            )
            .unwrap();
            let other = oid(
                capture["tables"]["pg_extension"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["extname"] == "pg_trgm")
                    .unwrap(),
                "oid",
            )
            .unwrap();
            let member = oid(
                capture["extension_members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["extname"] == "btree_gist" && row["catalog"] == "pg_type")
                    .unwrap(),
                "objid",
            )
            .unwrap();
            assert!(
                deps.has_direct_extension_member(extension, "pg_type", member),
                "reviewed exact direct membership must prove"
            );
            assert!(!deps.has_direct_extension_member(other, "pg_type", member));
            assert!(!deps.has_direct_extension_member(extension, "pg_proc", member));
            assert!(!deps.has_direct_extension_member(extension, "pg_type", 23));
            assert!(!deps.has_direct_extension_member(999999, "pg_type", member));
        }
    }
    #[test]
    #[cfg(unix)]
    #[ignore = "private local structural diagnostic; not live-role or endpoint acceptance"]
    fn private_inventory_expression_precheck() {
        let directory = std::path::PathBuf::from(
            std::env::var_os("PGDOG_PRIVATE_INVENTORY_DIR")
                .expect("private diagnostic directory required"),
        );
        let read = |name: &str| -> Value {
            serde_json::from_slice(&std::fs::read(directory.join(name)).unwrap()).unwrap()
        };
        let raw = read("icondo-private-full-relations.json");
        let global = read("icondo-private-full-dependencies.json");
        // This diagnostic tests captured shapes under synthetic eligible actor
        // facts. It never certifies the actual capture operator or live ACLs.
        let role = RoleRow {
            valid: true,
            oid: 20001,
            superuser: false,
            create_role: false,
            create_database: false,
            replication: false,
            bypass_rls: false,
            inherit: true,
            has_memberships: false,
        };
        let mut namespaces = raw["namespaces"].clone();
        for row in namespaces.as_array_mut().unwrap() {
            row["actor_oid"] = serde_json::json!("20001");
            row["has_create"] = serde_json::json!(false);
            row["has_usage"] = serde_json::json!(true);
        }
        let names = namespace_names(namespaces.as_array().unwrap()).unwrap();
        let authority = namespace_authority::prove(&role, &names, &namespaces).unwrap();
        let profile = reviewed_profiles::for_modules(12, &["btree_gist", "pg_trgm"]).unwrap();
        let deps = profile
            .validate_live_authorized(&global, 12, &authority)
            .expect("private dependency shape must match immutable reference");
        let attrs = attributes(&raw).unwrap();
        let requested = attrs
            .values()
            .flatten()
            .map(|row| oid(row, "atttypid").unwrap())
            .collect::<BTreeSet<_>>();
        let types = type_catalog::prove(
            &requested,
            rows(&raw, "types").unwrap(),
            rows(&raw, "enums").unwrap(),
            &deps,
            &role,
            &authority,
        )
        .expect("private type shapes must be proven");
        let type_rows = inventory(rows(&raw, "types").unwrap().iter(), "oid").unwrap();
        let columns = attrs
            .iter()
            .map(|(&id, attrs)| {
                let cols = attrs
                    .iter()
                    .map(|attribute| {
                        let ty = type_rows[&oid(attribute, "atttypid").unwrap()];
                        ColumnRow::from_catalog_metadata(
                            attribute,
                            ty,
                            &names[&oid(ty, "typnamespace").unwrap()],
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>();
                (id, cols)
            })
            .collect::<BTreeMap<_, _>>();
        let full_inventory = std::env::var_os("PGDOG_PROVE_PRIVATE_INVENTORY").is_some();
        let deparsed = if full_inventory {
            Some(read("private-prechecked-deparsed-expressions.json"))
        } else {
            None
        };
        let mut configs = BTreeMap::new();
        if let Some(deparsed) = &deparsed {
            for (field, filename, expected) in [
                ("capture_sha256", "icondo-private-full-relations.json", &raw),
                (
                    "dependency_capture_sha256",
                    "icondo-private-full-dependencies.json",
                    &global,
                ),
            ] {
                let bytes = std::fs::read(directory.join(filename)).unwrap();
                assert!(
                    serde_json::from_slice::<Value>(&bytes).unwrap() == *expected,
                    "private input changed before full proof"
                );
                let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &bytes);
                let hash = hash
                    .as_ref()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                assert!(
                    deparsed[field].as_str() == Some(hash.as_str()),
                    "private deparse input binding changed"
                );
            }
        }
        let mut seen = BTreeSet::new();
        let mut count = 0;
        let mut config_count = 0;
        let mut approved_sources = BTreeMap::new();
        for (key, source_field, relation_field, kind) in [
            ("indexes", "indexprs", "indrelid", 0),
            ("indexes", "indpred", "indrelid", 1),
            ("dependency_indexes", "indexprs", "indrelid", 0),
            ("dependency_indexes", "indpred", "indrelid", 1),
            ("constraints", "conbin", "conrelid", 2),
        ] {
            for row in rows(&raw, key).unwrap() {
                let Some(source) = row[source_field].as_str() else {
                    continue;
                };
                let relation = oid(row, relation_field).unwrap();
                let object = oid(
                    row,
                    if key == "constraints" {
                        "oid"
                    } else {
                        "indexrelid"
                    },
                )
                .unwrap();
                let catalog = if key == "constraints" {
                    "pg_constraint"
                } else {
                    "pg_index"
                };
                let source_hash =
                    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, source.as_bytes());
                let source_hash = source_hash
                    .as_ref()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                approved_sources.insert((catalog,source_field,object),serde_json::json!({"catalog":catalog,"source_field":source_field,
                    "relation_field":relation_field,"relation_oid":relation,"object_oid":object,"source_sha256":source_hash}));
                let context = match kind {
                    0 => node_tree::Context::index(relation),
                    1 => node_tree::Context::predicate(relation),
                    _ => node_tree::Context::check(relation),
                };
                for tree in node_tree::parse_and_extract_all(source, 12, context)
                    .expect("private stored tree structure must be admitted")
                {
                    if !seen.insert((*tree.source_digest(), tree.source_ordinal(), relation, kind))
                    {
                        continue;
                    }
                    let checked =
                        expression_proof::precheck(&tree, &deps, &columns[&relation], &types.enums)
                            .expect("private stored expression callbacks must be proven");
                    count += 1;
                    if checked.requires_regconfig() {
                        config_count += 1;
                        if let Some(deparsed) = &deparsed {
                            let matches = deparsed["sources"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .filter(|item| {
                                    item["catalog"] == catalog
                                        && item["source_field"] == source_field
                                        && item["object_oid"].as_u64() == Some(u64::from(object))
                                        && item["relation_oid"].as_u64()
                                            == Some(u64::from(relation))
                                        && item["source_sha256"].as_str()
                                            == Some(source_hash.as_str())
                                })
                                .collect::<Vec<_>>();
                            assert_eq!(
                                matches.len(),
                                1,
                                "private deparse source must bind exactly"
                            );
                            let name =
                                regconfig_name::builtin_name(matches[0]["sql"].as_str().unwrap())
                                    .expect("text-search configuration must be reviewed");
                            let config = deps
                                .rows("pg_ts_config")
                                .unwrap()
                                .find(|row| row["fields"]["cfgname"].as_str() == Some(name))
                                .unwrap();
                            let identity = config["identity"]
                                .as_str()
                                .map(str::to_owned)
                                .or_else(|| config["identity"].as_u64().map(|id| id.to_string()))
                                .unwrap();
                            let config_oid = deps
                                .runtime_oid_for_identity("pg_ts_config", &identity)
                                .unwrap();
                            checked.finish(Some(config_oid)).unwrap();
                            if let Some(previous) =
                                configs.insert(*tree.source_digest(), config_oid)
                            {
                                assert_eq!(previous, config_oid);
                            }
                        }
                    } else {
                        checked.finish(None).unwrap();
                    }
                }
            }
        }
        eprintln!(
            "private structural diagnostic: roots={} proven_types={} expression_roots={} pending_regconfigs={}",
            raw["roots"].as_array().unwrap().len(),
            requested.len(),
            count,
            if full_inventory { 0 } else { config_count }
        );
        assert_eq!(raw["roots"].as_array().unwrap().len(), 282);
        assert!(count >= 67);
        if full_inventory {
            let allowed = rows(&raw, "relations")
                .unwrap()
                .iter()
                .map(|row| {
                    (
                        names[&oid(row, "relnamespace").unwrap()].clone(),
                        text(row, "relname").unwrap().to_owned(),
                    )
                })
                .collect::<BTreeSet<_>>();
            let proven = prove(&raw, &deps, &role, &authority, &names, &allowed, &configs).expect(
                "all private READ shapes must pass full proof under synthetic eligible authority",
            );
            assert_eq!(proven.relations.len(), 282);
            eprintln!(
                "private full structural proof: proven=282 denied=0; endpoint acceptance still pending"
            );
            if std::env::var_os("PGDOG_EXPORT_OWNED_READ_SHAPE").is_some() {
                let request: Value = serde_json::from_slice(
                    &std::fs::read(directory.join("private-owned-shape.json")).unwrap(),
                )
                .unwrap();
                let original =
                    std::fs::read(directory.join("icondo-private-full-relations.json")).unwrap();
                let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &original)
                    .as_ref()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                assert!(
                    request["capture_sha256"].as_str() == Some(&hash),
                    "owned lineage must bind exact source input"
                );
                let export = owned_shape_export::export(
                    &raw,
                    &request["shape"],
                    deparsed.as_ref().unwrap(),
                    &deps,
                    &proven,
                )
                .expect(
                    "all proved private expressions/support must export to synthetic identifiers",
                );
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut output = std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .mode(0o600)
                    .open(directory.join("private-owned-read-proof.json"))
                    .unwrap();
                output
                    .write_all(&serde_json::to_vec(&export).unwrap())
                    .unwrap();
                eprintln!(
                    "private owned export: indexes={} constraints={} expressions={}",
                    export["index_support"].as_object().unwrap().len(),
                    export["constraint_support"].as_object().unwrap().len(),
                    export["expressions"].as_array().unwrap().len()
                );
            }
        }
        if std::env::var_os("PGDOG_EXPORT_PRIVATE_PRECHECK").is_some() {
            let bytes =
                std::fs::read(directory.join("icondo-private-full-relations.json")).unwrap();
            assert!(
                serde_json::from_slice::<Value>(&bytes).unwrap() == raw,
                "private input changed during proof"
            );
            let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &bytes);
            let hash = hash
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let dependency_bytes =
                std::fs::read(directory.join("icondo-private-full-dependencies.json")).unwrap();
            assert!(
                serde_json::from_slice::<Value>(&dependency_bytes).unwrap() == global,
                "private dependencies changed during proof"
            );
            let dependency_hash =
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &dependency_bytes);
            let dependency_hash = dependency_hash
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let receipt = serde_json::json!({"purpose":"private stored-expression precheck; synthetic authority, not live acceptance",
                "capture_sha256":hash,"dependency_capture_sha256":dependency_hash,"postgres_major":12,"profile_digest":deps.profile_digest(),
                "expression_roots":count,"pending_regconfigs":config_count,"sources":approved_sources.into_values().collect::<Vec<_>>()});
            let path = directory.join("private-expression-precheck.json");
            use std::os::unix::fs::OpenOptionsExt;
            let mut output = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            use std::io::Write;
            output
                .write_all(&serde_json::to_vec_pretty(&receipt).unwrap())
                .unwrap();
        }
    }

    #[test]
    fn supporting_constraint_inventory_is_bound_to_exact_foreign_key_index() {
        let root = serde_json::json!({"oid":"1","contype":"f","conindid":"77","conrelid":"2","confrelid":"3"});
        let support = serde_json::json!({"oid":"4","contype":"p","conindid":"77","conrelid":"3"});
        let raw = serde_json::json!({"constraints":[root],"dependency_constraints":[support],
            "dependency_indexes":[{"indexrelid":"77","indrelid":"3"}]});
        assert_eq!(constraint_inventory(&raw).unwrap().len(), 2);
        let mut bad = raw.clone();
        bad["dependency_constraints"][0]["conindid"] = serde_json::json!("78");
        assert!(constraint_inventory(&bad).is_err());
        bad = raw.clone();
        bad["dependency_constraints"][0]["conrelid"] = serde_json::json!("2");
        assert!(constraint_inventory(&bad).is_err());
        bad = raw.clone();
        bad["dependency_constraints"][0]["contype"] = serde_json::json!("c");
        assert!(constraint_inventory(&bad).is_err());
        bad = raw.clone();
        let support = bad["dependency_constraints"][0].clone();
        bad["constraints"].as_array_mut().unwrap().push(support);
        assert_eq!(constraint_inventory(&bad).unwrap().len(), 2);
        bad["constraints"][1]["conrelid"] = serde_json::json!("999");
        assert!(constraint_inventory(&bad).is_err());
        bad = raw.clone();
        bad["dependency_constraints"] = serde_json::json!([]);
        assert_eq!(constraint_inventory(&bad).unwrap().len(), 1);
    }

    #[test]
    fn stabilization_quotes_only_complete_relation_inventory_and_rejects_drift() {
        let raw = serde_json::json!({"capture_id":"a","namespaces":[{"oid":"2200","nspname":"safe\"ns"}],
            "relations":[{"oid":"17000","relnamespace":"2200","relname":"items\";SELECT 1--","relkind":"r"}],
            "relation_dependencies":[]});
        assert_eq!(
            lock_targets(&raw).unwrap(),
            vec!["\"safe\"\"ns\".\"items\"\";SELECT 1--\"".to_owned()]
        );
        let mut next = raw.clone();
        next["capture_id"] = serde_json::json!("b");
        assert!(stable_capture_equal(&raw, &next));
        next["relations"][0]["relowner"] = serde_json::json!("999");
        assert!(!stable_capture_equal(&raw, &next));
        next = raw.clone();
        next["relations"][0]["relnamespace"] = serde_json::json!("999");
        assert!(lock_targets(&next).is_err());
        next = raw.clone();
        next["relations"][0]["relkind"] = serde_json::json!("v");
        assert!(lock_targets(&next).is_err());
        next = raw.clone();
        next["relations"][0]["relname"] = serde_json::json!("bad\u{0000}name");
        assert!(lock_targets(&next).is_err());
    }

    #[test]
    fn full_relation_requires_approved_heap_and_actor_namespace() {
        // This path must not inherit authorization from the legacy table flag.
        let role = RoleRow {
            valid: true,
            oid: 20001,
            superuser: false,
            create_role: false,
            create_database: false,
            replication: false,
            bypass_rls: false,
            inherit: true,
            has_memberships: false,
        };
        let names = BTreeMap::from([(11, "pg_catalog".into()), (2200, "public".into())]);
        let root = std::path::PathBuf::from(
            std::env::var_os("PGDOG_PROFILE_TEST_FIXTURE_DIR")
                .expect("owned profile fixtures required"),
        );
        for major in [12, 18] {
            let profile: Value = serde_json::from_slice(
                &std::fs::read(root.join(format!(
                    "variants/read-dependency-profile-pg{major}-both.json"
                )))
                .unwrap(),
            )
            .unwrap();
            let mut capture: Value = serde_json::from_slice(
                &std::fs::read(root.join(format!("reference-extended-pg{major}.json"))).unwrap(),
            )
            .unwrap();
            capture["extension_members"]
                .as_array_mut()
                .unwrap()
                .retain(|row| {
                    matches!(
                        row["extname"].as_str(),
                        Some("plpgsql" | "pg_trgm" | "btree_gist")
                    )
                });
            capture["tables"]["pg_extension"]
                .as_array_mut()
                .unwrap()
                .retain(|row| matches!(row["extname"].as_str(), Some("pg_trgm" | "btree_gist")));
            let deps = dependency_profile::DependencyProof::from_test_values(
                &profile,
                &capture,
                major,
                profile["provenance"]["source_image"].as_str().unwrap(),
            )
            .unwrap();
            let security = serde_json::json!([
                {"oid":"11","nspname":"pg_catalog","nspowner":"10","nspacl":null,"has_create":false,"has_usage":true,"actor_oid":"20001"},
                {"oid":"2200","nspname":"public","nspowner":"10","nspacl":null,"has_create":false,"has_usage":true,"actor_oid":"20001"}]);
            let authority = namespace_authority::prove(&role, &names, &security).unwrap();
            let raw = serde_json::json!({"oid":"17000","relnamespace":"2200","relname":"items",
                "relkind":"r","relpersistence":"p","relowner":"10","relrowsecurity":false,
                "relforcerowsecurity":false,"relhasrules":false,"relispartition":false,"relam":"2"});
            assert!(
                relation_row(&raw, &names, true, &role, &authority, &deps)
                    .unwrap()
                    .has_inheritance
            );
            let mut bad = raw.clone();
            bad["relam"] = serde_json::json!("999999");
            assert!(relation_row(&bad, &names, true, &role, &authority, &deps).is_err());
            let mut types = Value::Array(Vec::new());
            types
                .as_array_mut()
                .unwrap()
                .push(deps.row("pg_type", "3802").unwrap()["fields"].clone());
            let mut ty = types[0].clone();
            ty["oid"] = serde_json::json!("3802");
            types[0] = ty;
            let shape = serde_json::json!({"roots":[17000],"relations":[raw],"relation_dependencies":[],
                "attributes":[{"attrelid":"17000","attnum":1,"attname":"payload","atttypid":"3802",
                    "attisdropped":false,"attnotnull":false,"attgenerated":"","attidentity":"","attcollation":"0","atttypmod":-1,"attndims":0}],
                "dependency_attributes":[],"types":types,"enums":[],"inheritance_edges":[],
                "indexes":[],"dependency_indexes":[],"index_relations":[],"dependency_index_relations":[],
                "index_attributes":[],"dependency_index_attributes":[],"constraints":[],"dependencies":[],"expression_statistics":[],"namespaces":[]});
            let allowed = BTreeSet::from([("public".into(), "items".into())]);
            let catalog = prove(
                &shape,
                &deps,
                &role,
                &authority,
                &names,
                &allowed,
                &BTreeMap::new(),
            )
            .unwrap();
            assert_eq!(catalog.relations[&17000].1[0].type_oid, 3802);
            assert!(catalog.capabilities[&3802].text_output);
            let owned_shape = serde_json::json!({"relations":{"17000":{"synthetic_name":"t0001",
                "source_attnums":{"1":{"source_relation_oid":17000,"source_attnum":1,"source_type_oid":3802,"column":"c0001"}}}},"types":{}});
            let exported = owned_shape_export::export(
                &shape,
                &owned_shape,
                &serde_json::json!({"sources":[]}),
                &deps,
                &catalog,
            )
            .unwrap();
            assert_eq!(exported["source_read_proof_complete"], true);
            let mut wrong_source = shape.clone();
            wrong_source["attributes"][0]["atttypid"] = serde_json::json!("23");
            assert!(
                owned_shape_export::export(
                    &wrong_source,
                    &owned_shape,
                    &serde_json::json!({"sources":[]}),
                    &deps,
                    &catalog
                )
                .is_err()
            );
            let mut wrong_lineage = owned_shape.clone();
            wrong_lineage["relations"]["17000"]["source_attnums"]["1"]["source_type_oid"] =
                serde_json::json!(23);
            assert!(
                owned_shape_export::export(
                    &shape,
                    &wrong_lineage,
                    &serde_json::json!({"sources":[]}),
                    &deps,
                    &catalog
                )
                .is_err()
            );
            let mut unproved_statistics = shape.clone();
            unproved_statistics["expression_statistics"] =
                serde_json::json!([{"oid":"19000","relation_oid":"17000"}]);
            assert!(
                prove(
                    &unproved_statistics,
                    &deps,
                    &role,
                    &authority,
                    &names,
                    &allowed,
                    &BTreeMap::new()
                )
                .is_err(),
                "full fallback must retain the expression-statistics denial before planning"
            );
            let proofs = catalog.proofs();
            assert!(proofs[&17000].matches_metadata(&catalog.metadata));
            let mut changed = catalog.metadata.clone();
            changed["dependency_digest"] = serde_json::json!([0]);
            assert!(
                !proofs[&17000].matches_metadata(&changed),
                "same relation proof cannot replay across dependency snapshots"
            );
            bad = raw.clone();
            bad["relowner"] = serde_json::json!("20001");
            assert!(relation_row(&bad, &names, true, &role, &authority, &deps).is_err());
        }
    }
}
