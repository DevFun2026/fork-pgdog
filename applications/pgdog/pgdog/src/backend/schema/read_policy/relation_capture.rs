//! Bounded, read-only relation metadata capture for the full-read proof.
//!
//! This module records catalog facts only. It deliberately does not deparse
//! expressions, plan statements, or fetch function bodies. Trust decisions
//! about relation rows and dependencies belong to the proof layer.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_json::{Map, Value};

use crate::{
    backend::{Server, server::ServerRequest},
    frontend::read_policy::PolicyError,
    net::messages::bind::Parameter as BindParameter,
};

const MAX_RELATIONS: usize = 4096;
const MAX_INHERITANCE_DEPTH: usize = 64;
const MAX_EDGES: usize = 8192;
const MAX_ROWS: usize = 20_000;
const MAX_QUERY_BYTES: usize = 4 * 1024 * 1024;
const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

const VERSION_SQL: &str = "SELECT pg_catalog.jsonb_build_object( \
    'server_version', pg_catalog.current_setting('server_version'), \
    'server_version_num', pg_catalog.current_setting('server_version_num')::pg_catalog.int4, \
    'postgres_major', pg_catalog.current_setting('server_version_num')::pg_catalog.int4 / 10000 \
)::pg_catalog.text WHERE $1::pg_catalog.int4 = 1";

const CHILD_EDGES_SQL: &str = "SELECT pg_catalog.jsonb_build_object( \
    'parent', i.inhparent::pg_catalog.text, 'child', i.inhrelid::pg_catalog.text \
)::pg_catalog.text FROM pg_catalog.pg_inherits AS i \
WHERE i.inhparent = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
ORDER BY i.inhparent, i.inhseqno, i.inhrelid LIMIT 8193";

const TOUCHING_EDGES_SQL: &str = "SELECT pg_catalog.jsonb_build_object( \
    'parent', i.inhparent::pg_catalog.text, 'child', i.inhrelid::pg_catalog.text, \
    'sequence', i.inhseqno::pg_catalog.text \
)::pg_catalog.text FROM pg_catalog.pg_inherits AS i \
WHERE i.inhparent = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
   OR i.inhrelid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
ORDER BY i.inhparent, i.inhseqno, i.inhrelid LIMIT 8193";

const RELATIONS_SQL: &str = "SELECT pg_catalog.to_jsonb(c)::pg_catalog.text \
FROM pg_catalog.pg_class AS c \
WHERE c.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
ORDER BY c.oid LIMIT 20001";

// Expression statistics remain outside the reviewed planner surface.
// Capture identifiers only, never statistic data or stored expression output.
// PG12 has no stxexprs column.
const EXPRESSION_STATISTICS_SQL: &str = "SELECT pg_catalog.jsonb_build_object('oid',s.oid::pg_catalog.text, 'relation_oid',s.stxrelid::pg_catalog.text)::pg_catalog.text FROM pg_catalog.pg_statistic_ext AS s WHERE s.stxrelid=ANY(pg_catalog.string_to_array($1,',')::pg_catalog.oid[]) AND s.stxexprs IS NOT NULL ORDER BY s.oid LIMIT 20001";
fn expression_statistics_sql(major: u32) -> Option<&'static str> {
    match major {
        18 => Some(EXPRESSION_STATISTICS_SQL),
        _ => None,
    }
}

macro_rules! attributes_sql {
    ($major_fields:literal) => {
        concat!(
            "SELECT pg_catalog.jsonb_build_object( ",
            "'attacl', a.attacl, 'attalign', a.attalign, 'attbyval', a.attbyval, ",
            "'attcollation', a.attcollation, 'attfdwoptions', a.attfdwoptions, ",
            "'attgenerated', a.attgenerated, 'atthasdef', a.atthasdef, ",
            "'atthasmissing', a.atthasmissing, ",
            "'attmissingval_present', (a.attmissingval IS NOT NULL), ",
            "'attidentity', a.attidentity, 'attinhcount', a.attinhcount, ",
            "'attisdropped', a.attisdropped, 'attislocal', a.attislocal, ",
            "'attlen', a.attlen, 'attname', a.attname, 'attndims', a.attndims, ",
            "'attnotnull', a.attnotnull, 'attnum', a.attnum, ",
            "'attoptions', a.attoptions, 'attrelid', a.attrelid, ",
            "'attstattarget', a.attstattarget, 'attstorage', a.attstorage, ",
            "'atttypid', a.atttypid, 'atttypmod', a.atttypmod",
            $major_fields,
            ")::pg_catalog.text FROM pg_catalog.pg_attribute AS a ",
            "WHERE a.attrelid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) ",
            "AND a.attnum > 0 ORDER BY a.attrelid, a.attnum LIMIT 20001"
        )
    };
}
const ATTRIBUTES_PG12_SQL: &str = attributes_sql!(", 'attcacheoff', a.attcacheoff");
const ATTRIBUTES_PG18_SQL: &str = attributes_sql!(", 'attcompression', a.attcompression");
fn attributes_sql(major: u32) -> Option<&'static str> {
    match major {
        12 => Some(ATTRIBUTES_PG12_SQL),
        18 => Some(ATTRIBUTES_PG18_SQL),
        _ => None,
    }
}

const CONSTRAINTS_SQL: &str = "SELECT pg_catalog.to_jsonb(c)::pg_catalog.text \
FROM pg_catalog.pg_constraint AS c \
WHERE c.conrelid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
ORDER BY c.conrelid, c.oid LIMIT 20001";

const INDEXES_SQL: &str = "SELECT pg_catalog.to_jsonb(i)::pg_catalog.text \
FROM pg_catalog.pg_index AS i \
WHERE i.indrelid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
ORDER BY i.indrelid, i.indexrelid LIMIT 20001";

const DEPENDENCY_INDEXES_SQL: &str = "SELECT pg_catalog.to_jsonb(i)::pg_catalog.text \
FROM pg_catalog.pg_index AS i \
WHERE i.indexrelid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
ORDER BY i.indexrelid LIMIT 20001";

const SUPPORTING_CONSTRAINTS_SQL: &str = "SELECT pg_catalog.to_jsonb(c)::pg_catalog.text \
FROM pg_catalog.pg_constraint AS c \
WHERE c.conindid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
  AND c.contype IN ('p', 'u') \
ORDER BY c.conindid, c.oid LIMIT 20001";

const INDEX_RELATIONS_SQL: &str = "SELECT pg_catalog.to_jsonb(c)::pg_catalog.text \
FROM pg_catalog.pg_class AS c \
WHERE c.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
ORDER BY c.oid LIMIT 20001";

const DEPENDENCIES_SQL: &str = "SELECT pg_catalog.to_jsonb(d)::pg_catalog.text \
FROM pg_catalog.pg_depend AS d \
WHERE (d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass \
       AND d.objid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[])) \
   OR (d.classid = 'pg_catalog.pg_constraint'::pg_catalog.regclass \
       AND d.objid = ANY(pg_catalog.string_to_array($2, ',')::pg_catalog.oid[])) \
   OR (d.classid = 'pg_catalog.pg_type'::pg_catalog.regclass \
       AND d.objid = ANY(pg_catalog.string_to_array($3, ',')::pg_catalog.oid[])) \
ORDER BY d.classid, d.objid, d.objsubid, d.refclassid, d.refobjid, d.refobjsubid LIMIT 20001";

macro_rules! type_rows_sql {
    ($subscript:literal) => {
        concat!(
            "SELECT (pg_catalog.to_jsonb(t) || pg_catalog.jsonb_build_object(",
            "'typinput', t.typinput::pg_catalog.oid, 'typoutput', t.typoutput::pg_catalog.oid, ",
            "'typreceive', t.typreceive::pg_catalog.oid, 'typsend', t.typsend::pg_catalog.oid, ",
            "'typmodin', t.typmodin::pg_catalog.oid, 'typmodout', t.typmodout::pg_catalog.oid, ",
            "'typanalyze', t.typanalyze::pg_catalog.oid",
            $subscript,
            "))::pg_catalog.text FROM pg_catalog.pg_type AS t ",
            "WHERE t.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) ",
            "ORDER BY t.oid LIMIT 20001"
        )
    };
}
const TYPES_SQL: &str = type_rows_sql!("");
const TYPES_PG18_SQL: &str = type_rows_sql!(", 'typsubscript', t.typsubscript::pg_catalog.oid");
fn types_sql(major: u32) -> Option<&'static str> {
    match major {
        12 => Some(TYPES_SQL),
        18 => Some(TYPES_PG18_SQL),
        _ => None,
    }
}

const ENUMS_SQL: &str = "SELECT pg_catalog.to_jsonb(e)::pg_catalog.text \
FROM pg_catalog.pg_enum AS e \
WHERE e.enumtypid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
ORDER BY e.enumtypid, e.enumsortorder, e.oid LIMIT 20001";

const NAMESPACES_SQL: &str = "SELECT pg_catalog.jsonb_build_object( \
    'oid', n.oid::pg_catalog.text, 'nspname', n.nspname, \
    'nspowner', n.nspowner::pg_catalog.text, 'nspacl', n.nspacl, \
    'has_create', pg_catalog.has_schema_privilege(current_user, n.oid, 'CREATE'), \
    'has_usage', pg_catalog.has_schema_privilege(current_user, n.oid, 'USAGE'), \
    'actor_oid', (SELECT r.oid::pg_catalog.text FROM pg_catalog.pg_roles AS r \
        WHERE r.rolname = current_user))::pg_catalog.text \
FROM pg_catalog.pg_namespace AS n \
WHERE n.oid = ANY(pg_catalog.string_to_array($1, ',')::pg_catalog.oid[]) \
ORDER BY n.oid LIMIT 20001";

#[derive(Debug, Clone, PartialEq, Eq)]
struct InheritanceClosure {
    relation_oids: Vec<u32>,
    edges: Vec<(u32, u32)>,
}

/// Capture relation metadata from the caller's already-protected transaction.
/// The returned snapshot is complete or the operation fails closed.
pub(crate) async fn capture(
    server: &mut Server,
    roots: &[u32],
    major: u32,
) -> Result<Value, PolicyError> {
    let roots = validated_roots(roots)?;
    if !matches!(major, 12 | 18) || !server.in_transaction() {
        return Err(PolicyError::unsupported());
    }
    server
        .enable_strict_protocol()
        .map_err(|_| PolicyError::unsupported())?;
    let read_only = server
        .fetch_all::<String>(ServerRequest::strict_internal(
            "SHOW transaction_read_only",
            &[],
        ))
        .await
        .map_err(|_| PolicyError::unsupported())?;
    let version = query_one_json(server, VERSION_SQL, &[BindParameter::new(b"1")]).await?;
    let actual_major = version
        .get("postgres_major")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(PolicyError::unsupported)?;
    let version_num = version
        .get("server_version_num")
        .and_then(Value::as_u64)
        .ok_or_else(PolicyError::unsupported)?;
    let read_only = read_only
        .first()
        .filter(|_| read_only.len() == 1)
        .map(String::as_str)
        .ok_or_else(PolicyError::unsupported)?;
    validate_preflight(server.in_transaction(), read_only, actual_major, major)?;
    if version_num / 10_000 != u64::from(major) {
        return Err(PolicyError::unsupported());
    }

    let closure = fetch_inheritance_closure(server, &roots).await?;
    let relation_ids = oid_csv(&closure.relation_oids)?;
    let relation_rows = query_rows(server, RELATIONS_SQL, &[bind(&relation_ids)]).await?;
    require_exact_oid_rows(&relation_rows, &closure.relation_oids, "oid")?;
    let attribute_query = attributes_sql(major).ok_or_else(PolicyError::unsupported)?;
    let attributes = query_rows(server, attribute_query, &[bind(&relation_ids)]).await?;
    check_limit(&attributes)?;
    let constraints = query_rows(server, CONSTRAINTS_SQL, &[bind(&relation_ids)]).await?;
    check_limit(&constraints)?;
    let indexes = query_rows(server, INDEXES_SQL, &[bind(&relation_ids)]).await?;
    check_limit(&indexes)?;
    let dependency_index_ids = foreign_key_index_oids(&constraints)?;
    let dependency_indexes = if dependency_index_ids.is_empty() {
        Vec::new()
    } else {
        let rows = query_rows(
            server,
            DEPENDENCY_INDEXES_SQL,
            &[bind(&oid_csv(&dependency_index_ids)?)],
        )
        .await?;
        require_exact_oid_rows(&rows, &dependency_index_ids, "indexrelid")?;
        rows
    };
    let dependency_constraints = if dependency_index_ids.is_empty() {
        Vec::new()
    } else {
        let rows = query_rows(
            server,
            SUPPORTING_CONSTRAINTS_SQL,
            &[bind(&oid_csv(&dependency_index_ids)?)],
        )
        .await?;
        check_limit(&rows)?;
        validate_supporting_constraints(&rows, &dependency_index_ids, &dependency_indexes)?
    };
    let dependency_index_relations = if dependency_index_ids.is_empty() {
        Vec::new()
    } else {
        let rows = query_rows(
            server,
            INDEX_RELATIONS_SQL,
            &[bind(&oid_csv(&dependency_index_ids)?)],
        )
        .await?;
        require_exact_oid_rows(&rows, &dependency_index_ids, "oid")?;
        rows
    };
    let dependency_index_attributes = if dependency_index_ids.is_empty() {
        Vec::new()
    } else {
        let rows = query_rows(
            server,
            attribute_query,
            &[bind(&oid_csv(&dependency_index_ids)?)],
        )
        .await?;
        check_limit(&rows)?;
        rows
    };

    let index_ids = rows_oid_set(&indexes, "indexrelid")?;
    let index_relations = if index_ids.is_empty() {
        Vec::new()
    } else {
        let rows = query_rows(server, INDEX_RELATIONS_SQL, &[bind(&oid_csv(&index_ids)?)]).await?;
        require_exact_oid_rows(&rows, &index_ids, "oid")?;
        rows
    };
    let index_attributes = if index_ids.is_empty() {
        Vec::new()
    } else {
        let rows = query_rows(server, attribute_query, &[bind(&oid_csv(&index_ids)?)]).await?;
        check_limit(&rows)?;
        rows
    };

    // Touching edges expose external ancestors and detect any descendant the
    // iterative scan failed to include. The latter is never silently omitted.
    let touching = query_rows(server, TOUCHING_EDGES_SQL, &[bind(&relation_ids)]).await?;
    check_limit(&touching)?;
    let mut edge_set = BTreeSet::new();
    let closure_set = closure
        .relation_oids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut external_ancestors = BTreeSet::new();
    for edge in &touching {
        let parent = json_oid(edge, "parent")?;
        let child = json_oid(edge, "child")?;
        if closure_set.contains(&parent) && !closure_set.contains(&child) {
            return Err(PolicyError::unsupported());
        }
        if closure_set.contains(&child) && !closure_set.contains(&parent) {
            external_ancestors.insert(parent);
        }
        if !edge_set.insert((parent, child)) {
            return Err(PolicyError::unsupported());
        }
    }
    if edge_set.len() > MAX_EDGES {
        return Err(PolicyError::unsupported());
    }
    let mut referenced_relation_ids = external_ancestors;
    for ref_oid in foreign_key_relation_oids(&constraints)? {
        if !closure_set.contains(&ref_oid) {
            referenced_relation_ids.insert(ref_oid);
        }
    }
    let relation_dependencies = if referenced_relation_ids.is_empty() {
        Vec::new()
    } else {
        let ids = referenced_relation_ids.iter().copied().collect::<Vec<_>>();
        let rows = query_rows(server, RELATIONS_SQL, &[bind(&oid_csv(&ids)?)]).await?;
        require_exact_oid_rows(&rows, &ids, "oid")?;
        rows
    };

    let mut dependency_attributes = Vec::new();
    if !referenced_relation_ids.is_empty() {
        dependency_attributes = query_rows(
            server,
            attribute_query,
            &[bind(&oid_csv(
                &referenced_relation_ids.iter().copied().collect::<Vec<_>>(),
            )?)],
        )
        .await?;
        check_limit(&dependency_attributes)?;
    }

    let expression_statistics = if let Some(query) = expression_statistics_sql(major) {
        let mut ids = relation_rows
            .iter()
            .chain(relation_dependencies.iter())
            .map(|row| json_oid(row, "oid"))
            .collect::<Result<Vec<_>, _>>()?;
        ids.sort_unstable();
        ids.dedup();
        let rows = query_rows(server, query, &[bind(&oid_csv(&ids)?)]).await?;
        check_limit(&rows)?;
        rows
    } else {
        Vec::new()
    };

    let mut type_ids = attribute_type_oids(&attributes)?;
    type_ids.extend(attribute_type_oids(&index_attributes)?);
    type_ids.extend(attribute_type_oids(&dependency_attributes)?);
    type_ids.extend(attribute_type_oids(&dependency_index_attributes)?);
    type_ids.sort_unstable();
    type_ids.dedup();
    if type_ids.len() > MAX_ROWS {
        return Err(PolicyError::unsupported());
    }
    let types = if type_ids.is_empty() {
        Vec::new()
    } else {
        let rows = query_rows(
            server,
            types_sql(major).ok_or_else(PolicyError::unsupported)?,
            &[bind(&oid_csv(&type_ids)?)],
        )
        .await?;
        require_exact_oid_rows(&rows, &type_ids, "oid")?;
        rows
    };
    let enum_type_ids = types
        .iter()
        .filter(|row| row.get("typtype").and_then(Value::as_str) == Some("e"))
        .map(|row| json_oid(row, "oid"))
        .collect::<Result<Vec<_>, _>>()?;
    let enums = if enum_type_ids.is_empty() {
        Vec::new()
    } else {
        let rows = query_rows(server, ENUMS_SQL, &[bind(&oid_csv(&enum_type_ids)?)]).await?;
        check_limit(&rows)?;
        rows
    };

    let mut namespace_ids = BTreeSet::new();
    for row in relation_rows
        .iter()
        .chain(index_relations.iter())
        .chain(dependency_index_relations.iter())
        .chain(relation_dependencies.iter())
    {
        namespace_ids.insert(json_oid(row, "relnamespace")?);
    }
    for row in &types {
        namespace_ids.insert(json_oid(row, "typnamespace")?);
    }
    let namespaces = if namespace_ids.is_empty() {
        return Err(PolicyError::unsupported());
    } else {
        let ids = namespace_ids.into_iter().collect::<Vec<_>>();
        let rows = query_rows(server, NAMESPACES_SQL, &[bind(&oid_csv(&ids)?)]).await?;
        require_exact_oid_rows(&rows, &ids, "oid")?;
        rows
    };
    check_limit(&namespaces)?;

    let index_and_relation_ids = closure
        .relation_oids
        .iter()
        .copied()
        .chain(index_ids.iter().copied())
        .chain(dependency_index_ids.iter().copied())
        .collect::<BTreeSet<_>>();
    let all_constraints = merge_constraint_rows(&constraints, &dependency_constraints)?;
    let constraint_ids = rows_oid_set(&all_constraints, "oid")?;
    let dependencies = query_rows(
        server,
        DEPENDENCIES_SQL,
        &[
            bind(&oid_csv(
                &index_and_relation_ids.into_iter().collect::<Vec<_>>(),
            )?),
            bind(&oid_csv(&constraint_ids)?),
            bind(&oid_csv(&type_ids)?),
        ],
    )
    .await?;
    check_limit(&dependencies)?;

    let mut output = Map::new();
    output.insert("postgres_major".into(), Value::from(major));
    output.insert("capture_id".into(), Value::String(next_capture_id()));
    output.insert("roots".into(), json_oid_array(&roots));
    output.insert("relations".into(), Value::Array(relation_rows));
    output.insert(
        "expression_statistics".into(),
        Value::Array(expression_statistics),
    );
    output.insert("attributes".into(), Value::Array(attributes));
    output.insert("constraints".into(), Value::Array(constraints));
    output.insert(
        "dependency_constraints".into(),
        Value::Array(dependency_constraints),
    );
    output.insert("indexes".into(), Value::Array(indexes));
    output.insert("index_relations".into(), Value::Array(index_relations));
    output.insert("index_attributes".into(), Value::Array(index_attributes));
    output.insert(
        "dependency_indexes".into(),
        Value::Array(dependency_indexes),
    );
    output.insert(
        "dependency_index_relations".into(),
        Value::Array(dependency_index_relations),
    );
    output.insert(
        "dependency_index_attributes".into(),
        Value::Array(dependency_index_attributes),
    );
    output.insert("inheritance_edges".into(), Value::Array(touching));
    output.insert(
        "inheritance_status".into(),
        serde_json::json!({
            "complete": true,
            "relation_count": closure.relation_oids.len(),
            "edge_count": edge_set.len(),
            "max_depth": inheritance_depth(&roots, &closure.edges)?,
        }),
    );
    output.insert("types".into(), Value::Array(types));
    output.insert("enums".into(), Value::Array(enums));
    output.insert("namespaces".into(), Value::Array(namespaces));
    output.insert("dependencies".into(), Value::Array(dependencies));
    output.insert(
        "relation_dependencies".into(),
        Value::Array(relation_dependencies),
    );
    output.insert(
        "dependency_attributes".into(),
        Value::Array(dependency_attributes),
    );
    let value = Value::Object(output);
    if serde_json::to_vec(&value)
        .map_err(|_| PolicyError::unsupported())?
        .len()
        > MAX_CAPTURE_BYTES
    {
        return Err(PolicyError::unsupported());
    }
    Ok(value)
}

fn validated_roots(roots: &[u32]) -> Result<Vec<u32>, PolicyError> {
    if roots.is_empty() || roots.len() > MAX_RELATIONS || roots.contains(&0) {
        return Err(PolicyError::unsupported());
    }
    let mut sorted = roots.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != roots.len() {
        return Err(PolicyError::unsupported());
    }
    Ok(sorted)
}

fn validate_preflight(
    in_transaction: bool,
    read_only: &str,
    actual_major: u32,
    requested_major: u32,
) -> Result<(), PolicyError> {
    if !in_transaction
        || read_only != "on"
        || actual_major != requested_major
        || !matches!(actual_major, 12 | 18)
    {
        return Err(PolicyError::unsupported());
    }
    Ok(())
}

fn analyze_inheritance(
    roots: &[u32],
    edges: &[(u32, u32)],
) -> Result<InheritanceClosure, PolicyError> {
    if roots.is_empty()
        || roots.len() > MAX_RELATIONS
        || roots.contains(&0)
        || edges.len() > MAX_EDGES
    {
        return Err(PolicyError::unsupported());
    }
    let mut children = BTreeMap::<u32, BTreeSet<u32>>::new();
    let mut unique_edges = BTreeSet::new();
    for &(parent, child) in edges {
        if parent == 0 || child == 0 || parent == child || !unique_edges.insert((parent, child)) {
            return Err(PolicyError::unsupported());
        }
        children.entry(parent).or_default().insert(child);
    }
    let mut relation_oids = roots.iter().copied().collect::<BTreeSet<_>>();
    let mut queue = VecDeque::new();
    for root in roots {
        queue.push_back((*root, 0usize));
    }
    let mut max_depth = 0usize;
    while let Some((parent, depth)) = queue.pop_front() {
        max_depth = max_depth.max(depth);
        if depth > MAX_INHERITANCE_DEPTH {
            return Err(PolicyError::unsupported());
        }
        if let Some(descendants) = children.get(&parent) {
            for child in descendants {
                if !relation_oids.insert(*child) {
                    // A revisited node is either a cycle or a multi-parent DAG.
                    // Distinguish them with a bounded rooted DFS below.
                    continue;
                }
                if relation_oids.len() > MAX_RELATIONS {
                    return Err(PolicyError::unsupported());
                }
                queue.push_back((*child, depth + 1));
            }
        }
    }
    // A rooted DFS with gray/black state rejects only back-edges, allowing a
    // legal multi-parent inheritance DAG while still detecting every cycle.
    let mut colors = BTreeMap::<u32, u8>::new();
    for root in roots {
        let mut stack = vec![(*root, false, 0usize)];
        while let Some((node, exit, depth)) = stack.pop() {
            if depth > MAX_INHERITANCE_DEPTH {
                return Err(PolicyError::unsupported());
            }
            if exit {
                colors.insert(node, 2);
                continue;
            }
            match colors.get(&node) {
                Some(1) => return Err(PolicyError::unsupported()),
                Some(2) => continue,
                _ => (),
            }
            colors.insert(node, 1);
            stack.push((node, true, depth));
            if let Some(descendants) = children.get(&node) {
                stack.extend(
                    descendants
                        .iter()
                        .rev()
                        .map(|child| (*child, false, depth + 1)),
                );
            }
        }
    }
    let edges = unique_edges
        .into_iter()
        .filter(|(parent, child)| relation_oids.contains(parent) && relation_oids.contains(child))
        .collect::<Vec<_>>();
    inheritance_depth(roots, &edges)?;
    Ok(InheritanceClosure {
        relation_oids: relation_oids.into_iter().collect(),
        edges,
    })
}

async fn fetch_inheritance_closure(
    server: &mut Server,
    roots: &[u32],
) -> Result<InheritanceClosure, PolicyError> {
    let mut discovered = roots.iter().copied().collect::<BTreeSet<_>>();
    let mut frontier = discovered.clone();
    let mut edge_pairs = BTreeSet::new();
    let mut rounds = 0usize;
    while !frontier.is_empty() {
        rounds += 1;
        if rounds > MAX_INHERITANCE_DEPTH + 1 {
            return Err(PolicyError::unsupported());
        }
        let ids = oid_csv(&frontier.iter().copied().collect::<Vec<_>>())?;
        let rows = query_rows(server, CHILD_EDGES_SQL, &[bind(&ids)]).await?;
        if rows.len() > MAX_EDGES {
            return Err(PolicyError::unsupported());
        }
        let mut next = BTreeSet::new();
        for row in rows {
            let parent = json_oid(&row, "parent")?;
            let child = json_oid(&row, "child")?;
            if !frontier.contains(&parent) || !edge_pairs.insert((parent, child)) {
                return Err(PolicyError::unsupported());
            }
            if edge_pairs.len() > MAX_EDGES {
                return Err(PolicyError::unsupported());
            }
            if !discovered.contains(&child) {
                next.insert(child);
                discovered.insert(child);
            }
        }
        if discovered.len() > MAX_RELATIONS {
            return Err(PolicyError::unsupported());
        }
        frontier = next;
    }
    analyze_inheritance(roots, &edge_pairs.into_iter().collect::<Vec<_>>())
}

fn inheritance_depth(roots: &[u32], edges: &[(u32, u32)]) -> Result<usize, PolicyError> {
    let mut children = BTreeMap::<u32, Vec<u32>>::new();
    let mut indegree = BTreeMap::<u32, usize>::new();
    let mut nodes = roots.iter().copied().collect::<BTreeSet<_>>();
    for (parent, child) in edges {
        children.entry(*parent).or_default().push(*child);
        nodes.extend([*parent, *child]);
        *indegree.entry(*child).or_default() += 1;
    }
    let mut distances = roots
        .iter()
        .map(|root| (*root, 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut ready = nodes
        .iter()
        .filter(|node| indegree.get(node).copied().unwrap_or_default() == 0)
        .copied()
        .collect::<VecDeque<_>>();
    let mut visited = 0usize;
    while let Some(node) = ready.pop_front() {
        visited += 1;
        let depth = distances.get(&node).copied().unwrap_or_default();
        if depth > MAX_INHERITANCE_DEPTH {
            return Err(PolicyError::unsupported());
        }
        if let Some(descendants) = children.get(&node) {
            for child in descendants {
                let child_depth = depth.checked_add(1).ok_or_else(PolicyError::unsupported)?;
                distances
                    .entry(*child)
                    .and_modify(|existing| *existing = (*existing).max(child_depth))
                    .or_insert(child_depth);
                let remaining = indegree
                    .get_mut(child)
                    .ok_or_else(PolicyError::unsupported)?;
                *remaining = remaining
                    .checked_sub(1)
                    .ok_or_else(PolicyError::unsupported)?;
                if *remaining == 0 {
                    ready.push_back(*child);
                }
            }
        }
    }
    if visited != nodes.len() {
        return Err(PolicyError::unsupported());
    }
    distances
        .values()
        .copied()
        .max()
        .filter(|depth| *depth <= MAX_INHERITANCE_DEPTH)
        .ok_or_else(PolicyError::unsupported)
}

fn row_count_overflow(count: usize, limit: usize) -> bool {
    count > limit
}

fn check_limit(rows: &[Value]) -> Result<(), PolicyError> {
    if row_count_overflow(rows.len(), MAX_ROWS) {
        Err(PolicyError::unsupported())
    } else {
        Ok(())
    }
}

async fn query_rows(
    server: &mut Server,
    sql: &str,
    params: &[BindParameter],
) -> Result<Vec<Value>, PolicyError> {
    let raw = server
        .fetch_all::<String>(ServerRequest::strict_internal(sql, params))
        .await
        .map_err(|_| PolicyError::unsupported())?;
    if raw.len() > MAX_ROWS {
        return Err(PolicyError::unsupported());
    }
    let mut rows = Vec::with_capacity(raw.len());
    let mut byte_count = 0usize;
    for text in raw {
        byte_count = byte_count
            .checked_add(text.len())
            .ok_or_else(PolicyError::unsupported)?;
        if text.len() > 1_048_576 || byte_count > MAX_QUERY_BYTES {
            return Err(PolicyError::unsupported());
        }
        rows.push(serde_json::from_str(&text).map_err(|_| PolicyError::unsupported())?);
    }
    Ok(rows)
}

async fn query_one_json(
    server: &mut Server,
    sql: &str,
    params: &[BindParameter],
) -> Result<Value, PolicyError> {
    let rows = query_rows(server, sql, params).await?;
    if rows.len() != 1 {
        return Err(PolicyError::unsupported());
    }
    rows.into_iter().next().ok_or_else(PolicyError::unsupported)
}

fn require_exact_oid_rows(rows: &[Value], expected: &[u32], key: &str) -> Result<(), PolicyError> {
    check_limit(rows)?;
    let actual = rows_oid_set(rows, key)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected || actual.len() != rows.len() {
        return Err(PolicyError::unsupported());
    }
    Ok(())
}

fn rows_oid_set(rows: &[Value], key: &str) -> Result<Vec<u32>, PolicyError> {
    let mut values = rows
        .iter()
        .map(|row| json_oid(row, key))
        .collect::<Result<Vec<_>, _>>()?;
    values.sort_unstable();
    values.dedup();
    Ok(values)
}

fn attribute_type_oids(rows: &[Value]) -> Result<Vec<u32>, PolicyError> {
    let mut type_oids = BTreeSet::new();
    let mut seen_attributes = BTreeSet::new();
    for row in rows {
        let relation_oid = json_oid(row, "attrelid")?;
        let number = json_i64(row.get("attnum").ok_or_else(PolicyError::unsupported)?)?;
        let dropped = row
            .get("attisdropped")
            .and_then(Value::as_bool)
            .ok_or_else(PolicyError::unsupported)?;
        let type_oid = json_oid_allow_zero(row, "atttypid")?;
        if number <= 0
            || !seen_attributes.insert((relation_oid, number))
            || (dropped && type_oid != 0)
            || (!dropped && type_oid == 0)
        {
            return Err(PolicyError::unsupported());
        }
        if !dropped {
            type_oids.insert(type_oid);
        }
    }
    Ok(type_oids.into_iter().collect())
}

fn foreign_key_index_oids(constraints: &[Value]) -> Result<Vec<u32>, PolicyError> {
    let mut oids = BTreeSet::new();
    for constraint in constraints {
        let kind = constraint
            .get("contype")
            .and_then(Value::as_str)
            .ok_or_else(PolicyError::unsupported)?;
        if kind == "f" {
            oids.insert(json_oid(constraint, "conindid")?);
        }
    }
    Ok(oids.into_iter().collect())
}

fn validate_supporting_constraints(
    rows: &[Value],
    referenced_index_ids: &[u32],
    dependency_indexes: &[Value],
) -> Result<Vec<Value>, PolicyError> {
    if referenced_index_ids.is_empty() {
        return if rows.is_empty() && dependency_indexes.is_empty() {
            Ok(Vec::new())
        } else {
            Err(PolicyError::unsupported())
        };
    }
    oid_csv(referenced_index_ids)?;
    require_exact_oid_rows(dependency_indexes, referenced_index_ids, "indexrelid")?;
    let mut index_relations = BTreeMap::new();
    for row in dependency_indexes {
        let index_oid = json_oid(row, "indexrelid")?;
        let relation_oid = json_oid(row, "indrelid")?;
        if index_relations.insert(index_oid, relation_oid).is_some() {
            return Err(PolicyError::unsupported());
        }
    }

    let mut seen_constraint_oids = BTreeSet::new();
    for row in rows {
        let kind = row
            .get("contype")
            .and_then(Value::as_str)
            .ok_or_else(PolicyError::unsupported)?;
        let constraint_oid = json_oid(row, "oid")?;
        let index_oid = json_oid(row, "conindid")?;
        let relation_oid = json_oid(row, "conrelid")?;
        if !matches!(kind, "p" | "u")
            || !seen_constraint_oids.insert(constraint_oid)
            || index_relations.get(&index_oid) != Some(&relation_oid)
        {
            return Err(PolicyError::unsupported());
        }
    }
    Ok(rows.to_vec())
}

fn merge_constraint_rows(
    root_constraints: &[Value],
    supporting_constraints: &[Value],
) -> Result<Vec<Value>, PolicyError> {
    let mut by_oid = BTreeMap::new();
    for row in root_constraints.iter().chain(supporting_constraints) {
        let oid = json_oid(row, "oid")?;
        if let Some(existing) = by_oid.get(&oid) {
            if existing != row {
                return Err(PolicyError::unsupported());
            }
        } else {
            by_oid.insert(oid, row.clone());
        }
    }
    Ok(by_oid.into_values().collect())
}

fn foreign_key_relation_oids(constraints: &[Value]) -> Result<Vec<u32>, PolicyError> {
    let mut oids = BTreeSet::new();
    for constraint in constraints {
        let kind = constraint
            .get("contype")
            .and_then(Value::as_str)
            .ok_or_else(PolicyError::unsupported)?;
        if kind == "f" {
            oids.insert(json_oid(constraint, "confrelid")?);
        }
    }
    Ok(oids.into_iter().collect())
}

fn json_i64(value: &Value) -> Result<i64, PolicyError> {
    match value {
        Value::Number(value) => value.as_i64().ok_or_else(PolicyError::unsupported),
        Value::String(value) => value.parse().map_err(|_| PolicyError::unsupported()),
        _ => Err(PolicyError::unsupported()),
    }
}

fn json_oid_allow_zero(row: &Value, key: &str) -> Result<u32, PolicyError> {
    row.get(key)
        .and_then(|value| match value {
            Value::String(value) => value.parse().ok(),
            Value::Number(value) => value.as_u64().and_then(|number| u32::try_from(number).ok()),
            _ => None,
        })
        .ok_or_else(PolicyError::unsupported)
}

fn json_oid(row: &Value, key: &str) -> Result<u32, PolicyError> {
    row.get(key)
        .and_then(|value| match value {
            Value::String(value) => value.parse::<u32>().ok(),
            Value::Number(value) => value.as_u64().and_then(|number| u32::try_from(number).ok()),
            _ => None,
        })
        .filter(|oid| *oid != 0)
        .ok_or_else(PolicyError::unsupported)
}

fn oid_csv(oids: &[u32]) -> Result<String, PolicyError> {
    if oids.contains(&0) {
        return Err(PolicyError::unsupported());
    }
    let mut sorted = oids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != oids.len() {
        return Err(PolicyError::unsupported());
    }
    Ok(sorted
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(","))
}

fn bind(value: &str) -> BindParameter {
    BindParameter::new(value.as_bytes())
}

fn json_oid_array(oids: &[u32]) -> Value {
    Value::Array(oids.iter().copied().map(Value::from).collect())
}

fn next_capture_id() -> String {
    format!("pgdog-live-relation-{}", uuid::Uuid::new_v4())
}

#[cfg(test)]
mod tests {
    #[test]
    fn expression_statistics_are_bounded_and_major_specific() {
        assert!(expression_statistics_sql(12).is_none());
        let sql = expression_statistics_sql(18).unwrap();
        assert!(sql.contains("s.stxexprs IS NOT NULL"));
        assert!(sql.contains("LIMIT 20001"));
        assert!(!sql.contains("pg_get_expr") && !sql.contains("to_jsonb(s)"));
        assert!(expression_statistics_sql(17).is_none());
    }

    #[test]
    fn type_capture_serializes_callback_oids_without_regproc_names() {
        for major in [12, 18] {
            let sql = super::types_sql(major).unwrap();
            for field in [
                "typinput",
                "typoutput",
                "typreceive",
                "typsend",
                "typmodin",
                "typmodout",
                "typanalyze",
            ] {
                assert!(
                    sql.contains(&format!("t.{field}::pg_catalog.oid")),
                    "callback {field} must retain its OID"
                );
            }
            assert_eq!(sql.contains("t.typsubscript"), major == 18);
        }
        assert!(super::types_sql(11).is_none());
    }
    use super::*;

    #[test]
    fn roots_are_sorted_deduplicated_and_fail_closed_on_invalid_or_excess_input() {
        assert_eq!(validated_roots(&[42, 7]).unwrap(), [7, 42]);
        assert!(validated_roots(&[]).is_err());
        assert!(validated_roots(&[0]).is_err());
        assert!(validated_roots(&[7, 7]).is_err());
        let too_many = (1..=MAX_RELATIONS as u32 + 1).collect::<Vec<_>>();
        assert!(validated_roots(&too_many).is_err());
    }

    #[test]
    fn inheritance_analysis_rejects_cycles_and_depth_overflow() {
        let closure = analyze_inheritance(&[10], &[(10, 11), (11, 12)]).unwrap();
        assert_eq!(closure.relation_oids, [10, 11, 12]);
        assert!(analyze_inheritance(&[10], &[(10, 11), (11, 10)]).is_err());

        let deep = (1..=MAX_INHERITANCE_DEPTH + 1)
            .map(|depth| (depth as u32, depth as u32 + 1))
            .collect::<Vec<_>>();
        assert!(analyze_inheritance(&[1], &deep).is_err());
    }

    #[test]
    fn capture_preflight_requires_transaction_read_only_and_matching_major() {
        assert!(validate_preflight(true, "on", 12, 12).is_ok());
        assert!(validate_preflight(false, "on", 12, 12).is_err());
        assert!(validate_preflight(true, "off", 12, 12).is_err());
        assert!(validate_preflight(true, "on", 13, 12).is_err());
        assert!(validate_preflight(true, "malformed", 12, 12).is_err());
    }

    #[test]
    fn all_catalog_sql_is_fixed_bound_and_truncation_detects_one_extra_row() {
        for sql in [
            VERSION_SQL,
            CHILD_EDGES_SQL,
            TOUCHING_EDGES_SQL,
            RELATIONS_SQL,
            ATTRIBUTES_PG12_SQL,
            ATTRIBUTES_PG18_SQL,
            CONSTRAINTS_SQL,
            INDEXES_SQL,
            DEPENDENCY_INDEXES_SQL,
            INDEX_RELATIONS_SQL,
            DEPENDENCIES_SQL,
            TYPES_SQL,
            ENUMS_SQL,
            NAMESPACES_SQL,
        ] {
            assert!(sql.starts_with("SELECT") || sql.starts_with("WITH"));
            assert!(
                sql.contains("$1"),
                "query must use a bound parameter: {sql}"
            );
        }
        assert!(row_count_overflow(MAX_ROWS + 1, MAX_ROWS));
        assert!(!row_count_overflow(MAX_ROWS, MAX_ROWS));
        assert!(CHILD_EDGES_SQL.contains(&format!("LIMIT {}", MAX_EDGES + 1)));
        assert!(TOUCHING_EDGES_SQL.contains(&format!("LIMIT {}", MAX_EDGES + 1)));
        assert!(NAMESPACES_SQL.contains("has_create"));
        assert!(NAMESPACES_SQL.contains("has_usage"));
        assert!(NAMESPACES_SQL.contains("actor_oid"));
    }

    #[test]
    fn attribute_projection_does_not_json_convert_polymorphic_missing_values() {
        for (major, sql) in [(12, ATTRIBUTES_PG12_SQL), (18, ATTRIBUTES_PG18_SQL)] {
            assert!(
                !sql.contains("to_jsonb(a)"),
                "whole-row pg_attribute conversion can execute attmissingval element I/O"
            );
            assert!(sql.contains("attmissingval_present"));
            assert!(sql.contains("a.attmissingval IS NOT NULL"));
            assert!(sql.contains("a.atttypid"));
            assert!(sql.contains("attstattarget"));
            assert_eq!(attributes_sql(major), Some(sql));
        }
        assert_eq!(attributes_sql(11), None);
    }

    #[test]
    fn inheritance_analysis_rejects_duplicate_edges_and_ignores_unreachable_rows() {
        assert!(analyze_inheritance(&[10], &[(10, 11), (10, 11)]).is_err());
        let closure = analyze_inheritance(&[10], &[(10, 11), (99, 100)]).unwrap();
        assert_eq!(closure.relation_oids, [10, 11]);
        assert_eq!(closure.edges, [(10, 11)]);
    }

    #[test]
    fn exact_catalog_rows_are_required_by_oid_and_duplicates_fail_closed() {
        let expected = [7, 42];
        let rows = [
            serde_json::json!({"oid": "7"}),
            serde_json::json!({"oid": "42"}),
        ];
        assert!(require_exact_oid_rows(&rows, &expected, "oid").is_ok());
        assert!(require_exact_oid_rows(&rows[..1], &expected, "oid").is_err());
        let duplicate = [
            serde_json::json!({"oid": "7"}),
            serde_json::json!({"oid": "7"}),
        ];
        assert!(require_exact_oid_rows(&duplicate, &expected, "oid").is_err());
        assert!(json_oid(&serde_json::json!({"oid": "0"}), "oid").is_err());
    }

    #[test]
    fn dropped_attribute_holes_are_preserved_but_do_not_require_a_type_row() {
        let dropped = [serde_json::json!({
            "attrelid": "10", "attnum": 2, "attisdropped": true, "atttypid": "0"
        })];
        assert_eq!(attribute_type_oids(&dropped).unwrap(), Vec::<u32>::new());
        let live = [serde_json::json!({
            "attrelid": "10", "attnum": 3, "attisdropped": false, "atttypid": "23"
        })];
        assert_eq!(attribute_type_oids(&live).unwrap(), [23]);
        let malformed_live = [serde_json::json!({
            "attrelid": "10", "attnum": 4, "attisdropped": false, "atttypid": "0"
        })];
        assert!(attribute_type_oids(&malformed_live).is_err());
        let malformed_dropped = [serde_json::json!({
            "attrelid": "10", "attnum": 2, "attisdropped": true, "atttypid": "23"
        })];
        assert!(attribute_type_oids(&malformed_dropped).is_err());
    }

    #[test]
    fn foreign_keys_select_exact_referenced_index_oids_and_reject_missing_index() {
        let constraints = [
            serde_json::json!({"contype": "f", "conindid": "77"}),
            serde_json::json!({"contype": "p", "conindid": "88"}),
            serde_json::json!({"contype": "f", "conindid": "77"}),
        ];
        assert_eq!(foreign_key_index_oids(&constraints).unwrap(), [77]);
        let missing = [serde_json::json!({"contype": "f", "conindid": "0"})];
        assert!(foreign_key_index_oids(&missing).is_err());
    }

    #[test]
    fn referenced_index_support_constraints_are_exact_and_merge_without_invention() {
        let dependency_indexes = [
            serde_json::json!({"indexrelid": "77", "indrelid": "10"}),
            serde_json::json!({"indexrelid": "88", "indrelid": "20"}),
        ];
        let supporting = [serde_json::json!({
            "oid": "700", "conrelid": "10", "conindid": "77", "contype": "p"
        })];

        let exact =
            validate_supporting_constraints(&supporting, &[77, 88], &dependency_indexes).unwrap();
        assert_eq!(exact, supporting);
        let empty = validate_supporting_constraints(&[], &[77], &dependency_indexes[..1]).unwrap();
        assert!(
            empty.is_empty(),
            "bare unique indexes need no fabricated constraint"
        );

        let outside = [serde_json::json!({
            "oid": "701", "conrelid": "10", "conindid": "99", "contype": "u"
        })];
        assert!(validate_supporting_constraints(&outside, &[77], &dependency_indexes).is_err());
        let wrong_relation = [serde_json::json!({
            "oid": "702", "conrelid": "20", "conindid": "77", "contype": "u"
        })];
        assert!(
            validate_supporting_constraints(&wrong_relation, &[77], &dependency_indexes).is_err()
        );
        let wrong_kind = [serde_json::json!({
            "oid": "703", "conrelid": "10", "conindid": "77", "contype": "f"
        })];
        assert!(validate_supporting_constraints(&wrong_kind, &[77], &dependency_indexes).is_err());

        let duplicate = [supporting[0].clone(), supporting[0].clone()];
        assert!(validate_supporting_constraints(&duplicate, &[77], &dependency_indexes).is_err());
        let conflict = [
            supporting[0].clone(),
            serde_json::json!({"oid": "700", "conrelid": "10", "conindid": "77", "contype": "u"}),
        ];
        assert!(validate_supporting_constraints(&conflict, &[77], &dependency_indexes).is_err());

        let merged = merge_constraint_rows(&supporting, &supporting).unwrap();
        assert_eq!(merged.len(), 1, "identical root/support rows merge once");
        assert!(merge_constraint_rows(
            &supporting,
            &[serde_json::json!({"oid": "700", "conrelid": "10", "conindid": "77", "contype": "u"})]
        )
        .is_err());
    }

    #[test]
    fn supporting_constraint_query_is_narrowly_bound_and_bounded() {
        assert!(SUPPORTING_CONSTRAINTS_SQL.contains("$1"));
        assert!(SUPPORTING_CONSTRAINTS_SQL.contains("conindid"));
        assert!(SUPPORTING_CONSTRAINTS_SQL.contains("contype IN ('p', 'u')"));
        assert!(SUPPORTING_CONSTRAINTS_SQL.contains(&format!("LIMIT {}", MAX_ROWS + 1)));
        assert!(!SUPPORTING_CONSTRAINTS_SQL.contains("confrelid"));
    }

    #[test]
    fn relation_dependencies_ignore_zero_confrelid_except_on_foreign_keys() {
        let constraints = [
            serde_json::json!({"contype": "p", "confrelid": "0"}),
            serde_json::json!({"contype": "c", "confrelid": "0"}),
            serde_json::json!({"contype": "f", "confrelid": "77"}),
        ];
        assert_eq!(foreign_key_relation_oids(&constraints).unwrap(), [77]);

        let missing = [serde_json::json!({"contype": "f", "confrelid": "0"})];
        assert!(foreign_key_relation_oids(&missing).is_err());
        let absent = [serde_json::json!({"contype": "f"})];
        assert!(foreign_key_relation_oids(&absent).is_err());
    }
}
