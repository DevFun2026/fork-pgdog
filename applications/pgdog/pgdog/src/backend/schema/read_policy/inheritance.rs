//! Exact manifest coverage for ordinary table inheritance, before client planning.
use super::rows::RelationRow;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn prove_closure(
    root: u32,
    relations: &BTreeMap<u32, RelationRow>,
    edges: &[(u32, u32)],
    allowed: &BTreeSet<(String, String)>,
    role_oid: u32,
) -> Result<Vec<u32>, ()> {
    const MAX_RELATIONS: usize = 4096;
    const MAX_EDGES: usize = 8192;
    const MAX_DEPTH: usize = 64;
    if root == 0 || role_oid == 0 || relations.len() > MAX_RELATIONS || edges.len() > MAX_EDGES {
        return Err(());
    }
    let mut children = BTreeMap::<u32, BTreeSet<u32>>::new();
    let mut touched = BTreeSet::new();
    for &(parent, child) in edges {
        if parent == 0
            || child == 0
            || !relations.contains_key(&parent)
            || !relations.contains_key(&child)
            || !children.entry(parent).or_default().insert(child)
        {
            return Err(());
        }
        touched.extend([parent, child]);
    }
    // Gray is on the current DFS path; black has been fully proven. An ordinary
    // multi-parent DAG may reach the same black node through several parents.
    let mut colors = BTreeMap::<u32, u8>::new();
    let mut stack = vec![(root, 0, false)];
    while let Some((oid, depth, exit)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(());
        }
        if exit {
            colors.insert(oid, 2);
            continue;
        }
        match colors.get(&oid).copied() {
            Some(1) => return Err(()),
            Some(2) => continue,
            _ => (),
        }
        let row = relations.get(&oid).ok_or(())?;
        if row.oid != oid
            || !row.valid
            || row.owner_oid == 0
            || row.owner_oid == role_oid
            || row.schema.is_empty()
            || row.name.is_empty()
            || row.kind != "r"
            || row.persistence != "p"
            || row.row_security
            || row.force_row_security
            || row.has_rules
            || row.is_partition
            || row.namespace_can_create
            || row.access_method != "heap"
            || row.has_inheritance != touched.contains(&oid)
            || !allowed.contains(&(row.schema.clone(), row.name.clone()))
        {
            return Err(());
        }
        colors.insert(oid, 1);
        stack.push((oid, depth, true));
        if let Some(descendants) = children.get(&oid) {
            stack.extend(
                descendants
                    .iter()
                    .rev()
                    .map(|child| (*child, depth + 1, false)),
            );
        }
    }
    Ok(colors.into_keys().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn relation(oid: u32, name: &str, inherited: bool) -> RelationRow {
        RelationRow {
            valid: true,
            oid,
            schema: "public".into(),
            name: name.into(),
            kind: "r".into(),
            persistence: "p".into(),
            owner_oid: 10,
            row_security: false,
            force_row_security: false,
            has_rules: false,
            is_partition: false,
            has_inheritance: inherited,
            namespace_can_create: false,
            access_method: "heap".into(),
        }
    }
    fn inventory() -> (BTreeMap<u32, RelationRow>, BTreeSet<(String, String)>) {
        let rows = [
            relation(1, "parent", true),
            relation(2, "child", true),
            relation(3, "leaf", true),
        ];
        let allowed = rows
            .iter()
            .map(|r| (r.schema.clone(), r.name.clone()))
            .collect();
        (rows.into_iter().map(|r| (r.oid, r)).collect(), allowed)
    }
    #[test]
    fn inheritance_proves_all_descendants_with_exact_manifest_coverage() {
        let (rows, allowed) = inventory();
        assert_eq!(
            prove_closure(1, &rows, &[(1, 2), (2, 3)], &allowed, 20),
            Ok(vec![1, 2, 3])
        );
    }
    #[test]
    fn unlisted_or_unsafe_grandchild_is_not_hidden_by_safe_parent() {
        let (mut rows, mut allowed) = inventory();
        allowed.remove(&("public".into(), "leaf".into()));
        assert!(prove_closure(1, &rows, &[(1, 2), (2, 3)], &allowed, 20).is_err());
        allowed.insert(("public".into(), "leaf".into()));
        rows.get_mut(&3).unwrap().has_rules = true;
        assert!(prove_closure(1, &rows, &[(1, 2), (2, 3)], &allowed, 20).is_err());
    }
    #[test]
    fn cycle_duplicate_missing_or_inconsistent_edges_deny() {
        let (mut rows, allowed) = inventory();
        for edges in [
            vec![(1, 2), (2, 3), (3, 1)],
            vec![(1, 2), (1, 2)],
            vec![(1, 99)],
        ] {
            assert!(prove_closure(1, &rows, &edges, &allowed, 20).is_err());
        }
        rows.get_mut(&1).unwrap().has_inheritance = false;
        assert!(prove_closure(1, &rows, &[(1, 2), (2, 3)], &allowed, 20).is_err());
    }
    #[test]
    fn multi_parent_dag_is_not_misclassified_as_a_cycle() {
        let (rows, allowed) = inventory();
        assert_eq!(
            prove_closure(1, &rows, &[(1, 2), (1, 3), (2, 3)], &allowed, 20),
            Ok(vec![1, 2, 3])
        );
    }
}
