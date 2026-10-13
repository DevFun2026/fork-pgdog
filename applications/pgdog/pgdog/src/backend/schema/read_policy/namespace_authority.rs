//! Actor-specific namespace authority is independent of reference object metadata.
use super::rows::RoleRow;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamespaceAuthorityProof {
    role_oid: u32,
    digest: [u8; 32],
    namespaces: BTreeMap<u32, String>,
    facts: BTreeMap<u32, Value>,
}

impl NamespaceAuthorityProof {
    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub(crate) fn covers(&self, namespace_oid: u32, role_oid: u32) -> bool {
        self.role_oid == role_oid && self.namespaces.contains_key(&namespace_oid)
    }
    pub(crate) fn matches_catalog_rows(&self, rows: &Value) -> bool {
        let Some(rows) = rows.as_array() else {
            return false;
        };
        if rows.len() != self.facts.len() {
            return false;
        }
        let mut seen = std::collections::BTreeSet::new();
        rows.iter().all(|row| {
            let Some(fields) = row.as_object() else {
                return false;
            };
            if fields.len() != 4
                || !["oid", "nspname", "nspowner", "nspacl"]
                    .iter()
                    .all(|key| fields.contains_key(*key))
            {
                return false;
            }
            let Ok(oid) = parse_oid(&fields["oid"]) else {
                return false;
            };
            let Some(expected) = self.facts.get(&oid) else {
                return false;
            };
            seen.insert(oid)
                && fields["nspname"] == expected["nspname"]
                && parse_oid(&fields["nspowner"]).ok() == parse_oid(&expected["nspowner"]).ok()
                && fields["nspacl"] == expected["nspacl"]
        })
    }
}

pub(crate) fn prove(
    role: &RoleRow,
    expected: &BTreeMap<u32, String>,
    captured: &Value,
) -> Result<NamespaceAuthorityProof, ()> {
    if !role.is_safe_application_role() || expected.is_empty() || expected.len() > 64 {
        return Err(());
    }
    let rows = captured.as_array().ok_or(())?;
    if rows.len() != expected.len() {
        return Err(());
    }
    let mut namespaces = BTreeMap::new();
    let mut complete_rows = BTreeMap::new();
    for row in rows {
        let fields = row.as_object().ok_or(())?;
        if fields.len() != 7
            || ![
                "oid",
                "nspname",
                "nspowner",
                "nspacl",
                "has_create",
                "actor_oid",
                "has_usage",
            ]
            .iter()
            .all(|key| fields.contains_key(*key))
        {
            return Err(());
        }
        let oid = parse_oid(&fields["oid"])?;
        let owner = parse_oid(&fields["nspowner"])?;
        let actor = parse_oid(&fields["actor_oid"])?;
        let name = fields["nspname"].as_str().ok_or(())?;
        if actor != role.oid
            || owner == role.oid
            || name.is_empty()
            || name.len() > 63
            || name.contains('\0')
            || expected.get(&oid).map(String::as_str) != Some(name)
            || fields["has_create"].as_bool() != Some(false)
            || fields["has_usage"].as_bool() != Some(true)
            || namespaces.insert(oid, name.to_owned()).is_some()
        {
            return Err(());
        }
        let acl = &fields["nspacl"];
        if !acl.is_null() {
            let entries = acl.as_array().ok_or(())?;
            if entries.len() > 1024
                || entries.iter().any(|entry| {
                    !entry
                        .as_str()
                        .is_some_and(|value| value.len() <= 4096 && !value.contains('\0'))
                })
            {
                return Err(());
            }
        }
        complete_rows.insert(oid, row.clone());
    }
    // Reference ACLs describe the disposable capture owner. Live ACLs are
    // retained in this actor-bound proof, never erased or replaced with them.
    let canonical = serde_json::to_vec(&(role.oid, &complete_rows)).map_err(|_| ())?;
    if canonical.len() > 256 * 1024 {
        return Err(());
    }
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &canonical);
    let mut digest = [0; 32];
    digest.copy_from_slice(hash.as_ref());
    Ok(NamespaceAuthorityProof {
        role_oid: role.oid,
        digest,
        namespaces,
        facts: complete_rows,
    })
}

fn parse_oid(value: &Value) -> Result<u32, ()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn role() -> RoleRow {
        RoleRow {
            valid: true,
            oid: 20001,
            superuser: false,
            create_role: false,
            create_database: false,
            replication: false,
            bypass_rls: false,
            inherit: true,
            has_memberships: false,
        }
    }
    fn namespaces() -> BTreeMap<u32, String> {
        [(11, "pg_catalog".into()), (2200, "public".into())].into()
    }
    fn capture() -> Value {
        json!([
            {"oid":"11","nspname":"pg_catalog","nspowner":"10",
             "nspacl":["postgres=UC/postgres","=U/postgres"],
             "has_create":false,"has_usage":true,"actor_oid":"20001"},
            {"oid":"2200","nspname":"public","nspowner":"10",
             "nspacl":["postgres=UC/postgres","=U/postgres","reader=U/postgres"],
             "has_create":false,"has_usage":true,"actor_oid":"20001"}
        ])
    }
    #[test]
    fn proves_actor_authority_and_binds_complete_acl_without_requiring_reference_acl() {
        let first = prove(&role(), &namespaces(), &capture()).unwrap();
        let mut changed = capture();
        changed[1]["nspacl"] = json!(["postgres=UC/postgres", "=U/postgres"]);
        let second = prove(&role(), &namespaces(), &changed).unwrap();
        assert_ne!(first.digest, second.digest);
        assert_eq!(first.role_oid, role().oid);
        assert_eq!(first.namespaces, namespaces());
    }
    #[test]
    fn authority_proof_cannot_be_paired_with_other_catalog_acl_or_owner() {
        let proof = prove(&role(), &namespaces(), &capture()).unwrap();
        let rows = json!([
            {"oid":"11","nspname":"pg_catalog","nspowner":"10",
                "nspacl":["postgres=UC/postgres","=U/postgres"]},
            {"oid":"2200","nspname":"public","nspowner":"10",
                "nspacl":["postgres=UC/postgres","=U/postgres","reader=U/postgres"]}
        ]);
        assert!(proof.matches_catalog_rows(&rows));
        let mut changed = rows.clone();
        changed[1]["nspacl"] = json!(["=UC/postgres"]);
        assert!(!proof.matches_catalog_rows(&changed));
        changed = rows.clone();
        changed[1]["nspowner"] = json!("20001");
        assert!(!proof.matches_catalog_rows(&changed));
        assert!(!proof.matches_catalog_rows(&json!([])));
    }
    #[test]
    fn rejects_mutable_owned_incomplete_duplicated_or_unbound_namespaces() {
        let mut mutable = capture();
        mutable[1]["has_create"] = json!(true);
        let mut no_usage = capture();
        no_usage[1]["has_usage"] = json!(false);
        let mut owned = capture();
        owned[1]["nspowner"] = json!(role().oid.to_string());
        let mut actor = capture();
        actor[1]["actor_oid"] = json!("20002");
        let mut malformed = capture();
        malformed[1]["nspacl"] = json!("unknown");
        let mut extra = capture();
        extra[1]["ignored"] = json!(false);
        let mut duplicate = capture();
        duplicate[1] = duplicate[0].clone();
        for bad in [
            mutable,
            no_usage,
            owned,
            actor,
            malformed,
            extra,
            duplicate,
            json!([]),
        ] {
            assert!(prove(&role(), &namespaces(), &bad).is_err());
        }
        let mut unsafe_role = role();
        unsafe_role.has_memberships = true;
        assert!(prove(&unsafe_role, &namespaces(), &capture()).is_err());
    }
}
