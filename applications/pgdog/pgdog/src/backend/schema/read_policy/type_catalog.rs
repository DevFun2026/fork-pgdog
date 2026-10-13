//! Projection capabilities derived from a closed dependency and actor proof.
use super::{
    dependency_profile::DependencyProof,
    namespace_authority::NamespaceAuthorityProof,
    rows::RoleRow,
    type_proof::{EnumTypeProof, TypeCapabilities},
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct ProvenTypes {
    pub(super) capabilities: BTreeMap<u32, TypeCapabilities>,
    pub(super) enums: BTreeMap<u32, EnumTypeProof>,
}

pub(super) fn prove(
    requested: &BTreeSet<u32>,
    types: &[Value],
    labels: &[Value],
    dependencies: &DependencyProof,
    role: &RoleRow,
    authority: &NamespaceAuthorityProof,
) -> Result<ProvenTypes, ()> {
    use super::type_proof::{
        self, BuiltinTypeProfile, EnumLabel, PgTypeMetadata, ReviewedCoreIoProfile, TypePermissions,
    };
    const PROJECTION_TYPES: &[u32] = &[
        16, 17, 20, 21, 23, 25, 700, 701, 1042, 1043, 1082, 1083, 1114, 1184, 1186, 1266, 1700,
        2950, 3802, 1007, 1009, 1182, 1231,
    ];
    if !role.is_safe_application_role()
        || requested.len() > 1600
        || types.len() > 20000
        || labels.len() > 20000
    {
        return Err(());
    }
    let permissions = TypePermissions {
        role_oid: role.oid,
        superuser: false,
        schemas_with_create: BTreeSet::new(),
        owner_role_memberships: BTreeSet::new(),
    };
    let projection = TypeCapabilities {
        text_output: true,
        binary_output: true,
        ..Default::default()
    };
    let mut approved = BTreeMap::new();
    let mut actual = BTreeMap::new();
    for row in dependencies.rows("pg_type").ok_or(())? {
        if row["identity"].as_u64().is_none() {
            continue;
        }
        let metadata = PgTypeMetadata::from_catalog_json(&row["fields"], dependencies.major())
            .map_err(|_| ())?;
        let capability = if PROJECTION_TYPES.contains(&metadata.oid) {
            projection
        } else {
            Default::default()
        };
        approved.insert(
            metadata.oid,
            BuiltinTypeProfile::new(metadata.clone(), capability),
        );
        actual.insert(metadata.oid, metadata);
    }
    let mut captured = BTreeMap::new();
    for row in types {
        let id = oid(row.get("oid"))?;
        if captured.insert(id, row).is_some() {
            return Err(());
        }
        if row.get("typtype").and_then(Value::as_str) == Some("e") {
            if !requested.contains(&id) {
                return Err(());
            }
        } else if !dependencies.matches_type_row(row) {
            return Err(());
        }
        // Index storage types are captured for index proof; they do not acquire
        // output capabilities merely by being present in this inventory.
        if requested.contains(&id) {
            let metadata =
                PgTypeMetadata::from_catalog_json(row, dependencies.major()).map_err(|_| ())?;
            actual.insert(id, metadata);
        }
    }
    let mut enum_labels = BTreeMap::<u32, Vec<EnumLabel>>::new();
    let mut label_ids = BTreeSet::new();
    for row in labels {
        let fields = row.as_object().ok_or(())?;
        if fields.len() != 4
            || !["oid", "enumtypid", "enumsortorder", "enumlabel"]
                .iter()
                .all(|key| fields.contains_key(*key))
        {
            return Err(());
        }
        let id = oid(row.get("oid"))?;
        if !label_ids.insert(id) {
            return Err(());
        }
        let enum_type_oid = oid(row.get("enumtypid"))?;
        if !captured.contains_key(&enum_type_oid) {
            return Err(());
        }
        let sort_order = row.get("enumsortorder").and_then(Value::as_f64).ok_or(())? as f32;
        if !sort_order.is_finite() {
            return Err(());
        }
        enum_labels
            .entry(enum_type_oid)
            .or_default()
            .push(EnumLabel {
                enum_type_oid,
                oid: id,
                sort_order,
                value: row
                    .get("enumlabel")
                    .and_then(Value::as_str)
                    .ok_or(())?
                    .to_owned(),
            });
    }
    let mut capabilities = BTreeMap::new();
    let mut enums = BTreeMap::new();
    for &id in requested {
        if !captured.contains_key(&id) {
            return Err(());
        }
        let metadata = actual.get(&id).ok_or(())?;
        if !authority.covers(metadata.schema_oid, role.oid) {
            return Err(());
        }
        if metadata.kind == b'e' {
            for (function, name) in [
                (3506, "enum_in"),
                (3507, "enum_out"),
                (3532, "enum_recv"),
                (3533, "enum_send"),
            ] {
                let identity = dependencies
                    .identity_for_runtime_oid("pg_proc", function)
                    .ok_or(())?;
                let fields = &dependencies.row("pg_proc", identity).ok_or(())?["fields"];
                if fields["proname"].as_str() != Some(name)
                    || oid(fields.get("pronamespace"))? != 11
                {
                    return Err(());
                }
            }
            let core_io = ReviewedCoreIoProfile {
                server_major: dependencies.major(),
                core_namespace_oid: 11,
                input_oid: 3506,
                output_oid: 3507,
                receive_oid: 3532,
                send_oid: 3533,
            };
            let labels = enum_labels.get(&id).ok_or(())?;
            let proof = type_proof::prove_dynamic_enum(metadata, labels, &permissions, &core_io)
                .map_err(|_| ())?;
            capabilities.insert(id, projection);
            enums.insert(id, proof);
        } else {
            if !PROJECTION_TYPES.contains(&id) || metadata.output_oid == 0 || metadata.send_oid == 0
            {
                return Err(());
            }
            let capability = type_proof::prove_builtin_type(id, &actual, &approved, &permissions)
                .map_err(|_| ())?;
            if !capability.text_output || !capability.binary_output {
                return Err(());
            }
            capabilities.insert(id, capability);
        }
    }
    Ok(ProvenTypes {
        capabilities,
        enums,
    })
}

fn oid(value: Option<&Value>) -> Result<u32, ()> {
    let value = value.ok_or(())?;
    let id = if let Some(text) = value.as_str() {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(());
        }
        text.parse::<u32>().map_err(|_| ())?
    } else {
        u32::try_from(value.as_u64().ok_or(())?).map_err(|_| ())?
    };
    if id == 0 { Err(()) } else { Ok(id) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_is_proved_from_complete_owned_type_metadata() {
        let directory = std::env::var("PGDOG_PROFILE_TEST_FIXTURE_DIR")
            .expect("owned full-profile fixture required");
        for major in [12, 18] {
            let profile: Value = serde_json::from_slice(
                &std::fs::read(format!(
                    "{directory}/variants/read-dependency-profile-pg{major}-both.json"
                ))
                .unwrap(),
            )
            .unwrap();
            let mut capture: Value = serde_json::from_slice(
                &std::fs::read(format!("{directory}/reference-extended-pg{major}.json")).unwrap(),
            )
            .unwrap();
            capture["extension_members"]
                .as_array_mut()
                .unwrap()
                .retain(|row| matches!(row["extname"].as_str(), Some("pg_trgm" | "btree_gist")));
            capture["tables"]["pg_extension"]
                .as_array_mut()
                .unwrap()
                .retain(|row| matches!(row["extname"].as_str(), Some("pg_trgm" | "btree_gist")));
            let pin = profile["provenance"]["source_image"].as_str().unwrap();
            let dependencies =
                DependencyProof::from_test_values(&profile, &capture, major, pin).unwrap();
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
            let namespace = capture["tables"]["pg_namespace"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["nspname"] == "pg_catalog")
                .unwrap();
            let mut row = namespace.clone();
            row["has_create"] = Value::Bool(false);
            row["has_usage"] = Value::Bool(true);
            row["actor_oid"] = Value::String("20001".into());
            let rows = Value::Array(vec![row]);
            let authority = super::super::namespace_authority::prove(
                &role,
                &[(11, "pg_catalog".into())].into(),
                &rows,
            )
            .unwrap();
            let ty = capture["tables"]["pg_type"]
                .as_array()
                .unwrap()
                .iter()
                .find(|ty| {
                    ty["typname"] == "jsonb"
                        && (ty["typnamespace"].as_str() == Some("11")
                            || ty["typnamespace"].as_u64() == Some(11))
                })
                .unwrap()
                .clone();
            let proof = prove(
                &[3802].into(),
                std::slice::from_ref(&ty),
                &[],
                &dependencies,
                &role,
                &authority,
            )
            .unwrap();
            assert!(
                dependencies.matches_type_row(&ty),
                "captured type must match the same complete dependency snapshot"
            );
            assert!(
                proof.capabilities[&3802].text_output && proof.capabilities[&3802].binary_output
            );
            assert!(!proof.capabilities[&3802].ordering);
            let mut changed = ty.clone();
            changed["typoutput"] = Value::String("999999".into());
            assert!(!dependencies.matches_type_row(&changed));
            assert!(
                prove(
                    &[3802].into(),
                    &[changed],
                    &[],
                    &dependencies,
                    &role,
                    &authority
                )
                .is_err()
            );
            assert!(
                prove(
                    &[999999].into(),
                    &[ty],
                    &[],
                    &dependencies,
                    &role,
                    &authority
                )
                .is_err()
            );
        }
    }
}
