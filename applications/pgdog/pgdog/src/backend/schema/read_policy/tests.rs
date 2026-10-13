use super::{rows::RelationRow, rows::RoleRow};
use std::collections::{BTreeMap, BTreeSet};

fn json_oid(row: &serde_json::Value, key: &str) -> u32 {
    row.get(key)
        .and_then(|value| match value {
            serde_json::Value::String(value) => value.parse().ok(),
            serde_json::Value::Number(value) => {
                value.as_u64().and_then(|value| u32::try_from(value).ok())
            }
            _ => None,
        })
        .filter(|oid| *oid != 0)
        .unwrap_or_else(|| panic!("relation capture has malformed {key}"))
}

fn json_oid_with_zero(row: &serde_json::Value, key: &str) -> u32 {
    row.get(key)
        .and_then(|value| match value {
            serde_json::Value::String(value) => value.parse().ok(),
            serde_json::Value::Number(value) => {
                value.as_u64().and_then(|value| u32::try_from(value).ok())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("relation capture has malformed {key}"))
}

fn json_rows<'a>(value: &'a serde_json::Value, key: &str) -> &'a [serde_json::Value] {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("relation capture is missing {key}"))
}

fn assert_attribute_has_safe_missing_value_shape(attribute: &serde_json::Value) -> bool {
    assert!(attribute.get("attmissingval").is_none());
    let has_missing = attribute
        .get("atthasmissing")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| panic!("relation capture has malformed atthasmissing flag"));
    let value_present = attribute
        .get("attmissingval_present")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or_else(|| panic!("relation capture has malformed missing-value presence flag"));
    assert_eq!(value_present, has_missing);
    value_present
}

fn assert_relation_capture_inventory(
    snapshot: &super::CatalogSnapshot,
    capture: &serde_json::Value,
    major: u32,
) {
    assert_eq!(
        capture
            .get("postgres_major")
            .and_then(serde_json::Value::as_u64),
        Some(u64::from(major))
    );
    assert!(
        capture
            .get("capture_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|id| !id.is_empty())
    );

    let snapshot_relations = snapshot
        .relations
        .values()
        .map(|entry| entry.relation.oid)
        .collect::<BTreeSet<_>>();
    let roots = json_rows(capture, "roots")
        .iter()
        .map(|oid| {
            oid.as_u64()
                .and_then(|oid| u32::try_from(oid).ok())
                .filter(|oid| *oid != 0)
                .unwrap_or_else(|| panic!("relation capture has malformed root OID"))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(roots, snapshot_relations);

    let relations = json_rows(capture, "relations");
    let relation_ids = relations
        .iter()
        .map(|row| json_oid(row, "oid"))
        .collect::<BTreeSet<_>>();
    assert_eq!(relation_ids.len(), relations.len());
    assert!(snapshot_relations.is_subset(&relation_ids));
    assert_eq!(capture["inheritance_status"]["complete"], true);
    assert_eq!(
        capture["inheritance_status"]["relation_count"].as_u64(),
        Some(relation_ids.len() as u64)
    );

    let attributes = json_rows(capture, "attributes");
    let mut observed_columns = BTreeMap::<u32, BTreeMap<i16, Option<u32>>>::new();
    let mut referenced_types = BTreeSet::new();
    for attribute in attributes {
        assert_attribute_has_safe_missing_value_shape(attribute);
        let relation_oid = json_oid(attribute, "attrelid");
        let number = attribute["attnum"]
            .as_i64()
            .and_then(|value| i16::try_from(value).ok())
            .unwrap_or_else(|| panic!("relation capture has malformed attribute number"));
        let dropped = attribute
            .get("attisdropped")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or_else(|| panic!("relation capture has malformed dropped-column flag"));
        let type_oid = if dropped {
            assert_eq!(json_oid_with_zero(attribute, "atttypid"), 0);
            None
        } else {
            let oid = json_oid(attribute, "atttypid");
            referenced_types.insert(oid);
            Some(oid)
        };
        assert!(number > 0 && relation_ids.contains(&relation_oid));
        assert!(
            observed_columns
                .entry(relation_oid)
                .or_default()
                .insert(number, type_oid)
                .is_none()
        );
    }
    for relation in snapshot.relations.values() {
        let observed = observed_columns
            .get(&relation.relation.oid)
            .expect("root has no captured columns");
        for column in &relation.columns {
            let number = column
                .attribute_number()
                .expect("snapshot column has no attribute number");
            assert_eq!(observed.get(&number), Some(&Some(column.type_oid)));
        }
    }

    let indexes = json_rows(capture, "indexes");
    let mut index_ids = BTreeSet::new();
    for index in indexes {
        assert!(relation_ids.contains(&json_oid(index, "indrelid")));
        assert!(index_ids.insert(json_oid(index, "indexrelid")));
    }
    let index_relations = json_rows(capture, "index_relations");
    let captured_index_ids = index_relations
        .iter()
        .map(|row| json_oid(row, "oid"))
        .collect::<BTreeSet<_>>();
    assert_eq!(captured_index_ids, index_ids);
    assert_eq!(captured_index_ids.len(), index_relations.len());
    let index_attributes = json_rows(capture, "index_attributes");
    let mut index_attribute_relations = BTreeSet::new();
    for attribute in index_attributes {
        assert!(!assert_attribute_has_safe_missing_value_shape(attribute));
        let relation_oid = json_oid(attribute, "attrelid");
        assert!(captured_index_ids.contains(&relation_oid));
        assert!(
            attribute["attnum"]
                .as_i64()
                .is_some_and(|number| number > 0)
        );
        if attribute["attisdropped"].as_bool().unwrap_or(false) {
            assert_eq!(json_oid_with_zero(attribute, "atttypid"), 0);
        } else {
            referenced_types.insert(json_oid(attribute, "atttypid"));
        }
        index_attribute_relations.insert(relation_oid);
    }
    assert_eq!(index_attribute_relations, captured_index_ids);

    let constraints = json_rows(capture, "constraints");
    let relation_dependencies = json_rows(capture, "relation_dependencies");
    let foreign_key_index_ids = constraints
        .iter()
        .filter(|row| row.get("contype").and_then(serde_json::Value::as_str) == Some("f"))
        .map(|row| json_oid(row, "conindid"))
        .collect::<BTreeSet<_>>();
    let dependency_indexes = json_rows(capture, "dependency_indexes");
    let dependency_index_ids = dependency_indexes
        .iter()
        .map(|row| json_oid(row, "indexrelid"))
        .collect::<BTreeSet<_>>();
    assert_eq!(dependency_index_ids, foreign_key_index_ids);
    for index in dependency_indexes {
        assert!(
            relation_ids.contains(&json_oid(index, "indrelid"))
                || relation_dependencies
                    .iter()
                    .any(|row| json_oid(row, "oid") == json_oid(index, "indrelid"))
        );
    }
    let dependency_index_relations = json_rows(capture, "dependency_index_relations");
    let dependency_index_relation_ids = dependency_index_relations
        .iter()
        .map(|row| json_oid(row, "oid"))
        .collect::<BTreeSet<_>>();
    assert_eq!(dependency_index_relation_ids, foreign_key_index_ids);
    let dependency_index_attributes = json_rows(capture, "dependency_index_attributes");
    let mut dependency_index_attribute_relations = BTreeSet::new();
    for attribute in dependency_index_attributes {
        assert!(!assert_attribute_has_safe_missing_value_shape(attribute));
        let relation_oid = json_oid(attribute, "attrelid");
        assert!(dependency_index_relation_ids.contains(&relation_oid));
        assert!(
            attribute["attnum"]
                .as_i64()
                .is_some_and(|number| number > 0)
        );
        if attribute["attisdropped"].as_bool().unwrap_or(false) {
            assert_eq!(json_oid_with_zero(attribute, "atttypid"), 0);
        } else {
            referenced_types.insert(json_oid(attribute, "atttypid"));
        }
        dependency_index_attribute_relations.insert(relation_oid);
    }
    assert_eq!(dependency_index_attribute_relations, foreign_key_index_ids);

    let dependency_constraints = json_rows(capture, "dependency_constraints");
    let mut supporting_constraint_ids = BTreeSet::new();
    for constraint in dependency_constraints {
        assert!(matches!(
            constraint
                .get("contype")
                .and_then(serde_json::Value::as_str),
            Some("p" | "u")
        ));
        let index_oid = json_oid(constraint, "conindid");
        let constraint_relation = json_oid(constraint, "conrelid");
        assert!(foreign_key_index_ids.contains(&index_oid));
        let index = dependency_indexes
            .iter()
            .find(|row| json_oid(row, "indexrelid") == index_oid)
            .expect("supporting constraint index was not captured");
        assert_eq!(json_oid(index, "indrelid"), constraint_relation);
        assert!(supporting_constraint_ids.insert(json_oid(constraint, "oid")));
    }

    let dependency_attributes = json_rows(capture, "dependency_attributes");
    let dependency_relation_ids = relation_dependencies
        .iter()
        .map(|row| json_oid(row, "oid"))
        .collect::<BTreeSet<_>>();
    assert_eq!(dependency_relation_ids.len(), relation_dependencies.len());
    for attribute in dependency_attributes {
        assert_attribute_has_safe_missing_value_shape(attribute);
        assert!(dependency_relation_ids.contains(&json_oid(attribute, "attrelid")));
        if attribute["attisdropped"].as_bool().unwrap_or(false) {
            assert_eq!(json_oid_with_zero(attribute, "atttypid"), 0);
        } else {
            referenced_types.insert(json_oid(attribute, "atttypid"));
        }
    }
    let types = json_rows(capture, "types");
    let type_ids = types
        .iter()
        .map(|row| json_oid(row, "oid"))
        .collect::<BTreeSet<_>>();
    assert_eq!(type_ids, referenced_types);
    assert_eq!(type_ids.len(), types.len());
    let enum_type_ids = types
        .iter()
        .filter(|row| row.get("typtype").and_then(serde_json::Value::as_str) == Some("e"))
        .map(|row| json_oid(row, "oid"))
        .collect::<BTreeSet<_>>();
    let enum_labels = json_rows(capture, "enums");
    let labeled_enum_ids = enum_labels
        .iter()
        .map(|row| json_oid(row, "enumtypid"))
        .collect::<BTreeSet<_>>();
    assert_eq!(labeled_enum_ids, enum_type_ids);

    let namespaces = json_rows(capture, "namespaces");
    let namespace_ids = namespaces
        .iter()
        .map(|row| json_oid(row, "oid"))
        .collect::<BTreeSet<_>>();
    let mut referenced_namespaces = relations
        .iter()
        .chain(index_relations)
        .chain(dependency_index_relations)
        .chain(relation_dependencies)
        .map(|row| json_oid(row, "relnamespace"))
        .collect::<BTreeSet<_>>();
    referenced_namespaces.extend(types.iter().map(|row| json_oid(row, "typnamespace")));
    assert_eq!(namespace_ids, referenced_namespaces);
    assert_eq!(namespace_ids.len(), namespaces.len());
}

#[test]
fn fixed_catalog_queries_parse_for_each_supported_major() {
    for major in [12, 18] {
        let registry = super::registry::ReadRegistry::for_major(major).unwrap();
        for index in 0..9 {
            let query = super::catalog_query(&registry, index);
            assert!(!query.is_empty(), "missing PG{major} catalog query {index}");
            assert!(
                pg_raw_parse::parse(query).is_ok(),
                "fixed PG{major} catalog query {index} does not parse"
            );
        }
    }
}

#[tokio::test]
async fn strict_read_catalog_gate_proves_ordinary_table_and_denies_role_or_visible_overload() {
    use crate::{
        backend::{ConnectReason, Oids, Server, ServerOptions, pool::Address},
        frontend::{
            read_policy::transaction::ReadTxState,
            read_policy::{ProcessPolicy, QueryPolicy},
        },
    };

    let raw = std::env::var("PGDOG_STRICT_TEST_CONFIG")
        .expect("owned strict-read core fixture is required; this test must not skip");
    let config: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(config["host"], "127.0.0.1");
    let app_password =
        std::fs::read_to_string(config["application_password_file"].as_str().unwrap()).unwrap();
    let owner_password =
        std::fs::read_to_string(config["owner_password_file"].as_str().unwrap()).unwrap();
    async fn connect(config: &serde_json::Value, user: &str, password: &str) -> Server {
        let address = Address {
            host: "127.0.0.1".into(),
            port: u16::try_from(config["postgres_port"].as_u64().unwrap()).unwrap(),
            user: user.into(),
            database_name: config["database"].as_str().unwrap().into(),
            passwords: vec![password.trim().to_owned().into()],
            ..Default::default()
        };
        Server::connect(
            &address,
            ServerOptions::default(),
            ConnectReason::Other,
            Oids::new(&Default::default()),
        )
        .await
        .unwrap()
    }
    let policy = ProcessPolicy::load(
        QueryPolicy::StrictRead,
        Some(std::path::Path::new(
            config["read_policy_file"].as_str().unwrap(),
        )),
    )
    .unwrap();

    async fn prove(
        server: &mut crate::backend::Server,
        policy: &ProcessPolicy,
        sql: &str,
        generation: u64,
    ) -> bool {
        use crate::frontend::read_policy::{
            ReadIsolation, admit_sql, transaction::ReadTransaction,
        };
        server.enable_strict_protocol().unwrap();
        let admitted = match admit_sql(sql) {
            Ok(admitted) => admitted,
            Err(_) => return false,
        };
        let mut transaction = ReadTransaction::default();
        if transaction
            .start(server, false, ReadIsolation::ReadCommitted)
            .await
            .is_err()
        {
            return false;
        }
        let verified = match super::CatalogSnapshot::load_for_policy(
            server,
            &admitted.catalog,
            generation,
            policy,
            "app",
        )
        .await
        {
            Ok(snapshot) => {
                let roots = snapshot
                    .relations
                    .values()
                    .map(|entry| entry.relation.oid)
                    .collect::<Vec<_>>();
                let major = snapshot.registry.major();
                match super::relation_capture::capture(server, &roots, major).await {
                    Ok(capture) => {
                        assert_relation_capture_inventory(&snapshot, &capture, major);
                        if sql == "SELECT strict_item_id FROM public.strict_extended" {
                            assert_eq!(capture["roots"].as_array().map(Vec::len), Some(1));
                            assert_eq!(
                                capture["dependency_constraints"].as_array().map(Vec::len),
                                Some(1)
                            );
                            assert_eq!(capture["dependency_constraints"][0]["contype"], "p");
                            let target_oid =
                                json_oid(&capture["dependency_constraints"][0], "conrelid");
                            assert!(
                                json_rows(&capture, "relation_dependencies")
                                    .iter()
                                    .any(|row| json_oid(row, "oid") == target_oid)
                            );
                        }
                        match snapshot.identity(policy, "app", generation) {
                            Ok(identity) => {
                                match super::verify_parse(
                                    policy,
                                    &admitted,
                                    &snapshot,
                                    identity.clone(),
                                    &[],
                                ) {
                                    Ok(proof) => {
                                        let wrong_major = if identity.backend_server_major == 12 {
                                            18
                                        } else {
                                            12
                                        };
                                        let mut mismatched_identity = identity.clone();
                                        mismatched_identity.backend_server_major = wrong_major;
                                        proof.matches_identity(&identity)
                                            && !proof.matches_identity(&mismatched_identity)
                                            && super::verify_parse(
                                                policy,
                                                &admitted,
                                                &snapshot,
                                                mismatched_identity,
                                                &[],
                                            )
                                            .is_err()
                                    }
                                    Err(error) => {
                                        eprintln!(
                                            "strict catalog verify denied: {}",
                                            error.reason()
                                        );
                                        false
                                    }
                                }
                            }
                            Err(error) => {
                                eprintln!("strict catalog identity denied: {}", error.reason());
                                false
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("strict relation capture denied: {}", error.reason());
                        false
                    }
                }
            }
            Err(error) => {
                eprintln!("strict catalog load denied: {}", error.reason());
                false
            }
        };
        let finish = transaction.finish(server, false).await;
        verified && finish.is_ok() && transaction.state == ReadTxState::Idle
    }

    async fn catalog_rejects(
        server: &mut crate::backend::Server,
        sql: &str,
        generation: u64,
    ) -> bool {
        use crate::frontend::read_policy::{
            ReadIsolation, admit_sql, transaction::ReadTransaction,
        };
        server.enable_strict_protocol().unwrap();
        let admitted = match admit_sql(sql) {
            Ok(admitted) => admitted,
            Err(_) => return false,
        };
        let mut transaction = ReadTransaction::default();
        if transaction
            .start(server, false, ReadIsolation::ReadCommitted)
            .await
            .is_err()
        {
            return false;
        }
        let rejected = super::CatalogSnapshot::load(server, &admitted.catalog, generation)
            .await
            .is_err();
        let finish = transaction.finish(server, false).await;
        rejected && finish.is_ok() && transaction.state == ReadTxState::Idle
    }

    // The normal manifest table and reviewed PG18 catalog should produce a
    // proof. This gate runs before the strict query engine forwards Parse/Query.
    let mut app = connect(&config, "strict_app", &app_password).await;
    assert!(
        prove(
            &mut app,
            &policy,
            "SELECT id, payload, texts, numbers, dates, integers, kind FROM public.strict_extended",
            1
        )
        .await,
        "full proof must allow JSONB, reviewed arrays, enum and a checked GIN/constraint table"
    );
    assert!(
        prove(
            &mut app,
            &policy,
            "SELECT strict_item_id FROM public.strict_extended",
            1
        )
        .await,
        "a single-root FK read must capture its distinct referenced PK constraint"
    );
    assert!(
        prove(
            &mut app,
            &policy,
            "SELECT id, value FROM public.strict_items",
            1
        )
        .await
    );

    // Install a same-name visible overload in the disposable fixture. The
    // query is rejected during catalog proof; it is never sent as client SQL.
    let mut owner = connect(&config, "fixture_owner", &owner_password).await;
    owner.execute_checked(
        "CREATE FUNCTION public.sum(integer) RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT $1'",
    ).await.unwrap();
    let mut app = connect(&config, "strict_app", &app_password).await;
    let overload_denied = !prove(&mut app, &policy, "SELECT sum(1)", 2).await;
    owner
        .execute_checked("DROP FUNCTION public.sum(integer)")
        .await
        .unwrap();

    // A role capability change also invalidates the proof even though the
    // SQL statement itself is ordinary SELECT.
    owner
        .execute_checked("ALTER ROLE strict_app CREATEDB")
        .await
        .unwrap();
    let mut app = connect(&config, "strict_app", &app_password).await;
    let role_denied = !prove(&mut app, &policy, "SELECT id FROM public.strict_items", 3).await;
    owner
        .execute_checked("ALTER ROLE strict_app NOCREATEDB")
        .await
        .unwrap();

    // The catalog gate also rejects indirect relation dependencies before the
    // user's SELECT can be forwarded: views, RLS, custom column types and
    // expression indexes are outside the strict v1 proof boundary.
    owner
        .execute_checked(
            "CREATE VIEW public.strict_view AS SELECT id, value FROM public.strict_items",
        )
        .await
        .unwrap();
    let mut app = connect(&config, "strict_app", &app_password).await;
    let view_denied =
        catalog_rejects(&mut app, "SELECT id, value FROM public.strict_view", 4).await;
    owner
        .execute_checked("DROP VIEW public.strict_view")
        .await
        .unwrap();

    owner.execute_checked(
        "CREATE TABLE public.strict_rls_items (id integer); ALTER TABLE public.strict_rls_items ENABLE ROW LEVEL SECURITY; GRANT SELECT ON public.strict_rls_items TO strict_app",
    ).await.unwrap();
    let mut app = connect(&config, "strict_app", &app_password).await;
    let rls_denied = catalog_rejects(&mut app, "SELECT id FROM public.strict_rls_items", 5).await;
    owner
        .execute_checked("DROP TABLE public.strict_rls_items")
        .await
        .unwrap();

    owner.execute_checked(
        "CREATE TYPE public.strict_custom_type AS (item integer); CREATE TABLE public.strict_custom_items (id public.strict_custom_type); GRANT SELECT ON public.strict_custom_items TO strict_app",
    ).await.unwrap();
    let mut app = connect(&config, "strict_app", &app_password).await;
    let custom_type_denied =
        catalog_rejects(&mut app, "SELECT id FROM public.strict_custom_items", 6).await;
    owner
        .execute_checked(
            "DROP TABLE public.strict_custom_items; DROP TYPE public.strict_custom_type",
        )
        .await
        .unwrap();

    owner.execute_checked(
        "CREATE INDEX strict_items_lower_value ON public.strict_items ((pg_catalog.lower(value)))",
    ).await.unwrap();
    let mut app = connect(&config, "strict_app", &app_password).await;
    let expression_index_denied =
        catalog_rejects(&mut app, "SELECT id FROM public.strict_items", 7).await;
    owner
        .execute_checked("DROP INDEX public.strict_items_lower_value")
        .await
        .unwrap();

    assert!(
        overload_denied,
        "visible user overload was not denied before client Parse"
    );
    assert!(
        role_denied,
        "role with database-creation capability received a proof"
    );
    assert!(
        view_denied,
        "view relation was not denied before client Parse"
    );
    assert!(rls_denied, "RLS table was not denied before client Parse");
    assert!(
        custom_type_denied,
        "custom column type was not denied before client Parse"
    );
    assert!(
        expression_index_denied,
        "expression index was not denied before client Parse"
    );
}

fn base_table() -> RelationRow {
    RelationRow {
        valid: true,
        oid: 16_384,
        schema: "app".into(),
        name: "items".into(),
        kind: "r".into(),
        persistence: "p".into(),
        owner_oid: 16_385,
        row_security: false,
        force_row_security: false,
        has_rules: false,
        is_partition: false,
        has_inheritance: false,
        namespace_can_create: false,
        access_method: "heap".into(),
    }
}

#[test]
fn ordinary_persistent_heap_table_without_hidden_dependencies_is_supported() {
    assert!(base_table().is_supported_base_table());
}

#[test]
fn views_foreign_temp_partitioned_inherited_and_rls_tables_are_rejected() {
    for mutate in [
        |r: &mut RelationRow| r.kind = "v".into(),
        |r: &mut RelationRow| r.kind = "f".into(),
        |r: &mut RelationRow| r.persistence = "t".into(),
        |r: &mut RelationRow| r.is_partition = true,
        |r: &mut RelationRow| r.has_inheritance = true,
        |r: &mut RelationRow| r.row_security = true,
        |r: &mut RelationRow| r.force_row_security = true,
        |r: &mut RelationRow| r.has_rules = true,
        |r: &mut RelationRow| r.namespace_can_create = true,
        |r: &mut RelationRow| r.access_method = "custom".into(),
    ] as [fn(&mut RelationRow); 10]
    {
        let mut row = base_table();
        mutate(&mut row);
        assert!(
            !row.is_supported_base_table(),
            "accepted unsafe relation: {row:?}"
        );
    }
}

#[test]
fn strict_read_rejects_roles_with_write_or_security_escape_capabilities() {
    let safe = RoleRow {
        valid: true,
        oid: 16_386,
        superuser: false,
        create_role: false,
        create_database: false,
        replication: false,
        bypass_rls: false,
        inherit: true,
        has_memberships: false,
    };
    assert!(safe.is_safe_application_role());
    for mutate in [
        |r: &mut RoleRow| r.superuser = true,
        |r: &mut RoleRow| r.create_role = true,
        |r: &mut RoleRow| r.create_database = true,
        |r: &mut RoleRow| r.replication = true,
        |r: &mut RoleRow| r.bypass_rls = true,
        |r: &mut RoleRow| r.has_memberships = true,
    ] as [fn(&mut RoleRow); 6]
    {
        let mut row = safe.clone();
        mutate(&mut row);
        assert!(
            !row.is_safe_application_role(),
            "accepted unsafe role: {row:?}"
        );
    }
}

#[test]
fn malformed_catalog_rows_are_never_treated_as_zero_or_absent_metadata() {
    let relation = RelationRow::from(crate::net::messages::DataRow::new());
    assert!(!relation.valid);
    assert!(!relation.is_supported_base_table());
    let role = RoleRow::from(crate::net::messages::DataRow::new());
    assert!(!role.valid);
    assert!(!role.is_safe_application_role());
}

#[tokio::test]
#[ignore = "private owned loopback diagnosis only"]
async fn owned_full_read_gate_diagnostic() {
    use crate::backend::{ConnectReason, Oids, Server, ServerOptions, pool::Address};
    use crate::frontend::read_policy::{
        ProcessPolicy, QueryPolicy, ReadIsolation, admit_sql, transaction::ReadTransaction,
    };
    let config: serde_json::Value =
        serde_json::from_str(&std::env::var("PGDOG_STRICT_TEST_CONFIG").unwrap()).unwrap();
    assert_eq!(config["host"], "127.0.0.1");
    let password =
        std::fs::read_to_string(config["application_password_file"].as_str().unwrap()).unwrap();
    let address = Address {
        host: "127.0.0.1".into(),
        port: config["postgres_port"].as_u64().unwrap() as u16,
        user: "strict_app".into(),
        database_name: "app".into(),
        passwords: vec![password.trim().to_owned().into()],
        ..Default::default()
    };
    let mut server = Server::connect(
        &address,
        ServerOptions::default(),
        ConnectReason::Other,
        Oids::new(&Default::default()),
    )
    .await
    .unwrap();
    server.enable_strict_protocol().unwrap();
    let policy = ProcessPolicy::load(
        QueryPolicy::StrictRead,
        Some(std::path::Path::new(
            config["read_policy_file"].as_str().unwrap(),
        )),
    )
    .unwrap();
    let admitted = admit_sql("SELECT * FROM public.t0001 LIMIT 1").unwrap();
    let mut tx = ReadTransaction::default();
    tx.start(&mut server, false, ReadIsolation::ReadCommitted)
        .await
        .unwrap();
    let snapshot =
        super::CatalogSnapshot::load_for_policy(&mut server, &admitted.catalog, 1, &policy, "app")
            .await
            .expect("owned full catalog must load");
    let identity = snapshot
        .identity(&policy, "app", 1)
        .expect("owned full catalog identity");
    super::verify_parse(&policy, &admitted, &snapshot, identity, &[])
        .expect("owned full parse proof");
    tx.finish(&mut server, false).await.unwrap();
}
