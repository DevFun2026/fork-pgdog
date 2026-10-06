use super::{rows::RelationRow, rows::RoleRow};

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
        let verified =
            match super::CatalogSnapshot::load(server, &admitted.catalog, generation).await {
                Ok(snapshot) => match snapshot.identity(policy, "app", generation) {
                    Ok(identity) => {
                        match super::verify_parse(policy, &admitted, &snapshot, identity, &[]) {
                            Ok(_) => true,
                            Err(error) => {
                                eprintln!("strict catalog verify denied: {}", error.reason());
                                false
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("strict catalog identity denied: {}", error.reason());
                        false
                    }
                },
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
