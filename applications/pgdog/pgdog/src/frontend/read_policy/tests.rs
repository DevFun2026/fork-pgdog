use super::*;

#[test]
fn strict_read_simple_case_requires_implicit_equality_proof() {
    let admitted =
        admit_sql("SELECT CASE 'a'::varchar WHEN 'a'::varchar THEN 1 ELSE 2 END").unwrap();
    assert!(admitted.catalog.operators.contains("\"=\""));
}
use crate::net::{FromBytes, Message, Prepare, ProtocolMessage};

fn manifest(db_name: &str, relation: &str) -> String {
    format!(
        "schema_revision = \"rev-1\"\n\n[[databases]]\nname = {db_name:?}\nrelations = [{relation:?}]\n"
    )
}

#[test]
fn admission_accepts_read_queries_from_the_postgres_parser() {
    for sql in [
        "SELECT 1",
        "SELECT CASE WHEN 1 = 1 THEN 'DELETE FROM x' ELSE 'x' END",
        "SELECT COALESCE(NULLIF(1, 2), 3)",
        "SELECT 1 UNION SELECT 2",
        "SELECT count(*) FROM app.orders",
        "WITH x AS (SELECT 1) SELECT * FROM x",
        "SELECT (SELECT 1)",
    ] {
        assert!(admit_sql(sql).is_ok(), "should admit {sql:?}");
    }
}

#[test]
fn admission_denies_writes_and_hidden_write_forms() {
    assert_eq!(
        admit_sql("SELECT 1; DELETE FROM app.orders")
            .unwrap_err()
            .sqlstate(),
        "25006"
    );
    for sql in [
        "SELECT 1 INTO app.copy_of_orders",
        "SELECT * FROM app.orders FOR UPDATE",
        "WITH x AS (DELETE FROM app.orders RETURNING *) SELECT * FROM x",
        "SELECT '/* DELETE FROM app.orders */' /* UPDATE x */",
    ] {
        // Quoted/commented tokens remain inert; the first three are write forms.
        let result = admit_sql(sql);
        if sql.starts_with("SELECT '") {
            assert!(result.is_ok(), "literal/comment should be inert: {sql}");
        } else {
            assert_eq!(result.unwrap_err().sqlstate(), "25006", "{sql}");
        }
    }
}

#[test]
fn admission_rejects_unknown_top_level_statements_and_maps_errors() {
    assert_eq!(admit_sql("SELECT FROM").unwrap_err().sqlstate(), "42601");
    assert_eq!(
        admit_sql("EXPLAIN SELECT 1").unwrap_err().sqlstate(),
        "0A000"
    );
    assert_eq!(
        admit_sql("COPY app.orders TO STDOUT")
            .unwrap_err()
            .sqlstate(),
        "0A000"
    );
    assert_eq!(
        admit_sql("INSERT INTO app.orders VALUES (1)")
            .unwrap_err()
            .sqlstate(),
        "25006"
    );
}

#[test]
fn admission_records_catalog_references_and_original_sql_fingerprint() {
    let sql = "SELECT count(o.id), $1::int4 FROM app.orders AS o WHERE o.id = $2";
    let admitted = admit_sql(sql).unwrap();
    assert_eq!(admitted.original_sql, sql);
    assert_eq!(
        admitted.catalog.relations,
        ["\"app\".\"orders\"".to_owned()].into()
    );
    assert!(admitted.catalog.functions.contains("\"count\""));
    assert!(admitted.catalog.operators.contains("\"=\""));
    assert!(admitted.catalog.types.contains("\"int4\""));
    assert!(admitted.catalog.parameter_refs.contains(&1));
    assert!(admitted.catalog.parameter_refs.contains(&2));
    assert!(admitted.catalog.parameter_type_requirements[&1].contains("\"int4\""));
    assert_ne!(admitted.fingerprint, [0; 32]);

    let nullif = admit_sql("SELECT NULLIF(1, 2)").unwrap();
    assert!(nullif.catalog.operators.contains("\"=\""));
    assert!(!nullif.catalog.operators.contains("="));
}

#[test]
fn admission_tracks_cte_names_per_statement_scope() {
    let admitted =
        admit_sql("WITH x AS (SELECT * FROM app.orders) SELECT * FROM x; SELECT * FROM x").unwrap();
    assert!(admitted.catalog.cte_references.contains("\"x\""));
    assert!(admitted.catalog.relations.contains("\"app\".\"orders\""));
    assert!(admitted.catalog.relations.contains("\"x\""));
}

#[test]
fn admission_denies_forward_and_recursive_cte_reference_scopes() {
    for sql in [
        "WITH first_cte AS (SELECT * FROM later_cte), later_cte AS (SELECT 1) SELECT * FROM first_cte",
        "WITH RECURSIVE tree AS (SELECT * FROM tree) SELECT * FROM tree",
    ] {
        assert_eq!(admit_sql(sql).unwrap_err().sqlstate(), "0A000", "{sql}");
    }
}

#[test]
fn admission_denies_mixed_transaction_control_batches_and_chain() {
    for sql in [
        "BEGIN READ ONLY; SELECT 1",
        "SELECT 1; COMMIT",
        "COMMIT AND CHAIN",
        "ROLLBACK AND CHAIN",
    ] {
        assert_eq!(admit_sql(sql).unwrap_err().sqlstate(), "0A000", "{sql}");
    }
}

#[test]
fn admission_denies_unreviewed_code_and_type_surfaces() {
    for sql in [
        "SELECT public.count(*)",
        "SELECT public.safe_looking_function(1)",
        "SELECT json_build_object('a', 1)",
        "SELECT sum(x) OVER () FROM app.orders",
        "SELECT ARRAY[1, 2]",
        "SELECT (1, 2)",
        "SELECT 1::public.my_domain",
        "SELECT 1::int4[]",
        "SELECT NULL::app.orders.id%TYPE",
        "SELECT 1 OPERATOR(public.=) 1",
    ] {
        assert_eq!(admit_sql(sql).unwrap_err().sqlstate(), "0A000", "{sql}");
    }
}

#[test]
fn admission_recognizes_read_only_control_and_rejects_empty_parse() {
    assert!(matches!(
        admit_sql("SHOW default_transaction_read_only")
            .unwrap()
            .actions
            .as_slice(),
        [ReadAction::ShowReadOnly]
    ));
    assert!(matches!(
        admit_sql("BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY")
            .unwrap()
            .actions
            .as_slice(),
        [ReadAction::Begin(ReadIsolation::Serializable)]
    ));
    assert!(matches!(
        admit_sql("COMMIT").unwrap().actions.as_slice(),
        [ReadAction::Commit]
    ));
    assert_eq!(admit_sql("").unwrap_err().sqlstate(), "0A000");
}

#[test]
fn admission_enforces_policy_resource_limits() {
    let at_statement_limit = vec!["SELECT 1"; 1_024].join(";");
    let over_statement_limit = vec!["SELECT 1"; 1_025].join(";");
    assert_eq!(admit_sql(&at_statement_limit).unwrap().actions.len(), 1_024);
    assert_eq!(
        admit_sql(&over_statement_limit).unwrap_err().sqlstate(),
        "0A000"
    );
    assert!(!super::admission::policy_limit_exceeded(65_536, 65_536));
    assert!(super::admission::policy_limit_exceeded(65_537, 65_536));
    assert!(!super::admission::policy_limit_exceeded(128, 128));
    assert!(super::admission::policy_limit_exceeded(129, 128));
}

#[test]
fn admission_rejects_overlarge_sql_before_parsing() {
    let too_large = format!("NOT_SQL {}", "x".repeat(super::admission::MAX_SQL_BYTES));
    assert_eq!(admit_sql(&too_large).unwrap_err().sqlstate(), "0A000");
}

#[test]
fn admission_bounds_nested_case_ast_depth() {
    let nested_case = format!(
        "SELECT {}1{}",
        "CASE WHEN TRUE THEN ".repeat(129),
        " END".repeat(129)
    );
    assert_eq!(admit_sql(&nested_case).unwrap_err().sqlstate(), "0A000");

    let nested_union = format!("SELECT 1{}", " UNION SELECT 1".repeat(129));
    assert_eq!(admit_sql(&nested_union).unwrap_err().sqlstate(), "0A000");
}

#[test]
fn admission_denies_selects_with_unknown_nodes() {
    // Set-returning functions are opaque dependencies and do not inherit the
    // SELECT root's allow decision.
    assert_eq!(
        admit_sql("SELECT * FROM generate_series(1, 3)")
            .unwrap_err()
            .sqlstate(),
        "0A000"
    );
}

#[test]
fn admission_message_gate_rejects_sql_less_escape_packets() {
    for code in ['F', 'd', 'c', 'f', 'X', 'Z', 'r'] {
        let packet = Message::new(bytes::Bytes::from(vec![code as u8, 0, 0, 0, 4]));
        assert_eq!(
            gate_message(&ProtocolMessage::Other(packet))
                .unwrap_err()
                .sqlstate(),
            "08P01"
        );
    }

    for code in ['d', 'c', 'f', 'F'] {
        let frame = match code {
            'f' => bytes::Bytes::from_static(b"f\0\0\0\x05\0"),
            _ => bytes::Bytes::from(vec![code as u8, 0, 0, 0, 4]),
        };
        let parsed = ProtocolMessage::from_bytes(frame).unwrap();
        assert_eq!(gate_message(&parsed).unwrap_err().sqlstate(), "08P01");
    }
    assert_eq!(
        gate_message(&ProtocolMessage::EnsurePrepared(Prepare::new(
            "internal", "SELECT 1"
        )))
        .unwrap_err()
        .sqlstate(),
        "08P01"
    );
    assert_eq!(
        gate_message(&ProtocolMessage::PrepareFromClient(Prepare::new(
            "client", "SELECT 1"
        )))
        .unwrap_err()
        .sqlstate(),
        "08P01"
    );
}

#[test]
fn manifest_contract_rejects_ambiguous_or_executable_entries() {
    let good = ReadManifest::parse(manifest("sales", "app.orders").as_bytes()).unwrap();
    assert_eq!(good.schema_revision(), "rev-1");
    assert_eq!(good.databases()[0].name(), "sales");
    assert_eq!(good.databases()[0].relations()[0].schema(), "app");
    assert_eq!(good.databases()[0].relations()[0].name(), "orders");

    let quoted =
        ReadManifest::parse(manifest("\"Sales DB\"", "\"app\".\"Order Items\"").as_bytes())
            .unwrap();
    assert_eq!(quoted.databases()[0].name(), "Sales DB");
    assert_eq!(quoted.databases()[0].relations()[0].schema(), "app");
    assert_eq!(quoted.databases()[0].relations()[0].name(), "Order Items");

    let quoted_dot =
        ReadManifest::parse(manifest("\"sales.eu\"", "\"schema.name\".\"table.name\"").as_bytes())
            .unwrap();
    assert_eq!(quoted_dot.databases()[0].name(), "sales.eu");
    assert_eq!(
        quoted_dot.databases()[0].relations()[0].schema(),
        "schema.name"
    );
    assert_eq!(
        quoted_dot.databases()[0].relations()[0].name(),
        "table.name"
    );

    let invalid = vec![
        manifest("sales", "app.*"),
        manifest("sales", "app.orders; DELETE FROM users"),
        "schema_revision = \" \"\n[[databases]]\nname=\"sales\"\nrelations=[\"orders\"]".to_owned(),
        "schema_revision = \"r\"\nunknown = true\n[[databases]]\nname=\"sales\"\nrelations=[\"orders\"]".to_owned(),
        "schema_revision = \"r\"\n[[databases]]\nname=\"sales\"\nrelations=[\"orders\", \"orders\"]".to_owned(),
        "schema_revision = \"r\"\n[[databases]]\nname=\"sales\"\nrelations=[\"orders\"]\n[[databases]]\nname=\"sales\"\nrelations=[\"other\"]".to_owned(),
    ];
    for source in invalid {
        assert!(ReadManifest::parse(source.as_bytes()).is_err(), "{source}");
    }
}

#[test]
fn process_policy_is_immutable_and_requires_a_manifest_in_strict_mode() {
    assert_eq!(QueryPolicy::default(), QueryPolicy::Unrestricted);
    assert_eq!(
        ProcessPolicy::load(QueryPolicy::StrictRead, None)
            .unwrap_err()
            .sqlstate(),
        "22023"
    );
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp.path(), manifest("sales", "app.orders")).unwrap();
    let policy = ProcessPolicy::load(QueryPolicy::StrictRead, Some(temp.path())).unwrap();
    assert_eq!(policy.mode(), QueryPolicy::StrictRead);
    assert!(policy.manifest().is_some());
    assert_ne!(policy.digest().0, [0; 32]);
}

#[test]
fn strict_process_policy_rejects_dry_run_and_user_replication_overrides() {
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp.path(), manifest("sales", "app.orders")).unwrap();
    let policy = ProcessPolicy::load(QueryPolicy::StrictRead, Some(temp.path())).unwrap();

    let mut config = crate::config::ConfigAndUsers::default();
    assert!(policy.validate_config(&config).is_ok());
    config.config.general.dry_run = true;
    assert_eq!(
        policy.validate_config(&config).unwrap_err().sqlstate(),
        "22023"
    );

    let mut config = crate::config::ConfigAndUsers::default();
    config.users.users.push(crate::config::User {
        name: "client".to_owned(),
        replication_mode: true,
        ..Default::default()
    });
    assert_eq!(
        policy.validate_config(&config).unwrap_err().sqlstate(),
        "22023"
    );
}

#[test]
fn strict_read_rejects_background_schema_and_auto_discovery_execution() {
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp.path(), manifest("sales", "app.orders")).unwrap();
    let policy = ProcessPolicy::load(QueryPolicy::StrictRead, Some(temp.path())).unwrap();
    let mut config = crate::config::ConfigAndUsers::default();
    config.config.general.load_schema = pgdog_config::LoadSchema::On;
    assert!(policy.validate_config(&config).is_err());
    config.config.general.load_schema = pgdog_config::LoadSchema::Auto;
    config.config.general.canonicalize_type_information = true;
    assert!(policy.validate_config(&config).is_err());
    config.config.general.canonicalize_type_information = false;
    config.config.databases.push(crate::config::Database {
        role: crate::config::Role::Auto,
        ..Default::default()
    });
    assert!(policy.validate_config(&config).is_err());
    config.config.databases.clear();
    config.users.users.push(crate::config::User {
        schema_admin: true,
        ..Default::default()
    });
    assert!(policy.validate_config(&config).is_err());
}

#[test]
fn strict_read_accepts_primary_unsharded_database_and_rejects_extra_shards() {
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp.path(), manifest("sales", "app.orders")).unwrap();
    let policy = ProcessPolicy::load(QueryPolicy::StrictRead, Some(temp.path())).unwrap();
    let mut config = crate::config::ConfigAndUsers::default();
    config.config.databases.push(crate::config::Database {
        name: "sales".into(),
        role: crate::config::Role::Primary,
        shard: 0,
        ..Default::default()
    });
    assert!(
        policy.validate_config(&config).is_ok(),
        "ordinary single-primary deployment must be supported"
    );
    config.config.databases[0].shard = 1;
    assert!(policy.validate_config(&config).is_err());
    config.config.databases.push(crate::config::Database {
        name: "sales".into(),
        role: crate::config::Role::Primary,
        shard: 0,
        ..Default::default()
    });
    assert!(policy.validate_config(&config).is_err());
}
