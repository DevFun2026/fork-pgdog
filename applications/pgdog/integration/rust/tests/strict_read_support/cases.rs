use super::{connect, fixture};
use tokio_postgres::Client;
use uuid::Uuid;

#[derive(Debug)]
struct Snapshot {
    rows: i64,
    sequence_value: i64,
    sequence_called: bool,
    schema_relations: i64,
    table_columns: i64,
}

async fn snapshot(client: &Client) -> Snapshot {
    let row = client.query_one(
        "SELECT (SELECT count(*) FROM public.strict_items)::bigint, \
                (SELECT last_value FROM public.strict_items_id_seq)::bigint, \
                (SELECT is_called FROM public.strict_items_id_seq), \
                (SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace \
                 AND relkind IN ('r', 'S', 'v', 'm', 'p'))::bigint, \
                (SELECT count(*) FROM pg_attribute WHERE attrelid = 'public.strict_items'::regclass \
                 AND attnum > 0 AND NOT attisdropped)::bigint",
        &[],
    ).await.expect("fixture snapshot query failed");
    Snapshot {
        rows: row.get(0),
        sequence_value: row.get(1),
        sequence_called: row.get(2),
        schema_relations: row.get(3),
        table_columns: row.get(4),
    }
}

pub async fn assert_app_dml_and_privileges(port: u16) {
    let client = connect(port).await;
    let fixture = fixture();
    let identity = client
        .query_one(
            "SELECT current_user, rolsuper, pg_get_userbyid(c.relowner) \
         FROM pg_roles r CROSS JOIN pg_class c WHERE r.rolname = current_user \
         AND c.oid = 'public.strict_items'::regclass",
            &[],
        )
        .await
        .expect("role identity query failed");
    let current_user: String = identity.get(0);
    let is_superuser: bool = identity.get(1);
    let table_owner: String = identity.get(2);
    assert_eq!(current_user, fixture.application_role);
    assert!(!is_superuser, "application role must not be superuser");
    assert_eq!(
        table_owner, fixture.owner_role,
        "application role must not own fixture objects"
    );

    let before = snapshot(&client).await;
    let marker = format!("strict-read-{}", Uuid::new_v4());
    let inserted = client
        .query_one(
            "INSERT INTO public.strict_items(value) VALUES ($1) RETURNING id",
            &[&marker],
        )
        .await
        .expect("DML-capable application INSERT failed");
    let id: i64 = inserted.get(0);
    let after_insert = snapshot(&client).await;
    assert_eq!(
        after_insert.rows,
        before.rows + 1,
        "row snapshot must observe INSERT"
    );
    assert!(
        after_insert.sequence_value > before.sequence_value
            || (!before.sequence_called && after_insert.sequence_called),
        "sequence snapshot must observe nextval"
    );
    assert_eq!(
        (after_insert.schema_relations, after_insert.table_columns),
        (before.schema_relations, before.table_columns),
        "INSERT must not change schema snapshot"
    );

    let changed = format!("{marker}-updated");
    assert_eq!(
        client
            .execute(
                "UPDATE public.strict_items SET value = $1 WHERE id = $2",
                &[&changed, &id]
            )
            .await
            .unwrap(),
        1
    );
    let selected = client
        .query_one(
            "SELECT value FROM public.strict_items WHERE id = $1",
            &[&id],
        )
        .await
        .unwrap();
    let value: String = selected.get(0);
    assert_eq!(value, changed);
    assert_eq!(
        client
            .execute("DELETE FROM public.strict_items WHERE id = $1", &[&id])
            .await
            .unwrap(),
        1
    );
    let after_delete = snapshot(&client).await;
    assert_eq!(
        after_delete.rows, before.rows,
        "row snapshot must observe DELETE"
    );
    assert!(after_delete.sequence_value >= after_insert.sequence_value);
    assert_eq!(
        (after_delete.schema_relations, after_delete.table_columns),
        (before.schema_relations, before.table_columns),
        "DML must not alter schema snapshot"
    );

    assert!(
        client
            .execute(
                "CREATE TABLE public.strict_read_forbidden_create(id integer)",
                &[]
            )
            .await
            .is_err(),
        "application role must not CREATE trusted schema objects"
    );
    assert!(
        client
            .execute(
                "ALTER TABLE public.strict_items ADD COLUMN strict_read_forbidden integer",
                &[]
            )
            .await
            .is_err(),
        "application role must not ALTER trusted schema objects"
    );
    let after_ddl = snapshot(&client).await;
    assert_eq!(
        (after_ddl.schema_relations, after_ddl.table_columns),
        (before.schema_relations, before.table_columns),
        "denied DDL must leave the schema snapshot unchanged"
    );
}

pub async fn strict_simple_select() {
    let fixture = fixture();
    let mut client = super::wire::WireClient::connect(
        (&fixture.host, fixture.read_port),
        &fixture.application_role,
        &fixture.database,
        std::fs::read_to_string(&fixture.application_password_file)
            .expect("app credential file")
            .trim(),
    )
    .await
    .expect("raw PostgreSQL wire startup failed");
    let messages = client
        .query("SELECT 1")
        .await
        .expect("simple SELECT failed");
    if !messages.iter().any(|message| message.code == b'D') {
        let diagnostic = messages
            .iter()
            .find(|message| message.code == b'E')
            .and_then(super::wire::Message::error_message)
            .unwrap_or_else(|| "no ErrorResponse received".to_owned());
        panic!("strict-read must return a DataRow for SELECT 1; server rejected it: {diagnostic}");
    }
    assert!(
        messages.iter().any(|message| message.code == b'Z'),
        "simple query must reach ReadyForQuery"
    );
}

pub async fn strict_simple_insert_is_denied() {
    let fixture = fixture();
    let client = connect(fixture.postgres_port).await;
    let before = snapshot(&client).await;
    drop(client);

    let mut wire = super::wire::WireClient::connect(
        (&fixture.host, fixture.read_port),
        &fixture.application_role,
        &fixture.database,
        std::fs::read_to_string(&fixture.application_password_file)
            .expect("app credential file")
            .trim(),
    )
    .await
    .expect("raw PostgreSQL wire startup failed");
    let messages = wire
        .query("INSERT INTO public.strict_items(value) VALUES ('strict-denied')")
        .await
        .expect("simple Query response failed");
    assert!(
        messages.iter().any(|message| message.code == b'E'),
        "strict-read must return ErrorResponse for INSERT"
    );
    assert!(
        messages.iter().any(|message| message.code == b'Z'),
        "denied simple Query must resynchronize at ReadyForQuery"
    );

    let after = snapshot(&connect(fixture.postgres_port).await).await;
    assert_eq!(
        after.rows, before.rows,
        "denied INSERT must not reach the backend"
    );
    assert_eq!(
        (after.sequence_value, after.sequence_called),
        (before.sequence_value, before.sequence_called),
        "denied INSERT must not consume a sequence value"
    );
    assert_eq!(
        (after.schema_relations, after.table_columns),
        (before.schema_relations, before.table_columns),
        "denied INSERT must not alter schema"
    );
}

pub async fn strict_simple_matrix() {
    let cfg = fixture();
    let mut wire = super::wire::WireClient::connect(
        (&cfg.host, cfg.read_port),
        &cfg.application_role,
        &cfg.database,
        std::fs::read_to_string(&cfg.application_password_file)
            .unwrap()
            .trim(),
    )
    .await
    .unwrap();
    let direct = connect(cfg.postgres_port).await;
    let before = snapshot(&direct).await;
    for sql in [
        "SELECT 1",
        "SELECT 1; SELECT 2",
        "SELECT id, value FROM public.strict_items WHERE id = 1",
        "SELECT count(*) FROM public.strict_items",
        "SELECT sum(id) FROM public.strict_items",
        "SELECT a.id FROM public.strict_items a JOIN public.strict_items b ON a.id = b.id",
        "WITH q AS (SELECT id FROM public.strict_items) SELECT id FROM q",
        "SELECT CASE WHEN 1=1 THEN 3 ELSE 4 END",
        "SELECT COALESCE(NULL::int4, 2)",
        "SELECT $$;DELETE FROM public.strict_items$$",
        "SELECT 'đọc dữ liệu' AS \"Tên\"",
    ] {
        let messages = wire.query(sql).await.unwrap();
        assert!(
            !messages.iter().any(|m| m.code == b'E'),
            "denied approved read {sql}: {:?}",
            messages
        );
        assert_eq!(messages.iter().filter(|m| m.code == b'Z').count(), 1);
        assert_eq!(messages.last().unwrap().payload.as_ref(), b"I");
    }

    // Prove the catalog gate rejects a visible overload before the backend can
    // Parse/execute it. The qualified owner control call demonstrates that the
    // function really would cause a side effect; the client query uses the
    // supported aggregate shape so AST-only admission is not the rejection.
    let owner_password = std::fs::read_to_string(&cfg.owner_password_file)
        .expect("owner credential file")
        .trim()
        .to_owned();
    let (owner, connection) = tokio_postgres::Config::new()
        .host(&cfg.host)
        .port(cfg.postgres_port)
        .user(&cfg.owner_role)
        .password(&owner_password)
        .dbname(&cfg.database)
        .connect(tokio_postgres::NoTls)
        .await
        .expect("fixture owner connection");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let canary_sequence = format!("strict_read_canary_{}", Uuid::new_v4().simple());
    owner
        .batch_execute(&format!(
            "CREATE SEQUENCE public.{canary_sequence}; \
             CREATE FUNCTION public.sum(smallint) RETURNS bigint \
             LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER AS $strict$ \
             BEGIN PERFORM nextval('public.{canary_sequence}'); \
             RAISE EXCEPTION 'strict_read_canary_executed'; END $strict$"
        ))
        .await
        .expect("install side-effecting visible aggregate overload");
    let direct_control = owner
        .query_one("SELECT public.sum(1::smallint)", &[])
        .await
        .expect_err("qualified control call must execute the canary exception");
    let direct_marker = direct_control
        .as_db_error()
        .is_some_and(|error| error.message().contains("strict_read_canary_executed"));
    let direct_sequence_row = owner
        .query_one(
            &format!("SELECT last_value, is_called FROM public.{canary_sequence}"),
            &[],
        )
        .await
        .expect("direct canary sequence snapshot");
    let direct_sequence_state: (i64, bool) =
        (direct_sequence_row.get(0), direct_sequence_row.get(1));

    let canary_result = wire.query("SELECT sum(1::smallint)").await;
    let canary_error = canary_result
        .as_ref()
        .ok()
        .and_then(|messages| messages.iter().find(|message| message.code == b'E'));
    let canary_denied_by_policy = canary_error.is_some_and(|message| {
        if message.error_message().as_deref() != Some("strict-read: unsupported_statement") {
            return false;
        }
        let mut fields = message.payload.iter().copied();
        while let Some(field) = fields.next() {
            if field == 0 {
                break;
            }
            let mut value = Vec::new();
            for byte in fields.by_ref() {
                if byte == 0 {
                    break;
                }
                value.push(byte);
            }
            if field == b'C' {
                return value.as_slice() == b"0A000";
            }
        }
        false
    });
    let endpoint_sequence_row = owner
        .query_one(
            &format!("SELECT last_value, is_called FROM public.{canary_sequence}"),
            &[],
        )
        .await
        .expect("endpoint canary sequence snapshot");
    let endpoint_sequence_state: (i64, bool) =
        (endpoint_sequence_row.get(0), endpoint_sequence_row.get(1));
    owner
        .batch_execute(&format!(
            "DROP FUNCTION public.sum(smallint); DROP SEQUENCE public.{canary_sequence}"
        ))
        .await
        .expect("remove side-effecting overload and canary sequence");

    assert!(
        direct_marker,
        "direct control must execute the function body"
    );
    assert!(
        direct_sequence_state.1,
        "direct control must mutate its sequence"
    );
    assert!(
        canary_denied_by_policy,
        "catalog gate must reject the AST-admissible aggregate candidate set with strict-read unsupported_statement/0A000; got {canary_result:?}"
    );
    assert!(
        endpoint_sequence_state == direct_sequence_state,
        "denied client query must not execute the visible side-effecting overload: before={direct_sequence_state:?} after={endpoint_sequence_state:?}"
    );

    for sql in [
        "INSERT INTO public.strict_items(value) VALUES ('denied')",
        "UPDATE public.strict_items SET value='denied'",
        "DELETE FROM public.strict_items",
        "TRUNCATE public.strict_items",
        "CREATE TABLE public.denied(id int)",
        "DROP TABLE public.strict_items",
        "ALTER TABLE public.strict_items ADD COLUMN denied int",
        "WITH x AS (DELETE FROM public.strict_items RETURNING *) SELECT * FROM x",
        "SELECT 1; INSERT INTO public.strict_items(value) VALUES ('denied')",
        "SELECT * INTO TEMP denied FROM public.strict_items",
        "SELECT * FROM public.strict_items FOR UPDATE",
        "SELECT nextval('public.strict_items_id_seq')",
        "SELECT set_config('transaction_read_only','off',false)",
        "SET transaction_read_only=off",
        "SET ROLE fixture_owner",
        "BEGIN READ WRITE",
        "COMMIT AND CHAIN",
        "COPY public.strict_items TO STDOUT",
        "EXPLAIN ANALYZE SELECT 1",
        "PREPARE denied AS SELECT 1",
        "EXECUTE denied",
    ] {
        let messages = wire.query(sql).await.unwrap();
        assert!(
            messages.iter().any(|m| m.code == b'E'),
            "accepted unsafe SQL {sql}"
        );
        assert!(
            !messages.iter().any(|m| m.code == b'D'),
            "executed part of denied batch {sql}"
        );
        assert_eq!(messages.iter().filter(|m| m.code == b'Z').count(), 1);
        assert_eq!(messages.last().unwrap().payload.as_ref(), b"I");
    }
    let after = snapshot(&direct).await;
    assert_eq!(format!("{before:?}"), format!("{after:?}"));
}

pub async fn strict_driver_prepared_transactions() {
    let cfg = fixture();
    let client = connect(cfg.read_port).await;
    let statement = client
        .prepare("SELECT $1::int4")
        .await
        .expect("Parse+Describe+Sync");
    for expected in [12i32, 34i32] {
        let row = client
            .query_one(&statement, &[&expected])
            .await
            .expect("Bind+Execute+Sync reproof");
        assert_eq!(row.get::<_, i32>(0), expected);
    }
    client.batch_execute("BEGIN").await.unwrap();
    let readonly = client
        .simple_query("SHOW transaction_read_only")
        .await
        .unwrap();
    assert!(readonly.iter().any(|item| matches!(item, tokio_postgres::SimpleQueryMessage::Row(row) if row.get(0) == Some("on"))));
    let error = client
        .batch_execute("DELETE FROM public.strict_items")
        .await
        .expect_err("must reject write");
    assert_eq!(error.code().unwrap().code(), "25006");
    let error = client
        .batch_execute("SELECT 1")
        .await
        .expect_err("failed transaction remains failed");
    assert_eq!(error.code().unwrap().code(), "25P02");
    client.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(
        client
            .query_one(&statement, &[&56i32])
            .await
            .unwrap()
            .get::<_, i32>(0),
        56
    );
}

pub async fn strict_reload_keeps_process_policy_and_manifest() {
    use std::{path::PathBuf, time::Duration};
    struct Restore(Vec<(PathBuf, String)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            for (path, contents) in &self.0 {
                std::fs::write(path, contents).expect("restore owned fixture file");
            }
        }
    }
    let config: serde_json::Value =
        serde_json::from_str(&std::env::var("PGDOG_STRICT_TEST_CONFIG").unwrap()).unwrap();
    let path = PathBuf::from(config["read_config_file"].as_str().unwrap());
    let manifest_path = PathBuf::from(config["read_policy_file"].as_str().unwrap());
    let pid = config["read_pid"].as_u64().expect("runner-owned read PID");
    let original = std::fs::read_to_string(&path).unwrap();
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    let _restore = Restore(vec![
        (path.clone(), original.clone()),
        (manifest_path.clone(), manifest.clone()),
    ]);
    let signal = || {
        assert!(
            std::process::Command::new("kill")
                .args(["-HUP", &pid.to_string()])
                .status()
                .unwrap()
                .success()
        );
    };
    std::fs::write(
        &path,
        original.replace("[general]", "[general]\nquery_log_stdout = true"),
    )
    .unwrap();
    signal();
    let log_path = path.parent().unwrap().join("read.log");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if std::fs::read_to_string(&log_path)
                .unwrap()
                .contains("strict_read_query_logging_forbidden")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("unsafe reload must be observably rejected");
    let cfg = fixture();
    let client = connect(cfg.read_port).await;
    client
        .simple_query("SELECT 1")
        .await
        .expect("previous safe configuration stays usable");
    let denied = client
        .batch_execute("DELETE FROM public.strict_items")
        .await
        .expect_err("reload cannot downgrade read mode");
    assert_eq!(denied.code().unwrap().code(), "25006");

    let owner_password = std::fs::read_to_string(&cfg.owner_password_file).unwrap();
    let (owner, connection) = tokio_postgres::Config::new()
        .host(&cfg.host)
        .port(cfg.postgres_port)
        .user(&cfg.owner_role)
        .password(owner_password.trim())
        .dbname(&cfg.database)
        .connect(tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    owner.batch_execute("CREATE TABLE public.strict_extra(id integer); GRANT SELECT ON public.strict_extra TO strict_app").await.unwrap();
    std::fs::write(&path, &original).unwrap();
    std::fs::write(
        &manifest_path,
        manifest.replace("fixture-v1", "fixture-v2").replace(
            "\"public.strict_items\"",
            "\"public.strict_items\", \"public.strict_extra\"",
        ),
    )
    .unwrap();
    signal();
    // A reload need not finish for this assertion: it must never publish the new
    // manifest into this process, either before or after config reload completes.
    for _ in 0..3 {
        let client = connect(cfg.read_port).await;
        let denied = client
            .simple_query("SELECT id FROM public.strict_extra")
            .await
            .expect_err("manifest changes require a process restart");
        assert_eq!(denied.code().unwrap().code(), "0A000");
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    owner
        .batch_execute("DROP TABLE public.strict_extra")
        .await
        .unwrap();
}

pub async fn strict_bootstrap_rejects_unsafe_string_mode_before_parameter_sync() {
    let cfg = fixture();
    let owner_password = std::fs::read_to_string(&cfg.owner_password_file).unwrap();
    let password = std::fs::read_to_string(&cfg.application_password_file).unwrap();
    let (owner, connection) = tokio_postgres::Config::new()
        .host(&cfg.host)
        .port(cfg.postgres_port)
        .user(&cfg.owner_role)
        .password(owner_password.trim())
        .dbname(&cfg.database)
        .connect(tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    // Synthetic credential came from this runner and contains only hex digits.
    assert!(password.trim().bytes().all(|b| b.is_ascii_hexdigit()));
    owner
        .batch_execute(&format!(
            "CREATE ROLE strict_strings LOGIN PASSWORD '{}'; \
         ALTER ROLE strict_strings SET standard_conforming_strings = off; \
         GRANT SELECT, INSERT, UPDATE, DELETE ON public.strict_items TO strict_strings; \
         GRANT USAGE, SELECT ON public.strict_items_id_seq TO strict_strings",
            password.trim()
        ))
        .await
        .unwrap();
    let before = snapshot(&owner).await;
    // Both quotes force existing parameter formatting down its literal branch;
    // a backslash must never become SQL before the strict transaction starts.
    let mut config = tokio_postgres::Config::new();
    config
        .host(&cfg.host)
        .port(cfg.read_port)
        .user("strict_strings")
        .password(password.trim())
        .dbname(&cfg.database)
        .application_name("x\"\\';INSERT INTO public.strict_items(value) VALUES ('injected');--");
    if let Ok((client, connection)) = config.connect(tokio_postgres::NoTls).await {
        tokio::spawn(async move {
            let _ = connection.await;
        });
        assert!(
            client.simple_query("SELECT 1").await.is_err(),
            "unsafe backend startup facts must fail closed"
        );
    }
    let after = snapshot(&owner).await;
    assert_eq!(before.rows, after.rows);
    assert_eq!(before.sequence_value, after.sequence_value);
    assert_eq!(before.sequence_called, after.sequence_called);
    owner
        .batch_execute("DROP OWNED BY strict_strings; DROP ROLE strict_strings")
        .await
        .unwrap();
}
