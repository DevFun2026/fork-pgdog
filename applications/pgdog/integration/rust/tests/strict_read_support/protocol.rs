use super::{
    fixture,
    wire::{Message, WireClient},
};
use bytes::{BufMut, BytesMut};
use std::time::Duration;

async fn connect() -> WireClient {
    let fixture = fixture();
    let password = std::fs::read_to_string(&fixture.application_password_file)
        .expect("application credential file")
        .trim()
        .to_owned();
    WireClient::connect(
        (&fixture.host, fixture.read_port),
        &fixture.application_role,
        &fixture.database,
        &password,
    )
    .await
    .expect("strict PostgreSQL wire startup")
}

fn cstring(payload: &mut BytesMut, value: &str) {
    payload.extend_from_slice(value.as_bytes());
    payload.put_u8(0);
}

fn parse(name: &str, sql: &str) -> BytesMut {
    let mut payload = BytesMut::new();
    cstring(&mut payload, name);
    cstring(&mut payload, sql);
    payload.put_i16(0);
    payload
}

fn bind(portal: &str, statement: &str) -> BytesMut {
    let mut payload = BytesMut::new();
    cstring(&mut payload, portal);
    cstring(&mut payload, statement);
    payload.put_i16(0); // parameter format codes
    payload.put_i16(0); // parameters
    payload.put_i16(0); // result format codes
    payload
}

fn describe(kind: u8, name: &str) -> BytesMut {
    let mut payload = BytesMut::new();
    payload.put_u8(kind);
    cstring(&mut payload, name);
    payload
}

fn execute(portal: &str, max_rows: i32) -> BytesMut {
    let mut payload = BytesMut::new();
    cstring(&mut payload, portal);
    payload.put_i32(max_rows);
    payload
}

fn close(kind: u8, name: &str) -> BytesMut {
    let mut payload = BytesMut::new();
    payload.put_u8(kind);
    cstring(&mut payload, name);
    payload
}

fn ready_status(message: &Message) -> u8 {
    assert_eq!(message.code, b'Z');
    *message.payload.last().expect("ReadyForQuery status")
}

fn error(messages: &[Message]) -> &Message {
    messages
        .iter()
        .find(|message| message.code == b'E')
        .expect("expected ErrorResponse")
}

pub async fn strict_wire_flush_returns_before_sync_and_named_statement_survives_epoch_change() {
    let mut wire = connect().await;
    wire.send(b'P', &parse("named", "SELECT 1")).await.unwrap();
    wire.send(b'H', &[]).await.unwrap();
    let parse_complete = wire.receive().await.unwrap();
    assert_eq!(
        parse_complete.code, b'1',
        "ParseComplete must be returned on Flush"
    );
    assert!(
        wire.receive_if_ready_within(Duration::from_millis(150))
            .await
            .unwrap()
            .is_none(),
        "Flush must not end the client protocol cycle with ReadyForQuery"
    );
    wire.send(b'S', &[]).await.unwrap();
    assert_eq!(ready_status(&wire.receive().await.unwrap()), b'I');

    wire.send(b'B', &bind("named_portal", "named"))
        .await
        .unwrap();
    wire.send(b'D', &describe(b'S', "named")).await.unwrap();
    wire.send(b'H', &[]).await.unwrap();
    let mut replies = Vec::new();
    for _ in 0..3 {
        replies.push(wire.receive().await.unwrap());
    }
    assert!(
        replies.iter().any(|message| message.code == b'2'),
        "BindComplete expected"
    );
    assert!(
        replies.iter().any(|message| message.code == b't'),
        "ParameterDescription expected"
    );
    assert!(
        replies.iter().any(|message| message.code == b'T'),
        "RowDescription expected"
    );
    wire.send(b'E', &execute("named_portal", 0)).await.unwrap();
    wire.send(b'S', &[]).await.unwrap();
    let replies = wire.receive_until_ready().await.unwrap();
    assert!(
        !replies.iter().any(|message| message.code == b'E'),
        "retained named statement should be re-prepared safely"
    );
    assert!(replies.iter().any(|message| message.code == b'D'));
    assert_eq!(ready_status(replies.last().unwrap()), b'I');
}

pub async fn strict_wire_resumes_suspended_portal_after_closing_its_statement() {
    let mut wire = connect().await;
    wire.send(
        b'P',
        &parse("rows", "SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3"),
    )
    .await
    .unwrap();
    wire.send(b'B', &bind("rows_portal", "rows")).await.unwrap();
    wire.send(b'C', &close(b'S', "rows")).await.unwrap();
    wire.send(b'E', &execute("rows_portal", 1)).await.unwrap();
    wire.send(b'H', &[]).await.unwrap();
    let mut replies = Vec::new();
    loop {
        let message = wire.receive().await.unwrap();
        let suspended = message.code == b's';
        replies.push(message);
        if suspended {
            break;
        }
    }
    assert!(replies.iter().any(|message| message.code == b'2'));
    assert!(
        replies.iter().any(|message| message.code == b'3'),
        "CloseComplete expected"
    );
    assert_eq!(
        replies
            .iter()
            .filter(|message| message.code == b'D')
            .count(),
        1
    );
    wire.send(b'E', &execute("rows_portal", 0)).await.unwrap();
    wire.send(b'S', &[]).await.unwrap();
    let replies = wire.receive_until_ready().await.unwrap();
    assert!(
        !replies.iter().any(|message| message.code == b'E'),
        "portal snapshot must survive statement close"
    );
    assert_eq!(
        replies
            .iter()
            .filter(|message| message.code == b'D')
            .count(),
        2
    );
    assert!(replies.iter().any(|message| message.code == b'C'));
    assert_eq!(ready_status(replies.last().unwrap()), b'I');
}

pub async fn strict_wire_error_discards_until_sync_then_returns_one_ready() {
    let mut wire = connect().await;
    wire.send(b'P', &parse("denied", "DELETE FROM public.strict_items"))
        .await
        .unwrap();
    wire.send(b'B', &bind("ignored", "denied")).await.unwrap();
    wire.send(b'E', &execute("ignored", 0)).await.unwrap();
    wire.send(b'S', &[]).await.unwrap();
    let replies = wire.receive_until_ready().await.unwrap();
    assert!(
        error(&replies)
            .error_message()
            .unwrap()
            .contains("strict-read")
    );
    assert_eq!(
        replies
            .iter()
            .filter(|message| message.code == b'Z')
            .count(),
        1
    );
    assert_eq!(ready_status(replies.last().unwrap()), b'I');
    assert!(
        wire.receive_if_ready_within(Duration::from_millis(150))
            .await
            .unwrap()
            .is_none(),
        "one Sync must produce exactly one ReadyForQuery"
    );
}

pub async fn strict_wire_explicit_transaction_stays_failed_until_rollback() {
    let mut wire = connect().await;
    let begin = wire.query("BEGIN").await.unwrap();
    assert!(!begin.iter().any(|message| message.code == b'E'));
    assert_eq!(ready_status(begin.last().unwrap()), b'T');
    let denied = wire.query("DELETE FROM public.strict_items").await.unwrap();
    assert!(denied.iter().any(|message| message.code == b'E'));
    assert_eq!(ready_status(denied.last().unwrap()), b'E');
    let aborted = wire.query("SELECT 1").await.unwrap();
    assert!(
        error(&aborted)
            .error_message()
            .unwrap()
            .contains("transaction_aborted")
    );
    assert_eq!(ready_status(aborted.last().unwrap()), b'E');
    let rollback = wire.query("ROLLBACK").await.unwrap();
    assert!(!rollback.iter().any(|message| message.code == b'E'));
    assert_eq!(ready_status(rollback.last().unwrap()), b'I');
}

pub async fn strict_wire_denies_fastpath_and_orphan_copy_data() {
    let mut call = BytesMut::new();
    call.put_i32(0); // function OID
    call.put_i16(0); // argument format count
    call.put_i16(0); // argument count
    call.put_i16(0); // result format
    for (code, payload) in [
        (b'F', call.as_ref()),
        (b'd', b"orphan copy payload".as_slice()),
        (b'c', b"".as_slice()),
        (b'f', b"orphan failure\0".as_slice()),
    ] {
        let mut wire = connect().await;
        wire.send(code, payload).await.unwrap();
        let denied = wire.receive().await.unwrap();
        assert_eq!(denied.code, b'E');
        assert_eq!(
            denied.error_message().as_deref(),
            Some("strict-read: unsupported_protocol_message")
        );
        // SQL-less unsupported subprotocols terminate with a bounded Fatal,
        // rather than falsely acknowledge a usable transaction with ReadyForQuery.
        assert!(wire.receive().await.is_err());
    }
}

pub async fn strict_wire_cancel_request_does_not_escape_strict_session() {
    let fixture = fixture();
    let password = std::fs::read_to_string(&fixture.application_password_file)
        .expect("application credential file")
        .trim()
        .to_owned();
    let mut wire = WireClient::connect(
        (&fixture.host, fixture.read_port),
        &fixture.application_role,
        &fixture.database,
        &password,
    )
    .await
    .expect("strict PostgreSQL wire startup");
    let first = wire.query("SELECT 1").await.unwrap();
    assert!(!first.iter().any(|message| message.code == b'E'));
    let (backend_pid, backend_secret) = wire.backend_key().expect("BackendKeyData from startup");
    WireClient::cancel_request(
        (&fixture.host, fixture.read_port),
        backend_pid,
        backend_secret,
    )
    .await
    .unwrap();
    let second = wire
        .query("SELECT 1")
        .await
        .expect("safe query after CancelRequest");
    assert!(!second.iter().any(|message| message.code == b'E'));
    assert!(second.iter().any(|message| message.code == b'D'));
    assert_eq!(ready_status(second.last().unwrap()), b'I');
}

pub async fn strict_wire_unknown_close_is_idempotent() {
    let mut wire = connect().await;
    wire.send(b'C', &close(b'S', "missing_statement"))
        .await
        .unwrap();
    wire.send(b'C', &close(b'P', "missing_portal"))
        .await
        .unwrap();
    wire.send(b'S', &[]).await.unwrap();
    let replies = wire.receive_until_ready().await.unwrap();
    assert!(!replies.iter().any(|message| message.code == b'E'));
    assert_eq!(
        replies
            .iter()
            .filter(|message| message.code == b'3')
            .count(),
        2,
        "unknown statement and portal Close should each complete idempotently"
    );
    assert_eq!(
        replies
            .iter()
            .filter(|message| message.code == b'Z')
            .count(),
        1
    );
}

pub async fn strict_wire_lost_backend_before_sync_fails_closed_and_reconnects() {
    let fixture = fixture();
    let password = std::fs::read_to_string(&fixture.application_password_file)
        .expect("application credential file")
        .trim()
        .to_owned();
    let app_name = format!("strict-read-loss-{}", uuid::Uuid::new_v4());
    let mut wire = WireClient::connect_named(
        (&fixture.host, fixture.read_port),
        &fixture.application_role,
        &fixture.database,
        &password,
        &app_name,
    )
    .await
    .expect("strict PostgreSQL wire startup");
    wire.send(b'P', &parse("paused", "SELECT 1")).await.unwrap();
    wire.send(b'H', &[]).await.unwrap();
    assert_eq!(
        wire.receive().await.unwrap().code,
        b'1',
        "Flush should complete Parse before Sync"
    );

    let owner_password = std::fs::read_to_string(&fixture.owner_password_file)
        .expect("fixture owner credential file")
        .trim()
        .to_owned();
    let mut owner_config = tokio_postgres::Config::new();
    owner_config
        .host(&fixture.host)
        .port(fixture.postgres_port)
        .user(&fixture.owner_role)
        .password(&owner_password)
        .dbname(&fixture.database)
        .application_name(format!("{app_name}-terminator"));
    let (owner, connection) = owner_config
        .connect(tokio_postgres::NoTls)
        .await
        .expect("connect as fixture owner");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("fixture owner connection ended: {error}");
        }
    });
    // PgDog's startup PID is a virtual cancellation identity, not a PostgreSQL
    // PID. Resolve only this test's unique backend tag in its owned database.
    let backend_pid: i32 = owner.query_one(
        "SELECT pid FROM pg_catalog.pg_stat_activity WHERE application_name = $1 AND datname = $2 AND usename = $3",
        &[&app_name, &fixture.database, &fixture.application_role],
    ).await.expect("exactly one tagged protected backend").get(0);
    let terminated: bool = owner
        .query_one("SELECT pg_terminate_backend($1)", &[&(backend_pid as i32)])
        .await
        .expect("terminate only the tagged strict backend")
        .get(0);
    assert!(
        terminated,
        "fixture owner should terminate the backend held by this wire session"
    );

    wire.send(b'S', &[]).await.unwrap();
    let replies = wire.receive_until_ready().await.unwrap();
    assert!(
        replies.iter().any(|message| message.code == b'E'),
        "failed implicit commit must produce ErrorResponse"
    );
    assert_eq!(
        replies
            .iter()
            .filter(|message| message.code == b'Z')
            .count(),
        1
    );
    assert_eq!(ready_status(replies.last().unwrap()), b'I');

    let recovered = wire
        .query("SELECT 1")
        .await
        .expect("fresh safe query after failed cleanup");
    assert!(!recovered.iter().any(|message| message.code == b'E'));
    assert!(recovered.iter().any(|message| message.code == b'D'));
    assert_eq!(ready_status(recovered.last().unwrap()), b'I');
}

pub async fn strict_wire_extended_controls_and_idle_commit() {
    let mut wire = connect().await;
    for (index, sql, tag, status) in [
        (0, "BEGIN", "BEGIN", b'T'),
        (1, "ROLLBACK", "ROLLBACK", b'I'),
        (2, "COMMIT", "COMMIT", b'I'),
    ] {
        let name = format!("control{index}");
        wire.send(b'P', &parse(&name, sql)).await.unwrap();
        wire.send(b'B', &bind("control_portal", &name))
            .await
            .unwrap();
        wire.send(b'D', &describe(b'P', "control_portal"))
            .await
            .unwrap();
        wire.send(b'E', &execute("control_portal", 0))
            .await
            .unwrap();
        wire.send(b'S', &[]).await.unwrap();
        let replies = wire.receive_until_ready().await.unwrap();
        assert!(
            !replies.iter().any(|m| m.code == b'E'),
            "extended {sql}: {replies:?}"
        );
        assert_eq!(replies.iter().filter(|m| m.code == b'Z').count(), 1);
        assert_eq!(ready_status(replies.last().unwrap()), status);
        assert_eq!(replies.iter().filter(|m| m.code == b'C').count(), 1);
        let command = replies.iter().find(|m| m.code == b'C').unwrap();
        assert_eq!(command.payload.as_ref(), format!("{tag}\0").as_bytes());
        // Closing the control portal is idempotent after a transaction ends.
        wire.send(b'C', &close(b'P', "control_portal"))
            .await
            .unwrap();
        wire.send(b'S', &[]).await.unwrap();
        let closed = wire.receive_until_ready().await.unwrap();
        assert_eq!(closed[0].code, b'3');
        assert_eq!(ready_status(closed.last().unwrap()), status);
    }
}

pub async fn strict_wire_partial_packets_and_unfinished_message_budget() {
    let mut wire = connect().await;
    let mut query = BytesMut::new();
    query.put_u8(b'Q');
    query.put_i32(13);
    query.extend_from_slice(b"SELECT 1\0");
    wire.send_fragment(&query[..3]).await.unwrap();
    assert!(
        wire.receive_if_ready_within(Duration::from_millis(100))
            .await
            .unwrap()
            .is_none()
    );
    wire.send_fragment(&query[3..]).await.unwrap();
    let replies = wire.receive_until_ready().await.unwrap();
    assert!(replies.iter().any(|m| m.code == b'D'));
    assert_eq!(replies.iter().filter(|m| m.code == b'Z').count(), 1);
    assert_eq!(ready_status(replies.last().unwrap()), b'I');

    // No Flush/Sync: an attacker must not grow the buffered request without a bound.
    for _ in 0..4097 {
        wire.send(b'D', &describe(b'S', "unknown")).await.unwrap();
    }
    let denied = wire.receive().await.unwrap();
    assert_eq!(denied.code, b'E');
    assert_eq!(
        denied.error_message().as_deref(),
        Some("strict-read: request_limit_exceeded")
    );
}

pub async fn strict_wire_active_cancel_releases_locked_backend() {
    let cfg = fixture();
    let password = std::fs::read_to_string(&cfg.application_password_file).unwrap();
    let owner_password = std::fs::read_to_string(&cfg.owner_password_file).unwrap();
    let app_name = format!("strict-cancel-{}", uuid::Uuid::new_v4());
    let mut wire = WireClient::connect_named(
        (&cfg.host, cfg.read_port),
        &cfg.application_role,
        &cfg.database,
        password.trim(),
        &app_name,
    )
    .await
    .unwrap();
    let (pid, secret) = wire.backend_key().unwrap();
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
    owner
        .batch_execute("BEGIN; LOCK TABLE public.strict_items IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let mut query = BytesMut::new();
    cstring(&mut query, "SELECT id FROM public.strict_items");
    wire.send(b'Q', &query).await.unwrap();
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let row = owner.query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND datname=$2 AND usename=$3 AND wait_event_type='Lock'",
                &[&app_name, &cfg.database, &cfg.application_role]).await.unwrap();
            if row.get::<_, i64>(0) == 1 { break; }
            owner.simple_query("SELECT pg_stat_clear_snapshot()").await.unwrap();
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await.expect("owned strict backend should block on the fixture lock before cancellation");
    WireClient::cancel_request((&cfg.host, cfg.read_port), pid, secret)
        .await
        .unwrap();
    let replies = wire.receive_until_ready().await.unwrap();
    assert_eq!(
        replies.iter().filter(|m| m.code == b'E').count(),
        1,
        "{replies:?}"
    );
    assert_eq!(replies.iter().filter(|m| m.code == b'Z').count(), 1);
    assert_eq!(ready_status(replies.last().unwrap()), b'I');
    owner.batch_execute("ROLLBACK").await.unwrap();
    let recovered = wire.query("SELECT 1").await.unwrap();
    assert!(!recovered.iter().any(|m| m.code == b'E'), "{recovered:?}");
    assert!(recovered.iter().any(|m| m.code == b'D'));
}

pub async fn strict_wire_query_timeout_discards_protected_backend() {
    let cfg = fixture();
    let password = std::fs::read_to_string(&cfg.application_password_file).unwrap();
    let owner_password = std::fs::read_to_string(&cfg.owner_password_file).unwrap();
    let app_name = format!("strict-timeout-{}", uuid::Uuid::new_v4());
    let mut wire = WireClient::connect_named(
        (&cfg.host, cfg.read_port),
        &cfg.application_role,
        &cfg.database,
        password.trim(),
        &app_name,
    )
    .await
    .unwrap();
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
    owner
        .batch_execute("BEGIN; LOCK TABLE public.strict_items IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let mut query = BytesMut::new();
    cstring(&mut query, "SELECT id FROM public.strict_items");
    wire.send(b'Q', &query).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let row = owner.query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND datname=$2 AND usename=$3 AND wait_event_type='Lock'",
                &[&app_name, &cfg.database, &cfg.application_role]).await.unwrap();
            if row.get::<_, i64>(0) == 1 { break; }
            owner.simple_query("SELECT pg_stat_clear_snapshot()").await.unwrap();
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await.expect("fault query must be active before proxy query timeout");
    // The proxy query_timeout is 4000ms for this owned fixture. An interrupted
    // internal exchange is not reusable and closes the client and its backend.
    assert!(
        wire.receive_until_ready().await.is_err(),
        "timed-out protocol cycle cannot be acknowledged as successful"
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let row = owner.query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND datname=$2 AND usename=$3",
                &[&app_name, &cfg.database, &cfg.application_role]).await.unwrap();
            if row.get::<_, i64>(0) == 0 { break; }
            owner.simple_query("SELECT pg_stat_clear_snapshot()").await.unwrap();
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }).await.expect("timed-out backend must be canceled and discarded while the conflicting lock remains held");
    owner.batch_execute("ROLLBACK").await.unwrap();
    let mut recovered = connect().await;
    let replies = recovered.query("SELECT 1").await.unwrap();
    assert!(!replies.iter().any(|m| m.code == b'E'));
    assert!(replies.iter().any(|m| m.code == b'D'));
}
