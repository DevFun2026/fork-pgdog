//! These tests only use the disposable fixture created by strict-read-tests.sh.
use super::{
    ReadIsolation,
    transaction::{ReadBackend, ReadTransaction},
};
use crate::{
    backend::{ConnectReason, Server, ServerOptions, pool::Address},
    net::{Bind, Execute, Flush, Parse, Protocol, ProtocolMessage},
};

async fn server() -> Server {
    let raw =
        std::env::var("PGDOG_STRICT_TEST_CONFIG").expect("owned strict-read fixture is required");
    let cfg: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(cfg["host"], "127.0.0.1");
    let password =
        std::fs::read_to_string(cfg["application_password_file"].as_str().unwrap()).unwrap();
    let address = Address {
        host: "127.0.0.1".into(),
        port: u16::try_from(cfg["postgres_port"].as_u64().unwrap()).unwrap(),
        user: cfg["application_role"].as_str().unwrap().into(),
        database_name: cfg["database"].as_str().unwrap().into(),
        passwords: vec![password.trim().to_owned().into()],
        ..Default::default()
    };
    let mut server = Server::connect(
        &address,
        ServerOptions::default(),
        ConnectReason::Other,
        crate::backend::Oids::new(&Default::default()),
    )
    .await
    .unwrap();
    server.enable_strict_protocol().unwrap();
    server
}

async fn exchange(server: &mut Server, messages: Vec<ProtocolMessage>) -> String {
    server.send(&messages.into()).await.unwrap();
    let mut codes = String::new();
    while server.has_more_messages() {
        codes.push(server.read().await.unwrap().code());
    }
    codes
}

#[tokio::test]
async fn strict_read_transaction_internal_commands_preserve_unnamed_statement() {
    let mut server = server().await;
    let mut transaction = ReadTransaction::default();
    transaction
        .start(&mut server, false, ReadIsolation::ReadCommitted)
        .await
        .unwrap();
    assert_eq!(
        exchange(
            &mut server,
            vec![Parse::new_anonymous("SELECT 1").into(), Flush.into()]
        )
        .await,
        "1"
    );
    assert_eq!(server.strict_barrier().await.unwrap(), 'T');
    assert_eq!(
        server
            .internal("SHOW transaction_read_only")
            .await
            .unwrap()
            .value
            .as_deref(),
        Some("on")
    );
    assert_eq!(
        exchange(
            &mut server,
            vec![
                Bind::new_statement("").into(),
                Execute::new().into(),
                Flush.into()
            ]
        )
        .await,
        "2DC"
    );
    assert_eq!(server.strict_barrier().await.unwrap(), 'T');
    transaction.finish(&mut server, true).await.unwrap();
    assert!(server.can_check_in());
}

#[tokio::test]
async fn strict_read_flush_does_not_wait_for_sync_and_portal_survives_internal_queries() {
    let mut server = server().await;
    let mut transaction = ReadTransaction::default();
    transaction
        .start(&mut server, true, ReadIsolation::ReadCommitted)
        .await
        .unwrap();
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        exchange(
            &mut server,
            vec![
                Parse::named("statement", "SELECT generate_series(1, 3)").into(),
                Bind::new_statement("statement")
                    .with_portal("portal")
                    .into(),
                Execute::new_portal_limit("portal", 1).into(),
                Flush.into(),
            ],
        ),
    )
    .await
    .expect("Flush waited for Sync");
    assert_eq!(first, "12Ds");
    assert_eq!(server.strict_barrier().await.unwrap(), 'T');
    server.internal("SHOW transaction_read_only").await.unwrap();
    assert_eq!(
        exchange(
            &mut server,
            vec![Execute::new_portal("portal").into(), Flush.into()]
        )
        .await,
        "DDC"
    );
    assert_eq!(server.strict_barrier().await.unwrap(), 'T');
    transaction.finish(&mut server, false).await.unwrap();
    assert!(server.can_check_in());
}
