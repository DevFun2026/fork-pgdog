pub mod cases;
pub mod protocol;
pub mod wire;

use serde_json::Value;
use std::{fs, path::PathBuf};
use tokio_postgres::{Client, Config, NoTls};

#[derive(Debug, Clone)]
pub struct Fixture {
    pub host: String,
    pub postgres_port: u16,
    pub read_port: u16,
    pub write_port: u16,
    pub database: String,
    pub application_role: String,
    pub owner_role: String,
    pub application_password_file: PathBuf,
    pub owner_password_file: PathBuf,
}

pub fn fixture() -> Fixture {
    let raw = std::env::var("PGDOG_STRICT_TEST_CONFIG")
        .expect("PGDOG_STRICT_TEST_CONFIG is required; fixture tests never skip without it");
    let value: Value = serde_json::from_str(&raw).expect("PGDOG_STRICT_TEST_CONFIG must be JSON");
    Fixture {
        host: value["host"]
            .as_str()
            .expect("fixture host missing")
            .to_owned(),
        postgres_port: value["postgres_port"]
            .as_u64()
            .expect("fixture postgres_port missing") as u16,
        read_port: value["read_port"]
            .as_u64()
            .expect("fixture read_port missing") as u16,
        write_port: value["write_port"]
            .as_u64()
            .expect("fixture write_port missing") as u16,
        database: value["database"]
            .as_str()
            .expect("fixture database missing")
            .to_owned(),
        application_role: value["application_role"]
            .as_str()
            .expect("application role missing")
            .to_owned(),
        owner_role: value["owner_role"]
            .as_str()
            .expect("owner role missing")
            .to_owned(),
        application_password_file: PathBuf::from(
            value["application_password_file"]
                .as_str()
                .expect("application credential path missing"),
        ),
        owner_password_file: PathBuf::from(
            value["owner_password_file"]
                .as_str()
                .expect("owner credential path missing"),
        ),
    }
}

pub async fn connect(port: u16) -> Client {
    let fixture = fixture();
    let password = fs::read_to_string(&fixture.application_password_file)
        .expect("application credential file must be readable")
        .trim()
        .to_owned();
    let mut config = Config::new();
    config
        .host(&fixture.host)
        .port(port)
        .user(&fixture.application_role)
        .password(&password)
        .dbname(&fixture.database)
        .application_name("strict-read-fixture");
    let (client, connection) = config
        .connect(NoTls)
        .await
        .expect("application connection failed");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("strict-read test connection ended: {error}");
        }
    });
    client
}
