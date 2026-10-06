//! Startup, SSLRequest messages.

use crate::net::{
    Error, c_string,
    messages::{BackendKeyData, ProtocolVersion},
    parameter::{ParameterValue, Parameters},
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::debug;

use std::{marker::Unpin, ops::Deref};

use super::{super::Parameter, FromBytes, Payload, Protocol, ToBytes};

const MAX_STRICT_STARTUP_LENGTH: i32 = 64 * 1024;
const MAX_STRICT_STARTUP_PARAMETERS: usize = 16;
const MAX_STRICT_STARTUP_FIELD_LENGTH: usize = 4096;

/// First message a client sends to the server
/// and a server expects from a client.
///
/// See: <https://www.postgresql.org/docs/current/protocol-message-formats.html>
#[derive(Debug, PartialEq)]
pub(crate) enum Startup {
    /// SSLRequest (F)
    Ssl,
    /// GSSENCRequest (F)
    GssEnc,
    /// StartupMessage (F)
    Startup {
        version: ProtocolVersion,
        params: Parameters,
        unrecognized_options: Vec<String>,
    },
    /// CancelRequet (F)
    Cancel { id: BackendKeyData },
}

impl Startup {
    /// Read Startup message from a stream.
    #[cfg(test)]
    pub(crate) async fn from_stream(stream: &mut (impl AsyncRead + Unpin)) -> Result<Self, Error> {
        Self::from_stream_policy(stream, false).await
    }

    pub(crate) async fn from_stream_policy(
        stream: &mut (impl AsyncRead + Unpin),
        strict: bool,
    ) -> Result<Self, Error> {
        let len = stream.read_i32().await?;
        let code = stream.read_i32().await?;

        if strict && !(8..=MAX_STRICT_STARTUP_LENGTH).contains(&len) {
            return Err(Error::UnexpectedPayload);
        }

        debug!("📡 => {}", code);

        match code {
            // SSLRequest (F)
            80877103 => {
                if strict && len != 8 {
                    return Err(Error::UnexpectedPayload);
                }
                Ok(Startup::Ssl)
            }
            // GSSENCRequest (F)
            80877104 => {
                if strict && len != 8 {
                    return Err(Error::UnexpectedPayload);
                }
                Ok(Startup::GssEnc)
            }
            // CancelRequest (F)
            80877102 => {
                let pid = stream.read_i32().await?;
                // CancelRequest secrets became variable-length in protocol 3.2.
                let secret_len = usize::try_from(len)
                    .ok()
                    .and_then(|len| len.checked_sub(12))
                    .ok_or(Error::UnexpectedPayload)?;
                let mut secret = vec![0_u8; secret_len];
                stream.read_exact(&mut secret).await?;

                Ok(Startup::Cancel {
                    id: BackendKeyData {
                        pid,
                        secret: crate::net::messages::backend_key::SecretKey::from_slice(&secret)?,
                    },
                })
            }
            // StartupMessage (F)
            code => {
                let version =
                    ProtocolVersion::from_i32(code).ok_or(Error::UnsupportedStartup(code))?;
                if version.major() != 3 {
                    return Err(Error::UnsupportedStartup(code));
                }

                let mut params = Parameters::default();
                let mut unrecognized_options = vec![];
                if strict {
                    let mut remaining =
                        usize::try_from(len - 8).map_err(|_| Error::UnexpectedPayload)?;
                    let mut count = 0;
                    loop {
                        let name = strict_startup_c_string(stream, &mut remaining).await?;
                        if name.is_empty() {
                            if remaining != 0 {
                                return Err(Error::UnexpectedPayload);
                            }
                            break;
                        }
                        count += 1;
                        if count > MAX_STRICT_STARTUP_PARAMETERS
                            || !matches!(
                                name.as_str(),
                                "user" | "database" | "application_name" | "client_encoding"
                            )
                        {
                            return Err(Error::UnexpectedPayload);
                        }
                        let value = strict_startup_c_string(stream, &mut remaining).await?;
                        if name == "client_encoding"
                            && !matches!(value.to_ascii_uppercase().as_str(), "UTF8" | "UTF-8")
                        {
                            return Err(Error::UnexpectedPayload);
                        }
                        params.insert(name, value);
                    }
                    return Ok(Startup::Startup {
                        version,
                        params,
                        unrecognized_options,
                    });
                }
                loop {
                    let name = c_string(stream).await?;

                    if name.is_empty() {
                        break;
                    }

                    let value = c_string(stream).await?;

                    if name.starts_with("_pq_.") {
                        // Reserved protocol options are reported back via
                        // NegotiateProtocolVersion rather than treated as
                        // normal startup parameters.
                        unrecognized_options.push(name);
                    } else if name == "search_path" {
                        let value = search_path(&value);
                        params.insert(name, value);
                    } else if name == "options" {
                        let value = value.replace('+', " ");
                        let kvs = value.split("-c");
                        for kv in kvs {
                            let mut nvs = kv.split("=");
                            let name = nvs.next();
                            let value = nvs.next();

                            if let Some(name) = name
                                && let Some(value) = value
                            {
                                let name = name.trim().to_string();
                                let value = value.trim().to_string();
                                if !name.is_empty() && !value.is_empty() {
                                    let value = if name == "search_path" {
                                        search_path(&value)
                                    } else {
                                        ParameterValue::from(value)
                                    };
                                    params.insert(name, value);
                                }
                            }
                        }
                    } else {
                        params.insert(name, value);
                    }
                }

                Ok(Startup::Startup {
                    version,
                    params,
                    unrecognized_options,
                })
            }
        }
    }

    /// Create new startup message from config.
    pub(crate) fn new(user: &str, database: &str, params: Vec<Parameter>) -> Self {
        Self::new_with_protocol_version(ProtocolVersion::V3_0, user, database, params)
    }

    /// Create new startup message with a specific protocol version.
    pub(crate) fn new_with_protocol_version(
        version: ProtocolVersion,
        user: &str,
        database: &str,
        mut params: Vec<Parameter>,
    ) -> Self {
        params.extend(vec![
            Parameter {
                name: "user".into(),
                value: user.into(),
            },
            Parameter {
                name: "database".into(),
                value: database.into(),
            },
        ]);
        Self::Startup {
            version,
            params: params.into(),
            unrecognized_options: vec![],
        }
    }

    /// Create new startup TLS request.
    pub(crate) fn tls() -> Self {
        Self::Ssl
    }
}

async fn strict_startup_c_string(
    stream: &mut (impl AsyncRead + Unpin),
    remaining: &mut usize,
) -> Result<String, Error> {
    let mut bytes = Vec::with_capacity((*remaining).min(MAX_STRICT_STARTUP_FIELD_LENGTH));
    loop {
        if *remaining == 0 {
            return Err(Error::UnexpectedPayload);
        }
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|_| Error::UnexpectedPayload)?;
        *remaining -= 1;
        if byte[0] == 0 {
            return String::from_utf8(bytes).map_err(|_| Error::UnexpectedPayload);
        }
        if bytes.len() >= MAX_STRICT_STARTUP_FIELD_LENGTH {
            return Err(Error::UnexpectedPayload);
        }
        bytes.push(byte[0]);
    }
}

impl super::ToBytes for Startup {
    fn to_bytes(&self) -> bytes::Bytes {
        match self {
            Startup::Ssl => {
                let mut buf = BytesMut::new();

                buf.put_i32(8);
                buf.put_i32(80877103);

                buf.freeze()
            }

            Startup::GssEnc => {
                let mut buf = BytesMut::new();

                buf.put_i32(8);
                buf.put_i32(80877104);

                buf.freeze()
            }

            Startup::Cancel { id } => {
                let mut payload = Payload::new();

                payload.put_i32(80877102);
                payload.put_i32(id.pid);
                payload.put_slice(id.secret.as_slice());

                payload.freeze()
            }

            Startup::Startup {
                version,
                params,
                unrecognized_options: _,
            } => {
                let mut params_buf = BytesMut::new();

                for (name, value) in params.deref() {
                    if let ParameterValue::String(value) = value {
                        params_buf.put_slice(name.as_bytes());
                        params_buf.put_u8(0);

                        params_buf.put(value.as_bytes());
                        params_buf.put_u8(0);
                    }
                }

                let mut payload = Payload::new();

                payload.put_i32(version.as_i32());
                payload.put(params_buf);
                payload.put_u8(0); // Terminating null character.

                payload.freeze()
            }
        }
    }
}

/// Reply to a SSLRequest (F) message.
#[derive(Debug, PartialEq)]
pub(crate) enum SslReply {
    Yes,
    No,
}

impl ToBytes for SslReply {
    fn to_bytes(&self) -> bytes::Bytes {
        match self {
            SslReply::Yes => Bytes::from("S"),
            SslReply::No => Bytes::from("N"),
        }
    }
}

impl std::fmt::Display for SslReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Yes => "S",
                Self::No => "N",
            }
        )
    }
}

impl Protocol for SslReply {
    fn code(&self) -> char {
        match self {
            SslReply::Yes => 'S',
            SslReply::No => 'N',
        }
    }
}

impl FromBytes for SslReply {
    fn from_bytes(mut bytes: Bytes) -> Result<Self, Error> {
        let answer = bytes.get_u8() as char;
        match answer {
            'S' => Ok(SslReply::Yes),
            'N' => Ok(SslReply::No),
            answer => Err(Error::UnexpectedSslReply(answer)),
        }
    }
}

fn search_path(value: &str) -> ParameterValue {
    let value = value
        .split(",")
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    ParameterValue::Tuple(value)
}

#[cfg(test)]
mod test {
    impl Startup {
        fn gss_enc() -> Self {
            Self::GssEnc
        }
    }

    use crate::net::FrontendPid;
    use crate::net::messages::{BackendKeyData, ProtocolVersion, ToBytes};

    use super::*;
    use bytes::{Buf, BufMut, BytesMut};
    use tokio::io::AsyncWriteExt;

    #[test]
    fn test_ssl() {
        let ssl = Startup::Ssl;
        let mut bytes = ssl.to_bytes();

        assert_eq!(bytes.get_i32(), 8); // len
        assert_eq!(bytes.get_i32(), 80877103); // request code
    }

    #[test]
    fn test_gssenc() {
        let gss = Startup::gss_enc();
        let mut bytes = gss.to_bytes();

        assert_eq!(bytes.get_i32(), 8); // len
        assert_eq!(bytes.get_i32(), 80877104); // request code
    }

    #[tokio::test]
    async fn test_startup() {
        let startup = Startup::Startup {
            version: ProtocolVersion::V3_0,
            params: vec![
                Parameter {
                    name: "user".into(),
                    value: "postgres".into(),
                },
                Parameter {
                    name: "database".into(),
                    value: "postgres".into(),
                },
            ]
            .into(),
            unrecognized_options: vec![],
        };

        let bytes = startup.to_bytes();

        assert_eq!(bytes.clone().get_i32(), 41);
    }

    #[tokio::test]
    async fn test_read_gssenc_request() {
        let (mut write, mut read) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let mut buf = BytesMut::new();
            buf.put_i32(8);
            buf.put_i32(80877104);
            write.write_all(&buf).await.unwrap();
        });

        let startup = Startup::from_stream(&mut read).await.unwrap();
        assert!(matches!(startup, Startup::GssEnc));
    }

    #[tokio::test]
    async fn test_read_startup_protocol_3_2() {
        let (mut write, mut read) = tokio::io::duplex(128);
        tokio::spawn(async move {
            let startup = Startup::new_with_protocol_version(
                ProtocolVersion::V3_2,
                "postgres",
                "postgres",
                vec![],
            );
            write.write_all(&startup.to_bytes()).await.unwrap();
        });

        let startup = Startup::from_stream(&mut read).await.unwrap();
        assert!(matches!(
            startup,
            Startup::Startup {
                version: ProtocolVersion::V3_2,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_read_startup_collects_unrecognized_protocol_options() {
        let (mut write, mut read) = tokio::io::duplex(128);
        tokio::spawn(async move {
            let mut payload = BytesMut::new();
            payload.put_i32(ProtocolVersion::V3_2.as_i32());
            payload.put_slice(b"user\0postgres\0");
            payload.put_slice(b"_pq_.command_tag\0v2\0");
            payload.put_u8(0);

            let mut bytes = BytesMut::new();
            bytes.put_i32(payload.len() as i32 + 4);
            bytes.put(payload);
            write.write_all(&bytes).await.unwrap();
        });

        let startup = Startup::from_stream(&mut read).await.unwrap();
        let Startup::Startup {
            version,
            params,
            unrecognized_options,
        } = startup
        else {
            panic!("expected startup message");
        };

        assert_eq!(version, ProtocolVersion::V3_2);
        assert_eq!(
            params.get("user").and_then(|v| v.as_str()),
            Some("postgres")
        );
        assert_eq!(unrecognized_options, vec!["_pq_.command_tag"]);
    }

    async fn startup_with_options(options: &str) -> Startup {
        let (mut write, mut read) = tokio::io::duplex(128);
        let options = options.to_string();
        tokio::spawn(async move {
            let mut payload = BytesMut::new();
            payload.put_i32(ProtocolVersion::V3_0.as_i32());
            payload.put_slice(b"user\0postgres\0");
            payload.put_slice(b"database\0postgres\0");
            payload.put_slice(b"options\0");
            payload.put_slice(options.as_bytes());
            payload.put_u8(0);
            payload.put_u8(0);

            let mut bytes = BytesMut::new();
            bytes.put_i32(payload.len() as i32 + 4);
            bytes.put(payload);
            write.write_all(&bytes).await.unwrap();
        });
        Startup::from_stream(&mut read).await.unwrap()
    }

    #[tokio::test]
    async fn test_options_space_encoded() {
        // options=-c pgdog.role=replica  (space decoded from %20 by libpq)
        let startup = startup_with_options("-c pgdog.role=replica").await;
        let Startup::Startup { params, .. } = startup else {
            panic!("expected startup message");
        };
        assert_eq!(
            params.get("pgdog.role").and_then(|v| v.as_str()),
            Some("replica")
        );
    }

    #[tokio::test]
    async fn test_options_plus_encoded() {
        // options=-c+pgdog.role=replica  (+ not decoded to space by libpq)
        let startup = startup_with_options("-c+pgdog.role=replica").await;
        let Startup::Startup { params, .. } = startup else {
            panic!("expected startup message");
        };
        assert_eq!(
            params.get("pgdog.role").and_then(|v| v.as_str()),
            Some("replica")
        );
    }

    #[tokio::test]
    async fn test_cancel_roundtrip_extended_secret() {
        let cancel = Startup::Cancel {
            id: BackendKeyData::new_frontend(ProtocolVersion::V3_2, FrontendPid::new()),
        };
        let bytes = cancel.to_bytes();

        let (mut write, mut read) = tokio::io::duplex(512);
        tokio::spawn(async move {
            write.write_all(&bytes).await.unwrap();
        });

        let roundtrip = Startup::from_stream(&mut read).await.unwrap();
        assert_eq!(roundtrip, cancel);
    }
}

#[cfg(test)]
mod strict_read_startup_tests {
    use super::*;

    fn raw_startup(params: &[(&str, &str)], declared_len: Option<i32>) -> Vec<u8> {
        let mut payload = BytesMut::new();
        payload.put_i32(ProtocolVersion::V3_0.as_i32());
        for (name, value) in params {
            payload.extend_from_slice(name.as_bytes());
            payload.put_u8(0);
            payload.extend_from_slice(value.as_bytes());
            payload.put_u8(0);
        }
        payload.put_u8(0);
        let length = declared_len.unwrap_or((payload.len() + 4) as i32);
        let mut message = BytesMut::new();
        message.put_i32(length);
        message.extend_from_slice(&payload);
        message.to_vec()
    }

    #[tokio::test]
    async fn strict_read_startup_rejects_options_before_expansion() {
        for name in [
            "options",
            "replication",
            "search_path",
            "_pq_.unknown",
            "role",
        ] {
            let startup = Startup::new(
                "app",
                "app",
                vec![Parameter {
                    name: name.into(),
                    value: "-c application_name=innocent".into(),
                }],
            );
            let bytes = startup.to_bytes();
            assert!(
                Startup::from_stream_policy(&mut &bytes[..], true)
                    .await
                    .is_err(),
                "accepted {name}"
            );
            assert!(
                Startup::from_stream_policy(&mut &bytes[..], false)
                    .await
                    .is_ok()
            );
        }
        let startup = Startup::new(
            "app",
            "app",
            vec![Parameter {
                name: "application_name".into(),
                value: "driver".into(),
            }],
        );
        assert!(
            Startup::from_stream_policy(&mut &startup.to_bytes()[..], true)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn strict_read_startup_bounds_declared_frame_and_parameter_count() {
        let valid = raw_startup(&[("user", "app"), ("database", "app")], None);
        let oversized = raw_startup(&[("user", "app"), ("database", "app")], Some(65_537));
        assert!(
            Startup::from_stream_policy(&mut &oversized[..], true)
                .await
                .is_err()
        );
        // Unrestricted parsing retains its legacy behavior for the same bytes.
        assert!(
            Startup::from_stream_policy(&mut &oversized[..], false)
                .await
                .is_ok()
        );

        let repeated = (0..17)
            .map(|_| ("application_name", "client"))
            .collect::<Vec<_>>();
        let too_many = raw_startup(&repeated, None);
        assert!(
            Startup::from_stream_policy(&mut &too_many[..], true)
                .await
                .is_err()
        );
        assert!(
            Startup::from_stream_policy(&mut &too_many[..], false)
                .await
                .is_ok()
        );
        assert!(
            Startup::from_stream_policy(&mut &valid[..], true)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn strict_read_startup_rejects_truncated_fields_without_consuming_next_frame() {
        let mut truncated = BytesMut::new();
        truncated.put_i32(12);
        truncated.put_i32(ProtocolVersion::V3_0.as_i32());
        truncated.extend_from_slice(b"user\0"); // Missing value and final terminator.
        let mut stream = BytesMut::from(&truncated[..]);
        stream.extend_from_slice(&raw_startup(&[("user", "next")], None));

        let mut reader = std::io::Cursor::new(stream);
        assert!(
            Startup::from_stream_policy(&mut reader, true)
                .await
                .is_err()
        );
        assert_eq!(
            reader.position(),
            12,
            "strict parser must stop at the declared frame boundary"
        );
    }

    #[tokio::test]
    async fn strict_read_startup_accepts_valid_fragmented_frame() {
        use tokio::io::AsyncWriteExt;

        let bytes = raw_startup(
            &[
                ("user", "app"),
                ("database", "app"),
                ("application_name", "driver"),
            ],
            None,
        );
        let (mut writer, mut reader) = tokio::io::duplex(8);
        tokio::spawn(async move {
            for byte in bytes {
                writer.write_all(&[byte]).await.unwrap();
            }
        });
        assert!(matches!(
            Startup::from_stream_policy(&mut reader, true)
                .await
                .unwrap(),
            Startup::Startup { .. }
        ));
    }
}
