use bytes::{BufMut, Bytes, BytesMut};
use std::{error::Error, fmt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Duration, timeout},
};

#[derive(Debug, Clone)]
pub struct Message {
    pub code: u8,
    pub payload: Bytes,
}

impl Message {
    pub fn error_message(&self) -> Option<String> {
        if self.code != b'E' {
            return None;
        }
        let mut position = 0;
        let mut message = None;
        while position < self.payload.len() {
            let field = self.payload[position];
            position += 1;
            if field == 0 {
                break;
            }
            let end = self.payload[position..]
                .iter()
                .position(|byte| *byte == 0)?;
            if field == b'M' {
                message = Some(
                    String::from_utf8_lossy(&self.payload[position..position + end]).into_owned(),
                );
            }
            position += end + 1;
        }
        message
    }
}

#[derive(Debug)]
pub struct WireError(String);

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for WireError {}

pub struct WireClient {
    stream: TcpStream,
    backend_pid: Option<u32>,
    backend_secret: Option<u32>,
}

impl WireClient {
    pub async fn connect(
        address: (&str, u16),
        user: &str,
        database: &str,
        password: &str,
    ) -> Result<Self, WireError> {
        Self::connect_named(address, user, database, password, "strict-read-wire").await
    }

    pub async fn connect_named(
        address: (&str, u16),
        user: &str,
        database: &str,
        password: &str,
        application_name: &str,
    ) -> Result<Self, WireError> {
        let mut stream = TcpStream::connect(address).await.map_err(io_error)?;
        let mut startup = BytesMut::new();
        startup.put_i32(196608);
        for (key, value) in [
            ("user", user),
            ("database", database),
            ("application_name", application_name),
        ] {
            startup.put_slice(key.as_bytes());
            startup.put_u8(0);
            startup.put_slice(value.as_bytes());
            startup.put_u8(0);
        }
        startup.put_u8(0);
        let mut frame = BytesMut::new();
        frame.put_i32((startup.len() + 4) as i32);
        frame.extend_from_slice(&startup);
        stream.write_all(&frame).await.map_err(io_error)?;

        let mut authenticated = false;
        let mut backend_pid = None;
        let mut backend_secret = None;
        loop {
            let message = read_message(&mut stream).await?;
            match message.code {
                b'R' => {
                    if message.payload.len() < 4 {
                        return Err(WireError("short AuthenticationRequest".into()));
                    }
                    let code = u32::from_be_bytes(message.payload[..4].try_into().unwrap());
                    match code {
                        0 => authenticated = true,
                        3 => {
                            let mut payload = BytesMut::from(password.as_bytes());
                            payload.put_u8(0);
                            write_message(&mut stream, b'p', &payload).await?;
                        }
                        _ => {
                            return Err(WireError(format!(
                                "unsupported PostgreSQL auth request {code}; fixture expects cleartext passthrough"
                            )));
                        }
                    }
                }
                b'K' if message.payload.len() == 8 => {
                    backend_pid =
                        Some(u32::from_be_bytes(message.payload[..4].try_into().unwrap()));
                    backend_secret =
                        Some(u32::from_be_bytes(message.payload[4..].try_into().unwrap()));
                }
                b'E' => {
                    return Err(WireError(format!(
                        "PostgreSQL startup failed: {}",
                        error_message(&message.payload)
                    )));
                }
                b'Z' if authenticated => {
                    return Ok(Self {
                        stream,
                        backend_pid,
                        backend_secret,
                    });
                }
                _ => {}
            }
        }
    }

    pub fn backend_key(&self) -> Option<(u32, u32)> {
        Some((self.backend_pid?, self.backend_secret?))
    }

    pub async fn cancel_request(
        address: (&str, u16),
        backend_pid: u32,
        backend_secret: u32,
    ) -> Result<(), WireError> {
        let mut stream = TcpStream::connect(address).await.map_err(io_error)?;
        let mut request = BytesMut::new();
        request.put_i32(16);
        request.put_i32(80877102);
        request.put_u32(backend_pid);
        request.put_u32(backend_secret);
        stream.write_all(&request).await.map_err(io_error)
    }

    pub async fn query(&mut self, sql: &str) -> Result<Vec<Message>, WireError> {
        let mut payload = BytesMut::from(sql.as_bytes());
        payload.put_u8(0);
        write_message(&mut self.stream, b'Q', &payload).await?;
        let mut messages = Vec::new();
        loop {
            let message = self.receive().await?;
            let done = message.code == b'Z';
            messages.push(message);
            if done {
                return Ok(messages);
            }
        }
    }

    pub async fn send(&mut self, code: u8, payload: &[u8]) -> Result<(), WireError> {
        write_message(&mut self.stream, code, payload).await
    }

    pub async fn send_fragment(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        self.stream.write_all(bytes).await.map_err(io_error)
    }

    pub async fn receive(&mut self) -> Result<Message, WireError> {
        timeout(Duration::from_secs(5), read_message(&mut self.stream))
            .await
            .map_err(|_| WireError("timed out waiting for PostgreSQL protocol response".into()))?
    }

    pub async fn receive_until_ready(&mut self) -> Result<Vec<Message>, WireError> {
        let mut messages = Vec::new();
        loop {
            let message = self.receive().await?;
            let ready = message.code == b'Z';
            messages.push(message);
            if ready {
                return Ok(messages);
            }
        }
    }

    pub async fn receive_if_ready_within(
        &mut self,
        wait: Duration,
    ) -> Result<Option<Message>, WireError> {
        let mut byte = [0u8; 1];
        match timeout(wait, self.stream.peek(&mut byte)).await {
            Ok(Ok(0)) => Err(WireError(
                "connection closed while waiting for response".into(),
            )),
            Ok(Ok(_)) => self.receive().await.map(Some),
            Ok(Err(error)) => Err(io_error(error)),
            Err(_) => Ok(None),
        }
    }
}

async fn read_message(stream: &mut TcpStream) -> Result<Message, WireError> {
    let code = stream.read_u8().await.map_err(io_error)?;
    let length = stream.read_u32().await.map_err(io_error)? as usize;
    if !(4..=16 * 1024 * 1024).contains(&length) {
        return Err(WireError(format!(
            "invalid PostgreSQL message length {length}"
        )));
    }
    let mut payload = vec![0u8; length - 4];
    stream.read_exact(&mut payload).await.map_err(io_error)?;
    Ok(Message {
        code,
        payload: Bytes::from(payload),
    })
}

async fn write_message(stream: &mut TcpStream, code: u8, payload: &[u8]) -> Result<(), WireError> {
    let mut frame = BytesMut::with_capacity(payload.len() + 5);
    frame.put_u8(code);
    frame.put_i32((payload.len() + 4) as i32);
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await.map_err(io_error)
}

fn error_message(payload: &[u8]) -> String {
    let mut position = 0;
    let mut message = "unknown PostgreSQL error".to_owned();
    while position < payload.len() {
        let field = payload[position];
        position += 1;
        if field == 0 {
            break;
        }
        if let Some(end) = payload[position..].iter().position(|byte| *byte == 0) {
            if field == b'M' {
                message = String::from_utf8_lossy(&payload[position..position + end]).into_owned();
            }
            position += end + 1;
        } else {
            break;
        }
    }
    message
}

fn io_error(error: std::io::Error) -> WireError {
    WireError(error.to_string())
}
