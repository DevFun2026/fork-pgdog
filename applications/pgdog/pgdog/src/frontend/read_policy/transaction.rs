//! Backend transaction ownership is independent of the client's I/T/E status.
use super::{PolicyError, ReadIsolation};
use crate::net::BackendPid;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ReadTxState {
    #[default]
    Idle,
    Implicit,
    Explicit,
    FailedExplicit,
}

#[derive(Debug)]
pub(crate) struct ReadReply {
    pub(crate) status: char,
    pub(crate) value: Option<String>,
}

pub(crate) trait ReadBackend {
    fn identity(&self) -> BackendPid;
    fn idle(&self) -> bool;
    async fn internal(&mut self, sql: &str) -> Result<ReadReply, PolicyError>;
}

#[derive(Debug, Default)]
pub(crate) struct ReadTransaction {
    pub(crate) state: ReadTxState,
    pub(crate) generation: u64,
    pub(crate) backend: Option<BackendPid>,
    pub(crate) failed: bool,
}

impl ReadTransaction {
    pub(crate) async fn start(
        &mut self,
        server: &mut impl ReadBackend,
        explicit: bool,
        isolation: ReadIsolation,
    ) -> Result<(), PolicyError> {
        if self.state != ReadTxState::Idle || self.failed || !server.idle() {
            return Err(PolicyError::protocol());
        }
        let identity = server.identity();
        let isolation = match isolation {
            ReadIsolation::ReadUncommitted => "READ UNCOMMITTED",
            ReadIsolation::ReadCommitted => "READ COMMITTED",
            ReadIsolation::RepeatableRead => "REPEATABLE READ",
            ReadIsolation::Serializable => "SERIALIZABLE",
        };
        // Mark uncertain before I/O. On any failure the caller must discard
        // this backend; an error must never make it eligible for reuse.
        self.failed = true;
        let begun = server
            .internal(&format!("BEGIN ISOLATION LEVEL {isolation} READ ONLY"))
            .await?;
        if begun.status != 'T' || server.identity() != identity {
            return Err(PolicyError::protocol());
        }
        let checked = server.internal("SHOW transaction_read_only").await?;
        if checked.status != 'T'
            || checked.value.as_deref() != Some("on")
            || server.identity() != identity
        {
            return Err(PolicyError::protocol());
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(PolicyError::protocol)?;
        self.backend = Some(identity);
        self.state = if explicit {
            ReadTxState::Explicit
        } else {
            ReadTxState::Implicit
        };
        self.failed = false;
        Ok(())
    }

    pub(crate) async fn finish(
        &mut self,
        server: &mut impl ReadBackend,
        commit: bool,
    ) -> Result<(), PolicyError> {
        if self.state == ReadTxState::Idle || self.backend != Some(server.identity()) || self.failed
        {
            return Err(PolicyError::protocol());
        }
        self.failed = true;
        let reply = server
            .internal(if commit { "COMMIT" } else { "ROLLBACK" })
            .await?;
        if reply.status != 'I' || self.backend != Some(server.identity()) {
            return Err(PolicyError::protocol());
        }
        self.state = ReadTxState::Idle;
        self.backend = None;
        self.failed = false;
        Ok(())
    }
}

impl ReadBackend for crate::backend::Server {
    fn identity(&self) -> BackendPid {
        self.id()
    }
    fn idle(&self) -> bool {
        self.can_check_in()
    }
    async fn internal(&mut self, sql: &str) -> Result<ReadReply, PolicyError> {
        use crate::{
            backend::server::ServerRequest,
            net::{DataRow, FromBytes, Protocol, ReadyForQuery, ToBytes},
        };
        let request = ServerRequest::strict_internal(sql, &[]);
        let result = self.execute_batch(request).await;
        let messages = match result {
            Ok(messages) => messages,
            Err(_) => {
                self.force_close();
                return Err(PolicyError::protocol());
            }
        };
        let mut status = None;
        let mut value = None;
        for message in messages {
            match message.code() {
                'Z' if status.is_none() => {
                    status = Some(
                        ReadyForQuery::from_bytes(message.to_bytes())
                            .map_err(|_| PolicyError::protocol())?
                            .status,
                    );
                }
                'D' if value.is_none() => {
                    let row = DataRow::from_bytes(message.to_bytes())
                        .map_err(|_| PolicyError::protocol())?;
                    if row.len() != 1 {
                        return Err(PolicyError::protocol());
                    }
                    value = row.get_text(0);
                    if value.is_none() {
                        return Err(PolicyError::protocol());
                    }
                }
                '1' | '2' | '3' | 'C' | 'N' | 'S' => (),
                _ => return Err(PolicyError::protocol()),
            }
        }
        Ok(ReadReply {
            status: status.ok_or_else(PolicyError::protocol)?,
            value,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct RecordingBackend {
        commands: Vec<String>,
        readonly: bool,
        active: bool,
    }
    impl ReadBackend for RecordingBackend {
        fn identity(&self) -> BackendPid {
            BackendPid::for_test(1)
        }
        fn idle(&self) -> bool {
            !self.active
        }
        async fn internal(&mut self, sql: &str) -> Result<ReadReply, PolicyError> {
            self.commands.push(sql.to_owned());
            self.active = true;
            Ok(ReadReply {
                status: 'T',
                value: sql
                    .starts_with("SHOW")
                    .then(|| if self.readonly { "on" } else { "off" }.to_owned()),
            })
        }
    }
    #[tokio::test]
    async fn strict_read_transaction_requires_acknowledged_read_only_before_use() {
        let mut server = RecordingBackend {
            commands: vec![],
            readonly: true,
            active: false,
        };
        let mut tx = ReadTransaction::default();
        tx.start(&mut server, false, ReadIsolation::ReadCommitted)
            .await
            .unwrap();
        assert_eq!(
            server.commands,
            [
                "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY",
                "SHOW transaction_read_only"
            ]
        );
        assert_eq!(tx.state, ReadTxState::Implicit);
        assert_eq!(tx.generation, 1);
        let mut writable = RecordingBackend {
            commands: vec![],
            readonly: false,
            active: false,
        };
        let mut tx = ReadTransaction::default();
        assert!(
            tx.start(&mut writable, false, ReadIsolation::ReadCommitted)
                .await
                .is_err()
        );
        assert_eq!(tx.state, ReadTxState::Idle);
    }

    struct ScriptedBackend {
        replies: std::collections::VecDeque<Result<ReadReply, PolicyError>>,
        commands: Vec<String>,
    }
    impl ReadBackend for ScriptedBackend {
        fn identity(&self) -> BackendPid {
            BackendPid::for_test(2)
        }
        fn idle(&self) -> bool {
            self.commands.is_empty()
        }
        async fn internal(&mut self, sql: &str) -> Result<ReadReply, PolicyError> {
            self.commands.push(sql.to_owned());
            self.replies
                .pop_front()
                .expect("unexpected internal command")
        }
    }
    fn reply(status: char, value: Option<&str>) -> Result<ReadReply, PolicyError> {
        Ok(ReadReply {
            status,
            value: value.map(str::to_owned),
        })
    }
    #[tokio::test]
    async fn strict_read_transaction_failed_setup_and_commit_cannot_be_reused() {
        for replies in [
            vec![Err(PolicyError::protocol())],
            vec![reply('I', None)],
            vec![reply('T', None), reply('T', Some("off"))],
            vec![reply('T', None), reply('E', None)],
        ] {
            let mut backend = ScriptedBackend {
                replies: replies.into(),
                commands: vec![],
            };
            let mut tx = ReadTransaction::default();
            assert!(
                tx.start(&mut backend, false, ReadIsolation::ReadCommitted)
                    .await
                    .is_err()
            );
            assert!(tx.failed);
            assert_eq!(tx.backend, None);
            assert_eq!(tx.generation, 0);
            assert!(
                tx.start(&mut backend, false, ReadIsolation::ReadCommitted)
                    .await
                    .is_err()
            );
        }
        for completion in [
            Err(PolicyError::protocol()),
            reply('T', None),
            reply('E', None),
        ] {
            let mut backend = ScriptedBackend {
                replies: vec![reply('T', None), reply('T', Some("on")), completion].into(),
                commands: vec![],
            };
            let mut tx = ReadTransaction::default();
            tx.start(&mut backend, false, ReadIsolation::ReadCommitted)
                .await
                .unwrap();
            assert!(tx.finish(&mut backend, true).await.is_err());
            assert!(tx.failed);
            assert_ne!(tx.state, ReadTxState::Idle);
            assert!(tx.finish(&mut backend, false).await.is_err());
            assert_eq!(backend.commands.last().unwrap(), "COMMIT");
        }
    }
    #[tokio::test]
    async fn strict_read_transaction_rollback_acknowledgement_releases_epoch() {
        let mut backend = ScriptedBackend {
            replies: vec![reply('T', None), reply('T', Some("on")), reply('I', None)].into(),
            commands: vec![],
        };
        let mut tx = ReadTransaction::default();
        tx.start(&mut backend, true, ReadIsolation::RepeatableRead)
            .await
            .unwrap();
        assert_eq!(tx.state, ReadTxState::Explicit);
        tx.state = ReadTxState::FailedExplicit;
        tx.finish(&mut backend, false).await.unwrap();
        assert_eq!(
            backend.commands,
            [
                "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
                "SHOW transaction_read_only",
                "ROLLBACK"
            ]
        );
        assert_eq!(tx.state, ReadTxState::Idle);
        assert_eq!(tx.backend, None);
        assert!(!tx.failed);
        assert_eq!(tx.generation, 1);
    }
}
