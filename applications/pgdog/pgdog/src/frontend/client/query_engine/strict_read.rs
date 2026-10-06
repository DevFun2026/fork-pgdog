//! The strict path runs before the normal router, rewrite and global cache path.
use super::*;
use crate::{
    backend::{
        Server,
        pool::connection::binding::Binding,
        schema::read_policy::{CatalogIdentity, CatalogProof, CatalogSnapshot, verify_parse},
    },
    frontend::{
        client::{Transaction, TransactionType},
        read_policy::{
            AdmittedSql, PolicyError, ReadAction, ReadIsolation, admit_sql,
            transaction::{ReadTransaction, ReadTxState},
        },
    },
    net::{
        Close, CommandComplete, Flush, FromBytes, Protocol, ProtocolMessage, Query, ReadyForQuery,
        Sync, ToBytes,
    },
};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Default)]
pub(super) struct StrictState {
    transaction: ReadTransaction,
    discard_until_sync: bool,
    prepared_names: Vec<String>,
    identity: Option<CatalogIdentity>,
    control_statements: std::collections::BTreeMap<String, ReadAction>,
    control_portals: std::collections::BTreeMap<String, ReadAction>,
}

impl Drop for QueryEngine {
    fn drop(&mut self) {
        if self.policy.mode() == crate::frontend::read_policy::QueryPolicy::StrictRead {
            // Includes cancellation of a future while an internal exchange is
            // incomplete, a frontend disconnect, and a suspended portal.
            self.backend.force_close();
        }
    }
}

impl QueryEngine {
    pub(super) async fn handle_strict_guarded(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        client_request: &mut ClientRequest,
    ) -> Result<QueryEngineResult, Error> {
        let timeout = context.timeouts.query_timeout(&State::Active);
        let cancel = self.backend.cancellation_token();
        let result = tokio::select! {
            result = crate::util::safe_timeout(timeout, Box::pin(self.handle_strict(context, client_request))) => result,
            _ = cancel.cancelled() => {
                Box::pin(self.strict_discard_active_backend()).await;
                return Err(Error::AdminTermination);
            }
        };
        match result {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(error)) => {
                Box::pin(self.strict_discard_active_backend()).await;
                Err(error)
            }
            Err(error) => {
                Box::pin(self.strict_discard_active_backend()).await;
                Err(error.into())
            }
        }
    }

    pub(super) async fn strict_discard_active_backend(&mut self) {
        // Terminate/EOF may remain unread while PostgreSQL waits on a lock or
        // executes a statement. Cancel out of band before discarding the socket.
        // A broken cancellation connection must not indefinitely delay cleanup.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            self.backend.cancel_query(),
        )
        .await;
        self.backend.force_close();
    }

    fn strict_server(&mut self) -> Result<&mut Server, Error> {
        match &mut *self.backend {
            Binding::Direct(server, 0)
                if !self.strict.transaction.failed
                    && self
                        .strict
                        .transaction
                        .backend
                        .is_none_or(|id| id == server.id()) =>
            {
                Ok(server)
            }
            _ => Err(PolicyError::protocol().into()),
        }
    }

    async fn strict_begin(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        explicit: bool,
        isolation: ReadIsolation,
    ) -> Result<(), Error> {
        if self.strict.transaction.state != ReadTxState::Idle {
            return Ok(());
        }
        let route = Route::write(
            crate::frontend::router::parser::ShardWithPriority::new_override_transaction(
                Shard::Direct(0),
            ),
        );
        if !self.connect(context, &route).await? {
            return Err(PolicyError::protocol().into());
        }
        let Binding::Direct(server, 0) = &mut *self.backend else {
            return Err(PolicyError::protocol().into());
        };
        server.enable_strict_protocol()?;
        self.strict
            .transaction
            .start(&mut **server, explicit, isolation)
            .await?;
        Ok(())
    }

    async fn strict_prove(
        &mut self,
        admitted: &AdmittedSql,
        parameter_oids: &[u32],
    ) -> Result<(CatalogIdentity, CatalogProof), Error> {
        let policy = self.policy.clone();
        let generation = self.strict.transaction.generation;
        let database = self.backend.cluster()?.identifier().database.clone();
        let server = self.strict_server()?;
        let snapshot = CatalogSnapshot::load(server, &admitted.catalog, generation).await?;
        let identity = snapshot.identity(&policy, &database, generation)?;
        if self
            .strict
            .identity
            .as_ref()
            .is_some_and(|previous| previous != &identity)
        {
            return Err(PolicyError::protocol().into());
        }
        let proof = verify_parse(
            &policy,
            admitted,
            &snapshot,
            identity.clone(),
            parameter_oids,
        )?;
        self.strict.identity = Some(identity.clone());
        Ok((identity, proof))
    }

    async fn strict_finish(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        commit: bool,
    ) -> Result<(), Error> {
        let Binding::Direct(server, 0) = &mut *self.backend else {
            return Err(PolicyError::protocol().into());
        };
        self.strict
            .transaction
            .finish(&mut **server, commit)
            .await?;
        // Named backend preparations belong to this protected epoch only.
        if !self.strict.prepared_names.is_empty() {
            let mut messages: Vec<ProtocolMessage> = self
                .strict
                .prepared_names
                .drain(..)
                .map(|name| Close::named(&name).into())
                .collect();
            messages.push(Sync.into());
            server.send(&messages.into()).await?;
            while server.has_more_messages() {
                let reply = server.read().await?;
                match reply.code() {
                    '3' | 'N' | 'S' => (),
                    'Z' if ReadyForQuery::from_bytes(reply.to_bytes())?.status == 'I' => (),
                    _ => return Err(PolicyError::protocol().into()),
                }
            }
        }
        context
            .strict_session
            .as_deref_mut()
            .ok_or_else(PolicyError::protocol)?
            .end_implicit_cycle();
        self.strict.identity = None;
        self.strict.control_portals.clear();
        if !self.backend.session_mode() {
            self.backend.disconnect();
        }
        Ok(())
    }

    fn strict_client_transaction(&self) -> Option<Transaction> {
        match self.strict.transaction.state {
            ReadTxState::Explicit => Some(Transaction::new(TransactionType::ReadOnly)),
            ReadTxState::FailedExplicit => Some(Transaction::new(TransactionType::ErrorReadOnly)),
            _ => None,
        }
    }

    async fn strict_ready(&mut self, context: &mut QueryEngineContext<'_>) -> Result<(), Error> {
        let status = match self.strict.transaction.state {
            ReadTxState::Explicit => 'T',
            ReadTxState::FailedExplicit => 'E',
            ReadTxState::Idle => 'I',
            ReadTxState::Implicit => return Err(PolicyError::protocol().into()),
        };
        context.transaction = self.strict_client_transaction();
        context.stream.send_flush(&ReadyForQuery { status }).await?;
        self.set_state(if status == 'I' {
            State::Idle
        } else {
            State::IdleInTransaction
        });
        Ok(())
    }

    async fn strict_deny(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        error: &PolicyError,
        extended: bool,
    ) -> Result<(), Error> {
        self.strict_deny_response(
            context,
            ErrorResponse {
                code: error.sqlstate().into(),
                message: format!("strict-read: {}", error.reason()),
                ..Default::default()
            },
            extended,
        )
        .await
    }

    async fn strict_deny_response(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        response: ErrorResponse,
        extended: bool,
    ) -> Result<(), Error> {
        let explicit = matches!(
            self.strict.transaction.state,
            ReadTxState::Explicit | ReadTxState::FailedExplicit
        );
        // Closing an uncertain connection is also rollback. Never pool it.
        self.backend.force_close();
        self.strict.prepared_names.clear();
        self.strict.identity = None;
        self.strict.control_portals.clear();
        let generation = self.strict.transaction.generation;
        self.strict.transaction = ReadTransaction::default();
        self.strict.transaction.generation = generation;
        if explicit {
            self.strict.transaction.state = ReadTxState::FailedExplicit;
        }
        context
            .strict_session
            .as_deref_mut()
            .ok_or_else(PolicyError::protocol)?
            .end_implicit_cycle();
        context.stream.send_flush(&response).await?;
        self.strict.discard_until_sync = extended;
        if !extended {
            self.strict_ready(context).await?;
        }
        Ok(())
    }

    async fn strict_simple(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        query: &Query,
    ) -> Result<(), Error> {
        if self.strict.transaction.state == ReadTxState::Implicit {
            return Err(PolicyError::protocol().into());
        }
        let _ = context
            .strict_session
            .as_deref_mut()
            .ok_or_else(PolicyError::protocol)?
            .close_statement("");
        self.strict.control_statements.remove("");
        let admitted = admit_sql(query.query())?;
        if self.strict.transaction.state == ReadTxState::FailedExplicit
            && !matches!(
                admitted.actions.as_slice(),
                [ReadAction::Commit | ReadAction::Rollback]
            )
        {
            context
                .stream
                .send_flush(&ErrorResponse {
                    code: "25P02".into(),
                    message: "strict-read: transaction_aborted".into(),
                    ..Default::default()
                })
                .await?;
            return self.strict_ready(context).await;
        }
        match admitted.actions.as_slice() {
            [ReadAction::Begin(isolation)] => {
                self.strict_begin(context, true, *isolation).await?;
                context.stream.send(&CommandComplete::new_begin()).await?;
            }
            [ReadAction::Commit | ReadAction::Rollback] => {
                let commit = matches!(admitted.actions[0], ReadAction::Commit);
                let failed = self.strict.transaction.state == ReadTxState::FailedExplicit;
                if matches!(
                    self.strict.transaction.state,
                    ReadTxState::Explicit | ReadTxState::FailedExplicit
                ) && self.backend.connected()
                {
                    self.strict_finish(context, commit).await?;
                } else {
                    self.strict.transaction.state = ReadTxState::Idle;
                }
                context
                    .stream
                    .send(&CommandComplete::from_str(if commit && !failed {
                        "COMMIT"
                    } else {
                        "ROLLBACK"
                    }))
                    .await?;
            }
            _ => {
                self.strict_begin(context, false, ReadIsolation::ReadCommitted)
                    .await?;
                self.strict_prove(&admitted, &[]).await?;
                let server = self.strict_server()?;
                server
                    .send(&vec![ProtocolMessage::Query(query.clone())].into())
                    .await?;
                let mut failed = false;
                while server.has_more_messages() {
                    let reply = server.read().await?;
                    if reply.code() == 'Z' {
                        let status = ReadyForQuery::from_bytes(reply.to_bytes())?.status;
                        if status != if failed { 'E' } else { 'T' } {
                            return Err(PolicyError::protocol().into());
                        }
                    } else if reply.code() == 'E' {
                        failed = true;
                        let error = ErrorResponse::from_bytes(reply.to_bytes())?;
                        context
                            .stream
                            .send(&ErrorResponse {
                                code: error.code,
                                message: "strict-read: backend_statement_failed".into(),
                                ..Default::default()
                            })
                            .await?;
                    } else {
                        context.stream.send(&reply).await?;
                    }
                }
                if self.strict.transaction.state == ReadTxState::Implicit {
                    self.strict_finish(context, !failed).await?;
                } else if failed {
                    self.strict.transaction.state = ReadTxState::FailedExplicit;
                }
            }
        }
        self.strict_ready(context).await
    }
}

impl QueryEngine {
    pub(super) async fn handle_strict(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        request: &mut ClientRequest,
    ) -> Result<QueryEngineResult, Error> {
        if context.strict_session.is_none() || context.admin {
            return Err(PolicyError::protocol().into());
        }
        self.stats.received(request.total_message_len());
        self.set_state(State::Active);
        for message in &request.messages {
            if self.strict.discard_until_sync {
                if matches!(message, ProtocolMessage::Sync(_)) {
                    self.strict.discard_until_sync = false;
                    self.strict_ready(context).await?;
                }
                continue;
            }
            let extended = !matches!(message, ProtocolMessage::Query(_));
            let result = match message {
                ProtocolMessage::Query(query) => self.strict_simple(context, query).await,
                _ => self.strict_extended(context, message).await,
            };
            if let Err(error) = result {
                let policy_error = match error {
                    Error::ReadPolicy(error) => error,
                    _ => PolicyError::new(
                        crate::frontend::read_policy::PolicyErrorKind::Unsupported,
                        "backend_enforcement_failed",
                    ),
                };
                self.strict_deny(context, &policy_error, extended).await?;
                if matches!(message, ProtocolMessage::Sync(_)) {
                    self.strict.discard_until_sync = false;
                    self.strict_ready(context).await?;
                }
            }
        }
        context.transaction = self.strict_client_transaction();
        self.update_stats(context);
        Ok(QueryEngineResult::Done(context.transaction()))
    }

    async fn strict_exchange(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        message: ProtocolMessage,
        visible: bool,
    ) -> Result<bool, Error> {
        let server = self.strict_server()?;
        if !server.in_transaction() {
            return Err(PolicyError::protocol().into());
        }
        server.send(&vec![message, Flush.into()].into()).await?;
        let mut error = None;
        while server.has_more_messages() {
            let reply = server.read().await?;
            if reply.code() == 'E' {
                error = Some(ErrorResponse::from_bytes(reply.to_bytes())?);
            } else if visible {
                context.stream.send(&reply).await?;
            }
        }
        let status = server.strict_barrier().await?;
        if let Some(error) = error {
            // An error in extended protocol discards messages through the next
            // client Sync. Its backend transaction is never reused.
            self.strict_deny_response(
                context,
                ErrorResponse {
                    code: error.code,
                    message: "strict-read: backend_statement_failed".into(),
                    ..Default::default()
                },
                true,
            )
            .await?;
            return Ok(false);
        }
        if status != 'T' {
            return Err(PolicyError::protocol().into());
        }
        Ok(true)
    }

    async fn strict_reprepare(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        name: &str,
    ) -> Result<bool, Error> {
        let statement = context
            .strict_session
            .as_deref()
            .ok_or_else(PolicyError::protocol)?
            .statement(name)?
            .clone();
        self.strict_begin(context, false, ReadIsolation::ReadCommitted)
            .await?;
        let (identity, proof) = self
            .strict_prove(&statement.admitted, &statement.parameter_oids)
            .await?;
        if context
            .strict_session
            .as_deref()
            .unwrap()
            .statement_for_identity(name, &identity)
            .is_ok()
        {
            return Ok(true);
        }
        let backend_name = strict_backend_name();
        if self.strict.prepared_names.len() >= 1024 {
            return Err(PolicyError::unsupported().into());
        }
        if !self
            .strict_exchange(
                context,
                statement.parse.renamed(&backend_name).into(),
                false,
            )
            .await?
        {
            return Ok(false);
        }
        self.strict.prepared_names.push(backend_name.clone());
        context
            .strict_session
            .as_deref_mut()
            .unwrap()
            .commit_revalidation(name, statement.generation, backend_name, identity, proof)?;
        Ok(true)
    }

    async fn strict_extended(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        message: &ProtocolMessage,
    ) -> Result<(), Error> {
        use crate::net::CloseComplete;
        if self.strict_control(context, message).await? {
            return Ok(());
        }
        match message {
            ProtocolMessage::Parse(parse) => {
                let pending = context
                    .strict_session
                    .as_deref_mut()
                    .unwrap()
                    .prepare(parse)?;
                if pending.admitted.actions.len() != 1 {
                    return Err(PolicyError::syntax().into());
                }
                self.strict_begin(context, false, ReadIsolation::ReadCommitted)
                    .await?;
                let (identity, proof) = self
                    .strict_prove(&pending.admitted, &pending.parameter_oids)
                    .await?;
                let backend_name = strict_backend_name();
                if self.strict.prepared_names.len() >= 1024 {
                    return Err(PolicyError::unsupported().into());
                }
                if self
                    .strict_exchange(context, parse.renamed(&backend_name).into(), true)
                    .await?
                {
                    self.strict.prepared_names.push(backend_name.clone());
                    context
                        .strict_session
                        .as_deref_mut()
                        .unwrap()
                        .commit_prepare(pending, backend_name, identity, proof)?;
                }
            }
            ProtocolMessage::Bind(bind) => {
                if bind.portal().is_empty() {
                    self.strict.control_portals.remove("");
                } else if self.strict.control_portals.contains_key(bind.portal()) {
                    return Err(PolicyError::duplicate_portal().into());
                }
                if !self.strict_reprepare(context, bind.statement()).await? {
                    return Ok(());
                }
                let identity = self
                    .strict
                    .identity
                    .clone()
                    .ok_or_else(PolicyError::protocol)?;
                let portal = context.strict_session.as_deref_mut().unwrap().bind(
                    bind.portal(),
                    bind.statement(),
                    &identity,
                )?;
                let mut bind = bind.clone();
                bind.rename(
                    portal
                        .statement
                        .backend_name
                        .as_deref()
                        .ok_or_else(PolicyError::stale_statement)?,
                );
                self.strict_exchange(context, bind.into(), true).await?;
            }
            ProtocolMessage::Describe(describe) if describe.is_statement() => {
                if !self.strict_reprepare(context, describe.statement()).await? {
                    return Ok(());
                }
                let identity = self
                    .strict
                    .identity
                    .as_ref()
                    .ok_or_else(PolicyError::protocol)?;
                let statement = context
                    .strict_session
                    .as_deref()
                    .unwrap()
                    .statement_for_identity(describe.statement(), identity)?;
                let mut describe = describe.clone();
                describe.rename(
                    statement
                        .backend_name
                        .as_deref()
                        .ok_or_else(PolicyError::stale_statement)?,
                );
                self.strict_exchange(context, describe.into(), true).await?;
            }
            ProtocolMessage::Describe(describe) if describe.is_portal() => {
                let identity = self
                    .strict
                    .identity
                    .as_ref()
                    .ok_or_else(PolicyError::stale_portal)?;
                context
                    .strict_session
                    .as_deref()
                    .unwrap()
                    .portal(describe.statement(), identity)?;
                self.strict_exchange(context, describe.clone().into(), true)
                    .await?;
            }
            ProtocolMessage::Execute(execute) => {
                let identity = self
                    .strict
                    .identity
                    .as_ref()
                    .ok_or_else(PolicyError::portal_not_found)?;
                context
                    .strict_session
                    .as_deref()
                    .unwrap()
                    .portal(execute.portal(), identity)?;
                self.strict_exchange(context, execute.clone().into(), true)
                    .await?;
            }
            ProtocolMessage::Close(close) if close.is_statement() => {
                let statement = context
                    .strict_session
                    .as_deref()
                    .unwrap()
                    .statement(close.name())
                    .ok()
                    .cloned();
                if let Some(statement) = statement {
                    if let Some(name) = statement.backend_name {
                        if !self
                            .strict_exchange(context, Close::named(&name).into(), false)
                            .await?
                        {
                            return Ok(());
                        }
                        self.strict
                            .prepared_names
                            .retain(|prepared| prepared != &name);
                    }
                    context
                        .strict_session
                        .as_deref_mut()
                        .unwrap()
                        .close_statement(close.name())?;
                }
                context.stream.send(&CloseComplete).await?;
            }
            ProtocolMessage::Close(close) if close.kind() == 'P' => {
                if !context
                    .strict_session
                    .as_deref()
                    .unwrap()
                    .contains_portal(close.name())
                {
                    context.stream.send(&CloseComplete).await?;
                    return Ok(());
                }
                let identity = self
                    .strict
                    .identity
                    .as_ref()
                    .ok_or_else(PolicyError::portal_not_found)?;
                context
                    .strict_session
                    .as_deref()
                    .unwrap()
                    .portal(close.name(), identity)?;
                if self
                    .strict_exchange(context, close.clone().into(), true)
                    .await?
                {
                    context
                        .strict_session
                        .as_deref_mut()
                        .unwrap()
                        .close_portal(close.name())?;
                }
            }
            ProtocolMessage::Other(message) if message.code() == 'H' => {
                context.stream.flush().await?;
            }
            ProtocolMessage::Sync(_) => {
                if self.strict.transaction.state == ReadTxState::Implicit {
                    self.strict_finish(context, true).await?;
                }
                if self.strict.transaction.state == ReadTxState::Idle {
                    self.strict.control_portals.clear();
                }
                self.strict_ready(context).await?;
            }
            _ => return Err(PolicyError::protocol().into()),
        }
        Ok(())
    }
}

fn strict_backend_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "__pgdog_strict_client_{}",
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

impl QueryEngine {
    /// The closed BEGIN/COMMIT/ROLLBACK grammar is interpreted locally. These
    /// statements never enter backend Parse/Bind/Execute or catalog resolution.
    async fn strict_control(
        &mut self,
        context: &mut QueryEngineContext<'_>,
        message: &ProtocolMessage,
    ) -> Result<bool, Error> {
        use crate::net::{
            BindComplete, CloseComplete, NoData, ParameterDescription, ParseComplete,
        };
        let failed = self.strict.transaction.state == ReadTxState::FailedExplicit;
        match message {
            ProtocolMessage::Parse(parse) => {
                if parse.name().starts_with("__pgdog_strict_") || parse.name().len() > 1024 {
                    return Err(PolicyError::unsupported().into());
                }
                if parse.name().is_empty() {
                    self.strict.control_statements.remove("");
                    let _ = context
                        .strict_session
                        .as_deref_mut()
                        .unwrap()
                        .close_statement("");
                } else if self.strict.control_statements.contains_key(parse.name()) {
                    return Err(PolicyError::duplicate_statement().into());
                }
                let admitted = admit_sql(parse.query())?;
                if let [
                    action @ (ReadAction::Begin(_) | ReadAction::Commit | ReadAction::Rollback),
                ] = admitted.actions.as_slice()
                {
                    if self.strict.control_statements.len() >= 1024 {
                        return Err(PolicyError::unsupported().into());
                    }
                    if parse.num_data_types() != 0 {
                        return Err(PolicyError::protocol().into());
                    }
                    if !parse.name().is_empty()
                        && context
                            .strict_session
                            .as_deref()
                            .unwrap()
                            .statement(parse.name())
                            .is_ok()
                    {
                        return Err(PolicyError::duplicate_statement().into());
                    }
                    if self.strict.transaction.state == ReadTxState::Implicit {
                        return Err(PolicyError::protocol().into());
                    }
                    self.strict
                        .control_statements
                        .insert(parse.name().to_owned(), action.clone());
                    context.stream.send(&ParseComplete).await?;
                    return Ok(true);
                }
            }
            ProtocolMessage::Bind(bind)
                if self
                    .strict
                    .control_statements
                    .contains_key(bind.statement()) =>
            {
                if bind.portal().starts_with("__pgdog_strict_")
                    || bind.portal().len() > 1024
                    || self.strict.control_portals.len() >= 1024
                    || !bind.params_raw().is_empty()
                {
                    return Err(PolicyError::protocol().into());
                }
                if bind.portal().is_empty() {
                    let _ = context
                        .strict_session
                        .as_deref_mut()
                        .unwrap()
                        .close_portal("");
                } else if self.strict.control_portals.contains_key(bind.portal())
                    || context
                        .strict_session
                        .as_deref()
                        .unwrap()
                        .contains_portal(bind.portal())
                {
                    return Err(PolicyError::duplicate_portal().into());
                }
                self.strict.control_portals.insert(
                    bind.portal().to_owned(),
                    self.strict.control_statements[bind.statement()].clone(),
                );
                context.stream.send(&BindComplete).await?;
                return Ok(true);
            }
            ProtocolMessage::Describe(describe)
                if describe.is_statement()
                    && self
                        .strict
                        .control_statements
                        .contains_key(describe.statement()) =>
            {
                context.stream.send(&ParameterDescription::empty()).await?;
                context.stream.send(&NoData).await?;
                return Ok(true);
            }
            ProtocolMessage::Describe(describe)
                if describe.is_portal()
                    && self
                        .strict
                        .control_portals
                        .contains_key(describe.statement()) =>
            {
                context.stream.send(&NoData).await?;
                return Ok(true);
            }
            ProtocolMessage::Execute(execute)
                if self.strict.control_portals.contains_key(execute.portal()) =>
            {
                let action = self.strict.control_portals[execute.portal()].clone();
                let tag = match action {
                    ReadAction::Begin(isolation) if !failed => {
                        if self.strict.transaction.state == ReadTxState::Implicit {
                            return Err(PolicyError::protocol().into());
                        }
                        self.strict_begin(context, true, isolation).await?;
                        "BEGIN"
                    }
                    ReadAction::Commit | ReadAction::Rollback => {
                        let commit = action == ReadAction::Commit && !failed;
                        if matches!(
                            self.strict.transaction.state,
                            ReadTxState::Explicit | ReadTxState::FailedExplicit
                        ) && self.backend.connected()
                        {
                            self.strict_finish(context, commit).await?;
                        } else {
                            self.strict.transaction.state = ReadTxState::Idle;
                            self.strict.control_portals.clear();
                        }
                        if commit { "COMMIT" } else { "ROLLBACK" }
                    }
                    _ => {
                        self.strict_deny_response(
                            context,
                            ErrorResponse {
                                code: "25P02".into(),
                                message: "strict-read: transaction_aborted".into(),
                                ..Default::default()
                            },
                            true,
                        )
                        .await?;
                        return Ok(true);
                    }
                };
                context.stream.send(&CommandComplete::from_str(tag)).await?;
                return Ok(true);
            }
            ProtocolMessage::Close(close)
                if close.is_statement()
                    && self
                        .strict
                        .control_statements
                        .remove(close.name())
                        .is_some() =>
            {
                context.stream.send(&CloseComplete).await?;
                return Ok(true);
            }
            ProtocolMessage::Close(close)
                if close.kind() == 'P'
                    && self.strict.control_portals.remove(close.name()).is_some() =>
            {
                context.stream.send(&CloseComplete).await?;
                return Ok(true);
            }
            _ => (),
        }
        if failed
            && !matches!(
                message,
                ProtocolMessage::Sync(_) | ProtocolMessage::Close(_) | ProtocolMessage::Other(_)
            )
        {
            self.strict_deny_response(
                context,
                ErrorResponse {
                    code: "25P02".into(),
                    message: "strict-read: transaction_aborted".into(),
                    ..Default::default()
                },
                true,
            )
            .await?;
            return Ok(true);
        }
        Ok(false)
    }
}
