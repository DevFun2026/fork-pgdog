//! Per-client strict extended-protocol statement and portal ownership.
//!
//! A registry entry is bookkeeping, not authorization: every backend-ready
//! statement and portal carries the immutable catalog proof and full backend
//! identity that admitted its original Parse.

use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Weak},
};

use crate::{
    backend::schema::read_policy::{CatalogIdentity, CatalogProof},
    net::Parse,
};

use super::{AdmittedSql, PolicyError, admit_sql};

const RESERVED_PREFIX: &str = "__pgdog_strict_";
const MAX_CLIENT_NAME_BYTES: usize = 1_024;
const MAX_STATEMENTS: usize = 1_024;
const MAX_PORTALS: usize = 1_024;
const MAX_SESSION_SQL_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_DECLARED_PARAMETERS: usize = 1_024;

#[derive(Debug)]
pub(crate) struct StrictSession {
    owner: Arc<()>,
    next_generation: u64,
    latest_unnamed_generation: Option<u64>,
    pending: BTreeMap<u64, PendingName>,
    statements: BTreeMap<String, Statement>,
    portals: BTreeMap<String, Portal>,
}

#[derive(Debug, Clone)]
enum PendingName {
    Named {
        name: String,
        admitted: Arc<AdmittedSql>,
    },
    Unnamed {
        admitted: Arc<AdmittedSql>,
    },
}

#[derive(Debug)]
pub(crate) struct PendingStatement {
    owner: Weak<()>,
    pub(crate) parse: Parse,
    pub(crate) admitted: Arc<AdmittedSql>,
    pub(crate) parameter_oids: Vec<u32>,
    pub(crate) generation: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct Statement {
    pub(crate) parse: Parse,
    pub(crate) admitted: Arc<AdmittedSql>,
    pub(crate) parameter_oids: Vec<u32>,
    pub(crate) generation: u64,
    pub(crate) backend_name: Option<String>,
    pub(crate) identity: Option<CatalogIdentity>,
    pub(crate) proof: Option<CatalogProof>,
}

#[derive(Debug, Clone)]
pub(crate) struct Portal {
    /// Snapshot semantics: closing/replacing the statement name does not
    /// invalidate an already bound portal.
    pub(crate) statement: Statement,
    pub(crate) identity: CatalogIdentity,
}

impl Default for StrictSession {
    fn default() -> Self {
        Self {
            owner: Arc::new(()),
            next_generation: 0,
            latest_unnamed_generation: None,
            pending: BTreeMap::new(),
            statements: BTreeMap::new(),
            portals: BTreeMap::new(),
        }
    }
}

impl StrictSession {
    /// Validate the original Parse before it can be renamed or sent to a
    /// backend. The returned pending object is bound to this client registry.
    pub(crate) fn prepare(&mut self, parse: &Parse) -> Result<PendingStatement, PolicyError> {
        let name = parse.name();
        if name.starts_with(RESERVED_PREFIX) {
            return Err(PolicyError::unsupported());
        }
        // PostgreSQL replaces the unnamed prepared statement as soon as a new
        // unnamed Parse is received, including when admission later rejects it.
        if name.is_empty() {
            self.statements.remove("");
            self.pending
                .retain(|_, pending| !matches!(pending, PendingName::Unnamed { .. }));
            self.latest_unnamed_generation = None;
        }
        let query_bytes = parse.query().len();
        if query_bytes > super::admission::MAX_SQL_BYTES
            || self.sql_memory_used().saturating_add(query_bytes) > MAX_SESSION_SQL_BYTES
        {
            return Err(PolicyError::unsupported());
        }
        if name.len() > MAX_CLIENT_NAME_BYTES
            || (self.statements.len() + self.pending.len() >= MAX_STATEMENTS
                && !self.statements.contains_key(name))
        {
            return Err(PolicyError::protocol());
        }
        if !name.is_empty()
            && (self.statements.contains_key(name)
                || self.pending.values().any(
                    |pending| matches!(pending, PendingName::Named { name: existing, .. } if existing == name),
                ))
        {
            return Err(PolicyError::duplicate_statement());
        }
        let admitted = Arc::new(admit_sql(parse.query())?);
        if admitted.actions.iter().any(|action| {
            !matches!(
                action,
                super::ReadAction::Select | super::ReadAction::ShowReadOnly
            )
        }) {
            return Err(PolicyError::unsupported());
        }
        let parameter_oids = declared_parameter_oids(parse)?;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or_else(PolicyError::protocol)?;
        let generation = self.next_generation;
        let pending_name = if name.is_empty() {
            self.latest_unnamed_generation = Some(generation);
            PendingName::Unnamed {
                admitted: admitted.clone(),
            }
        } else {
            PendingName::Named {
                name: name.to_owned(),
                admitted: admitted.clone(),
            }
        };
        self.pending.insert(generation, pending_name);
        Ok(PendingStatement {
            owner: Arc::downgrade(&self.owner),
            parse: parse.clone(),
            admitted,
            parameter_oids,
            generation,
        })
    }

    /// Commit only after the backend Parse succeeds and the catalog verifier
    /// has returned a proof for this exact SQL, declared-OID vector and
    /// backend/transaction identity.
    pub(crate) fn commit_prepare(
        &mut self,
        pending: PendingStatement,
        backend_name: String,
        identity: CatalogIdentity,
        proof: CatalogProof,
    ) -> Result<(), PolicyError> {
        if !Weak::ptr_eq(&pending.owner, &Arc::downgrade(&self.owner)) {
            return Err(PolicyError::stale_statement());
        }
        if !backend_name.starts_with(RESERVED_PREFIX)
            || !proof.matches_admission(&pending.admitted, &pending.parameter_oids)
            || !proof.matches_identity(&identity)
        {
            self.pending.remove(&pending.generation);
            return Err(PolicyError::stale_statement());
        }
        let Some(name_kind) = self.pending.remove(&pending.generation) else {
            return Err(PolicyError::stale_statement());
        };
        let name = match name_kind {
            PendingName::Named { name, .. } => name,
            PendingName::Unnamed { .. } => {
                if self.latest_unnamed_generation != Some(pending.generation) {
                    return Err(PolicyError::stale_statement());
                }
                String::new()
            }
        };
        if !name.is_empty() && self.statements.contains_key(&name) {
            return Err(PolicyError::duplicate_statement());
        }
        let statement = Statement {
            parse: pending.parse,
            admitted: pending.admitted,
            parameter_oids: pending.parameter_oids,
            generation: pending.generation,
            backend_name: Some(backend_name),
            identity: Some(identity),
            proof: Some(proof),
        };
        self.statements.insert(name, statement);
        Ok(())
    }

    /// Revalidate a retained client statement on a new backend transaction
    /// after Sync. Its original Parse and generation remain immutable; only a
    /// fresh backend name, identity and matching catalog proof are installed.
    pub(crate) fn commit_revalidation(
        &mut self,
        name: &str,
        expected_statement_generation: u64,
        backend_name: String,
        identity: CatalogIdentity,
        proof: CatalogProof,
    ) -> Result<(), PolicyError> {
        if !backend_name.starts_with(RESERVED_PREFIX) {
            return Err(PolicyError::stale_statement());
        }
        let statement = self
            .statements
            .get_mut(name)
            .ok_or_else(PolicyError::statement_not_found)?;
        if statement.generation != expected_statement_generation
            || !proof.matches_admission(&statement.admitted, &statement.parameter_oids)
            || !proof.matches_identity(&identity)
        {
            return Err(PolicyError::stale_statement());
        }
        statement.backend_name = Some(backend_name);
        statement.identity = Some(identity);
        statement.proof = Some(proof);
        Ok(())
    }

    /// Return the client's statement snapshot. Callers must use
    /// `statement_for_identity` before authorizing backend forwarding.
    pub(crate) fn statement(&self, name: &str) -> Result<&Statement, PolicyError> {
        self.statements
            .get(name)
            .ok_or_else(PolicyError::statement_not_found)
    }

    /// Find a statement whose proof is valid for this exact backend identity.
    pub(crate) fn statement_for_identity(
        &self,
        name: &str,
        identity: &CatalogIdentity,
    ) -> Result<&Statement, PolicyError> {
        let statement = self.statement(name)?;
        if !statement
            .backend_name
            .as_deref()
            .is_some_and(|name| name.starts_with(RESERVED_PREFIX))
            || statement.identity.as_ref() != Some(identity)
            || !statement.proof.as_ref().is_some_and(|proof| {
                proof.matches_admission(&statement.admitted, &statement.parameter_oids)
                    && proof.matches_identity(identity)
            })
        {
            return Err(PolicyError::stale_statement());
        }
        Ok(statement)
    }

    pub(crate) fn bind(
        &mut self,
        portal_name: &str,
        statement_name: &str,
        identity: &CatalogIdentity,
    ) -> Result<Portal, PolicyError> {
        if portal_name.len() > MAX_CLIENT_NAME_BYTES
            || statement_name.len() > MAX_CLIENT_NAME_BYTES
            || portal_name.starts_with(RESERVED_PREFIX)
            || statement_name.starts_with(RESERVED_PREFIX)
        {
            return Err(PolicyError::unsupported());
        }
        if self.portals.len() >= MAX_PORTALS && !self.portals.contains_key(portal_name) {
            return Err(PolicyError::protocol());
        }
        if !portal_name.is_empty() && self.portals.contains_key(portal_name) {
            return Err(PolicyError::duplicate_portal());
        }
        let statement = self
            .statement_for_identity(statement_name, identity)?
            .clone();
        let portal = Portal {
            statement,
            identity: identity.clone(),
        };
        self.portals.insert(portal_name.to_owned(), portal.clone());
        Ok(portal)
    }

    pub(crate) fn portal(
        &self,
        name: &str,
        identity: &CatalogIdentity,
    ) -> Result<&Portal, PolicyError> {
        let portal = self
            .portals
            .get(name)
            .ok_or_else(PolicyError::portal_not_found)?;
        if &portal.identity != identity
            || !portal.statement.proof.as_ref().is_some_and(|proof| {
                proof
                    .matches_admission(&portal.statement.admitted, &portal.statement.parameter_oids)
                    && proof.matches_identity(identity)
            })
        {
            return Err(PolicyError::stale_portal());
        }
        Ok(portal)
    }

    pub(crate) fn close_statement(&mut self, name: &str) -> Result<(), PolicyError> {
        if self.statements.remove(name).is_none() {
            return Err(PolicyError::statement_not_found());
        }
        Ok(())
    }

    pub(crate) fn close_portal(&mut self, name: &str) -> Result<(), PolicyError> {
        if self.portals.remove(name).is_none() {
            return Err(PolicyError::portal_not_found());
        }
        Ok(())
    }

    pub(crate) fn contains_portal(&self, name: &str) -> bool {
        self.portals.contains_key(name)
    }

    fn sql_memory_used(&self) -> usize {
        let mut seen = HashSet::new();
        let mut bytes = 0usize;
        let mut add = |sql: &Arc<AdmittedSql>| {
            if seen.insert(Arc::as_ptr(sql)) {
                bytes = bytes.saturating_add(sql.original_sql.len());
            }
        };
        for statement in self.statements.values() {
            add(&statement.admitted);
        }
        for pending in self.pending.values() {
            match pending {
                PendingName::Named { admitted, .. } | PendingName::Unnamed { admitted } => {
                    add(admitted)
                }
            }
        }
        for portal in self.portals.values() {
            add(&portal.statement.admitted);
        }
        bytes
    }

    /// End an implicit extended-query cycle. SQL identity remains available
    /// for revalidation, but no backend proof or portal survives the cycle.
    pub(crate) fn end_implicit_cycle(&mut self) {
        self.portals.clear();
        self.pending.clear();
        self.latest_unnamed_generation = None;
        for statement in self.statements.values_mut() {
            statement.backend_name = None;
            statement.identity = None;
            statement.proof = None;
        }
    }
}

fn declared_parameter_oids(parse: &Parse) -> Result<Vec<u32>, PolicyError> {
    let bytes = parse.data_types_ref();
    let raw = bytes.as_ref();
    let Some(count_bytes) = raw.get(..2) else {
        return Err(PolicyError::protocol());
    };
    let count = u16::from_be_bytes([count_bytes[0], count_bytes[1]]) as usize;
    let expected = count
        .checked_mul(4)
        .and_then(|n| n.checked_add(2))
        .ok_or_else(PolicyError::protocol)?;
    if raw.len() != expected || parse.num_data_types() as usize != count {
        return Err(PolicyError::protocol());
    }
    if count > MAX_DECLARED_PARAMETERS {
        return Err(PolicyError::unsupported());
    }
    raw[2..]
        .chunks_exact(4)
        .map(|oid| Ok(u32::from_be_bytes([oid[0], oid[1], oid[2], oid[3]])))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::schema::read_policy::CatalogProof;

    fn identity(generation: u64) -> CatalogIdentity {
        CatalogIdentity::for_test(generation)
    }

    fn prepare_committed(session: &mut StrictSession, name: &str, generation: u64) {
        let parse = Parse::named(name, "SELECT $1::int4").with_data_types(&[23]);
        let pending = session.prepare(&parse).unwrap();
        let proof = CatalogProof::for_test(
            &pending.admitted,
            &pending.parameter_oids,
            identity(generation),
        );
        session
            .commit_prepare(
                pending,
                "__pgdog_strict_1".into(),
                identity(generation),
                proof,
            )
            .unwrap();
    }

    #[test]
    fn registries_isolate_clients_and_unnamed_parse_replaces_previous() {
        let (mut left, mut right) = (StrictSession::default(), StrictSession::default());
        let pending = left.prepare(&Parse::named("named", "SELECT 1")).unwrap();
        let proof = CatalogProof::for_test(&pending.admitted, &pending.parameter_oids, identity(1));
        left.commit_prepare(pending, "__pgdog_strict_1".into(), identity(1), proof)
            .unwrap();
        assert!(right.statement("named").is_err());
        assert_eq!(
            left.prepare(&Parse::named("named", "SELECT 2"))
                .unwrap_err()
                .sqlstate(),
            "42P05"
        );

        let foreign_pending = right.prepare(&Parse::named("other", "SELECT 3")).unwrap();
        let foreign_proof = CatalogProof::for_test(
            &foreign_pending.admitted,
            &foreign_pending.parameter_oids,
            identity(1),
        );
        assert!(
            left.commit_prepare(
                foreign_pending,
                "__pgdog_strict_foreign".into(),
                identity(1),
                foreign_proof,
            )
            .is_err()
        );

        for query in ["SELECT 1", "SELECT 2"] {
            let pending = left.prepare(&Parse::new_anonymous(query)).unwrap();
            let proof =
                CatalogProof::for_test(&pending.admitted, &pending.parameter_oids, identity(1));
            left.commit_prepare(pending, "__pgdog_strict_unnamed".into(), identity(1), proof)
                .unwrap();
        }
        assert_eq!(left.statement("").unwrap().parse.query(), "SELECT 2");
    }

    #[test]
    fn portal_snapshot_survives_statement_close_and_named_portal_rebind_is_rejected() {
        let mut session = StrictSession::default();
        prepare_committed(&mut session, "s", 4);
        session.bind("p", "s", &identity(4)).unwrap();
        assert!(session.contains_portal("p"));
        session.close_statement("s").unwrap();
        assert_eq!(
            session
                .portal("p", &identity(4))
                .unwrap()
                .statement
                .parse
                .query(),
            "SELECT $1::int4"
        );
        assert!(session.bind("p", "s", &identity(4)).is_err());
        session.close_portal("p").unwrap();
        prepare_committed(&mut session, "s", 4);
        session.bind("p", "s", &identity(4)).unwrap();
    }

    #[test]
    fn transaction_controls_are_not_registered_as_backend_statements() {
        let mut session = StrictSession::default();
        for sql in ["BEGIN READ ONLY", "COMMIT", "ROLLBACK"] {
            assert!(session.prepare(&Parse::named("control", sql)).is_err());
            assert!(session.statement("control").is_err());
        }
    }

    #[test]
    fn pending_parse_sql_is_charged_to_the_per_client_budget() {
        let mut session = StrictSession::default();
        let mut pending = Vec::new();
        for index in 0..9 {
            let comment = "x".repeat(950_000);
            let sql = format!("SELECT 1 /*{comment}*/");
            let parse = Parse::named(format!("stmt_{index}"), sql);
            let result = session.prepare(&parse);
            if index < 8 {
                pending.push(result.expect("first eight parses fit under eight MiB"));
            } else {
                assert_eq!(result.unwrap_err().sqlstate(), "0A000");
            }
        }
        assert_eq!(pending.len(), 8);
    }

    #[test]
    fn retained_and_pending_sql_share_one_budget_without_portal_duplication() {
        let mut session = StrictSession::default();
        let large_query =
            |index: usize| format!("SELECT 1 /*{}*/", format!("x{index}").repeat(475_000));
        let identity = identity(1);
        for index in 0..5 {
            let parse = Parse::named(format!("retained_{index}"), large_query(index));
            let pending = session.prepare(&parse).unwrap();
            let proof = CatalogProof::for_test(
                &pending.admitted,
                &pending.parameter_oids,
                identity.clone(),
            );
            session
                .commit_prepare(
                    pending,
                    format!("__pgdog_strict_{index}"),
                    identity.clone(),
                    proof,
                )
                .unwrap();
            session
                .bind(
                    &format!("portal_{index}"),
                    &format!("retained_{index}"),
                    &identity,
                )
                .unwrap();
        }
        // Closing names does not free SQL still owned by portal snapshots.
        for index in 0..5 {
            session
                .close_statement(&format!("retained_{index}"))
                .unwrap();
        }
        let mut pending = Vec::new();
        for index in 5..9 {
            let result = session.prepare(&Parse::named(
                format!("pending_{index}"),
                large_query(index),
            ));
            if index < 8 {
                pending.push(result.expect("retained portals plus three pending statements fit"));
            } else {
                assert_eq!(result.unwrap_err().sqlstate(), "0A000");
            }
        }
        assert_eq!(pending.len(), 3);
        assert!(session.contains_portal("portal_0"));
    }

    #[test]
    fn stale_identity_and_reserved_names_fail_closed() {
        let mut session = StrictSession::default();
        assert!(
            session
                .prepare(&Parse::named("__pgdog_strict_user", "SELECT 1"))
                .is_err()
        );
        prepare_committed(&mut session, "s", 7);
        assert!(session.statement_for_identity("s", &identity(8)).is_err());
        assert!(
            session
                .bind("__pgdog_strict_portal", "s", &identity(7))
                .is_err()
        );
        session.end_implicit_cycle();
        assert!(session.statement("s").is_ok());
        assert!(session.statement_for_identity("s", &identity(7)).is_err());
        assert!(session.bind("p", "s", &identity(7)).is_err());
    }

    #[test]
    fn failed_unnamed_parse_still_replaces_the_previous_statement() {
        let mut session = StrictSession::default();
        let pending = session.prepare(&Parse::new_anonymous("SELECT 2")).unwrap();
        let proof = CatalogProof::for_test(&pending.admitted, &pending.parameter_oids, identity(1));
        session
            .commit_prepare(pending, "__pgdog_strict_unnamed".into(), identity(1), proof)
            .unwrap();
        assert!(
            session
                .prepare(&Parse::new_anonymous("DELETE FROM app.orders"))
                .is_err()
        );
        assert!(session.statement("").is_err());
    }

    #[test]
    fn parse_with_too_many_declared_oids_is_rejected_before_retaining_parameters() {
        let parse = Parse::named("large_oid_list", "SELECT 1").with_data_types(&vec![23; 1_025]);
        let mut session = StrictSession::default();
        assert_eq!(session.prepare(&parse).unwrap_err().sqlstate(), "0A000");
    }

    #[test]
    fn retained_statement_requires_fresh_matching_proof_before_reuse() {
        let mut session = StrictSession::default();
        prepare_committed(&mut session, "s", 2);
        let statement = session.statement("s").unwrap().clone();
        session.end_implicit_cycle();
        assert!(session.statement_for_identity("s", &identity(3)).is_err());
        let proof =
            CatalogProof::for_test(&statement.admitted, &statement.parameter_oids, identity(3));
        session
            .commit_revalidation(
                "s",
                statement.generation,
                "__pgdog_strict_revalidated".into(),
                identity(3),
                proof,
            )
            .unwrap();
        assert_eq!(
            session
                .statement_for_identity("s", &identity(3))
                .unwrap()
                .generation,
            statement.generation
        );
    }
}
