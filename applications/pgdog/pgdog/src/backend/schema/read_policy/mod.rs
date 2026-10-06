mod registry;
mod resolve;
mod rows;

use std::collections::BTreeMap;

use crate::{
    backend::{Server, server::ServerRequest},
    frontend::read_policy::{AdmittedSql, CatalogRequirements, PolicyError, ProcessPolicy},
    net::messages::{DataRow, Format, bind::Parameter as BindParameter},
};
use pgdog_postgres_types::Oid;

use self::rows::{ColumnRow, RelationRow, RoleRow};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogIdentity {
    pub(crate) backend_database_oid: u32,
    pub(crate) backend_role_oid: u32,
    pub(crate) connection: crate::net::messages::BackendPid,
    pub(crate) transaction_generation: u64,
    pub(crate) manifest_digest: [u8; 32],
    pub(crate) schema_revision: String,
    pub(crate) database_alias: String,
}

#[cfg(test)]
impl CatalogIdentity {
    pub(crate) fn for_test(transaction_generation: u64) -> Self {
        Self {
            backend_database_oid: 1,
            backend_role_oid: 2,
            connection: crate::net::messages::BackendPid::for_test(3),
            transaction_generation,
            manifest_digest: [4; 32],
            schema_revision: "test-revision".into(),
            database_alias: "test".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CatalogRelation {
    relation: RelationRow,
    columns: Vec<ColumnRow>,
    indexes_safe: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogSnapshot {
    database_oid: u32,
    role_oid: u32,
    server_major: u32,
    connection: crate::net::messages::BackendPid,
    transaction_generation: u64,
    search_path: Vec<String>,
    role: RoleRow,
    relations: BTreeMap<String, CatalogRelation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogProof {
    fingerprint: [u8; 32],
    parameter_oids: Vec<u32>,
    identity: CatalogIdentity,
}

impl CatalogProof {
    pub(crate) fn matches_admission(&self, admitted: &AdmittedSql, parameter_oids: &[u32]) -> bool {
        self.fingerprint == admitted.fingerprint && self.parameter_oids == parameter_oids
    }

    pub(crate) fn matches_identity(&self, identity: &CatalogIdentity) -> bool {
        &self.identity == identity
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        admitted: &AdmittedSql,
        parameter_oids: &[u32],
        identity: CatalogIdentity,
    ) -> Self {
        Self {
            fingerprint: admitted.fingerprint,
            parameter_oids: parameter_oids.to_vec(),
            identity,
        }
    }
}

impl CatalogSnapshot {
    pub(crate) async fn load(
        server: &mut Server,
        requirements: &CatalogRequirements,
        transaction_generation: u64,
    ) -> Result<Self, PolicyError> {
        // This must be checked on the exact Server before catalog lookup. An
        // unknown or idle transaction state is never treated as protected.
        if !server.in_transaction() {
            return Err(PolicyError::unsupported());
        }
        server
            .enable_strict_protocol()
            .map_err(|_| PolicyError::unsupported())?;
        let readonly = server
            .fetch_all::<String>(ServerRequest::strict_internal(
                "SHOW transaction_read_only",
                &[],
            ))
            .await
            .map_err(|_| PolicyError::unsupported())?;
        if readonly.as_slice() != ["on"] {
            return Err(PolicyError::unsupported());
        }
        for (setting, expected) in [
            ("SHOW standard_conforming_strings", "on"),
            ("SHOW client_encoding", "UTF8"),
        ] {
            let values = server
                .fetch_all::<String>(ServerRequest::strict_internal(setting, &[]))
                .await
                .map_err(|_| PolicyError::unsupported())?;
            if values.as_slice() != [expected] {
                return Err(PolicyError::unsupported());
            }
        }

        let path_rows = server
            .fetch_all::<String>(ServerRequest::strict_internal(catalog_query(0), &[]))
            .await
            .map_err(|_| PolicyError::unsupported())?;
        let search_path = path_rows
            .first()
            .and_then(|value| parse_pg_array(value))
            .ok_or_else(PolicyError::unsupported)?;
        if search_path.first().map(String::as_str) != Some("pg_catalog")
            || search_path
                .iter()
                .any(|schema| schema.starts_with("pg_temp"))
        {
            return Err(PolicyError::unsupported());
        }
        let identity_rows = server
            .fetch_all::<IdentityRow>(ServerRequest::strict_internal(catalog_query(1), &[]))
            .await
            .map_err(|_| PolicyError::unsupported())?;
        let identity = identity_rows
            .first()
            .filter(|row| row.valid)
            .ok_or_else(PolicyError::unsupported)?;
        if registry::server_major() != Some(identity.server_major) {
            return Err(PolicyError::unsupported());
        }

        let function_names = names_csv(&requirements.functions);
        let operator_names = names_csv(&requirements.operators);
        let overload_params = [
            BindParameter::new(function_names.as_bytes()),
            BindParameter::new(operator_names.as_bytes()),
            BindParameter::new(
                registry::candidate_oids_csv("pg_proc", &requirements.functions)
                    .ok_or_else(PolicyError::unsupported)?
                    .as_bytes(),
            ),
            BindParameter::new(
                registry::candidate_oids_csv("pg_operator", &requirements.operators)
                    .ok_or_else(PolicyError::unsupported)?
                    .as_bytes(),
            ),
        ];
        // Deny CREATE-capable application identities and schemas before local
        // resolution. A protected transaction is still required; this prevents
        // previously installed objects in mutable namespaces from becoming a
        // hidden resolution path.
        if identity.database_owner_oid == identity.role_oid
            || identity.can_create_in_database
            || identity.can_create_in_search_path
        {
            return Err(PolicyError::unsupported());
        }

        // Any visible same-name user overload is denied before the resolver
        // chooses a trusted pg_catalog signature.
        let overload_rows = server
            .fetch_all::<BoolRow>(ServerRequest::strict_internal(
                catalog_query(6),
                &overload_params,
            ))
            .await
            .map_err(|_| PolicyError::unsupported())?;
        if !overload_rows
            .first()
            .is_some_and(|row| row.valid && row.value)
        {
            #[cfg(test)]
            eprintln!("strict catalog visible candidate set differs from registry");
            return Err(PolicyError::unsupported());
        }

        let operator_family_oids =
            registry::expected_oids_csv("pg_opfamily").ok_or_else(PolicyError::unsupported)?;
        let amop_oids =
            registry::expected_oids_csv("pg_amop").ok_or_else(PolicyError::unsupported)?;
        let amproc_oids =
            registry::expected_oids_csv("pg_amproc").ok_or_else(PolicyError::unsupported)?;
        let cast_oids =
            registry::expected_oids_csv("pg_cast").ok_or_else(PolicyError::unsupported)?;
        let dependency_params = [
            BindParameter::new(registry::scalar_oids_csv().as_bytes()),
            BindParameter::new(
                registry::expected_oids_csv("pg_opclass")
                    .ok_or_else(PolicyError::unsupported)?
                    .as_bytes(),
            ),
            BindParameter::new(operator_family_oids.as_bytes()),
            BindParameter::new(amop_oids.as_bytes()),
            BindParameter::new(amproc_oids.as_bytes()),
            BindParameter::new(registry::scalar_oids_csv().as_bytes()),
            BindParameter::new(cast_oids.as_bytes()),
        ];
        let dependency_rows = server
            .fetch_all::<DependencyRow>(ServerRequest::strict_internal(
                catalog_query(8),
                &dependency_params,
            ))
            .await
            .map_err(|_| PolicyError::unsupported())?;
        if !dependency_rows.first().is_some_and(DependencyRow::all_safe) {
            #[cfg(test)]
            if let Some(row) = dependency_rows.first() {
                eprintln!(
                    "strict catalog planner dependency closure differs from registry: {row:?}"
                );
            }
            return Err(PolicyError::unsupported());
        }

        // Compare complete server rows for every catalog object in the pinned
        // dependency registry before allowing its resolver entries to be used.
        let oid_lists = registry::CATALOG_TABLES
            .iter()
            .map(|table| registry::expected_oids_csv(table).ok_or_else(PolicyError::unsupported))
            .collect::<Result<Vec<_>, _>>()?;
        let params = oid_lists
            .iter()
            .map(|ids| BindParameter::new(ids.as_bytes()))
            .collect::<Vec<_>>();
        let actual_rows = server
            .fetch_all::<RegistryRow>(ServerRequest::strict_internal(catalog_query(7), &params))
            .await
            .map_err(|_| PolicyError::unsupported())?;
        let mut actual_counts = BTreeMap::<String, usize>::new();
        #[cfg(test)]
        let capture_live_rows = std::env::var_os("STRICT_READ_CAPTURE_REGISTRY").is_some();
        #[cfg(test)]
        let mut live_rows = BTreeMap::<String, Vec<serde_json::Value>>::new();
        let mut registry_matches = true;
        for row in actual_rows {
            if !row.valid {
                registry_matches = false;
                continue;
            }
            let actual: serde_json::Value =
                serde_json::from_str(&row.json).map_err(|_| PolicyError::unsupported())?;
            #[cfg(test)]
            if capture_live_rows {
                live_rows
                    .entry(row.table.clone())
                    .or_default()
                    .push(actual.clone());
            }
            if !registry::exact_catalog_record(&row.table, row.oid, &actual) {
                #[cfg(test)]
                eprintln!(
                    "strict catalog mismatch table={} oid={} fields={:?}",
                    row.table,
                    row.oid,
                    registry::catalog_record_mismatch_fields(&row.table, row.oid, &actual),
                );
                registry_matches = false;
            }
            *actual_counts.entry(row.table).or_default() += 1;
        }
        #[cfg(test)]
        if capture_live_rows {
            let root = serde_json::json!({
                "postgres_major": registry::server_major().unwrap_or_default(),
                "source_image": registry::source_image().unwrap_or_default(),
                "tables": live_rows,
            });
            let path = std::env::var_os("STRICT_READ_CAPTURE_REGISTRY")
                .expect("capture path checked above");
            std::fs::write(
                path,
                serde_json::to_vec(&root).expect("catalog rows serialize"),
            )
            .expect("write disposable live catalog capture");
        }
        for table in registry::CATALOG_TABLES {
            if actual_counts.get(*table).copied() != registry::expected_count(table) {
                registry_matches = false;
            }
        }
        if !registry_matches {
            return Err(PolicyError::unsupported());
        }

        let role_rows = server
            .fetch_all::<RoleRow>(ServerRequest::strict_internal(catalog_query(5), &[]))
            .await
            .map_err(|_| PolicyError::unsupported())?;
        let role = role_rows
            .into_iter()
            .next()
            .filter(RoleRow::is_safe_application_role)
            .ok_or_else(PolicyError::unsupported)?;
        if role.oid != identity.role_oid {
            return Err(PolicyError::unsupported());
        }

        let mut relations = BTreeMap::new();
        for requested in &requirements.relations {
            if relations.contains_key(requested) {
                continue;
            }
            let params = [BindParameter::new(requested.as_bytes())];
            let relation_rows = server
                .fetch_all::<RelationRow>(ServerRequest::strict_internal(catalog_query(2), &params))
                .await
                .map_err(|_| PolicyError::unsupported())?;
            let relation = relation_rows
                .into_iter()
                .next()
                .filter(RelationRow::is_supported_base_table)
                .ok_or_else(PolicyError::unsupported)?;
            if relation.owner_oid == role.oid {
                return Err(PolicyError::unsupported());
            }
            let relation_id = BindParameter::new(relation.oid.to_string().as_bytes());
            let columns = server
                .fetch_all::<ColumnRow>(ServerRequest::strict_internal(
                    catalog_query(3),
                    std::slice::from_ref(&relation_id),
                ))
                .await
                .map_err(|_| PolicyError::unsupported())?;
            if columns.is_empty() || columns.iter().any(|column| !column.is_supported()) {
                return Err(PolicyError::unsupported());
            }
            let opclass_ids =
                registry::expected_opclass_oids_csv().ok_or_else(PolicyError::unsupported)?;
            let index_params = [
                relation_id.clone(),
                BindParameter::new(opclass_ids.as_bytes()),
            ];
            let indexes = server
                .fetch_all::<BoolRow>(ServerRequest::strict_internal(
                    catalog_query(4),
                    &index_params,
                ))
                .await
                .map_err(|_| PolicyError::unsupported())?;
            let indexes_safe = indexes.first().is_some_and(|row| row.valid && row.value);
            if !indexes_safe {
                return Err(PolicyError::unsupported());
            }
            relations.insert(
                requested.clone(),
                CatalogRelation {
                    relation,
                    columns,
                    indexes_safe,
                },
            );
        }

        Ok(Self {
            database_oid: identity.database_oid,
            role_oid: identity.role_oid,
            server_major: identity.server_major,
            connection: server.id(),
            transaction_generation,
            search_path,
            role,
            relations,
        })
    }

    pub(crate) fn identity(
        &self,
        policy: &ProcessPolicy,
        database_alias: &str,
        transaction_generation: u64,
    ) -> Result<CatalogIdentity, PolicyError> {
        let manifest = policy.manifest().ok_or_else(PolicyError::unsupported)?;
        let database = manifest
            .databases()
            .iter()
            .find(|db| db.name() == database_alias)
            .ok_or_else(PolicyError::unsupported)?;
        Ok(CatalogIdentity {
            backend_database_oid: self.database_oid,
            backend_role_oid: self.role_oid,
            connection: self.connection,
            transaction_generation: {
                if transaction_generation != self.transaction_generation {
                    return Err(PolicyError::unsupported());
                }
                self.transaction_generation
            },
            manifest_digest: policy.digest().0,
            schema_revision: manifest.schema_revision().to_owned(),
            database_alias: database.name().to_owned(),
        })
    }
}

pub(crate) fn verify_parse(
    policy: &ProcessPolicy,
    admitted: &AdmittedSql,
    catalog: &CatalogSnapshot,
    identity: CatalogIdentity,
    parameter_oids: &[u32],
) -> Result<CatalogProof, PolicyError> {
    if identity.backend_database_oid != catalog.database_oid
        || identity.backend_role_oid != catalog.role_oid
        || identity.connection != catalog.connection
        || identity.transaction_generation != catalog.transaction_generation
        || identity.manifest_digest != policy.digest().0
        || identity.schema_revision
            != policy
                .manifest()
                .ok_or_else(PolicyError::unsupported)?
                .schema_revision()
    {
        return Err(PolicyError::unsupported());
    }
    let database = policy
        .manifest()
        .and_then(|manifest| {
            manifest
                .databases()
                .iter()
                .find(|db| db.name() == identity.database_alias)
        })
        .ok_or_else(PolicyError::unsupported)?;
    if !catalog.role.is_safe_application_role()
        || catalog.search_path.first().map(String::as_str) != Some("pg_catalog")
    {
        return Err(PolicyError::unsupported());
    }
    for name in &admitted.catalog.relations {
        let relation = catalog
            .relations
            .get(name)
            .ok_or_else(PolicyError::unsupported)?;
        if !relation.relation.is_supported_base_table()
            || !relation.indexes_safe
            || !database.relations().iter().any(|expected| {
                expected.schema() == relation.relation.schema
                    && expected.name() == relation.relation.name
            })
        {
            return Err(PolicyError::unsupported());
        }
        // Every column is checked, not just referenced columns: row/tuple
        // expansion and planner dependency paths cannot hide custom types.
        if relation.columns.iter().any(|column| !column.is_supported()) {
            return Err(PolicyError::unsupported());
        }
    }
    resolve::prove(admitted, catalog, parameter_oids)?;
    Ok(CatalogProof {
        fingerprint: admitted.fingerprint,
        parameter_oids: parameter_oids.to_vec(),
        identity,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityRow {
    valid: bool,
    database_oid: u32,
    role_oid: u32,
    database_owner_oid: u32,
    can_create_in_database: bool,
    can_create_in_search_path: bool,
    server_major: u32,
}
impl From<DataRow> for IdentityRow {
    fn from(row: DataRow) -> Self {
        let database_oid = row.get::<Oid>(2, Format::Text).map(Oid::get);
        let role_oid = row.get::<Oid>(3, Format::Text).map(Oid::get);
        let database_owner_oid = row.get::<Oid>(4, Format::Text).map(Oid::get);
        let can_create_in_database = row.get::<bool>(5, Format::Text);
        let can_create_in_search_path = row.get::<bool>(6, Format::Text);
        let server_version = row.get_text(7).and_then(|value| value.parse::<u32>().ok());
        Self {
            valid: row.get_text(0).is_some()
                && row.get_text(1).is_some()
                && database_oid.is_some()
                && role_oid.is_some()
                && database_owner_oid.is_some()
                && can_create_in_search_path.is_some()
                && can_create_in_database.is_some()
                && server_version.is_some(),
            database_oid: database_oid.unwrap_or_default(),
            role_oid: role_oid.unwrap_or_default(),
            database_owner_oid: database_owner_oid.unwrap_or_default(),
            can_create_in_database: can_create_in_database.unwrap_or(true),
            can_create_in_search_path: can_create_in_search_path.unwrap_or(true),
            server_major: server_version
                .map(|value| value / 10_000)
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoolRow {
    valid: bool,
    value: bool,
}
impl From<DataRow> for BoolRow {
    fn from(row: DataRow) -> Self {
        let value = row.get::<bool>(0, Format::Text);
        Self {
            valid: value.is_some(),
            value: value.unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DependencyRow {
    valid: bool,
    safe_opclasses: bool,
    safe_amop: bool,
    safe_amproc: bool,
    safe_casts: bool,
}
impl DependencyRow {
    fn all_safe(&self) -> bool {
        self.valid && self.safe_opclasses && self.safe_amop && self.safe_amproc && self.safe_casts
    }
}
impl From<DataRow> for DependencyRow {
    fn from(row: DataRow) -> Self {
        let values = (0..4)
            .map(|index| row.get::<bool>(index, Format::Text))
            .collect::<Vec<_>>();
        Self {
            valid: values.iter().all(Option::is_some),
            safe_opclasses: values[0].unwrap_or(false),
            safe_amop: values[1].unwrap_or(false),
            safe_amproc: values[2].unwrap_or(false),
            safe_casts: values[3].unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryRow {
    valid: bool,
    table: String,
    oid: u32,
    json: String,
}
impl From<DataRow> for RegistryRow {
    fn from(row: DataRow) -> Self {
        let table = row.get_text(0);
        let oid = row.get::<Oid>(1, Format::Text).map(Oid::get);
        let json = row.get_text(2);
        Self {
            valid: table.is_some() && oid.is_some() && json.is_some(),
            table: table.unwrap_or_default(),
            oid: oid.unwrap_or_default(),
            json: json.unwrap_or_default(),
        }
    }
}

const CATALOG_SQL: &str = include_str!("catalog.sql");
fn catalog_query(index: usize) -> &'static str {
    CATALOG_SQL.split(';').nth(index).unwrap_or_default().trim()
}

fn parse_pg_array(value: &str) -> Option<Vec<String>> {
    let body = value.strip_prefix('{')?.strip_suffix('}')?;
    if body.is_empty() {
        return Some(vec![]);
    }
    let mut schemas = Vec::new();
    for value in body.split(',') {
        if value.is_empty() || value.contains('"') || value.contains('\\') {
            return None;
        }
        schemas.push(value.to_owned());
    }
    Some(schemas)
}

fn names_csv(names: &std::collections::BTreeSet<String>) -> String {
    names
        .iter()
        .filter_map(|name| name.rsplit('.').next())
        .map(|name| name.trim_matches('"'))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests;
