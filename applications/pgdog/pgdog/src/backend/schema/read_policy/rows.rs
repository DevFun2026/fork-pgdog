use crate::net::messages::{DataRow, Format};
use pgdog_postgres_types::Oid;

/// Catalog facts used by the strict-read proof. Every OID is read from the
/// protected backend and retained alongside its qualified name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelationRow {
    pub(crate) valid: bool,
    pub(crate) oid: u32,
    pub(crate) schema: String,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) persistence: String,
    pub(crate) owner_oid: u32,
    pub(crate) row_security: bool,
    pub(crate) force_row_security: bool,
    pub(crate) has_rules: bool,
    pub(crate) is_partition: bool,
    pub(crate) has_inheritance: bool,
    pub(crate) namespace_can_create: bool,
    pub(crate) access_method: String,
}

impl RelationRow {
    pub(crate) fn is_supported_base_table(&self) -> bool {
        self.oid != 0
            && self.valid
            && self.owner_oid != 0
            && !self.schema.is_empty()
            && !self.name.is_empty()
            && self.kind == "r"
            && self.persistence == "p"
            && !self.row_security
            && !self.force_row_security
            && !self.has_rules
            && !self.is_partition
            && !self.has_inheritance
            && !self.namespace_can_create
            && self.access_method == "heap"
    }
}

impl From<DataRow> for RelationRow {
    fn from(row: DataRow) -> Self {
        let oid = row.get::<Oid>(0, Format::Text).map(Oid::get);
        let schema = row.get_text(1);
        let name = row.get_text(2);
        let kind = row.get_text(3);
        let persistence = row.get_text(4);
        let owner_oid = row.get::<Oid>(5, Format::Text).map(Oid::get);
        let row_security = row.get::<bool>(6, Format::Text);
        let force_row_security = row.get::<bool>(7, Format::Text);
        let has_rules = row.get::<bool>(8, Format::Text);
        let is_partition = row.get::<bool>(9, Format::Text);
        let has_inheritance = row.get::<bool>(10, Format::Text);
        let namespace_can_create = row.get::<bool>(11, Format::Text);
        let access_method = row.get_text(12);
        let valid = [
            oid.is_some(),
            schema.is_some(),
            name.is_some(),
            kind.is_some(),
            persistence.is_some(),
            owner_oid.is_some(),
            row_security.is_some(),
            force_row_security.is_some(),
            has_rules.is_some(),
            is_partition.is_some(),
            has_inheritance.is_some(),
            access_method.is_some(),
            namespace_can_create.is_some(),
        ]
        .into_iter()
        .all(|value| value);
        Self {
            valid,
            oid: oid.unwrap_or_default(),
            schema: schema.unwrap_or_default(),
            name: name.unwrap_or_default(),
            kind: kind.unwrap_or_default(),
            persistence: persistence.unwrap_or_default(),
            owner_oid: owner_oid.unwrap_or_default(),
            row_security: row_security.unwrap_or(true),
            force_row_security: force_row_security.unwrap_or(true),
            has_rules: has_rules.unwrap_or(true),
            is_partition: is_partition.unwrap_or(true),
            has_inheritance: has_inheritance.unwrap_or(true),
            namespace_can_create: namespace_can_create.unwrap_or(true),
            access_method: access_method.unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ColumnRow {
    pub(crate) valid: bool,
    pub(crate) relation_oid: u32,
    pub(crate) name: String,
    pub(crate) type_oid: u32,
    pub(crate) type_schema: String,
    pub(crate) type_name: String,
    pub(crate) type_kind: String,
    pub(crate) base_type_oid: u32,
    pub(crate) type_input_oid: u32,
    pub(crate) type_output_oid: u32,
    pub(crate) type_receive_oid: u32,
    pub(crate) type_send_oid: u32,
    pub(crate) not_null: bool,
    pub(crate) generated: String,
    pub(crate) identity: String,
    pub(crate) collation_oid: u32,
}

impl ColumnRow {
    pub(crate) fn is_supported(&self) -> bool {
        self.valid
            && !self.name.is_empty()
            && self.type_schema == "pg_catalog"
            && self.type_kind == "b"
            && self.base_type_oid == 0
            && self.generated.is_empty()
            && self.identity.is_empty()
            && crate::backend::schema::read_policy::registry::trusted_type_io(
                self.type_oid,
                &self.type_name,
                self.type_input_oid,
                self.type_output_oid,
                self.type_receive_oid,
                self.type_send_oid,
                self.collation_oid,
            )
            && (self.collation_oid == 0 || matches!(self.collation_oid, 100 | 950 | 951))
    }
}

impl From<DataRow> for ColumnRow {
    fn from(row: DataRow) -> Self {
        let relation_oid = row.get::<Oid>(0, Format::Text).map(Oid::get);
        let name = row.get_text(1);
        let type_oid = row.get::<Oid>(2, Format::Text).map(Oid::get);
        let type_schema = row.get_text(3);
        let type_name = row.get_text(4);
        let type_kind = row.get_text(5);
        let base_type_oid = row.get::<Oid>(6, Format::Text).map(Oid::get);
        let type_input_oid = row.get::<Oid>(7, Format::Text).map(Oid::get);
        let type_output_oid = row.get::<Oid>(8, Format::Text).map(Oid::get);
        let type_receive_oid = row.get::<Oid>(9, Format::Text).map(Oid::get);
        let type_send_oid = row.get::<Oid>(10, Format::Text).map(Oid::get);
        let not_null = row.get::<bool>(11, Format::Text);
        let generated = row.get_text(12);
        let identity = row.get_text(13);
        let collation_oid = row.get::<Oid>(14, Format::Text).map(Oid::get);
        let valid = [
            relation_oid.is_some(),
            name.is_some(),
            type_oid.is_some(),
            type_schema.is_some(),
            type_name.is_some(),
            not_null.is_some(),
            type_kind.is_some(),
            base_type_oid.is_some(),
            type_input_oid.is_some(),
            type_output_oid.is_some(),
            type_receive_oid.is_some(),
            type_send_oid.is_some(),
            generated.is_some(),
            identity.is_some(),
            collation_oid.is_some(),
        ]
        .into_iter()
        .all(|value| value);
        Self {
            valid,
            relation_oid: relation_oid.unwrap_or_default(),
            name: name.unwrap_or_default(),
            type_oid: type_oid.unwrap_or_default(),
            type_schema: type_schema.unwrap_or_default(),
            type_name: type_name.unwrap_or_default(),
            type_kind: type_kind.unwrap_or_default(),
            base_type_oid: base_type_oid.unwrap_or_default(),
            type_input_oid: type_input_oid.unwrap_or_default(),
            type_output_oid: type_output_oid.unwrap_or_default(),
            type_receive_oid: type_receive_oid.unwrap_or_default(),
            type_send_oid: type_send_oid.unwrap_or_default(),
            not_null: not_null.unwrap_or(false),
            generated: generated.unwrap_or_default(),
            identity: identity.unwrap_or_default(),
            collation_oid: collation_oid.unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoleRow {
    pub(crate) valid: bool,
    pub(crate) oid: u32,
    pub(crate) superuser: bool,
    pub(crate) create_role: bool,
    pub(crate) create_database: bool,
    pub(crate) replication: bool,
    pub(crate) bypass_rls: bool,
    pub(crate) inherit: bool,
    pub(crate) has_memberships: bool,
}

impl RoleRow {
    pub(crate) fn is_safe_application_role(&self) -> bool {
        self.valid
            && self.oid != 0
            && !self.superuser
            && !self.create_role
            && !self.create_database
            && !self.replication
            && !self.bypass_rls
            && !self.has_memberships
    }
}

impl From<DataRow> for RoleRow {
    fn from(row: DataRow) -> Self {
        let oid = row.get::<Oid>(0, Format::Text).map(Oid::get);
        let superuser = row.get::<bool>(1, Format::Text);
        let create_role = row.get::<bool>(2, Format::Text);
        let create_database = row.get::<bool>(3, Format::Text);
        let replication = row.get::<bool>(4, Format::Text);
        let bypass_rls = row.get::<bool>(5, Format::Text);
        let inherit = row.get::<bool>(6, Format::Text);
        let has_memberships = row.get::<bool>(7, Format::Text);
        let valid = [
            oid.is_some(),
            superuser.is_some(),
            create_role.is_some(),
            create_database.is_some(),
            replication.is_some(),
            bypass_rls.is_some(),
            inherit.is_some(),
            has_memberships.is_some(),
        ]
        .into_iter()
        .all(|v| v);
        Self {
            valid,
            oid: oid.unwrap_or_default(),
            superuser: superuser.unwrap_or(true),
            create_role: create_role.unwrap_or(true),
            create_database: create_database.unwrap_or(true),
            replication: replication.unwrap_or(true),
            bypass_rls: bypass_rls.unwrap_or(true),
            inherit: inherit.unwrap_or(false),
            has_memberships: has_memberships.unwrap_or(true),
        }
    }
}
