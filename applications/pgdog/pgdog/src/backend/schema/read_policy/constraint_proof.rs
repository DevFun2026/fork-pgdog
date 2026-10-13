//! Typed proof for PostgreSQL constraints bound to relation, index, expression,
//! and immutable dependency evidence.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{
    dependency_profile::DependencyProof, expression_proof::ExpressionProof,
    index_proof::IndexProof, node_tree::ExpressionKind, rows::ColumnRow, type_proof::EnumTypeProof,
};

const MAX_CONSTRAINT_BYTES: usize = 1024 * 1024;
const MAX_KEY_COLUMNS: usize = 32;
const MAX_RELATION_COLUMNS: usize = 1600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    InvalidMetadata,
    UnsupportedConstraint,
    MissingProof,
    TypeMismatch,
    OperatorMismatch,
    IndexMismatch,
    ExpressionMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConstraintProof {
    constraint_oid: u32,
    relation_oid: u32,
    proof_digest: [u8; 32],
    dependency_digest: [u8; 32],
    enum_digests: BTreeMap<u32, [u8; 32]>,
}

impl ConstraintProof {
    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.proof_digest
    }

    #[cfg(test)]
    pub(crate) fn constraint_oid(&self) -> u32 {
        self.constraint_oid
    }

    #[cfg(test)]
    pub(crate) fn relation_oid(&self) -> u32 {
        self.relation_oid
    }

    #[cfg(test)]
    pub(crate) fn matches_dependencies(&self, dependencies: &DependencyProof) -> bool {
        self.dependency_digest == *dependencies.digest()
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "relation columns, referenced columns, index/expression evidence, dependency profile, and enum proofs are independent trust inputs and are clearer as explicit proof inputs than as an opaque aggregate"
)]
pub(crate) fn prove(
    constraint: &Value,
    relation_oid: u32,
    columns: &[ColumnRow],
    referenced_columns: &BTreeMap<u32, Vec<ColumnRow>>,
    indexes: &BTreeMap<u32, IndexProof>,
    check: Option<&ExpressionProof>,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
) -> Result<ConstraintProof, Error> {
    if relation_oid == 0 || !matches!(dependencies.major(), 12 | 18) {
        return Err(Error::InvalidMetadata);
    }
    let fields = constraint.as_object().ok_or(Error::InvalidMetadata)?;
    validate_constraint_field_shape(fields, dependencies.major())?;
    if serde_json::to_vec(constraint)
        .map_err(|_| Error::InvalidMetadata)?
        .len()
        > MAX_CONSTRAINT_BYTES
    {
        return Err(Error::InvalidMetadata);
    }
    let constraint_oid = oid(fields.get("oid"), false)?;
    if oid(fields.get("conrelid"), false)? != relation_oid
        || oid(fields.get("contypid"), true)? != 0
    {
        return Err(Error::InvalidMetadata);
    }
    let kind = fields
        .get("contype")
        .and_then(Value::as_str)
        .filter(|kind| kind.len() == 1)
        .ok_or(Error::InvalidMetadata)?;
    let name = fields
        .get("conname")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty() && name.len() <= 63 && !name.contains('\0'))
        .ok_or(Error::InvalidMetadata)?;
    let _ = name;
    oid(fields.get("connamespace"), false)?;
    let deferrable = boolean(fields.get("condeferrable"))?;
    let deferred = boolean(fields.get("condeferred"))?;
    let validated = boolean(fields.get("convalidated"))?;
    let _local = boolean(fields.get("conislocal"))?;
    let _noinherit = boolean(fields.get("connoinherit"))?;
    let inhcount = number(fields.get("coninhcount"))?;
    // NOT VALID controls planner inference, not callback safety. CHECK/FK
    // still traverse exactly the same closed expression/operator proof below.
    if deferred && !deferrable
        || !(0..=MAX_KEY_COLUMNS as i64).contains(&inhcount)
        || (!validated && !matches!(kind, "c" | "f"))
    {
        return Err(Error::InvalidMetadata);
    }
    let update_action = one_char(fields.get("confupdtype"))?;
    let delete_action = one_char(fields.get("confdeltype"))?;
    let match_type = one_char(fields.get("confmatchtype"))?;
    let actions_valid = if kind == "f" {
        matches!(update_action, 'a' | 'r' | 'c' | 'n' | 'd')
            && matches!(delete_action, 'a' | 'r' | 'c' | 'n' | 'd')
            && matches!(match_type, 's' | 'f')
    } else {
        (update_action, delete_action, match_type) == (' ', ' ', ' ')
    };
    if !actions_valid {
        return Err(Error::UnsupportedConstraint);
    }
    let delete_set_columns = if dependencies.major() == 18 {
        if boolean(fields.get("conperiod"))? {
            return Err(Error::UnsupportedConstraint);
        }
        if !boolean(fields.get("conenforced"))? {
            return Err(Error::UnsupportedConstraint);
        }
        let set_columns = optional_i16_vector(fields.get("confdelsetcols"), MAX_RELATION_COLUMNS)?;
        if kind != "f" && !set_columns.is_empty() {
            return Err(Error::InvalidMetadata);
        }
        if kind == "f" {
            if !matches!(delete_action, 'n' | 'd') && !set_columns.is_empty() {
                return Err(Error::InvalidMetadata);
            }
            if set_columns.iter().any(|attnum| *attnum <= 0) {
                return Err(Error::InvalidMetadata);
            }
        }
        set_columns
    } else {
        Vec::new()
    };
    let local_columns = column_map(columns, relation_oid)?;
    let mut enum_digests = BTreeMap::new();
    let mut used_indexes = BTreeMap::<u32, [u8; 32]>::new();

    match kind {
        "c" => {
            if check.is_none()
                || !fields
                    .get("conbin")
                    .and_then(Value::as_str)
                    .is_some_and(|source| {
                        !source.is_empty() && source.len() <= MAX_CONSTRAINT_BYTES
                    })
                || oid(fields.get("conindid"), true)? != 0
                || oid(fields.get("confrelid"), true)? != 0
                || fields.get("confkey").is_some_and(|value| !value.is_null())
                || fields
                    .get("conpfeqop")
                    .is_some_and(|value| !value.is_null())
                || fields
                    .get("conppeqop")
                    .is_some_and(|value| !value.is_null())
                || fields
                    .get("conffeqop")
                    .is_some_and(|value| !value.is_null())
                || fields
                    .get("conexclop")
                    .is_some_and(|value| !value.is_null())
            {
                return Err(Error::ExpressionMismatch);
            }
            let expression = check.ok_or(Error::MissingProof)?;
            let source = fields["conbin"].as_str().ok_or(Error::InvalidMetadata)?;
            if expression.kind() != ExpressionKind::Check
                || expression.relation_oid() != relation_oid
                || expression.source_digest() != &sha256(source.as_bytes())
                || expression.source_ordinal() != 0
                || expression.root_type() != 16
                || !expression.matches_dependencies(dependencies)
            {
                return Err(Error::ExpressionMismatch);
            }
            merge_enum_digests(expression.enum_digests(), enums, &mut enum_digests)?;
            let key = optional_i16_vector(fields.get("conkey"), MAX_RELATION_COLUMNS)?;
            for attnum in key {
                if !local_columns.contains_key(&attnum) {
                    return Err(Error::TypeMismatch);
                }
            }
        }
        "p" | "u" => {
            if check.is_some()
                || fields.get("conbin").is_some_and(|value| !value.is_null())
                || oid(fields.get("confrelid"), true)? != 0
                || fields.get("confkey").is_some_and(|value| !value.is_null())
                || fields
                    .get("conpfeqop")
                    .is_some_and(|value| !value.is_null())
                || fields
                    .get("conppeqop")
                    .is_some_and(|value| !value.is_null())
                || fields
                    .get("conffeqop")
                    .is_some_and(|value| !value.is_null())
                || fields
                    .get("conexclop")
                    .is_some_and(|value| !value.is_null())
            {
                return Err(Error::InvalidMetadata);
            }
            let key = required_i16_vector(fields.get("conkey"), MAX_KEY_COLUMNS)?;
            let index_oid = oid(fields.get("conindid"), false)?;
            let index = indexes.get(&index_oid).ok_or(Error::MissingProof)?;
            if index.index_oid() != index_oid
                || index.relation_oid() != relation_oid
                || !index.matches_dependencies(dependencies)
                || !index.is_unique()
                || index.is_exclusion()
                || index.is_immediate() == deferrable
                || index.has_predicate()
                || index.key_attnums() != key.as_slice()
                || (kind == "p" && !index.is_primary())
                || (kind == "u" && index.is_primary())
            {
                return Err(Error::IndexMismatch);
            }
            let observed = columns_for_attnums(&local_columns, &key)?;
            if observed
                .iter()
                .map(|column| column.type_oid)
                .ne(index.key_types().iter().copied())
            {
                return Err(Error::TypeMismatch);
            }
            for column in observed {
                record_type(column.type_oid, dependencies, enums, &mut enum_digests)?;
            }
            used_indexes.insert(index_oid, *index.digest());
        }
        "f" => {
            if check.is_some()
                || fields.get("conbin").is_some_and(|value| !value.is_null())
                || fields
                    .get("conexclop")
                    .is_some_and(|value| !value.is_null())
            {
                return Err(Error::InvalidMetadata);
            }
            let foreign_key = required_i16_vector(fields.get("conkey"), MAX_KEY_COLUMNS)?;
            let referenced_key = required_i16_vector(fields.get("confkey"), MAX_KEY_COLUMNS)?;
            if delete_set_columns
                .iter()
                .any(|attnum| !foreign_key.contains(attnum))
            {
                return Err(Error::InvalidMetadata);
            }
            if foreign_key.len() != referenced_key.len() {
                return Err(Error::TypeMismatch);
            }
            if match_type == 'f' && foreign_key.is_empty() {
                return Err(Error::InvalidMetadata);
            }
            let referenced_relation = oid(fields.get("confrelid"), false)?;
            let referenced = referenced_columns
                .get(&referenced_relation)
                .ok_or(Error::MissingProof)?;
            let referenced_map = column_map(referenced, referenced_relation)?;
            let local = columns_for_attnums(&local_columns, &foreign_key)?;
            let remote = columns_for_attnums(&referenced_map, &referenced_key)?;
            let index_oid = oid(fields.get("conindid"), false)?;
            let index = indexes.get(&index_oid).ok_or(Error::MissingProof)?;
            if index.index_oid() != index_oid
                || index.relation_oid() != referenced_relation
                || !index.matches_dependencies(dependencies)
                || !index.is_unique()
                || !index.is_immediate()
                || index.is_exclusion()
                || index.has_predicate()
                || index.key_attnums() != referenced_key.as_slice()
                || index.key_types().len() != referenced_key.len()
                || remote
                    .iter()
                    .map(|column| column.type_oid)
                    .ne(index.key_types().iter().copied())
            {
                return Err(Error::IndexMismatch);
            }
            let pfeq = required_oid_vector(fields.get("conpfeqop"), foreign_key.len())?;
            let ppeq = required_oid_vector(fields.get("conppeqop"), foreign_key.len())?;
            let ffeq = required_oid_vector(fields.get("conffeqop"), foreign_key.len())?;
            for position in 0..foreign_key.len() {
                prove_equality_operator(
                    pfeq[position],
                    remote[position].type_oid,
                    local[position].type_oid,
                    dependencies,
                    enums,
                    &mut enum_digests,
                )?;
                prove_equality_operator(
                    ppeq[position],
                    remote[position].type_oid,
                    remote[position].type_oid,
                    dependencies,
                    enums,
                    &mut enum_digests,
                )?;
                prove_equality_operator(
                    ffeq[position],
                    local[position].type_oid,
                    local[position].type_oid,
                    dependencies,
                    enums,
                    &mut enum_digests,
                )?;
                record_type(
                    local[position].type_oid,
                    dependencies,
                    enums,
                    &mut enum_digests,
                )?;
                record_type(
                    remote[position].type_oid,
                    dependencies,
                    enums,
                    &mut enum_digests,
                )?;
            }
            used_indexes.insert(index_oid, *index.digest());
        }
        "x" => {
            if check.is_some()
                || fields.get("conbin").is_some_and(|value| !value.is_null())
                || oid(fields.get("confrelid"), true)? != 0
                || fields.get("confkey").is_some_and(|value| !value.is_null())
                || fields
                    .get("conpfeqop")
                    .is_some_and(|value| !value.is_null())
                || fields
                    .get("conppeqop")
                    .is_some_and(|value| !value.is_null())
                || fields
                    .get("conffeqop")
                    .is_some_and(|value| !value.is_null())
            {
                return Err(Error::InvalidMetadata);
            }
            let key = nonnegative_i16_vector(fields.get("conkey"), MAX_KEY_COLUMNS)?;
            let index_oid = oid(fields.get("conindid"), false)?;
            let index = indexes.get(&index_oid).ok_or(Error::MissingProof)?;
            if index.index_oid() != index_oid
                || index.relation_oid() != relation_oid
                || !index.matches_dependencies(dependencies)
                || !index.is_exclusion()
                || index.is_immediate() == deferrable
                || index.is_unique()
                || index.is_primary()
                || index.key_attnums() != key.as_slice()
            {
                return Err(Error::IndexMismatch);
            }
            let operators = required_oid_vector(fields.get("conexclop"), key.len())?;
            if index.key_types().len() != key.len() {
                return Err(Error::TypeMismatch);
            }
            for (position, (operator, type_oid)) in
                operators.iter().zip(index.key_types()).enumerate()
            {
                // PostgreSQL's exclusion operators use GiST search strategy 3
                // for the reviewed equality and range-overlap keys. Bind each
                // operator to the family's exact key position before proving
                // its callback semantics.
                if !index.supports_exclusion_operator(position, *operator, 3, dependencies) {
                    return Err(Error::OperatorMismatch);
                }
                prove_exclusion_operator(
                    *operator,
                    *type_oid,
                    dependencies,
                    enums,
                    &mut enum_digests,
                )?;
                record_type(*type_oid, dependencies, enums, &mut enum_digests)?;
            }
            for attnum in key.iter().filter(|attnum| **attnum > 0) {
                let column = local_columns.get(attnum).ok_or(Error::TypeMismatch)?;
                record_type(column.type_oid, dependencies, enums, &mut enum_digests)?;
            }
            used_indexes.insert(index_oid, *index.digest());
        }
        "n" if dependencies.major() == 18 => {
            if check.is_some()
                || fields.get("conbin").is_some_and(|value| !value.is_null())
                || oid(fields.get("conindid"), true)? != 0
                || oid(fields.get("confrelid"), true)? != 0
                || fields.get("confkey").is_some_and(|value| !value.is_null())
                || fields
                    .get("conpfeqop")
                    .is_some_and(|value| !value.is_null())
                || fields
                    .get("conppeqop")
                    .is_some_and(|value| !value.is_null())
                || fields
                    .get("conffeqop")
                    .is_some_and(|value| !value.is_null())
                || fields
                    .get("conexclop")
                    .is_some_and(|value| !value.is_null())
                || deferrable
                || deferred
            {
                return Err(Error::InvalidMetadata);
            }
            let key = required_i16_vector(fields.get("conkey"), 1)?;
            let column = *columns_for_attnums(&local_columns, &key)?
                .first()
                .ok_or(Error::TypeMismatch)?;
            if !column.not_null {
                return Err(Error::TypeMismatch);
            }
            record_type(column.type_oid, dependencies, enums, &mut enum_digests)?;
        }
        _ => return Err(Error::UnsupportedConstraint),
    }

    let expression_binding = check.map(expression_binding);
    let encoded = serde_json::to_vec(&(
        constraint,
        dependencies.digest(),
        used_indexes,
        expression_binding,
        &enum_digests,
    ))
    .map_err(|_| Error::InvalidMetadata)?;
    let proof_digest = sha256(&encoded);
    Ok(ConstraintProof {
        constraint_oid,
        relation_oid,
        proof_digest,
        dependency_digest: *dependencies.digest(),
        enum_digests,
    })
}

fn validate_constraint_field_shape(fields: &Map<String, Value>, major: u32) -> Result<(), Error> {
    const COMMON: &[&str] = &[
        "oid",
        "conname",
        "connamespace",
        "contype",
        "condeferrable",
        "condeferred",
        "convalidated",
        "conrelid",
        "contypid",
        "conindid",
        "conparentid",
        "confrelid",
        "confupdtype",
        "confdeltype",
        "confmatchtype",
        "conislocal",
        "coninhcount",
        "connoinherit",
        "conkey",
        "confkey",
        "conpfeqop",
        "conppeqop",
        "conffeqop",
        "conexclop",
        "conbin",
    ];
    if !matches!(major, 12 | 18) {
        return Err(Error::InvalidMetadata);
    }
    let expected_len = COMMON.len() + if major == 18 { 3 } else { 0 };
    if fields.len() != expected_len
        || fields.keys().any(|key| {
            !(COMMON.contains(&key.as_str())
                || major == 18
                    && matches!(key.as_str(), "conperiod" | "conenforced" | "confdelsetcols"))
        })
        || (major == 18
            && ["conperiod", "conenforced", "confdelsetcols"]
                .iter()
                .any(|key| !fields.contains_key(*key)))
    {
        return Err(Error::InvalidMetadata);
    }
    Ok(())
}

type ExpressionBinding<'a> = (
    &'a [u8; 32],
    usize,
    u32,
    u32,
    &'static str,
    &'a BTreeMap<u32, [u8; 32]>,
);

fn expression_binding(expression: &ExpressionProof) -> ExpressionBinding<'_> {
    let kind = match expression.kind() {
        ExpressionKind::Check => "check",
        ExpressionKind::IndexExpression => "index_expression",
        ExpressionKind::Predicate => "predicate",
    };
    (
        expression.source_digest(),
        expression.source_ordinal(),
        expression.root_type(),
        expression.relation_oid(),
        kind,
        expression.enum_digests(),
    )
}

fn merge_enum_digests(
    source: &BTreeMap<u32, [u8; 32]>,
    enums: &BTreeMap<u32, EnumTypeProof>,
    target: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<(), Error> {
    for (type_oid, digest) in source {
        if enums
            .get(type_oid)
            .is_none_or(|proof| proof.type_oid() != *type_oid || proof.digest() != digest)
            || target
                .insert(*type_oid, *digest)
                .is_some_and(|previous| previous != *digest)
        {
            return Err(Error::TypeMismatch);
        }
    }
    Ok(())
}

fn column_map(
    columns: &[ColumnRow],
    relation_oid: u32,
) -> Result<BTreeMap<i16, &ColumnRow>, Error> {
    if columns.is_empty() || columns.len() > MAX_RELATION_COLUMNS {
        return Err(Error::InvalidMetadata);
    }
    let mut by_attnum = BTreeMap::new();
    for column in columns {
        let attnum = column.attribute_number().ok_or(Error::InvalidMetadata)?;
        if !column.valid
            || column.relation_oid != relation_oid
            || column.type_oid == 0
            || !column.generated.is_empty()
            || !column.identity.is_empty()
            || by_attnum.insert(attnum, column).is_some()
        {
            return Err(Error::InvalidMetadata);
        }
    }
    Ok(by_attnum)
}

fn columns_for_attnums<'a>(
    columns: &BTreeMap<i16, &'a ColumnRow>,
    attnums: &[i16],
) -> Result<Vec<&'a ColumnRow>, Error> {
    if attnums.is_empty() || attnums.len() > MAX_KEY_COLUMNS {
        return Err(Error::InvalidMetadata);
    }
    let mut seen = BTreeSet::new();
    attnums
        .iter()
        .map(|attnum| {
            if *attnum <= 0 || !seen.insert(*attnum) {
                return Err(Error::InvalidMetadata);
            }
            columns.get(attnum).copied().ok_or(Error::TypeMismatch)
        })
        .collect()
}

fn record_type(
    type_oid: u32,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<(), Error> {
    if type_oid == 0 {
        return Err(Error::TypeMismatch);
    }
    if let Some(proof) = enums.get(&type_oid) {
        if proof.type_oid() != type_oid {
            return Err(Error::TypeMismatch);
        }
        enum_digests.insert(type_oid, *proof.digest());
        return Ok(());
    }
    runtime_fields(dependencies, "pg_type", type_oid).map(|_| ())
}

fn prove_equality_operator(
    operator_oid: u32,
    left_type: u32,
    right_type: u32,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<(), Error> {
    let fields = runtime_fields(dependencies, "pg_operator", operator_oid)?;
    let namespace = oid(fields.get("oprnamespace"), false)?;
    let name = fields.get("oprname").and_then(Value::as_str);
    let formal_left = catalog_oid(fields.get("oprleft"), "pg_type", dependencies, false)?;
    let formal_right = catalog_oid(fields.get("oprright"), "pg_type", dependencies, false)?;
    let function_oid = catalog_oid(fields.get("oprcode"), "pg_proc", dependencies, false)?;
    if namespace != 11
        || !is_core_identity(dependencies, "pg_operator", operator_oid)
        || name != Some("=")
        || fields.get("oprkind").and_then(Value::as_str) != Some("b")
        || oid(fields.get("oprresult"), false)? != 16
        || fields.get("oprcanmerge").and_then(Value::as_bool) != Some(true)
        || !type_argument_matches(left_type, formal_left, dependencies, enums, enum_digests)?
        || !type_argument_matches(right_type, formal_right, dependencies, enums, enum_digests)?
    {
        return Err(Error::OperatorMismatch);
    }
    let proc = runtime_fields(dependencies, "pg_proc", function_oid)?;
    let proc_namespace = oid(proc.get("pronamespace"), false)?;
    let proc_args = oid_vector(proc.get("proargtypes"), 16, Some(dependencies))?;
    let callback_name = proc
        .get("proname")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if proc_namespace != 11
        || !is_core_identity(dependencies, "pg_proc", function_oid)
        || !EQUALITY_CALLBACKS.contains(&callback_name)
        || catalog_oid(proc.get("prorettype"), "pg_type", dependencies, false)? != 16
        || proc_args != [formal_left, formal_right]
        || proc.get("prokind").and_then(Value::as_str) != Some("f")
        || proc.get("provolatile").and_then(Value::as_str) != Some("i")
        || proc.get("proisstrict").and_then(Value::as_bool) != Some(true)
        || proc.get("prosecdef").and_then(Value::as_bool) != Some(false)
        || proc.get("prolang").and_then(parse_u32_value) != Some(12)
    {
        return Err(Error::OperatorMismatch);
    }
    Ok(())
}

const EQUALITY_CALLBACKS: &[&str] = &[
    "booleq",
    "byteaeq",
    "chareq",
    "nameeq",
    "int2eq",
    "int4eq",
    "int8eq",
    "texteq",
    "bpchareq",
    "float4eq",
    "float8eq",
    "numeric_eq",
    "date_eq",
    "time_eq",
    "timetz_eq",
    "timestamp_eq",
    "timestamptz_eq",
    "interval_eq",
    "uuid_eq",
    "enum_eq",
    "array_eq",
    "range_eq",
];

fn prove_exclusion_operator(
    operator_oid: u32,
    key_type: u32,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<(), Error> {
    if key_type == 1043 {
        // varchar keys are admitted only through the reviewed text equality
        // operator and its already-validated binary-coercion closure.
        return prove_equality_operator(
            operator_oid,
            key_type,
            key_type,
            dependencies,
            enums,
            enum_digests,
        );
    }
    if key_type != 3910 {
        return Err(Error::OperatorMismatch);
    }
    prove_range_type(key_type, dependencies)?;
    let fields = runtime_fields(dependencies, "pg_operator", operator_oid)?;
    let formal_left = catalog_oid(fields.get("oprleft"), "pg_type", dependencies, false)?;
    let formal_right = catalog_oid(fields.get("oprright"), "pg_type", dependencies, false)?;
    let function_oid = catalog_oid(fields.get("oprcode"), "pg_proc", dependencies, false)?;
    if !is_core_identity(dependencies, "pg_operator", operator_oid)
        || oid(fields.get("oprnamespace"), false)? != 11
        || fields.get("oprname").and_then(Value::as_str) != Some("&&")
        || fields.get("oprkind").and_then(Value::as_str) != Some("b")
        || oid(fields.get("oprresult"), false)? != 16
        || formal_left != 3831
        || formal_right != 3831
    {
        return Err(Error::OperatorMismatch);
    }
    let proc = runtime_fields(dependencies, "pg_proc", function_oid)?;
    if !is_core_identity(dependencies, "pg_proc", function_oid)
        || oid(proc.get("pronamespace"), false)? != 11
        || proc.get("proname").and_then(Value::as_str) != Some("range_overlaps")
        || catalog_oid(proc.get("prorettype"), "pg_type", dependencies, false)? != 16
        || oid_vector(proc.get("proargtypes"), 16, Some(dependencies))? != [3831, 3831]
        || proc.get("prokind").and_then(Value::as_str) != Some("f")
        || proc.get("provolatile").and_then(Value::as_str) != Some("i")
        || proc.get("proisstrict").and_then(Value::as_bool) != Some(true)
        || proc.get("prosecdef").and_then(Value::as_bool) != Some(false)
        || proc.get("prolang").and_then(parse_u32_value) != Some(12)
    {
        return Err(Error::OperatorMismatch);
    }
    Ok(())
}

fn type_argument_matches(
    actual: u32,
    formal: u32,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<bool, Error> {
    if actual == formal {
        record_type(actual, dependencies, enums, enum_digests)?;
        return Ok(true);
    }
    if formal == 3500 && enums.contains_key(&actual) {
        record_type(actual, dependencies, enums, enum_digests)?;
        return Ok(true);
    }
    if formal == 3831 && actual == 3910 {
        prove_range_type(actual, dependencies)?;
        return Ok(true);
    }
    if formal == 2277 && is_approved_array_type(actual, dependencies) {
        return Ok(true);
    }
    Ok(has_binary_cast(actual, formal, dependencies))
}

fn is_approved_array_type(type_oid: u32, dependencies: &DependencyProof) -> bool {
    const ARRAYS: &[u32] = &[1007, 1009, 1182, 1231];
    if !ARRAYS.contains(&type_oid) {
        return false;
    }
    runtime_fields(dependencies, "pg_type", type_oid)
        .ok()
        .is_some_and(|fields| {
            oid(fields.get("typnamespace"), false).ok() == Some(11)
                && fields.get("typtype").and_then(Value::as_str) == Some("b")
                && fields.get("typcategory").and_then(Value::as_str) == Some("A")
                && oid(fields.get("typbasetype"), true).ok() == Some(0)
                && oid(fields.get("typelem"), false)
                    .ok()
                    .is_some_and(|element| {
                        runtime_fields(dependencies, "pg_type", element)
                            .ok()
                            .and_then(|fields| oid(fields.get("typarray"), true).ok())
                            == Some(type_oid)
                    })
        })
}

fn prove_range_type(type_oid: u32, dependencies: &DependencyProof) -> Result<(), Error> {
    let ty = runtime_fields(dependencies, "pg_type", type_oid)?;
    let range = runtime_fields(dependencies, "pg_range", type_oid)?;
    if type_oid != 3910
        || oid(ty.get("typnamespace"), false)? != 11
        || oid(ty.get("typowner"), false)? != 10
        || ty.get("typtype").and_then(Value::as_str) != Some("r")
        || oid(range.get("rngtypid"), false)? != type_oid
        || oid(range.get("rngsubtype"), false)? != 1184
    {
        return Err(Error::TypeMismatch);
    }
    Ok(())
}

fn has_binary_cast(source: u32, target: u32, dependencies: &DependencyProof) -> bool {
    dependencies.rows("pg_cast").is_some_and(|rows| {
        rows.into_iter().any(|row| {
            let Some(fields) = row.get("fields") else {
                return false;
            };
            catalog_oid(fields.get("castsource"), "pg_type", dependencies, false).ok()
                == Some(source)
                && catalog_oid(fields.get("casttarget"), "pg_type", dependencies, false).ok()
                    == Some(target)
                && fields.get("castmethod").and_then(Value::as_str) == Some("b")
                && oid(fields.get("castfunc"), true).ok() == Some(0)
        })
    })
}

fn is_core_identity(dependencies: &DependencyProof, catalog: &str, oid: u32) -> bool {
    dependencies
        .identity_for_runtime_oid(catalog, oid)
        .is_some_and(|identity| !identity.starts_with('$'))
}

fn runtime_fields<'a>(
    dependencies: &'a DependencyProof,
    catalog: &str,
    oid: u32,
) -> Result<&'a Value, Error> {
    let identity = dependencies
        .identity_for_runtime_oid(catalog, oid)
        .ok_or(Error::MissingProof)?;
    dependencies
        .row(catalog, identity)
        .and_then(|row| row.get("fields"))
        .filter(|fields| fields.is_object())
        .ok_or(Error::MissingProof)
}

fn catalog_oid(
    value: Option<&Value>,
    catalog: &str,
    dependencies: &DependencyProof,
    allow_zero: bool,
) -> Result<u32, Error> {
    let value = value.ok_or(Error::InvalidMetadata)?;
    if let Some(identity) = value
        .as_str()
        .filter(|text| !text.is_empty() && !text.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return dependencies
            .runtime_oid_for_identity(catalog, identity)
            .ok_or(Error::MissingProof);
    }
    oid(Some(value), allow_zero)
}

fn oid(value: Option<&Value>, allow_zero: bool) -> Result<u32, Error> {
    let value = value.ok_or(Error::InvalidMetadata)?;
    let parsed = parse_u32_value(value).ok_or(Error::InvalidMetadata)?;
    if parsed == 0 && !allow_zero {
        Err(Error::InvalidMetadata)
    } else {
        Ok(parsed)
    }
}

fn parse_u32_value(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
        .or_else(|| {
            value
                .as_str()
                .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|text| text.parse().ok())
        })
}

fn boolean(value: Option<&Value>) -> Result<bool, Error> {
    value.and_then(Value::as_bool).ok_or(Error::InvalidMetadata)
}

fn one_char(value: Option<&Value>) -> Result<char, Error> {
    let text = value
        .and_then(Value::as_str)
        .filter(|text| text.len() == 1)
        .ok_or(Error::InvalidMetadata)?;
    text.chars().next().ok_or(Error::InvalidMetadata)
}

fn number(value: Option<&Value>) -> Result<i64, Error> {
    let value = value.ok_or(Error::InvalidMetadata)?;
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .ok_or(Error::InvalidMetadata)
}

fn optional_i16_vector(value: Option<&Value>, max: usize) -> Result<Vec<i16>, Error> {
    let Some(value) = value else {
        return Err(Error::InvalidMetadata);
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let values = match value {
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_i64()
                    .or_else(|| item.as_str().and_then(|text| text.parse().ok()))
                    .and_then(|number| i16::try_from(number).ok())
                    .ok_or(Error::InvalidMetadata)
            })
            .collect::<Result<Vec<_>, _>>()?,
        Value::String(text) => text
            .split_whitespace()
            .map(|item| item.parse::<i16>().map_err(|_| Error::InvalidMetadata))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(Error::InvalidMetadata),
    };
    let unique = values.iter().copied().collect::<BTreeSet<_>>();
    if values.len() > max || values.iter().any(|number| *number < 0) || unique.len() != values.len()
    {
        return Err(Error::InvalidMetadata);
    }
    Ok(values)
}

fn required_i16_vector(value: Option<&Value>, max: usize) -> Result<Vec<i16>, Error> {
    let vector = nonnegative_i16_vector(value, max)?;
    if vector.is_empty() || vector.contains(&0) {
        return Err(Error::InvalidMetadata);
    }
    Ok(vector)
}

fn nonnegative_i16_vector(value: Option<&Value>, max: usize) -> Result<Vec<i16>, Error> {
    let vector = optional_i16_vector(value, max)?;
    let nonzero = vector
        .iter()
        .copied()
        .filter(|value| *value > 0)
        .collect::<BTreeSet<_>>();
    if vector.is_empty()
        || vector.iter().any(|value| *value < 0)
        || nonzero.len() != vector.iter().filter(|value| **value > 0).count()
    {
        return Err(Error::InvalidMetadata);
    }
    Ok(vector)
}

fn required_oid_vector(value: Option<&Value>, expected_len: usize) -> Result<Vec<u32>, Error> {
    let vector = oid_vector(value, expected_len, None)?;
    if expected_len == 0 || vector.len() != expected_len || vector.contains(&0) {
        return Err(Error::InvalidMetadata);
    }
    Ok(vector)
}

fn oid_vector(
    value: Option<&Value>,
    max: usize,
    dependencies: Option<&DependencyProof>,
) -> Result<Vec<u32>, Error> {
    let value = value.ok_or(Error::InvalidMetadata)?;
    let items = match value {
        Value::Array(items) => items.iter().collect::<Vec<_>>(),
        Value::String(text) => {
            if text.is_empty() {
                Vec::new()
            } else {
                return text
                    .split_whitespace()
                    .map(|item| item.parse::<u32>().map_err(|_| Error::InvalidMetadata))
                    .collect::<Result<Vec<_>, _>>()
                    .and_then(|items| {
                        if items.len() <= max {
                            Ok(items)
                        } else {
                            Err(Error::InvalidMetadata)
                        }
                    });
            }
        }
        _ => return Err(Error::InvalidMetadata),
    };
    if items.len() > max {
        return Err(Error::InvalidMetadata);
    }
    items
        .into_iter()
        .map(|value| {
            if let Some(dependencies) = dependencies {
                catalog_oid(Some(value), "pg_type", dependencies, true)
            } else {
                oid(Some(value), true)
            }
        })
        .collect()
}

fn sha256(value: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, value);
    let mut output = [0; 32];
    output.copy_from_slice(digest.as_ref());
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::schema::read_policy::{
            expression_proof, index_proof, namespace_authority, node_tree, rows::RoleRow,
        },
        net::messages::DataRow,
    };
    use serde_json::json;

    const ACTOR: u32 = 20_001;
    const RELATION: u32 = 90_000;
    const REFERENCE_RELATION: u32 = 90_010;

    fn fixture(major: u32) -> DependencyProof {
        let directory = std::env::var("PGDOG_PROFILE_TEST_FIXTURE_DIR")
            .expect("owned dependency fixture path is set");
        let profile: Value = serde_json::from_slice(
            &std::fs::read(format!(
                "{directory}/variants/read-dependency-profile-pg{major}-both.json"
            ))
            .unwrap(),
        )
        .unwrap();
        let pin = profile["provenance"]["source_image"].as_str().unwrap();
        let mut capture: Value = serde_json::from_slice(
            &std::fs::read(format!("{directory}/reference-extended-pg{major}.json")).unwrap(),
        )
        .unwrap();
        capture["tables"]["pg_extension"] = Value::Array(
            capture["tables"]["pg_extension"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["extname"] == "btree_gist" || row["extname"] == "pg_trgm")
                .cloned()
                .collect(),
        );
        capture["extension_members"] = Value::Array(
            capture["extension_members"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| {
                    row["extname"] == "plpgsql"
                        || row["extname"] == "btree_gist"
                        || row["extname"] == "pg_trgm"
                })
                .cloned()
                .collect(),
        );
        capture["module_sha256"] = Value::Array(
            capture["module_sha256"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|line| {
                    line.as_str().unwrap().contains("/btree_gist.so")
                        || line.as_str().unwrap().contains("/pg_trgm.so")
                })
                .cloned()
                .collect(),
        );
        DependencyProof::from_test_values(&profile, &capture, major, pin).unwrap()
    }

    fn authority() -> super::super::namespace_authority::NamespaceAuthorityProof {
        let role = RoleRow {
            valid: true,
            oid: ACTOR,
            superuser: false,
            create_role: false,
            create_database: false,
            replication: false,
            bypass_rls: false,
            inherit: true,
            has_memberships: false,
        };
        let expected = [(2_200, "public".to_owned())].into();
        let rows = json!([{
            "oid": "2200", "nspname": "public", "nspowner": "10",
            "nspacl": null, "has_create": false, "actor_oid": ACTOR.to_string(),
            "has_usage": true
        }]);
        namespace_authority::prove(&role, &expected, &rows).unwrap()
    }

    fn column(
        proof: &DependencyProof,
        relation: u32,
        type_oid: u32,
        attnum: u32,
        not_null: bool,
    ) -> ColumnRow {
        let identity = proof.identity_for_runtime_oid("pg_type", type_oid).unwrap();
        let fields = proof
            .row("pg_type", identity)
            .unwrap()
            .get("fields")
            .unwrap();
        let namespace_oid = parse_u32_value(&fields["typnamespace"]).unwrap();
        let namespace_identity = proof
            .identity_for_runtime_oid("pg_namespace", namespace_oid)
            .unwrap();
        let namespace = proof.row("pg_namespace", namespace_identity).unwrap()["fields"]["nspname"]
            .as_str()
            .unwrap();
        ColumnRow::from(DataRow::from_columns(vec![
            relation.to_string(),
            "value".to_owned(),
            type_oid.to_string(),
            namespace.to_owned(),
            fields["typname"].as_str().unwrap().to_owned(),
            fields["typtype"].as_str().unwrap().to_owned(),
            parse_u32_value(&fields["typbasetype"]).unwrap().to_string(),
            parse_u32_value(&fields["typinput"]).unwrap().to_string(),
            parse_u32_value(&fields["typoutput"]).unwrap().to_string(),
            parse_u32_value(&fields["typreceive"]).unwrap().to_string(),
            parse_u32_value(&fields["typsend"]).unwrap().to_string(),
            if not_null {
                "t".to_owned()
            } else {
                "f".to_owned()
            },
            String::new(),
            String::new(),
            parse_u32_value(&fields["typcollation"])
                .unwrap_or(0)
                .to_string(),
            attnum.to_string(),
            "-1".to_owned(),
            "0".to_owned(),
        ]))
    }

    fn opclass(proof: &DependencyProof, method: u32, input_type: u32) -> u32 {
        proof
            .rows("pg_opclass")
            .unwrap()
            .find_map(|row| {
                let fields = row.get("fields")?;
                (parse_u32_value(fields.get("opcmethod")?) == Some(method)
                    && parse_u32_value(fields.get("opcintype")?) == Some(input_type))
                .then(|| runtime_oid(proof, "pg_opclass", row))
                .flatten()
            })
            .expect("profiled opclass for method/type")
    }

    fn operator(proof: &DependencyProof, name: &str, left: u32, right: u32) -> u32 {
        proof
            .rows("pg_operator")
            .unwrap()
            .find_map(|row| {
                let fields = row.get("fields")?;
                (fields.get("oprname").and_then(Value::as_str) == Some(name)
                    && parse_u32_value(fields.get("oprleft")?) == Some(left)
                    && parse_u32_value(fields.get("oprright")?) == Some(right))
                .then(|| runtime_oid(proof, "pg_operator", row))
                .flatten()
            })
            .expect("profiled operator signature")
    }

    fn runtime_oid(proof: &DependencyProof, catalog: &str, row: &Value) -> Option<u32> {
        let identity = row.get("identity")?;
        let identity = identity
            .as_str()
            .map(str::to_owned)
            .or_else(|| parse_u32_value(identity).map(|oid| oid.to_string()))?;
        proof.runtime_oid_for_identity(catalog, &identity)
    }

    struct TestIndexSpec {
        relation_oid: u32,
        index_oid: u32,
        method: u32,
        key_type: u32,
        unique: bool,
        primary: bool,
        exclusion: bool,
        immediate: bool,
    }

    fn index_metadata(proof: &DependencyProof, spec: TestIndexSpec) -> (Value, Value) {
        let TestIndexSpec {
            relation_oid,
            index_oid,
            method,
            key_type,
            unique,
            primary,
            exclusion,
            immediate,
        } = spec;
        let class = opclass(proof, method, key_type);
        let mut index = json!({
            "indexrelid": index_oid, "indrelid": relation_oid,
            "indnatts": 1, "indnkeyatts": 1,
            "indisunique": unique, "indisprimary": primary,
            "indisexclusion": exclusion, "indimmediate": immediate,
            "indisclustered": false, "indisvalid": true, "indcheckxmin": false,
            "indisready": true, "indislive": true, "indisreplident": false,
            "indkey": [1], "indcollation": [0], "indclass": [class],
            "indoption": [0], "indexprs": null, "indpred": null
        });
        if proof.major() >= 15 {
            index["indnullsnotdistinct"] = json!(false);
        }
        let relation = json!({
            "oid": index_oid, "relname": "proof_constraint_idx", "relnamespace": 2200,
            "reltype": 0, "reloftype": 0, "relowner": 10, "relam": method,
            "relfilenode": 0, "reltablespace": 0, "relpages": 0, "reltuples": -1,
            "relallvisible": 0, "reltoastrelid": 0, "relhasindex": false,
            "relisshared": false, "relpersistence": "p", "relkind": "i", "relnatts": 1,
            "relchecks": 0, "relhasrules": false, "relhastriggers": false,
            "relhassubclass": false, "relrowsecurity": false, "relforcerowsecurity": false,
            "relispopulated": true, "relreplident": "n", "relispartition": false,
            "relrewrite": 0, "relfrozenxid": "0", "relminmxid": "0", "relacl": null,
            "reloptions": null, "relpartbound": null
        });
        (index, relation)
    }

    fn prove_index(proof: &DependencyProof, spec: TestIndexSpec, column: &ColumnRow) -> IndexProof {
        let (index, class) = index_metadata(proof, spec);
        index_proof::prove(
            &index,
            &class,
            index_proof::ProofContext {
                columns: std::slice::from_ref(column),
                expression_proofs: &[],
                predicate: None,
                dependencies: proof,
                enums: &BTreeMap::new(),
                role_oid: ACTOR,
                authority: &authority(),
                index_attribute_options: &[None],
            },
        )
        .expect("index proof uses an actual profiled opclass")
    }

    fn constraint_row(major: u32, oid: u32, relation: u32, kind: &str) -> Value {
        let mut row = json!({
            "oid": oid.to_string(), "conname": "proof_constraint", "connamespace": "2200",
            "contype": kind, "condeferrable": false, "condeferred": false,
            "convalidated": true, "conrelid": relation.to_string(), "contypid": "0",
            "conindid": "0", "conparentid": "0", "confrelid": "0",
            "confupdtype": "a", "confdeltype": "a", "confmatchtype": "s",
            "conislocal": true, "coninhcount": 0, "connoinherit": false,
            "conkey": [1], "confkey": null, "conpfeqop": null, "conppeqop": null,
            "conffeqop": null, "conexclop": null, "conbin": null
        });
        if major == 18 {
            row["conperiod"] = json!(false);
            row["conenforced"] = json!(true);
            row["confdelsetcols"] = Value::Null;
        }
        // PostgreSQL uses blank action bytes on non-FK catalog rows.
        if kind != "f" {
            row["confupdtype"] = json!(" ");
            row["confdeltype"] = json!(" ");
            row["confmatchtype"] = json!(" ");
        }
        row
    }

    fn raw_constraint(major: u32) -> Value {
        let mut fields = json!({
            "oid": "90001",
            "conname": "proof_check",
            "connamespace": "2200",
            "contype": "c",
            "condeferrable": false,
            "condeferred": false,
            "convalidated": true,
            "conrelid": "90000",
            "contypid": "0",
            "conindid": "0",
            "conparentid": "0",
            "confrelid": "0",
            "confupdtype": "a",
            "confdeltype": "a",
            "confmatchtype": "s",
            "conislocal": true,
            "coninhcount": 0,
            "connoinherit": false,
            "conkey": [1],
            "confkey": null,
            "conpfeqop": null,
            "conppeqop": null,
            "conffeqop": null,
            "conexclop": null,
            "conbin": "{CONST :consttype 16}"
        });
        if major == 18 {
            fields["conperiod"] = json!(false);
            fields["conenforced"] = json!(true);
            fields["confdelsetcols"] = Value::Null;
        }
        fields
    }

    #[test]
    fn constraint_rows_require_exact_major_specific_catalog_fields() {
        for major in [12, 18] {
            let row = raw_constraint(major);
            let fields = row.as_object().unwrap();
            assert_eq!(validate_constraint_field_shape(fields, major), Ok(()));
        }

        let pg12 = raw_constraint(12);
        let mut unexpected_pg12 = pg12.as_object().unwrap().clone();
        unexpected_pg12.insert("conperiod".into(), json!(false));
        assert_eq!(
            validate_constraint_field_shape(&unexpected_pg12, 12),
            Err(Error::InvalidMetadata)
        );

        let pg18 = raw_constraint(18);
        let mut missing_pg18 = pg18.as_object().unwrap().clone();
        missing_pg18.remove("conperiod");
        assert_eq!(
            validate_constraint_field_shape(&missing_pg18, 18),
            Err(Error::InvalidMetadata)
        );
        let mut missing_enforced = pg18.as_object().unwrap().clone();
        missing_enforced.remove("conenforced");
        assert_eq!(
            validate_constraint_field_shape(&missing_enforced, 18),
            Err(Error::InvalidMetadata)
        );
        let mut missing_delete_columns = pg18.as_object().unwrap().clone();
        missing_delete_columns.remove("confdelsetcols");
        assert_eq!(
            validate_constraint_field_shape(&missing_delete_columns, 18),
            Err(Error::InvalidMetadata)
        );
    }

    #[test]
    fn constraint_attribute_vectors_reject_duplicate_or_invalid_attnums() {
        assert_eq!(
            optional_i16_vector(Some(&json!([1, 1])), MAX_RELATION_COLUMNS),
            Err(Error::InvalidMetadata)
        );
        assert_eq!(
            optional_i16_vector(Some(&json!("1 2 1")), MAX_RELATION_COLUMNS),
            Err(Error::InvalidMetadata)
        );
        assert_eq!(
            optional_i16_vector(Some(&json!([0, -1])), MAX_RELATION_COLUMNS),
            Err(Error::InvalidMetadata)
        );
        assert_eq!(
            required_i16_vector(Some(&json!([1, 0])), MAX_KEY_COLUMNS),
            Err(Error::InvalidMetadata)
        );
        assert_eq!(
            optional_i16_vector(Some(&json!([])), MAX_RELATION_COLUMNS),
            Ok(Vec::new())
        );
    }

    fn boolean_var(major: u32) -> String {
        if major == 12 {
            "{VAR :varno 1 :varattno 1 :vartype 16 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnoold 1 :varoattno 1 :location 1}".to_owned()
        } else {
            "{VAR :varno 1 :varattno 1 :vartype 16 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnullingrels (b) :varreturningtype 0 :varnosyn 1 :varattnosyn 1 :location -1}".to_owned()
        }
    }

    fn check_expression(
        proof: &DependencyProof,
        relation_oid: u32,
        source: &str,
    ) -> ExpressionProof {
        let tree = node_tree::parse_and_extract(
            source,
            proof.major(),
            node_tree::Context::check(relation_oid),
        )
        .unwrap();
        expression_proof::precheck(
            &tree,
            proof,
            &[column(proof, relation_oid, 16, 1, false)],
            &BTreeMap::new(),
        )
        .unwrap()
        .finish(None)
        .unwrap()
    }

    #[test]
    fn proves_check_primary_unique_and_foreign_keys_from_typed_catalog_rows() {
        for major in [12, 18] {
            let dependencies = fixture(major);
            let relation_column = column(&dependencies, RELATION, 23, 1, true);

            let source = boolean_var(major);
            let check_expression = check_expression(&dependencies, RELATION, &source);
            let mut check = constraint_row(major, 91_001, RELATION, "c");
            check["conbin"] = json!(source);
            let check_proof = prove(
                &check,
                RELATION,
                &[column(&dependencies, RELATION, 16, 1, false)],
                &BTreeMap::new(),
                &BTreeMap::new(),
                Some(&check_expression),
                &dependencies,
                &BTreeMap::new(),
            )
            .expect("typed boolean CHECK should prove");
            assert_eq!(check_proof.constraint_oid(), 91_001);
            assert_eq!(check_proof.relation_oid(), RELATION);
            assert!(check_proof.matches_dependencies(&dependencies));
            assert_ne!(check_proof.digest(), &[0; 32]);
            let mut renamed_check = check.clone();
            renamed_check["conname"] = json!("renamed_proof_check");
            let renamed_proof = prove(
                &renamed_check,
                RELATION,
                &[column(&dependencies, RELATION, 16, 1, false)],
                &BTreeMap::new(),
                &BTreeMap::new(),
                Some(&check_expression),
                &dependencies,
                &BTreeMap::new(),
            )
            .expect("metadata-only constraint rename retains a valid proof");
            assert_ne!(check_proof.digest(), renamed_proof.digest());
            assert!(!check_proof.matches_dependencies(&fixture(if major == 12 { 18 } else { 12 })));

            for (kind, index_oid, primary) in [("p", 91_010, true), ("u", 91_011, false)] {
                let index = prove_index(
                    &dependencies,
                    TestIndexSpec {
                        relation_oid: RELATION,
                        index_oid,
                        method: 403,
                        key_type: 23,
                        unique: true,
                        primary,
                        exclusion: false,
                        immediate: true,
                    },
                    &relation_column,
                );
                let mut row = constraint_row(major, index_oid + 1, RELATION, kind);
                row["conindid"] = json!(index_oid.to_string());
                let index_map = [(index_oid, index)].into();
                let proof = prove(
                    &row,
                    RELATION,
                    std::slice::from_ref(&relation_column),
                    &BTreeMap::new(),
                    &index_map,
                    None,
                    &dependencies,
                    &BTreeMap::new(),
                )
                .expect("primary or unique constraint must bind an authentic unique index");
                assert!(proof.matches_dependencies(&dependencies));

                let mut deferrable = row.clone();
                deferrable["condeferrable"] = json!(true);
                assert_eq!(
                    prove(
                        &deferrable,
                        RELATION,
                        std::slice::from_ref(&relation_column),
                        &BTreeMap::new(),
                        &index_map,
                        None,
                        &dependencies,
                        &BTreeMap::new(),
                    ),
                    Err(Error::IndexMismatch),
                    "a deferrable constraint must use a non-immediate index"
                );
            }

            let deferred_index = prove_index(
                &dependencies,
                TestIndexSpec {
                    relation_oid: RELATION,
                    index_oid: 91_012,
                    method: 403,
                    key_type: 23,
                    unique: true,
                    primary: false,
                    exclusion: false,
                    immediate: false,
                },
                &relation_column,
            );
            let mut deferred_unique = constraint_row(major, 91_013, RELATION, "u");
            deferred_unique["conindid"] = json!(91_012);
            deferred_unique["condeferrable"] = json!(true);
            deferred_unique["condeferred"] = json!(true);
            let deferred_index_map = [(91_012, deferred_index)].into();
            prove(
                &deferred_unique,
                RELATION,
                std::slice::from_ref(&relation_column),
                &BTreeMap::new(),
                &deferred_index_map,
                None,
                &dependencies,
                &BTreeMap::new(),
            )
            .expect("deferrable unique constraints bind to non-immediate indexes");

            let referenced_column = column(&dependencies, REFERENCE_RELATION, 23, 1, true);
            let referenced_index = prove_index(
                &dependencies,
                TestIndexSpec {
                    relation_oid: REFERENCE_RELATION,
                    index_oid: 91_020,
                    method: 403,
                    key_type: 23,
                    unique: true,
                    primary: false,
                    exclusion: false,
                    immediate: true,
                },
                &referenced_column,
            );
            let equality = operator(&dependencies, "=", 23, 23);
            let mut foreign_key = constraint_row(major, 91_021, RELATION, "f");
            foreign_key["conindid"] = json!(91_020);
            foreign_key["confrelid"] = json!(REFERENCE_RELATION);
            foreign_key["confkey"] = json!([1]);
            foreign_key["conpfeqop"] = json!([equality]);
            foreign_key["conppeqop"] = json!([equality]);
            foreign_key["conffeqop"] = json!([equality]);
            let indexes = [(91_020, referenced_index)].into();
            let referenced_columns = [(REFERENCE_RELATION, vec![referenced_column])].into();
            let foreign_key_proof = prove(
                &foreign_key,
                RELATION,
                std::slice::from_ref(&relation_column),
                &referenced_columns,
                &indexes,
                None,
                &dependencies,
                &BTreeMap::new(),
            )
            .expect(
                "FK must bind typed keys, profiled equality callbacks, and referenced unique index",
            );
            assert_eq!(foreign_key_proof.relation_oid(), RELATION);
            assert!(foreign_key_proof.matches_dependencies(&dependencies));

            if major == 18 {
                let mut set_null_subset = foreign_key.clone();
                set_null_subset["confdeltype"] = json!("n");
                set_null_subset["confdelsetcols"] = json!([1]);
                assert!(
                    prove(
                        &set_null_subset,
                        RELATION,
                        std::slice::from_ref(&relation_column),
                        &referenced_columns,
                        &indexes,
                        None,
                        &dependencies,
                        &BTreeMap::new(),
                    )
                    .is_ok()
                );

                let mut outside_subset = set_null_subset.clone();
                outside_subset["confdelsetcols"] = json!([2]);
                assert!(
                    prove(
                        &outside_subset,
                        RELATION,
                        std::slice::from_ref(&relation_column),
                        &referenced_columns,
                        &indexes,
                        None,
                        &dependencies,
                        &BTreeMap::new(),
                    )
                    .is_err()
                );

                let mut subset_without_set_action = set_null_subset.clone();
                subset_without_set_action["confdeltype"] = json!("a");
                assert!(
                    prove(
                        &subset_without_set_action,
                        RELATION,
                        std::slice::from_ref(&relation_column),
                        &referenced_columns,
                        &indexes,
                        None,
                        &dependencies,
                        &BTreeMap::new(),
                    )
                    .is_err()
                );
            }

            let mut not_valid = foreign_key.clone();
            not_valid["convalidated"] = json!(false);
            let not_valid_proof = prove(
                &not_valid,
                RELATION,
                std::slice::from_ref(&relation_column),
                &referenced_columns,
                &indexes,
                None,
                &dependencies,
                &BTreeMap::new(),
            )
            .expect("NOT VALID foreign key still requires the same complete safe callback proof");
            assert_ne!(foreign_key_proof.digest(), not_valid_proof.digest());
            not_valid["conpfeqop"] = json!([999_999]);
            assert!(
                prove(
                    &not_valid,
                    RELATION,
                    std::slice::from_ref(&relation_column),
                    &referenced_columns,
                    &indexes,
                    None,
                    &dependencies,
                    &BTreeMap::new()
                )
                .is_err()
            );

            let mut wrong_equality = foreign_key.clone();
            wrong_equality["conpfeqop"] = json!([operator(&dependencies, "=", 25, 25)]);
            assert!(
                prove(
                    &wrong_equality,
                    RELATION,
                    std::slice::from_ref(&relation_column),
                    &referenced_columns,
                    &indexes,
                    None,
                    &dependencies,
                    &BTreeMap::new(),
                )
                .is_err()
            );

            let mut unknown_operator = foreign_key.clone();
            unknown_operator["conpfeqop"] = json!([999_999]);
            assert!(
                prove(
                    &unknown_operator,
                    RELATION,
                    std::slice::from_ref(&relation_column),
                    &referenced_columns,
                    &indexes,
                    None,
                    &dependencies,
                    &BTreeMap::new(),
                )
                .is_err()
            );

            let mut incompatible_key = foreign_key.clone();
            let text_column = column(&dependencies, REFERENCE_RELATION, 25, 1, true);
            let incompatible_columns = [(REFERENCE_RELATION, vec![text_column])].into();
            assert!(
                prove(
                    &incompatible_key,
                    RELATION,
                    std::slice::from_ref(&relation_column),
                    &incompatible_columns,
                    &indexes,
                    None,
                    &dependencies,
                    &BTreeMap::new(),
                )
                .is_err()
            );
            incompatible_key["conpfeqop"] = json!([operator(&dependencies, "=", 25, 25)]);
            assert!(
                prove(
                    &incompatible_key,
                    RELATION,
                    std::slice::from_ref(&relation_column),
                    &incompatible_columns,
                    &indexes,
                    None,
                    &dependencies,
                    &BTreeMap::new(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn check_proof_rejects_source_context_and_relation_replay() {
        let dependencies = fixture(18);
        let source = boolean_var(18);
        let expression = check_expression(&dependencies, RELATION, &source);
        let mut row = constraint_row(18, 92_001, RELATION, "c");
        row["conbin"] = json!(format!("{source} "));
        assert_eq!(
            prove(
                &row,
                RELATION,
                &[column(&dependencies, RELATION, 16, 1, false)],
                &BTreeMap::new(),
                &BTreeMap::new(),
                Some(&expression),
                &dependencies,
                &BTreeMap::new(),
            ),
            Err(Error::ExpressionMismatch)
        );
        row["conbin"] = json!(source);
        assert_eq!(
            prove(
                &row,
                REFERENCE_RELATION,
                &[column(&dependencies, RELATION, 16, 1, false)],
                &BTreeMap::new(),
                &BTreeMap::new(),
                Some(&expression),
                &dependencies,
                &BTreeMap::new(),
            ),
            Err(Error::InvalidMetadata)
        );

        let unknown = format!(
            "{{FUNCEXPR :funcid 999999 :funcresulttype 16 :funcretset false :funcvariadic false :funcformat 0 :funccollid 0 :inputcollid 0 :args ({source}) :location -1}}"
        );
        let tree = node_tree::parse_and_extract(&unknown, 18, node_tree::Context::check(RELATION))
            .unwrap();
        assert!(
            expression_proof::precheck(
                &tree,
                &dependencies,
                &[column(&dependencies, RELATION, 16, 1, false)],
                &BTreeMap::new(),
            )
            .is_err()
        );

        let predicate_tree =
            node_tree::parse_and_extract(&source, 18, node_tree::Context::predicate(RELATION))
                .unwrap();
        let predicate_proof = expression_proof::precheck(
            &predicate_tree,
            &dependencies,
            &[column(&dependencies, RELATION, 16, 1, false)],
            &BTreeMap::new(),
        )
        .unwrap()
        .finish(None)
        .unwrap();
        row["conbin"] = json!(source);
        assert_eq!(
            prove(
                &row,
                RELATION,
                &[column(&dependencies, RELATION, 16, 1, false)],
                &BTreeMap::new(),
                &BTreeMap::new(),
                Some(&predicate_proof),
                &dependencies,
                &BTreeMap::new(),
            ),
            Err(Error::ExpressionMismatch)
        );
    }

    #[test]
    fn rejects_foreign_keys_that_reference_partial_unique_indexes() {
        for major in [12, 18] {
            let dependencies = fixture(major);
            let local = column(&dependencies, RELATION, 16, 1, true);
            let remote = column(&dependencies, REFERENCE_RELATION, 16, 1, true);
            let source = boolean_var(major);
            let tree = node_tree::parse_and_extract(
                &source,
                major,
                node_tree::Context::predicate(REFERENCE_RELATION),
            )
            .unwrap();
            let predicate = expression_proof::precheck(
                &tree,
                &dependencies,
                std::slice::from_ref(&remote),
                &BTreeMap::new(),
            )
            .unwrap()
            .finish(None)
            .unwrap();
            let (mut index, class) = index_metadata(
                &dependencies,
                TestIndexSpec {
                    relation_oid: REFERENCE_RELATION,
                    index_oid: 94_010,
                    method: 403,
                    key_type: 16,
                    unique: true,
                    primary: false,
                    exclusion: false,
                    immediate: true,
                },
            );
            index["indpred"] = json!(source);
            let index = index_proof::prove(
                &index,
                &class,
                index_proof::ProofContext {
                    columns: std::slice::from_ref(&remote),
                    expression_proofs: &[],
                    predicate: Some(&predicate),
                    dependencies: &dependencies,
                    enums: &BTreeMap::new(),
                    role_oid: ACTOR,
                    authority: &authority(),
                    index_attribute_options: &[None],
                },
            )
            .expect("partial unique index itself is a valid index proof");
            assert!(index.has_predicate());

            let equality = operator(&dependencies, "=", 16, 16);
            let mut foreign_key = constraint_row(major, 94_011, RELATION, "f");
            foreign_key["conindid"] = json!(94_010);
            foreign_key["confrelid"] = json!(REFERENCE_RELATION);
            foreign_key["confkey"] = json!([1]);
            foreign_key["conpfeqop"] = json!([equality]);
            foreign_key["conppeqop"] = json!([equality]);
            foreign_key["conffeqop"] = json!([equality]);
            assert_eq!(
                prove(
                    &foreign_key,
                    RELATION,
                    &[local],
                    &[(REFERENCE_RELATION, vec![remote])].into(),
                    &[(94_010, index)].into(),
                    None,
                    &dependencies,
                    &BTreeMap::new(),
                ),
                Err(Error::IndexMismatch)
            );
        }
    }

    #[test]
    fn proves_pg18_not_null_constraint_from_catalog_column_flag() {
        let dependencies = fixture(18);
        let row = constraint_row(18, 93_001, RELATION, "n");
        let proof = prove(
            &row,
            RELATION,
            &[column(&dependencies, RELATION, 23, 1, true)],
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            &dependencies,
            &BTreeMap::new(),
        )
        .expect("PG18 not-null constraints bind to the actual not-null column");
        assert!(proof.matches_dependencies(&dependencies));
        assert_eq!(proof.constraint_oid(), 93_001);
        let mut not_enforced = row.clone();
        not_enforced["conenforced"] = json!(false);
        assert_eq!(
            prove(
                &not_enforced,
                RELATION,
                &[column(&dependencies, RELATION, 23, 1, true)],
                &BTreeMap::new(),
                &BTreeMap::new(),
                None,
                &dependencies,
                &BTreeMap::new(),
            ),
            Err(Error::UnsupportedConstraint)
        );
        let mut foreign_delete_columns = row.clone();
        foreign_delete_columns["confdelsetcols"] = json!([1]);
        assert!(
            prove(
                &foreign_delete_columns,
                RELATION,
                &[column(&dependencies, RELATION, 23, 1, true)],
                &BTreeMap::new(),
                &BTreeMap::new(),
                None,
                &dependencies,
                &BTreeMap::new(),
            )
            .is_err()
        );
        assert!(
            prove(
                &row,
                RELATION,
                &[column(&dependencies, RELATION, 23, 1, false)],
                &BTreeMap::new(),
                &BTreeMap::new(),
                None,
                &dependencies,
                &BTreeMap::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn proves_partial_exclusion_only_through_bound_predicate_index_proof() {
        for major in [12, 18] {
            let dependencies = fixture(major);
            let bool_column = column(&dependencies, RELATION, 16, 1, false);
            let range_column = column(&dependencies, RELATION, 3910, 2, false);
            let columns = [bool_column.clone(), range_column.clone()];
            let predicate_source = boolean_var(major);
            let predicate_tree = node_tree::parse_and_extract(
                &predicate_source,
                major,
                node_tree::Context::predicate(RELATION),
            )
            .unwrap();
            let predicate_proof = expression_proof::precheck(
                &predicate_tree,
                &dependencies,
                &columns,
                &BTreeMap::new(),
            )
            .unwrap()
            .finish(None)
            .unwrap();

            let (mut index, index_relation) = index_metadata(
                &dependencies,
                TestIndexSpec {
                    relation_oid: RELATION,
                    index_oid: 96_001,
                    method: 783,
                    key_type: 3831,
                    unique: false,
                    primary: false,
                    exclusion: true,
                    immediate: true,
                },
            );
            index["indkey"] = json!([2]);
            index["indpred"] = json!(predicate_source);
            let index_proof = index_proof::prove(
                &index,
                &index_relation,
                index_proof::ProofContext {
                    columns: &columns,
                    expression_proofs: &[],
                    predicate: Some(&predicate_proof),
                    dependencies: &dependencies,
                    enums: &BTreeMap::new(),
                    role_oid: ACTOR,
                    authority: &authority(),
                    index_attribute_options: &[None],
                },
            )
            .expect("index proof binds exact predicate source, relation, and dependencies");
            assert!(index_proof.has_predicate());

            let overlap = operator(&dependencies, "&&", 3831, 3831);
            let mut exclusion = constraint_row(major, 96_002, RELATION, "x");
            exclusion["conkey"] = json!([2]);
            exclusion["conindid"] = json!(96_001);
            exclusion["conexclop"] = json!([overlap]);
            let proof = prove(
                &exclusion,
                RELATION,
                &columns,
                &BTreeMap::new(),
                &[(96_001, index_proof.clone())].into(),
                None,
                &dependencies,
                &BTreeMap::new(),
            )
            .unwrap_or_else(|error| panic!("PG{major} bound partial exclusion: {error:?}"));
            assert!(proof.matches_dependencies(&dependencies));
            assert_ne!(proof.digest(), &[0; 32]);

            let mut changed_source = index.clone();
            changed_source["indpred"] = json!(format!("{predicate_source} "));
            assert_eq!(
                index_proof::prove(
                    &changed_source,
                    &index_relation,
                    index_proof::ProofContext {
                        columns: &columns,
                        expression_proofs: &[],
                        predicate: Some(&predicate_proof),
                        dependencies: &dependencies,
                        enums: &BTreeMap::new(),
                        role_oid: ACTOR,
                        authority: &authority(),
                        index_attribute_options: &[None],
                    },
                ),
                Err(index_proof::Error::ExpressionMismatch),
                "predicate proof cannot be replayed against different node-tree text"
            );

            let other_relation_column = column(&dependencies, REFERENCE_RELATION, 16, 1, false);
            let other_tree = node_tree::parse_and_extract(
                &predicate_source,
                major,
                node_tree::Context::predicate(REFERENCE_RELATION),
            )
            .unwrap();
            let other_predicate = expression_proof::precheck(
                &other_tree,
                &dependencies,
                &[other_relation_column],
                &BTreeMap::new(),
            )
            .unwrap()
            .finish(None)
            .unwrap();
            assert_eq!(
                index_proof::prove(
                    &index,
                    &index_relation,
                    index_proof::ProofContext {
                        columns: &columns,
                        expression_proofs: &[],
                        predicate: Some(&other_predicate),
                        dependencies: &dependencies,
                        enums: &BTreeMap::new(),
                        role_oid: ACTOR,
                        authority: &authority(),
                        index_attribute_options: &[None],
                    },
                ),
                Err(index_proof::Error::ExpressionMismatch),
                "predicate proof from another relation cannot authorize this index"
            );
        }
    }

    #[test]
    fn proves_two_key_partial_gist_exclusion_with_family_bound_varchar_equality() {
        for major in [12, 18] {
            let dependencies = fixture(major);
            let bool_column = column(&dependencies, RELATION, 16, 1, false);
            let varchar_column = column(&dependencies, RELATION, 1043, 2, false);
            let range_column = column(&dependencies, RELATION, 3910, 3, false);
            let columns = [
                bool_column.clone(),
                varchar_column.clone(),
                range_column.clone(),
            ];
            let predicate_source = boolean_var(major);
            let predicate_tree = node_tree::parse_and_extract(
                &predicate_source,
                major,
                node_tree::Context::predicate(RELATION),
            )
            .unwrap();
            let predicate_proof = expression_proof::precheck(
                &predicate_tree,
                &dependencies,
                &columns,
                &BTreeMap::new(),
            )
            .unwrap()
            .finish(None)
            .unwrap();

            let (mut index, mut index_relation) = index_metadata(
                &dependencies,
                TestIndexSpec {
                    relation_oid: RELATION,
                    index_oid: 96_101,
                    method: 783,
                    key_type: 25,
                    unique: false,
                    primary: false,
                    exclusion: true,
                    immediate: true,
                },
            );
            let text_opclass = opclass(&dependencies, 783, 25);
            let range_opclass = opclass(&dependencies, 783, 3831);
            index["indnatts"] = json!(2);
            index["indnkeyatts"] = json!(2);
            index["indkey"] = json!([2, 3]);
            index["indcollation"] = json!([100, 0]);
            index["indclass"] = json!([text_opclass, range_opclass]);
            index["indoption"] = json!([0, 0]);
            index["indpred"] = json!(predicate_source);
            index_relation["relnatts"] = json!(2);
            let index_proof = index_proof::prove(
                &index,
                &index_relation,
                index_proof::ProofContext {
                    columns: &columns,
                    expression_proofs: &[],
                    predicate: Some(&predicate_proof),
                    dependencies: &dependencies,
                    enums: &BTreeMap::new(),
                    role_oid: ACTOR,
                    authority: &authority(),
                    index_attribute_options: &[None, None],
                },
            )
            .expect("both keys use reviewed GiST families and the predicate is bound");
            assert_eq!(index_proof.key_types(), &[1043, 3910]);
            assert!(index_proof.has_predicate());

            let varchar_equal = operator(&dependencies, "=", 25, 25);
            let range_overlap = operator(&dependencies, "&&", 3831, 3831);
            let mut exclusion = constraint_row(major, 96_102, RELATION, "x");
            exclusion["conkey"] = json!([2, 3]);
            exclusion["conindid"] = json!(96_101);
            exclusion["conexclop"] = json!([varchar_equal, range_overlap]);
            let indexes = [(96_101, index_proof)].into();
            let proof = prove(
                &exclusion,
                RELATION,
                &columns,
                &BTreeMap::new(),
                &indexes,
                None,
                &dependencies,
                &BTreeMap::new(),
            )
            .unwrap_or_else(|error| panic!("PG{major} mixed GiST exclusion: {error:?}"));
            assert!(proof.matches_dependencies(&dependencies));
            assert_ne!(proof.digest(), &[0; 32]);

            let mut swapped = exclusion.clone();
            swapped["conexclop"] = json!([range_overlap, varchar_equal]);
            assert_eq!(
                prove(
                    &swapped,
                    RELATION,
                    &columns,
                    &BTreeMap::new(),
                    &indexes,
                    None,
                    &dependencies,
                    &BTreeMap::new(),
                ),
                Err(Error::OperatorMismatch),
                "each exclusion operator must be supported by its corresponding key family"
            );

            let mut unknown = exclusion.clone();
            unknown["conexclop"] = json!([999_999, range_overlap]);
            assert!(
                prove(
                    &unknown,
                    RELATION,
                    &columns,
                    &BTreeMap::new(),
                    &indexes,
                    None,
                    &dependencies,
                    &BTreeMap::new(),
                )
                .is_err(),
                "unprofiled exclusion callbacks must fail closed"
            );

            let bpchar_equal = operator(&dependencies, "=", 1042, 1042);
            let mut unsafe_cast = exclusion;
            unsafe_cast["conexclop"] = json!([bpchar_equal, range_overlap]);
            assert!(
                prove(
                    &unsafe_cast,
                    RELATION,
                    &columns,
                    &BTreeMap::new(),
                    &indexes,
                    None,
                    &dependencies,
                    &BTreeMap::new(),
                )
                .is_err(),
                "varchar exclusion cannot reach bpchar equality via unreviewed coercion"
            );
        }
    }

    #[test]
    fn proves_pg18_tstzrange_exclusion_from_profiled_gist_metadata() {
        let dependencies = fixture(18);
        let range_column = column(&dependencies, RELATION, 3910, 1, false);
        let (index, index_relation) = index_metadata(
            &dependencies,
            TestIndexSpec {
                relation_oid: RELATION,
                index_oid: 95_001,
                method: 783,
                key_type: 3831,
                unique: false,
                primary: false,
                exclusion: true,
                immediate: true,
            },
        );
        let index_proof = index_proof::prove(
            &index,
            &index_relation,
            index_proof::ProofContext {
                columns: std::slice::from_ref(&range_column),
                expression_proofs: &[],
                predicate: None,
                dependencies: &dependencies,
                enums: &BTreeMap::new(),
                role_oid: ACTOR,
                authority: &authority(),
                index_attribute_options: &[None],
            },
        )
        .expect("profiled GiST range_ops must prove a real tstzrange key");
        assert_eq!(index_proof.key_types(), &[3910]);
        assert!(index_proof.is_exclusion());
        assert!(index_proof.is_immediate());

        let overlap = operator(&dependencies, "&&", 3831, 3831);
        let mut constraint = constraint_row(18, 95_002, RELATION, "x");
        constraint["conindid"] = json!(95_001);
        constraint["conexclop"] = json!([overlap]);
        let indexes = [(95_001, index_proof)].into();
        let proof = prove(
            &constraint,
            RELATION,
            std::slice::from_ref(&range_column),
            &BTreeMap::new(),
            &indexes,
            None,
            &dependencies,
            &BTreeMap::new(),
        )
        .expect("profiled range_overlaps exclusion is supported");
        assert!(proof.matches_dependencies(&dependencies));
        assert_ne!(proof.digest(), &[0; 32]);

        let mut unknown_operator = constraint.clone();
        unknown_operator["conexclop"] = json!([999_999]);
        assert!(
            prove(
                &unknown_operator,
                RELATION,
                std::slice::from_ref(&range_column),
                &BTreeMap::new(),
                &indexes,
                None,
                &dependencies,
                &BTreeMap::new(),
            )
            .is_err(),
            "an unprofiled exclusion operator must fail closed"
        );

        let mut wrong_type = constraint.clone();
        wrong_type["conkey"] = json!([2]);
        let incompatible_columns = [range_column, column(&dependencies, RELATION, 23, 2, false)];
        assert_eq!(
            prove(
                &wrong_type,
                RELATION,
                &incompatible_columns,
                &BTreeMap::new(),
                &indexes,
                None,
                &dependencies,
                &BTreeMap::new(),
            ),
            Err(Error::IndexMismatch)
        );

        let mut deferrable = constraint;
        deferrable["condeferrable"] = json!(true);
        assert_eq!(
            prove(
                &deferrable,
                RELATION,
                &[column(&dependencies, RELATION, 3910, 1, false)],
                &BTreeMap::new(),
                &indexes,
                None,
                &dependencies,
                &BTreeMap::new(),
            ),
            Err(Error::IndexMismatch)
        );
    }
}
