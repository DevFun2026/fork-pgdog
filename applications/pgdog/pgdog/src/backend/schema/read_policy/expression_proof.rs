//! Typed semantic checks for parsed catalog expression trees.
//!
//! `node_tree` establishes bounded syntax and extracts typed references. This
//! module binds those references to an already validated runtime catalog
//! snapshot and a specific relation's real column metadata.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    dependency_profile::DependencyProof,
    node_tree::{self, ExpressionKind, TreeProof},
    rows::ColumnRow,
    type_proof::EnumTypeProof,
};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    InvalidTree,
    MissingCatalogObject,
    TypeNotApproved,
    FunctionNotApproved,
    OperatorNotApproved,
    CastNotApproved,
    CollationNotApproved,
    VarMismatch,
    ConstantNotApproved,
    RegconfigUnresolved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpressionProof {
    dependency_digest: [u8; 32],
    enum_digests: BTreeMap<u32, [u8; 32]>,
    regconfig_oid: Option<u32>,
    root_type: u32,
    relation_oid: u32,
    source_digest: [u8; 32],
    source_ordinal: usize,
    kind: ExpressionKind,
}

impl ExpressionProof {
    pub(crate) fn root_type(&self) -> u32 {
        self.root_type
    }

    pub(crate) fn relation_oid(&self) -> u32 {
        self.relation_oid
    }

    pub(crate) fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }

    pub(crate) fn source_ordinal(&self) -> usize {
        self.source_ordinal
    }

    pub(crate) fn kind(&self) -> ExpressionKind {
        self.kind
    }

    pub(crate) fn enum_digests(&self) -> &BTreeMap<u32, [u8; 32]> {
        &self.enum_digests
    }

    pub(crate) fn matches_dependencies(&self, dependencies: &DependencyProof) -> bool {
        self.dependency_digest == *dependencies.digest()
    }

    #[cfg(test)]
    pub(crate) fn regconfig_oid(&self) -> Option<u32> {
        self.regconfig_oid
    }
}

pub(crate) struct CheckedExpression<'a> {
    dependencies: &'a DependencyProof,
    enum_digests: BTreeMap<u32, [u8; 32]>,
    requires_regconfig: bool,
    root_type: u32,
    relation_oid: u32,
    source_digest: [u8; 32],
    source_ordinal: usize,
    kind: ExpressionKind,
}

impl CheckedExpression<'_> {
    pub(crate) fn requires_regconfig(&self) -> bool {
        self.requires_regconfig
    }

    pub(crate) fn finish(
        self,
        resolved_regconfig_oid: Option<u32>,
    ) -> Result<ExpressionProof, Error> {
        if self.requires_regconfig != resolved_regconfig_oid.is_some() {
            return Err(Error::RegconfigUnresolved);
        }
        if let Some(oid) = resolved_regconfig_oid {
            prove_regconfig_closure(self.dependencies, oid)?;
        }
        Ok(ExpressionProof {
            dependency_digest: *self.dependencies.digest(),
            enum_digests: self.enum_digests,
            regconfig_oid: resolved_regconfig_oid,
            root_type: self.root_type,
            relation_oid: self.relation_oid,
            source_digest: self.source_digest,
            source_ordinal: self.source_ordinal,
            kind: self.kind,
        })
    }
}

pub(crate) fn precheck<'a>(
    tree: &TreeProof,
    dependencies: &'a DependencyProof,
    columns: &[ColumnRow],
    enums: &BTreeMap<u32, EnumTypeProof>,
) -> Result<CheckedExpression<'a>, Error> {
    if tree.major != dependencies.major()
        || !matches!(tree.major, 12 | 18)
        || tree.relation_oid == 0
        || tree.vars.len() > 4096
        || tree.requirements.types.len() > 4096
        || tree.requirements.functions.len() > 4096
        || tree.requirements.operators.len() > 4096
        || tree.requirements.casts.len() > 4096
        || tree.requirements.collations.len() > 4096
        || tree.requirements.constants.len() > 4096
        || tree.function_calls.len() > 4096
        || tree.operator_calls.len() > 4096
        || tree.scalar_array_calls.len() > 4096
    {
        return Err(Error::InvalidTree);
    }
    let root_type = tree
        .root_type
        .filter(|oid| *oid != 0)
        .ok_or(Error::InvalidTree)?;
    if matches!(
        tree.kind,
        node_tree::ExpressionKind::Check | node_tree::ExpressionKind::Predicate
    ) && root_type != 16
    {
        return Err(Error::InvalidTree);
    }

    let mut enum_digests = BTreeMap::new();
    for var in &tree.vars {
        if var.varno != 1
            || var.relation_oid != tree.relation_oid
            || !(1..=1600).contains(&var.attno)
        {
            return Err(Error::VarMismatch);
        }
        let attnum = i16::try_from(var.attno).map_err(|_| Error::VarMismatch)?;
        let column = columns
            .iter()
            .find(|column| column.attribute_number() == Some(attnum))
            .ok_or(Error::VarMismatch)?;
        if !column.valid
            || column.relation_oid != tree.relation_oid
            || column.type_oid != var.type_oid
            || column.collation_oid != var.collation_oid
            || !column.generated.is_empty()
            || !column.identity.is_empty()
        {
            return Err(Error::VarMismatch);
        }
        check_column_type(column, dependencies, enums, &mut enum_digests)?;
    }

    let mut requires_regconfig = false;
    for call in &tree.function_calls {
        let row = runtime_row(dependencies, "pg_proc", call.funcid)?;
        let fields = row_fields(row)?;
        check_function_row(fields)?;
        if call.format == 1 {
            check_function_cast(call, dependencies)?;
        } else if call.format == 0 {
            requires_regconfig |=
                check_known_function(call, fields, dependencies, enums, &mut enum_digests)?;
        } else {
            return Err(Error::FunctionNotApproved);
        }
        for (index, argument) in call.argument_types.iter().enumerate() {
            if *argument == 3734 {
                if !is_explicit_tsvector_config_call(call, fields) || index != 0 {
                    return Err(Error::TypeNotApproved);
                }
                check_special_type(*argument, dependencies)?;
            } else {
                check_data_type(*argument, dependencies, enums, &mut enum_digests)?;
            }
        }
        check_result_type(call.result_type, dependencies, enums, &mut enum_digests)?;
    }

    // The extractor records every node type, including types that do not occur
    // in a function signature (for example array element/result nodes). Prove
    // the complete set independently of the function and operator checks.
    for oid in &tree.requirements.types {
        match *oid {
            3734 if requires_regconfig => check_special_type(*oid, dependencies)?,
            3734 => return Err(Error::TypeNotApproved),
            3614 => check_special_type(*oid, dependencies)?,
            3910 => check_tstzrange(dependencies)?,
            _ => check_data_type(*oid, dependencies, enums, &mut enum_digests)?,
        }
    }

    let mut observed_operators = BTreeSet::<u32>::new();
    for call in &tree.operator_calls {
        observed_operators.insert(call.opno);
        prove_operator_call(
            dependencies,
            call.opno,
            call.opfuncid,
            &call.argument_types,
            call.result_type,
            enums,
            &mut enum_digests,
        )?;
    }
    for call in &tree.scalar_array_calls {
        observed_operators.insert(call.opno);
        if call.result_type != 16 {
            return Err(Error::OperatorNotApproved);
        }
        let element = prove_array_type(call.array_type, dependencies, enums, &mut enum_digests)?;
        if element != call.left_type {
            return Err(Error::OperatorNotApproved);
        }
        prove_operator_call(
            dependencies,
            call.opno,
            call.opfuncid,
            &[call.left_type, element],
            call.result_type,
            enums,
            &mut enum_digests,
        )?;
    }
    exact_set(&tree.requirements.operators, &observed_operators)
        .map_err(|_| Error::OperatorNotApproved)?;

    let mut observed_functions = BTreeSet::<u32>::new();
    for call in &tree.function_calls {
        observed_functions.insert(call.funcid);
    }
    for call in tree
        .operator_calls
        .iter()
        .map(|call| call.opfuncid)
        .chain(tree.scalar_array_calls.iter().map(|call| call.opfuncid))
    {
        observed_functions.insert(call);
    }
    exact_set(&tree.requirements.functions, &observed_functions)
        .map_err(|_| Error::FunctionNotApproved)?;

    for cast in &tree.requirements.casts {
        check_data_type(cast.source_type, dependencies, enums, &mut enum_digests)?;
        check_data_type(cast.target_type, dependencies, enums, &mut enum_digests)?;
        let matches = dependencies
            .rows("pg_cast")
            .ok_or(Error::MissingCatalogObject)?
            .filter(|row| {
                row.get("fields").is_some_and(|fields| {
                    number(fields.get("castsource")) == Some(cast.source_type)
                        && number(fields.get("casttarget")) == Some(cast.target_type)
                })
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(Error::CastNotApproved);
        }
        let f = row_fields(matches[0])?;
        if f["castmethod"].as_str() != Some("b") || number(f.get("castfunc")) != Some(0) {
            return Err(Error::CastNotApproved);
        }
    }

    let regconfig_constants = tree
        .requirements
        .constants
        .iter()
        .filter(|constant| constant.type_oid == 3734 && !constant.is_null)
        .count();
    let any_regconfig_constant = tree
        .requirements
        .constants
        .iter()
        .any(|constant| constant.type_oid == 3734);
    if (requires_regconfig && regconfig_constants != 1)
        || (!requires_regconfig && any_regconfig_constant)
        || tree.requirements.constants.len() > 4096
    {
        return Err(Error::ConstantNotApproved);
    }
    let mut constant_bytes = 0usize;
    for constant in &tree.requirements.constants {
        constant_bytes = constant_bytes
            .checked_add(constant.bytes.len())
            .ok_or(Error::ConstantNotApproved)?;
        if constant_bytes > 256 * 1024 || constant.bytes.len() > 64 * 1024 {
            return Err(Error::ConstantNotApproved);
        }
        if constant.type_oid == 3734 {
            if !requires_regconfig
                || constant.is_null
                || constant.type_len != 4
                || !constant.by_value
                || constant.bytes.len() != 8
            {
                return Err(Error::ConstantNotApproved);
            }
            check_special_type(constant.type_oid, dependencies)?;
            continue;
        }
        if enums.contains_key(&constant.type_oid) {
            return Err(Error::ConstantNotApproved);
        }
        check_data_type(constant.type_oid, dependencies, enums, &mut enum_digests)
            .map_err(|_| Error::ConstantNotApproved)?;
        let type_fields = type_fields(dependencies, constant.type_oid)?;
        if number_i64(type_fields.get("typlen")) != Some(constant.type_len as i64)
            || type_fields.get("typbyval").and_then(Value::as_bool) != Some(constant.by_value)
        {
            return Err(Error::ConstantNotApproved);
        }
    }

    for oid in &tree.requirements.collations {
        check_collation(*oid, dependencies)?;
    }
    if root_type == 3734 || root_type == 2281 || root_type == 2277 || root_type == 2283 {
        return Err(Error::TypeNotApproved);
    }
    check_result_type(root_type, dependencies, enums, &mut enum_digests)?;

    Ok(CheckedExpression {
        dependencies,
        enum_digests,
        requires_regconfig,
        root_type,
        relation_oid: tree.relation_oid,
        source_digest: *tree.source_digest(),
        source_ordinal: tree.source_ordinal(),
        kind: tree.kind,
    })
}

const SCALAR_TYPES: &[u32] = &[
    16, 17, 20, 21, 23, 25, 700, 701, 1042, 1043, 1082, 1083, 1114, 1184, 1186, 1266, 1700, 2950,
    3802,
];
const ARRAY_TYPES: &[u32] = &[1007, 1009, 1182, 1231];
const CHAR_COLLATIONS: &[u32] = &[100, 950, 951];
const MAX_TYPE_DEPTH: usize = 8;

fn exact_set(expected: &[u32], observed: &BTreeSet<u32>) -> Result<(), ()> {
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if &expected == observed {
        Ok(())
    } else {
        Err(())
    }
}

fn runtime_row<'a>(
    proof: &'a DependencyProof,
    catalog: &str,
    oid: u32,
) -> Result<&'a Value, Error> {
    if oid == 0 {
        return Err(Error::MissingCatalogObject);
    }
    let identity = proof
        .identity_for_runtime_oid(catalog, oid)
        .ok_or(Error::MissingCatalogObject)?;
    proof
        .row(catalog, identity)
        .ok_or(Error::MissingCatalogObject)
}

fn row_fields(row: &Value) -> Result<&Value, Error> {
    row.get("fields")
        .filter(|fields| fields.is_object())
        .ok_or(Error::MissingCatalogObject)
}

fn number(value: Option<&Value>) -> Option<u32> {
    let value = value?;
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
        .or_else(|| value.as_str().and_then(|s| s.parse::<u32>().ok()))
}

fn number_i64(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok()))
        .or_else(|| value.as_str().and_then(|s| s.parse::<i64>().ok()))
}

fn oid_vector(value: Option<&Value>) -> Option<Vec<u32>> {
    value?
        .as_array()?
        .iter()
        .map(|value| number(Some(value)))
        .collect()
}

fn type_fields(proof: &DependencyProof, oid: u32) -> Result<&Value, Error> {
    row_fields(runtime_row(proof, "pg_type", oid)?)
}

fn check_column_type(
    column: &ColumnRow,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<(), Error> {
    if column.type_kind == "e" {
        let proof = enums.get(&column.type_oid).ok_or(Error::TypeNotApproved)?;
        let capabilities = proof.capabilities();
        let metadata = proof.metadata();
        if proof.type_oid() != column.type_oid
            || !capabilities.text_output
            || !capabilities.binary_output
            || !capabilities.text_input
            || !capabilities.binary_input
            || metadata.oid != column.type_oid
            || metadata.schema_oid == 0
            || metadata.owner_oid == 0
            || metadata.name != column.type_name
            || column.type_schema.is_empty()
            || metadata.kind != b'e'
            || column.type_kind != "e"
            || metadata.base_type_oid != column.base_type_oid
            || metadata.input_oid != column.type_input_oid
            || metadata.output_oid != column.type_output_oid
            || metadata.receive_oid != column.type_receive_oid
            || metadata.send_oid != column.type_send_oid
            || metadata.collation_oid != column.collation_oid
        {
            return Err(Error::TypeNotApproved);
        }
        enum_digests.insert(column.type_oid, *proof.digest());
        return Ok(());
    }
    check_data_type(column.type_oid, dependencies, enums, enum_digests)?;
    let fields = type_fields(dependencies, column.type_oid)?;
    let namespace_oid = number(fields.get("typnamespace")).ok_or(Error::TypeNotApproved)?;
    let namespace = runtime_row(dependencies, "pg_namespace", namespace_oid)?;
    let namespace = row_fields(namespace)?;
    if namespace.get("nspname").and_then(Value::as_str) != Some(column.type_schema.as_str())
        || fields.get("typname").and_then(Value::as_str) != Some(column.type_name.as_str())
        || fields.get("typtype").and_then(Value::as_str) != Some(column.type_kind.as_str())
        || number(fields.get("typbasetype")) != Some(column.base_type_oid)
        || number(fields.get("typinput")) != Some(column.type_input_oid)
        || number(fields.get("typoutput")) != Some(column.type_output_oid)
        || number(fields.get("typreceive")) != Some(column.type_receive_oid)
        || number(fields.get("typsend")) != Some(column.type_send_oid)
        || number(fields.get("typcollation")) != Some(column.collation_oid)
    {
        return Err(Error::VarMismatch);
    }
    Ok(())
}

fn check_data_type(
    oid: u32,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<(), Error> {
    if let Some(proof) = enums.get(&oid) {
        let capabilities = proof.capabilities();
        if proof.type_oid() != oid
            || !capabilities.text_output
            || !capabilities.binary_output
            || !capabilities.text_input
            || !capabilities.binary_input
        {
            return Err(Error::TypeNotApproved);
        }
        enum_digests.insert(oid, *proof.digest());
        return Ok(());
    }
    let fields = type_fields(dependencies, oid)?;
    if ARRAY_TYPES.contains(&oid) {
        prove_array_type(oid, dependencies, enums, enum_digests)?;
        return Ok(());
    }
    if !SCALAR_TYPES.contains(&oid)
        || number(fields.get("typnamespace")) != Some(11)
        || fields.get("typtype").and_then(Value::as_str) != Some("b")
        || number(fields.get("typbasetype")) != Some(0)
        || number(fields.get("typelem")) != Some(0)
        || number(fields.get("typowner")) != Some(10)
    {
        return Err(Error::TypeNotApproved);
    }
    Ok(())
}

fn check_result_type(
    oid: u32,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<(), Error> {
    if SCALAR_TYPES.contains(&oid) || ARRAY_TYPES.contains(&oid) || enums.contains_key(&oid) {
        return check_data_type(oid, dependencies, enums, enum_digests);
    }
    if oid == 3614 {
        check_special_type(oid, dependencies)
    } else if oid == 3910 {
        check_tstzrange(dependencies)
    } else {
        Err(Error::TypeNotApproved)
    }
}

fn prove_array_type(
    oid: u32,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<u32, Error> {
    if !ARRAY_TYPES.contains(&oid) {
        return Err(Error::TypeNotApproved);
    }
    prove_array_inner(
        oid,
        dependencies,
        enums,
        enum_digests,
        0,
        &mut BTreeSet::new(),
    )
}

fn prove_array_inner(
    oid: u32,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
    depth: usize,
    visiting: &mut BTreeSet<u32>,
) -> Result<u32, Error> {
    if depth >= MAX_TYPE_DEPTH || !visiting.insert(oid) {
        return Err(Error::TypeNotApproved);
    }
    let result = (|| {
        let array = type_fields(dependencies, oid)?;
        let element_oid = number(array.get("typelem"))
            .filter(|oid| *oid != 0)
            .ok_or(Error::TypeNotApproved)?;
        if number(array.get("typnamespace")) != Some(11)
            || array.get("typtype").and_then(Value::as_str) != Some("b")
            || array.get("typcategory").and_then(Value::as_str) != Some("A")
            || number(array.get("typbasetype")) != Some(0)
            || number_i64(array.get("typlen")) != Some(-1)
        {
            return Err(Error::TypeNotApproved);
        }
        let element = type_fields(dependencies, element_oid)?;
        if number(element.get("typarray")) != Some(oid) || !SCALAR_TYPES.contains(&element_oid) {
            return Err(Error::TypeNotApproved);
        }
        check_data_type(element_oid, dependencies, enums, enum_digests)?;
        Ok(element_oid)
    })();
    visiting.remove(&oid);
    result
}

fn check_special_type(oid: u32, dependencies: &DependencyProof) -> Result<(), Error> {
    let fields = type_fields(dependencies, oid)?;
    let (typtype, category) = match oid {
        3734 => ("b", "N"),
        3614 => ("b", "U"),
        _ => return Err(Error::TypeNotApproved),
    };
    if number(fields.get("typnamespace")) != Some(11)
        || fields.get("typtype").and_then(Value::as_str) != Some(typtype)
        || fields.get("typcategory").and_then(Value::as_str) != Some(category)
        || number(fields.get("typbasetype")) != Some(0)
        || number(fields.get("typelem")) != Some(0)
        || number(fields.get("typowner")) != Some(10)
    {
        return Err(Error::TypeNotApproved);
    }
    Ok(())
}

fn check_tstzrange(dependencies: &DependencyProof) -> Result<(), Error> {
    let fields = type_fields(dependencies, 3910)?;
    if number(fields.get("typnamespace")) != Some(11)
        || fields.get("typtype").and_then(Value::as_str) != Some("r")
        || number(fields.get("typbasetype")) != Some(0)
        || number(fields.get("typowner")) != Some(10)
    {
        return Err(Error::TypeNotApproved);
    }
    let range = runtime_row(dependencies, "pg_range", 3910)?;
    let range = row_fields(range)?;
    if number(range.get("rngtypid")) != Some(3910)
        || number(range.get("rngsubtype")) != Some(1184)
        || runtime_row(dependencies, "pg_type", 1184).is_err()
    {
        return Err(Error::TypeNotApproved);
    }
    Ok(())
}

fn check_collation(oid: u32, dependencies: &DependencyProof) -> Result<(), Error> {
    if !CHAR_COLLATIONS.contains(&oid) {
        return Err(Error::CollationNotApproved);
    }
    let fields = row_fields(runtime_row(dependencies, "pg_collation", oid)?)?;
    if number(fields.get("collnamespace")) != Some(11) {
        return Err(Error::CollationNotApproved);
    }
    Ok(())
}

fn check_function_row(fields: &Value) -> Result<(), Error> {
    if number(fields.get("pronamespace")) != Some(11)
        || number(fields.get("prolang")) != Some(12)
        || fields.get("prokind").and_then(Value::as_str) != Some("f")
        || fields.get("proretset").and_then(Value::as_bool) != Some(false)
        || fields.get("prosecdef").and_then(Value::as_bool) != Some(false)
        || !fields.get("proconfig").is_some_and(Value::is_null)
        || !matches!(
            fields.get("provolatile").and_then(Value::as_str),
            Some("i" | "s")
        )
    {
        return Err(Error::FunctionNotApproved);
    }
    Ok(())
}

fn is_explicit_tsvector_config_call(call: &super::node_tree::FunctionCall, fields: &Value) -> bool {
    fields.get("proname").and_then(Value::as_str) == Some("to_tsvector")
        && call.argument_types == [3734, 25]
        && call.result_type == 3614
        && oid_vector(fields.get("proargtypes")).as_deref() == Some([3734, 25].as_slice())
        && number(fields.get("prorettype")) == Some(3614)
}

fn check_known_function(
    call: &super::node_tree::FunctionCall,
    fields: &Value,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<bool, Error> {
    let name = fields
        .get("proname")
        .and_then(Value::as_str)
        .ok_or(Error::FunctionNotApproved)?;
    let args = call.argument_types.as_slice();
    let result = call.result_type;
    let signature = oid_vector(fields.get("proargtypes")).ok_or(Error::FunctionNotApproved)?;
    let actual_result = number(fields.get("prorettype")).ok_or(Error::FunctionNotApproved)?;
    let variadic = number(fields.get("provariadic")).unwrap_or(0);
    let is_concat = name == "concat"
        && signature == [2276]
        && actual_result == 25
        && variadic == 2276
        && !args.is_empty()
        && args.len() <= 8
        && args
            .iter()
            .all(|oid| SCALAR_TYPES.contains(oid) && !enums.contains_key(oid));
    let allowed = is_concat
        || matches!(
            (name, args, result),
            ("lower", [25], 25)
                | ("right", [25, 23], 25)
                | ("textcat", [25, 25], 25)
                | ("jsonb_object_field_text", [3802, 25], 25)
                | ("date_trunc", [25, 1114], 1114)
                | ("date_trunc", [25, 1184], 1184)
                | ("date_trunc", [25, 1184, 25], 1184)
                | ("date_trunc", [25, 1186], 1186)
                | ("timezone", [25, 1184], 1114)
                | ("timezone", [1186, 1184], 1114)
                | ("timezone", [25, 1114], 1184)
                | ("timezone", [1186, 1114], 1184)
                | ("timezone", [25, 1266], 1266)
                | ("timezone", [1186, 1266], 1266)
                | ("timezone", [1184], 1114)
                | ("timezone", [1114], 1184)
                | ("timezone", [1266], 1266)
                | ("interval", [1186, 23], 1186)
                | ("interval", [1083], 1186)
                | ("time", [1114], 1083)
                | ("time", [1186], 1083)
                | ("time", [1083, 23], 1083)
                | ("time", [1184], 1083)
                | ("time", [1266], 1083)
                | ("tstzrange", [1184, 1184], 3910)
                | ("tstzrange", [1184, 1184, 25], 3910)
        )
        || is_explicit_tsvector_config_call(call, fields);
    if !allowed
        || (!is_concat && signature != args)
        || actual_result != result
        || !matches!(
            fields.get("provolatile").and_then(Value::as_str),
            Some("i" | "s")
        )
    {
        return Err(Error::FunctionNotApproved);
    }
    for arg in args {
        if *arg == 3734 {
            if !is_explicit_tsvector_config_call(call, fields) {
                return Err(Error::TypeNotApproved);
            }
            check_special_type(*arg, dependencies)?;
        } else {
            check_data_type(*arg, dependencies, enums, enum_digests)?;
        }
    }
    if matches!(name, "to_tsvector") {
        check_special_type(result, dependencies)?;
    } else {
        check_result_type(result, dependencies, enums, enum_digests)?;
    }
    Ok(is_explicit_tsvector_config_call(call, fields))
}

fn check_function_cast(
    call: &super::node_tree::FunctionCall,
    dependencies: &DependencyProof,
) -> Result<(), Error> {
    if call.argument_types.len() != 1 || call.result_type == 0 {
        return Err(Error::CastNotApproved);
    }
    let source = call.argument_types[0];
    let target = call.result_type;
    let matches = dependencies
        .rows("pg_cast")
        .ok_or(Error::MissingCatalogObject)?
        .filter(|row| {
            row.get("fields").is_some_and(|fields| {
                number(fields.get("castsource")) == Some(source)
                    && number(fields.get("casttarget")) == Some(target)
                    && number(fields.get("castfunc")) == Some(call.funcid)
                    && fields.get("castmethod").and_then(Value::as_str) == Some("f")
            })
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(Error::CastNotApproved);
    }
    let proc = row_fields(runtime_row(dependencies, "pg_proc", call.funcid)?)?;
    if oid_vector(proc.get("proargtypes")).as_deref() != Some([source].as_slice())
        || number(proc.get("prorettype")) != Some(target)
    {
        return Err(Error::CastNotApproved);
    }
    Ok(())
}

fn prove_operator_call(
    dependencies: &DependencyProof,
    opno: u32,
    opfuncid: u32,
    args: &[u32],
    result: u32,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<(), Error> {
    if args.len() != 2 {
        return Err(Error::OperatorNotApproved);
    }
    let operator = row_fields(runtime_row(dependencies, "pg_operator", opno)?)?;
    if number(operator.get("oprnamespace")) != Some(11)
        || number(operator.get("oprleft")) != Some(args[0])
        || number(operator.get("oprright")) != Some(args[1])
        || number(operator.get("oprresult")) != Some(result)
        || number(operator.get("oprcode")) != Some(opfuncid)
    {
        return Err(Error::OperatorNotApproved);
    }
    if enums.contains_key(&args[0]) || enums.contains_key(&args[1]) {
        return Err(Error::OperatorNotApproved);
    }
    check_data_type(args[0], dependencies, enums, enum_digests)?;
    check_data_type(args[1], dependencies, enums, enum_digests)?;
    check_result_type(result, dependencies, enums, enum_digests)?;
    let implementation = row_fields(runtime_row(dependencies, "pg_proc", opfuncid)?)?;
    check_function_row(implementation)?;
    if number(implementation.get("pronamespace")) != Some(11)
        || oid_vector(implementation.get("proargtypes")).as_deref() != Some(args)
        || number(implementation.get("prorettype")) != Some(result)
        || implementation.get("provolatile").and_then(Value::as_str) != Some("i")
    {
        return Err(Error::OperatorNotApproved);
    }
    Ok(())
}

fn prove_regconfig_closure(dependencies: &DependencyProof, oid: u32) -> Result<(), Error> {
    let identity = dependencies
        .identity_for_runtime_oid("pg_ts_config", oid)
        .ok_or(Error::RegconfigUnresolved)?;
    let (config_name, expected_dicts): (&str, &[&str]) = match identity {
        "$builtin:pg_ts_config:pg_catalog.simple" => {
            ("simple", &["$builtin:pg_ts_dict:pg_catalog.simple"])
        }
        "$builtin:pg_ts_config:pg_catalog.english" => (
            "english",
            &[
                "$builtin:pg_ts_dict:pg_catalog.english_stem",
                "$builtin:pg_ts_dict:pg_catalog.simple",
            ],
        ),
        _ => return Err(Error::RegconfigUnresolved),
    };
    let config = row_fields(runtime_row(dependencies, "pg_ts_config", oid)?)?;
    if config.get("cfgname").and_then(Value::as_str) != Some(config_name)
        || number(config.get("cfgnamespace")) != Some(11)
        || number(config.get("cfgowner")) != Some(10)
    {
        return Err(Error::RegconfigUnresolved);
    }
    let parser_oid = number(config.get("cfgparser")).ok_or(Error::RegconfigUnresolved)?;
    let parser_row = runtime_row(dependencies, "pg_ts_parser", parser_oid)?;
    let parser = row_fields(parser_row)?;
    if parser.get("prsname").and_then(Value::as_str) != Some("default")
        || number(parser.get("prsnamespace")) != Some(11)
    {
        return Err(Error::RegconfigUnresolved);
    }
    prove_parser_callbacks(dependencies, parser)?;

    let mut observed_dicts = BTreeSet::new();
    let mut map_keys = BTreeSet::new();
    for row in dependencies
        .rows("pg_ts_config_map")
        .ok_or(Error::MissingCatalogObject)?
    {
        let fields = row_fields(row)?;
        if fields.get("mapcfg").and_then(Value::as_str) != Some(identity) {
            continue;
        }
        let dictionary = fields
            .get("mapdict")
            .and_then(Value::as_str)
            .ok_or(Error::RegconfigUnresolved)?;
        if !expected_dicts.contains(&dictionary) {
            return Err(Error::RegconfigUnresolved);
        }
        let token = number(fields.get("maptokentype")).ok_or(Error::RegconfigUnresolved)?;
        let sequence = number(fields.get("mapseqno")).ok_or(Error::RegconfigUnresolved)?;
        if token == 0 || sequence == 0 || !map_keys.insert((token, sequence)) {
            return Err(Error::RegconfigUnresolved);
        }
        observed_dicts.insert(dictionary);
    }
    if observed_dicts.len() != expected_dicts.len()
        || expected_dicts
            .iter()
            .any(|dictionary| !observed_dicts.contains(dictionary))
    {
        return Err(Error::RegconfigUnresolved);
    }
    for dictionary in expected_dicts {
        let expected_template = match *dictionary {
            "$builtin:pg_ts_dict:pg_catalog.simple" => "$builtin:pg_ts_template:pg_catalog.simple",
            "$builtin:pg_ts_dict:pg_catalog.english_stem" => {
                "$builtin:pg_ts_template:pg_catalog.snowball"
            }
            _ => return Err(Error::RegconfigUnresolved),
        };
        let dict = row_fields(
            dependencies
                .row("pg_ts_dict", dictionary)
                .ok_or(Error::RegconfigUnresolved)?,
        )?;
        if dict.get("dictname").and_then(Value::as_str)
            != Some(match *dictionary {
                "$builtin:pg_ts_dict:pg_catalog.simple" => "simple",
                "$builtin:pg_ts_dict:pg_catalog.english_stem" => "english_stem",
                _ => return Err(Error::RegconfigUnresolved),
            })
            || number(dict.get("dictnamespace")) != Some(11)
            || number(dict.get("dictowner")) != Some(10)
            || dict.get("dicttemplate").and_then(Value::as_str) != Some(expected_template)
        {
            return Err(Error::RegconfigUnresolved);
        }
        prove_template_callbacks(dependencies, expected_template)?;
    }
    Ok(())
}

fn prove_parser_callbacks(dependencies: &DependencyProof, parser: &Value) -> Result<(), Error> {
    let callbacks: [(&str, &str, &[u32], u32); 5] = [
        ("prsstart", "prsd_start", &[2281, 23], 2281),
        ("prstoken", "prsd_nexttoken", &[2281, 2281, 2281], 2281),
        ("prsend", "prsd_end", &[2281], 2278),
        ("prsheadline", "prsd_headline", &[2281, 2281, 3615], 2281),
        ("prslextype", "prsd_lextype", &[2281], 2281),
    ];
    for (field, name, arguments, result) in callbacks {
        prove_textsearch_callback(
            dependencies,
            parser.get(field).ok_or(Error::RegconfigUnresolved)?,
            name,
            arguments,
            result,
            "i",
            "s",
        )?;
    }
    Ok(())
}

fn prove_template_callbacks(dependencies: &DependencyProof, identity: &str) -> Result<(), Error> {
    let (name, init, lexize, volatility, parallel) = match identity {
        "$builtin:pg_ts_template:pg_catalog.simple" => {
            ("simple", "dsimple_init", "dsimple_lexize", "i", "s")
        }
        "$builtin:pg_ts_template:pg_catalog.snowball" => {
            ("snowball", "dsnowball_init", "dsnowball_lexize", "v", "u")
        }
        _ => return Err(Error::RegconfigUnresolved),
    };
    let template = dependencies
        .row("pg_ts_template", identity)
        .ok_or(Error::RegconfigUnresolved)?;
    let fields = row_fields(template)?;
    if fields.get("tmplname").and_then(Value::as_str) != Some(name)
        || number(fields.get("tmplnamespace")) != Some(11)
    {
        return Err(Error::RegconfigUnresolved);
    }
    prove_textsearch_callback(
        dependencies,
        fields.get("tmplinit").ok_or(Error::RegconfigUnresolved)?,
        init,
        &[2281],
        2281,
        volatility,
        parallel,
    )?;
    prove_textsearch_callback(
        dependencies,
        fields.get("tmpllexize").ok_or(Error::RegconfigUnresolved)?,
        lexize,
        &[2281, 2281, 2281, 2281],
        2281,
        volatility,
        parallel,
    )?;
    Ok(())
}

fn prove_textsearch_callback(
    dependencies: &DependencyProof,
    reference: &Value,
    expected_name: &str,
    expected_arguments: &[u32],
    expected_result: u32,
    expected_volatility: &str,
    expected_parallel: &str,
) -> Result<(), Error> {
    let row = if let Some(identity) = reference.as_str().filter(|value| value.starts_with('$')) {
        dependencies
            .row("pg_proc", identity)
            .ok_or(Error::RegconfigUnresolved)?
    } else {
        let oid = number(Some(reference)).ok_or(Error::RegconfigUnresolved)?;
        runtime_row(dependencies, "pg_proc", oid)?
    };
    let proc = row_fields(row)?;
    if proc.get("proname").and_then(Value::as_str) != Some(expected_name)
        || number(proc.get("pronamespace")) != Some(11)
        || oid_vector(proc.get("proargtypes")).as_deref() != Some(expected_arguments)
        || number(proc.get("prorettype")) != Some(expected_result)
        || proc.get("provolatile").and_then(Value::as_str) != Some(expected_volatility)
        || proc.get("proisstrict").and_then(Value::as_bool) != Some(true)
        || proc.get("prosecdef").and_then(Value::as_bool) != Some(false)
        || proc.get("prokind").and_then(Value::as_str) != Some("f")
        || !proc.get("proconfig").is_some_and(Value::is_null)
        || proc.get("proparallel").and_then(Value::as_str) != Some(expected_parallel)
    {
        return Err(Error::RegconfigUnresolved);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::schema::read_policy::{
            dependency_profile::DependencyProof, node_tree, rows::ColumnRow,
        },
        net::messages::DataRow,
    };
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn fixture_values(major: u32) -> Option<(Value, Value, String)> {
        let directory = std::env::var("PGDOG_PROFILE_TEST_FIXTURE_DIR").ok()?;
        let profile: Value = serde_json::from_slice(
            &std::fs::read(format!(
                "{directory}/variants/read-dependency-profile-pg{major}-both.json"
            ))
            .ok()?,
        )
        .ok()?;
        let pin = profile["provenance"]["source_image"].as_str()?.to_owned();
        let mut capture: Value = serde_json::from_slice(
            &std::fs::read(format!("{directory}/reference-extended-pg{major}.json")).ok()?,
        )
        .ok()?;
        let selected = profile["enabled_extensions"].as_array()?;
        let selected = selected
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        capture["tables"]["pg_extension"] = Value::Array(
            capture["tables"]["pg_extension"]
                .as_array()?
                .iter()
                .filter(|row| {
                    row["extname"]
                        .as_str()
                        .is_some_and(|name| selected.contains(name))
                })
                .cloned()
                .collect(),
        );
        capture["extension_members"] = Value::Array(
            capture["extension_members"]
                .as_array()?
                .iter()
                .filter(|row| {
                    row["extname"]
                        .as_str()
                        .is_some_and(|name| name == "plpgsql" || selected.contains(name))
                })
                .cloned()
                .collect(),
        );
        capture["module_sha256"] = Value::Array(
            capture["module_sha256"]
                .as_array()?
                .iter()
                .filter(|line| {
                    line.as_str().is_some_and(|line| {
                        selected
                            .iter()
                            .any(|name| line.contains(&format!("/{name}.so")))
                    })
                })
                .cloned()
                .collect(),
        );
        Some((profile, capture, pin))
    }

    fn fixture(major: u32) -> Option<DependencyProof> {
        let (profile, capture, pin) = fixture_values(major)?;
        DependencyProof::from_test_values(&profile, &capture, major, &pin).ok()
    }

    fn explicit_tsvector_expression(proof: &DependencyProof, major: u32) -> node_tree::TreeProof {
        let relation = 90_004;
        let tsvector = oid_by_name(proof, "pg_proc", "proname", "to_tsvector");
        node_tree::parse_and_extract(
            &format!(
                "{{FUNCEXPR :funcid {tsvector} :funcresulttype 3614 :funcretset false :funcvariadic false :funcformat 0 :funccollid 0 :inputcollid 100 :args ({{CONST :consttype 3734 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location -1 :constvalue 4 [ 1 0 0 0 0 0 0 0 ]}} {{CONST :consttype 25 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval false :constisnull false :location -1 :constvalue 4 [ 116 101 120 116 ]}}) :location -1}}"
            ),
            major,
            node_tree::Context::index(relation),
        )
        .unwrap()
    }

    fn fields<'a>(proof: &'a DependencyProof, table: &str, oid: u32) -> &'a Value {
        let identity = proof
            .identity_for_runtime_oid(table, oid)
            .expect("fixture contains requested OID");
        proof
            .row(table, identity)
            .expect("fixture row")
            .get("fields")
            .unwrap()
    }

    fn field_oid(row: &Value, name: &str) -> u32 {
        row[name]
            .as_u64()
            .or_else(|| row[name].as_str().and_then(|s| s.parse().ok()))
            .unwrap() as u32
    }

    fn column(proof: &DependencyProof, relation: u32, type_oid: u32, attnum: i16) -> ColumnRow {
        let ty = fields(proof, "pg_type", type_oid);
        let ns = field_oid(ty, "typnamespace");
        let ns_identity = proof.identity_for_runtime_oid("pg_namespace", ns).unwrap();
        let namespace = proof.row("pg_namespace", ns_identity).unwrap();
        let namespace = &namespace["fields"]["nspname"];
        ColumnRow::from(DataRow::from_columns(vec![
            relation.to_string(),
            "value".to_owned(),
            type_oid.to_string(),
            namespace.as_str().unwrap().to_owned(),
            ty["typname"].as_str().unwrap().to_owned(),
            ty["typtype"].as_str().unwrap().to_owned(),
            field_oid(ty, "typbasetype").to_string(),
            field_oid(ty, "typinput").to_string(),
            field_oid(ty, "typoutput").to_string(),
            field_oid(ty, "typreceive").to_string(),
            field_oid(ty, "typsend").to_string(),
            "f".to_owned(),
            String::new(),
            String::new(),
            field_oid(ty, "typcollation").to_string(),
            attnum.to_string(),
            "-1".to_owned(),
            "0".to_owned(),
        ]))
    }

    fn oid_by_name(proof: &DependencyProof, table: &str, name_field: &str, name: &str) -> u32 {
        proof
            .rows(table)
            .unwrap()
            .find_map(|row| {
                let f = row.get("fields")?;
                let selected_signature = match name {
                    "lower" => {
                        oid_vector(f.get("proargtypes")).as_deref() == Some([25].as_slice())
                            && field_oid(f, "prorettype") == 25
                    }
                    "to_tsvector" => {
                        oid_vector(f.get("proargtypes")).as_deref() == Some([3734, 25].as_slice())
                            && field_oid(f, "prorettype") == 3614
                    }
                    _ => true,
                };
                (f[name_field].as_str()? == name && selected_signature)
                    .then(|| row["identity"].as_u64().map(|n| n as u32))
                    .flatten()
            })
            .expect("fixture contains function/operator")
    }

    fn var(major: u32, attnum: i16, type_oid: u32, collation: u32) -> String {
        let legacy = if major == 12 {
            format!(":varnoold 1 :varoattno {attnum}")
        } else {
            format!(":varnullingrels (b) :varreturningtype 0 :varnosyn 1 :varattnosyn {attnum}")
        };
        format!(
            "{{VAR :varno 1 :varattno {attnum} :vartype {type_oid} :vartypmod -1 :varcollid {collation} :varlevelsup 0 {legacy} :location -1}}"
        )
    }

    #[test]
    fn proves_profiled_function_and_binds_var_to_real_attribute_number() {
        let Some(proof) = fixture(18) else { return };
        let relation = 90_001;
        let lower = oid_by_name(&proof, "pg_proc", "proname", "lower");
        let tree = node_tree::parse_and_extract(
            &format!(
                "{{FUNCEXPR :funcid {lower} :funcresulttype 25 :funcretset false :funcvariadic false :funcformat 0 :funccollid 100 :inputcollid 100 :args ({}) :location -1}}",
                var(18, 4, 25, 100)
            ),
            18,
            node_tree::Context::index(relation),
        )
        .unwrap();
        let text_column = column(&proof, relation, 25, 4);
        precheck(&tree, &proof, &[text_column], &BTreeMap::new()).unwrap();

        let textcat = oid_by_name(&proof, "pg_proc", "proname", "textcat");
        let repeated_var = var(18, 4, 25, 100);
        let repeated = node_tree::parse_and_extract(
            &format!(
                "{{FUNCEXPR :funcid {textcat} :funcresulttype 25 :funcretset false :funcvariadic false :funcformat 0 :funccollid 100 :inputcollid 100 :args ({repeated_var} {repeated_var}) :location -1}}"
            ),
            18,
            node_tree::Context::index(relation),
        )
        .unwrap();
        assert_eq!(repeated.vars.len(), 1);
        precheck(
            &repeated,
            &proof,
            &[column(&proof, relation, 25, 4)],
            &BTreeMap::new(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_an_immutable_operator_callback_as_a_direct_function_call() {
        let Some(proof) = fixture(18) else { return };
        let eq = proof
            .rows("pg_proc")
            .unwrap()
            .find(|row| {
                let f = &row["fields"];
                f["proname"].as_str() == Some("int4eq")
                    && f["proargtypes"] == serde_json::json!([23, 23])
                    && field_oid(f, "prorettype") == 16
            })
            .unwrap()["identity"]
            .as_u64()
            .unwrap() as u32;
        let relation = 90_002;
        let tree = node_tree::parse_and_extract(
            &format!(
                "{{FUNCEXPR :funcid {eq} :funcresulttype 16 :funcretset false :funcvariadic false :funcformat 0 :funccollid 0 :inputcollid 0 :args ({{CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location -1 :constvalue 4 [ 1 0 0 0 0 0 0 0 ]}} {{CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location -1 :constvalue 4 [ 1 0 0 0 0 0 0 0 ]}}) :location -1}}"
            ),
            18,
            node_tree::Context::index(relation),
        )
        .unwrap();
        assert!(precheck(&tree, &proof, &[], &BTreeMap::new()).is_err());
    }

    #[test]
    fn rejects_var_type_mismatch_and_unproven_operator_function_pair() {
        let Some(proof) = fixture(18) else { return };
        let relation = 90_003;
        let bad_var = node_tree::parse_and_extract(
            &var(18, 4, 25, 100),
            18,
            node_tree::Context::index(relation),
        )
        .unwrap();
        let int_column = column(&proof, relation, 23, 4);
        assert!(precheck(&bad_var, &proof, &[int_column], &BTreeMap::new()).is_err());

        let operator = proof
            .rows("pg_operator")
            .unwrap()
            .find(|row| {
                let f = &row["fields"];
                f["oprname"].as_str() == Some("=")
                    && field_oid(f, "oprleft") == 23
                    && field_oid(f, "oprright") == 23
            })
            .unwrap();
        let opno = operator["identity"].as_u64().unwrap() as u32;
        let opfunc = field_oid(&operator["fields"], "oprcode");
        let tree = node_tree::parse_and_extract(
            &format!(
                "{{OPEXPR :opno {opno} :opfuncid {opfunc} :opresulttype 16 :opretset false :opcollid 0 :inputcollid 0 :args ({} {{CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location -1 :constvalue 4 [ 1 0 0 0 0 0 0 0 ]}}) :location -1}}",
                var(18, 4, 23, 0)
            ),
            18,
            node_tree::Context::check(relation),
        )
        .unwrap();
        let mut forged = tree;
        forged.operator_calls[0].opfuncid = 999_999;
        assert!(
            precheck(
                &forged,
                &proof,
                &[column(&proof, relation, 23, 4)],
                &BTreeMap::new()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_pseudotype_constants_and_requires_semantic_regconfig_resolution() {
        let Some(proof) = fixture(18) else { return };
        let relation = 90_004;
        let pseudo = node_tree::parse_and_extract(
            "{CONST :consttype 2281 :consttypmod -1 :constcollid 0 :constlen 8 :constbyval true :constisnull false :location -1 :constvalue 8 [ 1 0 0 0 0 0 0 0 ]}",
            18,
            node_tree::Context::index(relation),
        )
        .unwrap();
        assert!(precheck(&pseudo, &proof, &[], &BTreeMap::new()).is_err());

        let tsvector = oid_by_name(&proof, "pg_proc", "proname", "to_tsvector");
        let tree = node_tree::parse_and_extract(
            &format!(
                "{{FUNCEXPR :funcid {tsvector} :funcresulttype 3614 :funcretset false :funcvariadic false :funcformat 0 :funccollid 0 :inputcollid 100 :args ({{CONST :consttype 3734 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location -1 :constvalue 4 [ 1 0 0 0 0 0 0 0 ]}} {{CONST :consttype 25 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval false :constisnull false :location -1 :constvalue 4 [ 116 101 120 116 ]}}) :location -1}}"
            ),
            18,
            node_tree::Context::index(relation),
        )
        .unwrap();
        let checked = precheck(&tree, &proof, &[], &BTreeMap::new()).unwrap();
        assert!(checked.requires_regconfig());
        assert!(checked.finish(None).is_err());
        assert!(
            precheck(&tree, &proof, &[], &BTreeMap::new())
                .unwrap()
                .finish(Some(1))
                .is_err()
        );
        let simple = proof
            .runtime_oid_for_identity("pg_ts_config", "$builtin:pg_ts_config:pg_catalog.simple")
            .unwrap();
        assert!(
            precheck(&tree, &proof, &[], &BTreeMap::new())
                .unwrap()
                .finish(Some(simple))
                .is_ok()
        );
    }

    #[test]
    fn accepts_reviewed_simple_and_english_config_closures_for_pg12_and_pg18() {
        for major in [12, 18] {
            let proof = fixture(major).expect("owned both-module PG profile fixtures are required");
            let tree = explicit_tsvector_expression(&proof, major);
            for name in ["simple", "english"] {
                let identity = format!("$builtin:pg_ts_config:pg_catalog.{name}");
                let config_oid = proof
                    .runtime_oid_for_identity("pg_ts_config", &identity)
                    .expect("reviewed builtin config exists");
                let checked = precheck(&tree, &proof, &[], &BTreeMap::new()).unwrap();
                assert!(checked.requires_regconfig());
                let result = checked.finish(Some(config_oid));
                assert!(result.is_ok(), "major {major}, {name}: {result:?}");
            }
        }
    }

    #[test]
    fn rejects_tampered_config_map_dictionary_and_template_callback_profiles() {
        for major in [12, 18] {
            let (profile, original, pin) =
                fixture_values(major).expect("owned both-module PG profile fixtures are required");
            let oid = |table: &str, field: &str, name: &str| -> String {
                original["tables"][table]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row[field] == name)
                    .unwrap()["oid"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            };
            let english_config = oid("pg_ts_config", "cfgname", "english");
            let simple_dict = oid("pg_ts_dict", "dictname", "simple");
            let english_dict = oid("pg_ts_dict", "dictname", "english_stem");
            let simple_template = oid("pg_ts_template", "tmplname", "simple");
            let snowball_template = oid("pg_ts_template", "tmplname", "snowball");

            let mut bad_map = original.clone();
            let map = bad_map["tables"]["pg_ts_config_map"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["mapcfg"] == english_config && row["mapdict"] == simple_dict)
                .unwrap();
            map["mapdict"] = english_dict.into();
            assert!(DependencyProof::from_test_values(&profile, &bad_map, major, &pin).is_err());

            let mut bad_callback = original.clone();
            let template = bad_callback["tables"]["pg_ts_template"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["oid"] == snowball_template)
                .unwrap();
            template["tmpllexize"] = "0".into();
            assert!(
                DependencyProof::from_test_values(&profile, &bad_callback, major, &pin).is_err()
            );

            let mut bad_dictionary = original.clone();
            let dictionary = bad_dictionary["tables"]["pg_ts_dict"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["dictname"] == "english_stem")
                .unwrap();
            dictionary["dicttemplate"] = simple_template.into();
            assert!(
                DependencyProof::from_test_values(&profile, &bad_dictionary, major, &pin).is_err()
            );
        }
    }
}
