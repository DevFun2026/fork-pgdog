//! Binds catalog index rows to the already-proven table columns, expressions,
//! and immutable operator/access-method dependency profile.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    dependency_profile::DependencyProof,
    expression_proof::ExpressionProof,
    namespace_authority::NamespaceAuthorityProof,
    node_tree::{self, ExpressionKind},
    rows::ColumnRow,
    type_proof::EnumTypeProof,
};

const MAX_INDEX_ATTRIBUTES: usize = 32;
const MAX_RELATION_COLUMNS: usize = 1_600;
const MAX_INDEX_METADATA_BYTES: usize = 1024 * 1024;
const SCALAR_TYPES: &[u32] = &[
    16, 17, 20, 21, 23, 25, 700, 701, 1042, 1043, 1082, 1083, 1114, 1184, 1186, 1266, 1700, 2950,
    3802,
];
const ARRAY_TYPES: &[u32] = &[1007, 1009, 1182, 1231];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    InvalidMetadata,
    MissingDependency,
    UnapprovedMethod,
    UnapprovedOpclass,
    TypeMismatch,
    CollationMismatch,
    ExpressionMismatch,
    MutableNamespace,
    UnsupportedOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexProof {
    index_oid: u32,
    relation_oid: u32,
    method: String,
    unique: bool,
    primary: bool,
    exclusion: bool,
    immediate: bool,
    predicate_present: bool,
    key_types: Vec<u32>,
    key_attnums: Vec<i16>,
    key_families: Vec<u32>,
    index_row_digest: [u8; 32],
    columns_digest: [u8; 32],
    proof_digest: [u8; 32],
    dependency_digest: [u8; 32],
    namespace_digest: [u8; 32],
    enum_digests: BTreeMap<u32, [u8; 32]>,
}

/// Independent catalog and policy evidence required to prove an index row.
/// Keeping these inputs named makes the trust boundaries visible at callsites.
pub(crate) struct ProofContext<'a> {
    pub(crate) columns: &'a [ColumnRow],
    pub(crate) expression_proofs: &'a [ExpressionProof],
    pub(crate) predicate: Option<&'a ExpressionProof>,
    pub(crate) dependencies: &'a DependencyProof,
    pub(crate) enums: &'a BTreeMap<u32, EnumTypeProof>,
    pub(crate) role_oid: u32,
    pub(crate) authority: &'a NamespaceAuthorityProof,
    pub(crate) index_attribute_options: &'a [Option<Vec<String>>],
}

impl IndexProof {
    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.proof_digest
    }

    pub(crate) fn matches_dependencies(&self, dependencies: &DependencyProof) -> bool {
        self.dependency_digest == *dependencies.digest()
    }

    pub(crate) fn index_oid(&self) -> u32 {
        self.index_oid
    }

    pub(crate) fn relation_oid(&self) -> u32 {
        self.relation_oid
    }

    pub(crate) fn is_unique(&self) -> bool {
        self.unique
    }

    pub(crate) fn is_primary(&self) -> bool {
        self.primary
    }

    pub(crate) fn is_exclusion(&self) -> bool {
        self.exclusion
    }

    pub(crate) fn is_immediate(&self) -> bool {
        self.immediate
    }

    pub(crate) fn has_predicate(&self) -> bool {
        self.predicate_present
    }

    pub(crate) fn key_types(&self) -> &[u32] {
        &self.key_types
    }

    pub(crate) fn key_attnums(&self) -> &[i16] {
        &self.key_attnums
    }

    /// Check that a profiled GiST search operator belongs to this exact key's
    /// already-proved operator family and strategy.
    pub(crate) fn supports_exclusion_operator(
        &self,
        key_position: usize,
        operator_oid: u32,
        strategy: u16,
        dependencies: &DependencyProof,
    ) -> bool {
        if !self.exclusion
            || self.method != "gist"
            || !self.matches_dependencies(dependencies)
            || operator_oid == 0
        {
            return false;
        }
        let Some(family_oid) = self.key_families.get(key_position).copied() else {
            return false;
        };
        let Ok(family) = runtime_fields(dependencies, "pg_opfamily", family_oid) else {
            return false;
        };
        let Ok(method_oid) = oid(family.get("opfmethod"), false) else {
            return false;
        };
        dependencies.rows("pg_amop").is_some_and(|rows| {
            rows.into_iter().any(|row| {
                let Some(fields) = row.get("fields") else {
                    return false;
                };
                catalog_oid_ref(dependencies, "pg_opfamily", fields.get("amopfamily"), false).ok()
                    == Some(family_oid)
                    && catalog_oid_ref(dependencies, "pg_operator", fields.get("amopopr"), false)
                        .ok()
                        == Some(operator_oid)
                    && oid(fields.get("amopmethod"), false).ok() == Some(method_oid)
                    && fields.get("amoppurpose").and_then(Value::as_str) == Some("s")
                    && number(fields.get("amopstrategy"))
                        .ok()
                        .and_then(|value| u16::try_from(value).ok())
                        == Some(strategy)
            })
        })
    }
}

/// Prove one complete raw `pg_index` row and its raw `pg_class` index row.
/// `index_attribute_options` must cover every index attribute, including
/// INCLUDE attributes; until an option grammar is reviewed, every entry must
/// be absent.
pub(crate) fn prove(
    index: &Value,
    index_relation: &Value,
    context: ProofContext<'_>,
) -> Result<IndexProof, Error> {
    let ProofContext {
        columns,
        expression_proofs,
        predicate,
        dependencies,
        enums,
        role_oid,
        authority,
        index_attribute_options,
    } = context;
    if !matches!(dependencies.major(), 12 | 18)
        || role_oid == 0
        || columns.is_empty()
        || columns.len() > MAX_RELATION_COLUMNS
    {
        return Err(Error::InvalidMetadata);
    }
    let major = dependencies.major();
    let index_fields = raw_object(index)?;
    validate_index_field_shape(index_fields, major)?;
    let class_fields = raw_object(index_relation)?;
    if serde_json::to_vec(&(index, index_relation))
        .map_err(|_| Error::InvalidMetadata)?
        .len()
        > MAX_INDEX_METADATA_BYTES
    {
        return Err(Error::InvalidMetadata);
    }
    let index_oid = oid(index_fields.get("indexrelid"), false)?;
    let relation_oid = oid(index_fields.get("indrelid"), false)?;
    if oid(class_fields.get("oid"), false)? != index_oid
        || oid(class_fields.get("relowner"), false)? == role_oid
        || oid(class_fields.get("relowner"), false)? == 0
        || oid(class_fields.get("relnamespace"), false)? == 0
        || class_fields.get("relkind").and_then(Value::as_str) != Some("i")
        || class_fields.get("relpersistence").and_then(Value::as_str) != Some("p")
        || class_fields.get("relispartition").and_then(Value::as_bool) != Some(false)
        || class_fields
            .get("relname")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(Error::InvalidMetadata);
    }
    let namespace_oid = oid(class_fields.get("relnamespace"), false)?;
    if !authority.covers(namespace_oid, role_oid) {
        return Err(Error::MutableNamespace);
    }
    let method_oid = oid(class_fields.get("relam"), false)?;
    let method = prove_access_method(dependencies, method_oid)?;

    let natts = bounded_usize(index_fields.get("indnatts"), MAX_INDEX_ATTRIBUTES)?;
    let nkeyatts = bounded_usize(index_fields.get("indnkeyatts"), natts)?;
    if natts == 0 || nkeyatts == 0 || nkeyatts > natts || index_attribute_options.len() != natts {
        return Err(Error::InvalidMetadata);
    }
    if bounded_usize(class_fields.get("relnatts"), MAX_RELATION_COLUMNS)? != natts {
        return Err(Error::InvalidMetadata);
    }
    if index_attribute_options.iter().any(Option::is_some) {
        return Err(Error::UnsupportedOptions);
    }
    let attnums = signed_vector(index_fields.get("indkey"), natts)?;
    let key_attnums = attnums[..nkeyatts]
        .iter()
        .map(|attnum| i16::try_from(*attnum).map_err(|_| Error::InvalidMetadata))
        .collect::<Result<Vec<_>, _>>()?;
    let mut key_types = vec![0; nkeyatts];
    let mut key_families = vec![0; nkeyatts];
    let collations = oid_vector(index_fields.get("indcollation"), nkeyatts)?;
    let opclasses = oid_vector(index_fields.get("indclass"), nkeyatts)?;
    let options = signed_vector(index_fields.get("indoption"), nkeyatts)?;
    if attnums.len() != natts
        || collations.len() != nkeyatts
        || opclasses.len() != nkeyatts
        || options.len() != nkeyatts
    {
        return Err(Error::InvalidMetadata);
    }
    for option in &options {
        if *option < 0
            || if method == "btree" {
                *option & !3 != 0
            } else {
                *option != 0
            }
        {
            return Err(Error::UnsupportedOptions);
        }
    }

    let unique = boolean(index_fields.get("indisunique"))?;
    let primary = boolean(index_fields.get("indisprimary"))?;
    let exclusion = boolean(index_fields.get("indisexclusion"))?;
    let immediate = boolean(index_fields.get("indimmediate"))?;
    let _clustered = boolean(index_fields.get("indisclustered"))?;
    let valid = boolean(index_fields.get("indisvalid"))?;
    let checkxmin = boolean(index_fields.get("indcheckxmin"))?;
    let ready = boolean(index_fields.get("indisready"))?;
    let live = boolean(index_fields.get("indislive"))?;
    let replica_identity = boolean(index_fields.get("indisreplident"))?;
    if !valid
        || checkxmin
        || !ready
        || !live
        || (primary && (!unique || exclusion))
        || (replica_identity && !unique)
        || (exclusion && unique)
        || (!immediate && !unique && !exclusion)
        || (major == 18 && boolean(index_fields.get("indnullsnotdistinct"))? && !unique)
    {
        return Err(Error::InvalidMetadata);
    }

    let expressions = index_fields.get("indexprs").ok_or(Error::InvalidMetadata)?;
    let expression_slots = attnums[..nkeyatts]
        .iter()
        .filter(|attnum| **attnum == 0)
        .count();
    if (expression_slots == 0) != expressions.is_null()
        || (expression_slots > 0
            && (expressions.as_str().is_none_or(|value| value.is_empty())
                || expression_slots != expression_proofs.len()))
        || (expression_slots == 0 && !expression_proofs.is_empty())
    {
        return Err(Error::ExpressionMismatch);
    }
    if let Some(predicate) = predicate {
        let predicate_source = index_fields
            .get("indpred")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .ok_or(Error::ExpressionMismatch)?;
        if predicate_source.len() > node_tree::MAX_BYTES {
            return Err(Error::ExpressionMismatch);
        }
        if predicate.relation_oid() != relation_oid
            || predicate.kind() != ExpressionKind::Predicate
            || predicate.source_digest() != &source_digest(predicate_source)
            || predicate.source_ordinal() != 0
            || predicate.root_type() != 16
            || !predicate.matches_dependencies(dependencies)
        {
            return Err(Error::ExpressionMismatch);
        }
    } else if index_fields
        .get("indpred")
        .is_none_or(|value| !value.is_null())
    {
        return Err(Error::ExpressionMismatch);
    }
    let expression_source = expressions.as_str().unwrap_or_default();
    if expression_source.len() > node_tree::MAX_BYTES {
        return Err(Error::ExpressionMismatch);
    }
    if expression_proofs
        .iter()
        .enumerate()
        .any(|(ordinal, proof)| {
            !proof.matches_dependencies(dependencies)
                || proof.relation_oid() != relation_oid
                || proof.kind() != ExpressionKind::IndexExpression
                || proof.source_digest() != &source_digest(expression_source)
                || proof.source_ordinal() != ordinal
        })
    {
        return Err(Error::ExpressionMismatch);
    }

    let mut by_attnum = BTreeMap::new();
    for column in columns {
        let attnum = column.attribute_number().ok_or(Error::InvalidMetadata)?;
        if !column.valid
            || column.relation_oid != relation_oid
            || column.name.is_empty()
            || !column.generated.is_empty()
            || !column.identity.is_empty()
            || by_attnum.insert(attnum, column).is_some()
        {
            return Err(Error::InvalidMetadata);
        }
    }
    let mut enum_digests = BTreeMap::new();
    let mut expression_index = 0usize;
    for position in 0..natts {
        let attnum = attnums[position];
        if attnum <= 0 {
            if position >= nkeyatts || attnum != 0 {
                return Err(Error::InvalidMetadata);
            }
            continue;
        }
        let column = by_attnum
            .get(&i16::try_from(attnum).map_err(|_| Error::InvalidMetadata)?)
            .ok_or(Error::InvalidMetadata)?;
        prove_column_type(column, dependencies, enums, &mut enum_digests)?;
        if position < nkeyatts {
            key_types[position] = column.type_oid;
            let mut key_context = KeyProofContext {
                dependencies,
                enums,
                role_oid,
                authority,
                enum_digests: &mut enum_digests,
            };
            prove_key(
                opclasses[position],
                collations[position],
                column.type_oid,
                column.collation_oid,
                method_oid,
                method,
                &mut key_context,
            )?;
            key_families[position] = opclass_family(opclasses[position], dependencies)?;
        }
    }
    for position in 0..nkeyatts {
        if attnums[position] == 0 {
            let proof = expression_proofs
                .get(expression_index)
                .ok_or(Error::ExpressionMismatch)?;
            key_types[position] = proof.root_type();
            expression_index += 1;
            let mut key_context = KeyProofContext {
                dependencies,
                enums,
                role_oid,
                authority,
                enum_digests: &mut enum_digests,
            };
            prove_expression_type(
                proof,
                opclasses[position],
                collations[position],
                method_oid,
                method,
                &mut key_context,
            )?;
            key_families[position] = opclass_family(opclasses[position], dependencies)?;
        }
    }
    if expression_index != expression_proofs.len() {
        return Err(Error::ExpressionMismatch);
    }
    if key_types.contains(&0) {
        return Err(Error::InvalidMetadata);
    }
    for proof in expression_proofs.iter().chain(predicate) {
        for (type_oid, digest) in proof.enum_digests() {
            if enums
                .get(type_oid)
                .is_none_or(|enum_proof| enum_proof.digest() != digest)
            {
                return Err(Error::TypeMismatch);
            }
            if enum_digests
                .insert(*type_oid, *digest)
                .is_some_and(|previous| previous != *digest)
            {
                return Err(Error::TypeMismatch);
            }
        }
    }

    let raw_index = serde_json::to_vec(index).map_err(|_| Error::InvalidMetadata)?;
    let encoded_columns = serde_json::to_vec(columns).map_err(|_| Error::InvalidMetadata)?;
    let index_row_digest = digest_bytes(&raw_index);
    let columns_digest = digest_bytes(&encoded_columns);
    let encoded = serde_json::to_vec(&(
        index,
        index_relation,
        columns,
        index_attribute_options,
        dependencies.digest(),
        authority.digest(),
        expression_proofs
            .iter()
            .map(ExpressionProof::root_type)
            .collect::<Vec<_>>(),
        predicate.map(ExpressionProof::root_type),
        &key_families,
        &enum_digests,
    ))
    .map_err(|_| Error::InvalidMetadata)?;
    if encoded.len() > MAX_INDEX_METADATA_BYTES {
        return Err(Error::InvalidMetadata);
    }
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &encoded);
    let mut digest = [0; 32];
    digest.copy_from_slice(hash.as_ref());
    Ok(IndexProof {
        index_oid,
        relation_oid,
        method: method.to_owned(),
        unique,
        primary,
        exclusion,
        immediate,
        predicate_present: predicate.is_some(),
        key_types,
        key_attnums,
        key_families,
        index_row_digest,
        columns_digest,
        proof_digest: digest,
        dependency_digest: *dependencies.digest(),
        namespace_digest: *authority.digest(),
        enum_digests,
    })
}

/// Validate complete physical index attributes against the already-proved
/// logical key types and the version-pinned access-method catalog closure.
pub(crate) fn validate_attributes(
    proof: &IndexProof,
    index: &Value,
    attributes: &[Value],
    columns: &[ColumnRow],
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
) -> Result<[u8; 32], Error> {
    let fields = raw_object(index)?;
    validate_index_field_shape(fields, dependencies.major())?;
    if !proof.matches_dependencies(dependencies)
        || digest_json(index)? != proof.index_row_digest
        || digest_json(columns)? != proof.columns_digest
        || oid(fields.get("indexrelid"), false)? != proof.index_oid
        || oid(fields.get("indrelid"), false)? != proof.relation_oid
    {
        return Err(Error::InvalidMetadata);
    }
    let natts = bounded_usize(fields.get("indnatts"), MAX_INDEX_ATTRIBUTES)?;
    let nkeyatts = bounded_usize(fields.get("indnkeyatts"), natts)?;
    if natts == 0
        || nkeyatts == 0
        || nkeyatts > natts
        || attributes.len() != natts
        || proof.key_types.len() != nkeyatts
        || proof.key_attnums.len() != nkeyatts
    {
        return Err(Error::InvalidMetadata);
    }
    let attnums = signed_vector(fields.get("indkey"), natts)?;
    let collations = oid_vector(fields.get("indcollation"), nkeyatts)?;
    let opclasses = oid_vector(fields.get("indclass"), nkeyatts)?;
    if attnums.len() != natts || collations.len() != nkeyatts || opclasses.len() != nkeyatts {
        return Err(Error::InvalidMetadata);
    }
    let mut by_attnum = BTreeMap::new();
    for column in columns {
        let attnum = column.attribute_number().ok_or(Error::InvalidMetadata)?;
        if !column.valid
            || column.relation_oid != proof.relation_oid
            || column.name.is_empty()
            || by_attnum.insert(attnum, column).is_some()
        {
            return Err(Error::InvalidMetadata);
        }
    }

    let mut stored_enum_digests = BTreeMap::new();
    for (type_oid, digest) in &proof.enum_digests {
        if enums.get(type_oid).is_none_or(|enum_proof| {
            enum_proof.digest() != digest || enum_proof.type_oid() != *type_oid
        }) {
            return Err(Error::TypeMismatch);
        }
        stored_enum_digests.insert(*type_oid, *digest);
    }
    for (position, attribute) in attributes.iter().enumerate() {
        let attribute_fields = raw_object(attribute)?;
        validate_attribute_field_shape(attribute_fields, dependencies.major())?;
        let attnum = u32::try_from(position + 1).map_err(|_| Error::InvalidMetadata)?;
        let stored_type = oid(attribute_fields.get("atttypid"), false)?;
        if oid(attribute_fields.get("attrelid"), false)? != proof.index_oid
            || oid(attribute_fields.get("attnum"), false)? != attnum
            || boolean(attribute_fields.get("attisdropped"))?
            || boolean(attribute_fields.get("attnotnull"))?
            || boolean(attribute_fields.get("atthasdef"))?
            || boolean(attribute_fields.get("atthasmissing"))?
            || boolean(attribute_fields.get("attmissingval_present"))?
            || !boolean(attribute_fields.get("attislocal"))?
            || number(attribute_fields.get("attinhcount"))? != 0
            || number(attribute_fields.get("attndims"))? < 0
            || number(attribute_fields.get("attndims"))? > 6
            || attribute_fields
                .get("attname")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || attribute_fields.get("attgenerated").and_then(Value::as_str) != Some("")
            || attribute_fields.get("attidentity").and_then(Value::as_str) != Some("")
            || !attribute_fields.get("attacl").is_some_and(Value::is_null)
            || !attribute_fields
                .get("attfdwoptions")
                .is_some_and(Value::is_null)
            || !attribute_fields
                .get("attoptions")
                .is_some_and(Value::is_null)
        {
            return Err(Error::UnsupportedOptions);
        }

        let (expected_type, expected_collation, expected_modifier, expected_dimensions) =
            if position < nkeyatts {
                let key_attnum = attnums[position];
                if i16::try_from(key_attnum).map_err(|_| Error::InvalidMetadata)?
                    != proof.key_attnums[position]
                {
                    return Err(Error::InvalidMetadata);
                }
                let key_type = proof.key_types[position];
                let expected_type = expected_storage_type(
                    key_type,
                    opclasses[position],
                    proof.method.as_str(),
                    dependencies,
                    enums,
                    &mut stored_enum_digests,
                )?;
                if key_attnum > 0 {
                    let column_number =
                        i16::try_from(key_attnum).map_err(|_| Error::InvalidMetadata)?;
                    let column = by_attnum
                        .get(&column_number)
                        .ok_or(Error::InvalidMetadata)?;
                    if column.type_oid != key_type {
                        return Err(Error::TypeMismatch);
                    }
                    prove_column_type(column, dependencies, enums, &mut stored_enum_digests)?;
                    (
                        expected_type,
                        collations[position],
                        if expected_type == column.type_oid {
                            column.type_modifier().ok_or(Error::InvalidMetadata)?
                        } else {
                            -1
                        },
                        column.array_dimensions().ok_or(Error::InvalidMetadata)?,
                    )
                } else {
                    // Expression keys have no source column carrying a typmod or
                    // declared array rank. PostgreSQL stores the default metadata.
                    (expected_type, collations[position], -1, 0)
                }
            } else {
                if attnums[position] <= 0 {
                    return Err(Error::InvalidMetadata);
                }
                let column_number =
                    i16::try_from(attnums[position]).map_err(|_| Error::InvalidMetadata)?;
                let column = by_attnum
                    .get(&column_number)
                    .ok_or(Error::InvalidMetadata)?;
                prove_column_type(column, dependencies, enums, &mut stored_enum_digests)?;
                (
                    column.type_oid,
                    column.collation_oid,
                    column.type_modifier().ok_or(Error::InvalidMetadata)?,
                    column.array_dimensions().ok_or(Error::InvalidMetadata)?,
                )
            };
        if stored_type != expected_type
            || oid(attribute_fields.get("attcollation"), true)? != expected_collation
            || number(attribute_fields.get("atttypmod"))? != i64::from(expected_modifier)
            || number(attribute_fields.get("attndims"))? != i64::from(expected_dimensions)
        {
            return Err(Error::TypeMismatch);
        }
        validate_stored_type(
            attribute_fields,
            stored_type,
            dependencies,
            enums,
            &mut stored_enum_digests,
        )?;
    }
    for (type_oid, digest) in &stored_enum_digests {
        if enums
            .get(type_oid)
            .is_none_or(|proof| proof.digest() != digest)
        {
            return Err(Error::TypeMismatch);
        }
    }
    let encoded = serde_json::to_vec(&(
        proof.digest(),
        index,
        attributes,
        columns,
        dependencies.digest(),
        &stored_enum_digests,
    ))
    .map_err(|_| Error::InvalidMetadata)?;
    if encoded.len() > MAX_INDEX_METADATA_BYTES {
        return Err(Error::InvalidMetadata);
    }
    Ok(digest_bytes(&encoded))
}

fn expected_storage_type(
    key_type: u32,
    opclass_oid: u32,
    method: &str,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<u32, Error> {
    let opclass = runtime_fields(dependencies, "pg_opclass", opclass_oid)?;
    let input_type = oid(opclass.get("opcintype"), false)?;
    let key_storage = catalog_oid_ref(dependencies, "pg_type", opclass.get("opckeytype"), true)?;
    let expected = if method == "hash" {
        if key_storage != 0 {
            return Err(Error::TypeMismatch);
        }
        23 // Hash indexes store the 32-bit hash value.
    } else if key_storage == 0 {
        match method {
            "btree" | "gist" => key_type,
            // A zero key type has no general GIN storage interpretation.
            _ => return Err(Error::UnapprovedMethod),
        }
    } else if key_storage == 2283 {
        if input_type != 2277 || !ARRAY_TYPES.contains(&key_type) {
            return Err(Error::TypeMismatch);
        }
        prove_type_oid(key_type, dependencies, enums, enum_digests)?;
        let array = runtime_fields(dependencies, "pg_type", key_type)?;
        let element = oid(array.get("typelem"), false)?;
        let element_fields = runtime_fields(dependencies, "pg_type", element)?;
        if oid(element_fields.get("typarray"), false)? != key_type {
            return Err(Error::TypeMismatch);
        }
        element
    } else {
        let storage_fields = runtime_fields(dependencies, "pg_type", key_storage)?;
        if storage_fields.get("typtype").and_then(Value::as_str) == Some("p") {
            return Err(Error::TypeMismatch);
        }
        key_storage
    };
    if expected == 0 {
        return Err(Error::TypeMismatch);
    }
    if enums.contains_key(&expected) {
        prove_type_oid(expected, dependencies, enums, enum_digests)?;
    }
    Ok(expected)
}

fn validate_stored_type(
    attribute: &serde_json::Map<String, Value>,
    type_oid: u32,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<(), Error> {
    if let Some(enum_proof) = enums.get(&type_oid) {
        if enum_proof.type_oid() != type_oid {
            return Err(Error::TypeMismatch);
        }
        enum_digests.insert(type_oid, *enum_proof.digest());
    }
    let fields = runtime_fields(dependencies, "pg_type", type_oid)?;
    if catalog_oid_ref(dependencies, "pg_type", fields.get("oid"), false)? != type_oid
        || fields.get("typtype").and_then(Value::as_str) == Some("p")
        || number(attribute.get("attlen"))? != number(fields.get("typlen"))?
        || boolean(attribute.get("attbyval"))? != boolean(fields.get("typbyval"))?
        || attribute.get("attalign").and_then(Value::as_str)
            != fields.get("typalign").and_then(Value::as_str)
        || attribute.get("attstorage").and_then(Value::as_str)
            != fields.get("typstorage").and_then(Value::as_str)
    {
        return Err(Error::TypeMismatch);
    }
    let input = catalog_oid_ref(dependencies, "pg_proc", fields.get("typinput"), false)?;
    let output = catalog_oid_ref(dependencies, "pg_proc", fields.get("typoutput"), false)?;
    if input == 0 || output == 0 {
        return Err(Error::MissingDependency);
    }
    for callback in ["typreceive", "typsend"] {
        if catalog_oid_ref(dependencies, "pg_proc", fields.get(callback), true)? == 0 {
            continue;
        }
    }
    Ok(())
}

fn validate_attribute_field_shape(
    fields: &serde_json::Map<String, Value>,
    major: u32,
) -> Result<(), Error> {
    let mut expected = [
        "attacl",
        "attalign",
        "attbyval",
        "attcollation",
        "attfdwoptions",
        "attgenerated",
        "atthasdef",
        "atthasmissing",
        "attidentity",
        "attinhcount",
        "attisdropped",
        "attislocal",
        "attlen",
        "attmissingval_present",
        "attname",
        "attndims",
        "attnotnull",
        "attnum",
        "attoptions",
        "attrelid",
        "attstattarget",
        "attstorage",
        "atttypid",
        "atttypmod",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    match major {
        12 => {
            expected.insert("attcacheoff");
            if number(fields.get("attstattarget"))? != -1 {
                return Err(Error::InvalidMetadata);
            }
        }
        18 => {
            expected.insert("attcompression");
            if !fields.get("attstattarget").is_some_and(Value::is_null) {
                return Err(Error::InvalidMetadata);
            }
        }
        _ => return Err(Error::InvalidMetadata),
    }
    if fields.len() != expected.len() || fields.keys().any(|key| !expected.contains(key.as_str())) {
        return Err(Error::InvalidMetadata);
    }
    if major == 12 && number(fields.get("attcacheoff"))? != -1 {
        return Err(Error::InvalidMetadata);
    }
    if major == 18
        && fields
            .get("attcompression")
            .and_then(Value::as_str)
            .is_none_or(|value| !matches!(value, "" | "p" | "l"))
    {
        return Err(Error::InvalidMetadata);
    }
    Ok(())
}

fn digest_json<T: serde::Serialize + ?Sized>(value: &T) -> Result<[u8; 32], Error> {
    let encoded = serde_json::to_vec(value).map_err(|_| Error::InvalidMetadata)?;
    if encoded.len() > MAX_INDEX_METADATA_BYTES {
        return Err(Error::InvalidMetadata);
    }
    Ok(digest_bytes(&encoded))
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut digest = [0; 32];
    digest.copy_from_slice(hash.as_ref());
    digest
}

fn raw_object(value: &Value) -> Result<&serde_json::Map<String, Value>, Error> {
    value.as_object().ok_or(Error::InvalidMetadata)
}

fn source_digest(source: &str) -> [u8; 32] {
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, source.as_bytes());
    let mut digest = [0; 32];
    digest.copy_from_slice(hash.as_ref());
    digest
}

fn validate_index_field_shape(
    fields: &serde_json::Map<String, Value>,
    major: u32,
) -> Result<(), Error> {
    let common = [
        "indexrelid",
        "indrelid",
        "indnatts",
        "indnkeyatts",
        "indisunique",
        "indisprimary",
        "indisexclusion",
        "indimmediate",
        "indisclustered",
        "indisvalid",
        "indcheckxmin",
        "indisready",
        "indislive",
        "indisreplident",
        "indkey",
        "indcollation",
        "indclass",
        "indoption",
        "indexprs",
        "indpred",
    ];
    let mut expected = common
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if major == 18 {
        expected.insert("indnullsnotdistinct");
    }
    if !matches!(major, 12 | 18)
        || fields.len() != expected.len()
        || fields.keys().any(|key| !expected.contains(key.as_str()))
    {
        return Err(Error::InvalidMetadata);
    }
    Ok(())
}

fn oid(value: Option<&Value>, allow_zero: bool) -> Result<u32, Error> {
    let value = value.ok_or(Error::InvalidMetadata)?;
    let parsed = value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| {
            value
                .as_str()
                .filter(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|text| text.parse::<u32>().ok())
        })
        .ok_or(Error::InvalidMetadata)?;
    if parsed == 0 && !allow_zero {
        Err(Error::InvalidMetadata)
    } else {
        Ok(parsed)
    }
}

fn catalog_oid_ref(
    dependencies: &DependencyProof,
    catalog: &str,
    value: Option<&Value>,
    allow_zero: bool,
) -> Result<u32, Error> {
    let value = value.ok_or(Error::InvalidMetadata)?;
    if let Some(identity) = value
        .as_str()
        .filter(|text| !text.is_empty() && !text.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return dependencies
            .runtime_oid_for_identity(catalog, identity)
            .ok_or(Error::MissingDependency);
    }
    oid(Some(value), allow_zero)
}

fn number(value: Option<&Value>) -> Result<i64, Error> {
    let value = value.ok_or(Error::InvalidMetadata)?;
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .ok_or(Error::InvalidMetadata)
}

fn bounded_usize(value: Option<&Value>, max: usize) -> Result<usize, Error> {
    usize::try_from(number(value)?)
        .ok()
        .filter(|value| *value <= max)
        .ok_or(Error::InvalidMetadata)
}

fn boolean(value: Option<&Value>) -> Result<bool, Error> {
    value.and_then(Value::as_bool).ok_or(Error::InvalidMetadata)
}

fn signed_vector(value: Option<&Value>, max: usize) -> Result<Vec<i64>, Error> {
    let values = value
        .and_then(Value::as_array)
        .ok_or(Error::InvalidMetadata)?;
    if values.len() > max {
        return Err(Error::InvalidMetadata);
    }
    values.iter().map(|value| number(Some(value))).collect()
}

fn oid_vector(value: Option<&Value>, max: usize) -> Result<Vec<u32>, Error> {
    let values = value
        .and_then(Value::as_array)
        .ok_or(Error::InvalidMetadata)?;
    if values.len() > max {
        return Err(Error::InvalidMetadata);
    }
    values.iter().map(|value| oid(Some(value), true)).collect()
}

fn runtime_fields<'a>(
    dependencies: &'a DependencyProof,
    catalog: &str,
    oid: u32,
) -> Result<&'a Value, Error> {
    let identity = dependencies
        .identity_for_runtime_oid(catalog, oid)
        .ok_or(Error::MissingDependency)?;
    dependencies
        .row(catalog, identity)
        .and_then(|row| row.get("fields"))
        .filter(|fields| fields.is_object())
        .ok_or(Error::MissingDependency)
}

fn prove_access_method(
    dependencies: &DependencyProof,
    method_oid: u32,
) -> Result<&'static str, Error> {
    let fields = runtime_fields(dependencies, "pg_am", method_oid)?;
    let name = fields
        .get("amname")
        .and_then(Value::as_str)
        .ok_or(Error::UnapprovedMethod)?;
    let handler_oid = oid(fields.get("amhandler"), false)?;
    let expected_handler = match name {
        "btree" => "bthandler",
        "hash" => "hashhandler",
        "gin" => "ginhandler",
        "gist" => "gisthandler",
        _ => return Err(Error::UnapprovedMethod),
    };
    if fields.get("amtype").and_then(Value::as_str) != Some("i") {
        return Err(Error::UnapprovedMethod);
    }
    let handler_fields = runtime_fields(dependencies, "pg_proc", handler_oid)?;
    if handler_fields.get("proname").and_then(Value::as_str) != Some(expected_handler)
        || number(handler_fields.get("prorettype"))? != 325
        || handler_fields
            .get("proargtypes")
            .and_then(Value::as_array)
            .is_none_or(|args| args.len() != 1 || oid(args.first(), false).ok() != Some(2281))
        || handler_fields.get("prokind").and_then(Value::as_str) != Some("f")
        || handler_fields.get("prosecdef").and_then(Value::as_bool) != Some(false)
        || !handler_fields.get("proconfig").is_some_and(Value::is_null)
        || handler_fields.get("provolatile").and_then(Value::as_str) != Some("v")
    {
        return Err(Error::UnapprovedMethod);
    }
    // The returned name is one of four static literals above.
    Ok(match name {
        "btree" => "btree",
        "hash" => "hash",
        "gin" => "gin",
        "gist" => "gist",
        _ => unreachable!(),
    })
}

fn prove_column_type(
    column: &ColumnRow,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<(), Error> {
    if let Some(proof) = enums.get(&column.type_oid) {
        let metadata = proof.metadata();
        let capabilities = proof.capabilities();
        if proof.type_oid() != column.type_oid
            || namespace_name(dependencies, metadata.schema_oid)? != column.type_schema
            || metadata.name != column.type_name
            || metadata.kind != b'e'
            || metadata.base_type_oid != column.base_type_oid
            || metadata.input_oid != column.type_input_oid
            || metadata.output_oid != column.type_output_oid
            || metadata.receive_oid != column.type_receive_oid
            || metadata.send_oid != column.type_send_oid
            || metadata.collation_oid != column.collation_oid
            || metadata.owner_oid == 0
            || metadata.schema_oid == 0
            || column.type_schema.is_empty()
            || column.type_kind != "e"
            || !capabilities.text_output
            || !capabilities.binary_output
            || !capabilities.text_input
            || !capabilities.binary_input
        {
            return Err(Error::TypeMismatch);
        }
        enum_digests.insert(column.type_oid, *proof.digest());
        return Ok(());
    }
    let fields = runtime_fields(dependencies, "pg_type", column.type_oid)?;
    if namespace_name(dependencies, oid(fields.get("typnamespace"), false)?)? != column.type_schema
        || fields.get("typname").and_then(Value::as_str) != Some(column.type_name.as_str())
        || fields.get("typtype").and_then(Value::as_str) != Some(column.type_kind.as_str())
        || oid(fields.get("typbasetype"), true)? != column.base_type_oid
        || oid(fields.get("typinput"), false)? != column.type_input_oid
        || oid(fields.get("typoutput"), false)? != column.type_output_oid
        || oid(fields.get("typreceive"), false)? != column.type_receive_oid
        || oid(fields.get("typsend"), false)? != column.type_send_oid
        || oid(fields.get("typcollation"), true)? != column.collation_oid
    {
        return Err(Error::TypeMismatch);
    }
    prove_type_oid(column.type_oid, dependencies, enums, enum_digests)
}

fn namespace_name(dependencies: &DependencyProof, namespace_oid: u32) -> Result<String, Error> {
    let identity = dependencies
        .identity_for_runtime_oid("pg_namespace", namespace_oid)
        .ok_or(Error::MissingDependency)?;
    runtime_fields(dependencies, "pg_namespace", namespace_oid)?
        .get("nspname")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|name| !name.is_empty() && !identity.is_empty())
        .ok_or(Error::MissingDependency)
}

fn prove_type_oid(
    type_oid: u32,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<(), Error> {
    if let Some(proof) = enums.get(&type_oid) {
        let c = proof.capabilities();
        if proof.type_oid() != type_oid
            || !c.text_output
            || !c.binary_output
            || !c.text_input
            || !c.binary_input
        {
            return Err(Error::TypeMismatch);
        }
        enum_digests.insert(type_oid, *proof.digest());
        return Ok(());
    }
    let fields = runtime_fields(dependencies, "pg_type", type_oid)?;
    if ARRAY_TYPES.contains(&type_oid) {
        let elem = oid(fields.get("typelem"), false)?;
        let elem_fields = runtime_fields(dependencies, "pg_type", elem)?;
        if number(fields.get("typnamespace"))? != 11
            || fields.get("typtype").and_then(Value::as_str) != Some("b")
            || fields.get("typcategory").and_then(Value::as_str) != Some("A")
            || number(fields.get("typbasetype"))? != 0
            || number(fields.get("typlen"))? != -1
            || oid(elem_fields.get("typarray"), true)? != type_oid
            || !SCALAR_TYPES.contains(&elem)
        {
            return Err(Error::TypeMismatch);
        }
        return prove_type_oid(elem, dependencies, enums, enum_digests);
    }
    if SCALAR_TYPES.contains(&type_oid) {
        if number(fields.get("typnamespace"))? != 11
            || fields.get("typtype").and_then(Value::as_str) != Some("b")
            || number(fields.get("typbasetype"))? != 0
            || oid(fields.get("typelem"), true)? != 0
            || oid(fields.get("typowner"), false)? != 10
        {
            return Err(Error::TypeMismatch);
        }
        return Ok(());
    }
    if type_oid == 3614 {
        if number(fields.get("typnamespace"))? != 11
            || fields.get("typtype").and_then(Value::as_str) != Some("b")
            || oid(fields.get("typowner"), false)? != 10
        {
            return Err(Error::TypeMismatch);
        }
        return Ok(());
    }
    if type_oid == 3910 {
        let range = runtime_fields(dependencies, "pg_range", type_oid)?;
        if fields.get("typtype").and_then(Value::as_str) != Some("r")
            || number(fields.get("typnamespace"))? != 11
            || oid(fields.get("typowner"), false)? != 10
            || oid(range.get("rngsubtype"), false)? != 1184
        {
            return Err(Error::TypeMismatch);
        }
        return prove_type_oid(1184, dependencies, enums, enum_digests);
    }
    Err(Error::TypeMismatch)
}

struct KeyProofContext<'a> {
    dependencies: &'a DependencyProof,
    enums: &'a BTreeMap<u32, EnumTypeProof>,
    role_oid: u32,
    authority: &'a NamespaceAuthorityProof,
    enum_digests: &'a mut BTreeMap<u32, [u8; 32]>,
}

fn prove_key(
    opclass_oid: u32,
    index_collation: u32,
    actual_type: u32,
    actual_collation: u32,
    method_oid: u32,
    method: &str,
    context: &mut KeyProofContext<'_>,
) -> Result<(), Error> {
    let dependencies = context.dependencies;
    let enums = context.enums;
    let role_oid = context.role_oid;
    let authority = context.authority;
    let enum_digests = &mut *context.enum_digests;
    let opc = runtime_fields(dependencies, "pg_opclass", opclass_oid)?;
    if oid(opc.get("opcmethod"), false)? != method_oid {
        return Err(Error::UnapprovedOpclass);
    }
    let namespace = oid(opc.get("opcnamespace"), false)?;
    if namespace != 11 && namespace != 2200 {
        return Err(Error::UnapprovedOpclass);
    }
    if namespace != 11 && !authority.covers(namespace, role_oid) {
        return Err(Error::MutableNamespace);
    }
    let input_type = oid(opc.get("opcintype"), false)?;
    if !opclass_accepts_type(
        input_type,
        actual_type,
        method,
        dependencies,
        enums,
        enum_digests,
    )? {
        return Err(Error::TypeMismatch);
    }
    prove_type_oid(actual_type, dependencies, enums, enum_digests)?;
    let expected_collation = type_collation_oid(actual_type, dependencies, enums)?;
    if index_collation != actual_collation
        || index_collation != expected_collation
        || !matches!(index_collation, 0 | 100 | 950 | 951)
        || (input_type == 3802 && index_collation != 0)
    {
        return Err(Error::CollationMismatch);
    }
    let family_oid = catalog_oid_ref(dependencies, "pg_opfamily", opc.get("opcfamily"), false)?;
    let family = runtime_fields(dependencies, "pg_opfamily", family_oid)?;
    if oid(family.get("opfmethod"), false)? != method_oid
        || oid(family.get("opfnamespace"), false)? != namespace
    {
        return Err(Error::UnapprovedOpclass);
    }
    if namespace == 2200 {
        let identity = dependencies
            .identity_for_runtime_oid("pg_opclass", opclass_oid)
            .ok_or(Error::UnapprovedOpclass)?;
        let extension = if identity.starts_with("$extension:pg_trgm:") {
            "pg_trgm"
        } else if identity.starts_with("$extension:btree_gist:") {
            "btree_gist"
        } else {
            return Err(Error::UnapprovedOpclass);
        };
        if !dependencies.has_extension_identity(extension, identity) {
            return Err(Error::UnapprovedOpclass);
        }
        let family_identity = dependencies
            .identity_for_runtime_oid("pg_opfamily", family_oid)
            .ok_or(Error::UnapprovedOpclass)?;
        if !family_identity.starts_with(&format!("$extension:{extension}:"))
            || !dependencies.has_extension_identity(extension, family_identity)
        {
            return Err(Error::UnapprovedOpclass);
        }
    }
    Ok(())
}

fn opclass_family(opclass_oid: u32, dependencies: &DependencyProof) -> Result<u32, Error> {
    let opclass = runtime_fields(dependencies, "pg_opclass", opclass_oid)?;
    catalog_oid_ref(dependencies, "pg_opfamily", opclass.get("opcfamily"), false)
}

fn opclass_accepts_type(
    input_type: u32,
    actual_type: u32,
    method: &str,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
    enum_digests: &mut BTreeMap<u32, [u8; 32]>,
) -> Result<bool, Error> {
    if input_type == actual_type {
        return Ok(true);
    }
    match input_type {
        2277 => Ok(ARRAY_TYPES.contains(&actual_type)
            && prove_type_oid(actual_type, dependencies, enums, enum_digests).is_ok()),
        3500 => Ok(enums.contains_key(&actual_type)
            && prove_type_oid(actual_type, dependencies, enums, enum_digests).is_ok()),
        3831 => Ok(actual_type == 3910
            && prove_type_oid(actual_type, dependencies, enums, enum_digests).is_ok()),
        25 if actual_type == 1043 => Ok(has_binary_cast(actual_type, input_type, dependencies)),
        25 if actual_type == 1042 => Ok(has_known_bpchar_text_cast(dependencies)),
        _ => {
            let _ = method;
            Ok(false)
        }
    }
}

fn type_collation_oid(
    type_oid: u32,
    dependencies: &DependencyProof,
    enums: &BTreeMap<u32, EnumTypeProof>,
) -> Result<u32, Error> {
    if let Some(proof) = enums.get(&type_oid) {
        return Ok(proof.metadata().collation_oid);
    }
    if matches!(type_oid, 1042 | 1043) {
        return Ok(100);
    }
    oid(
        runtime_fields(dependencies, "pg_type", type_oid)?.get("typcollation"),
        true,
    )
}

fn has_binary_cast(source: u32, target: u32, dependencies: &DependencyProof) -> bool {
    dependencies.rows("pg_cast").is_some_and(|rows| {
        rows.into_iter().any(|row| {
            let Some(fields) = row.get("fields") else {
                return false;
            };
            oid(fields.get("castsource"), false).ok() == Some(source)
                && oid(fields.get("casttarget"), false).ok() == Some(target)
                && fields.get("castmethod").and_then(Value::as_str) == Some("b")
                && oid(fields.get("castfunc"), true).ok() == Some(0)
        })
    })
}

fn has_known_bpchar_text_cast(dependencies: &DependencyProof) -> bool {
    dependencies.rows("pg_cast").is_some_and(|rows| {
        rows.into_iter().any(|row| {
            let Some(fields) = row.get("fields") else {
                return false;
            };
            oid(fields.get("castsource"), false).ok() == Some(1042)
                && oid(fields.get("casttarget"), false).ok() == Some(25)
                && fields.get("castmethod").and_then(Value::as_str) == Some("f")
                && fields.get("castcontext").and_then(Value::as_str) == Some("i")
                && oid(fields.get("castfunc"), false).ok() == Some(401)
        })
    }) && runtime_fields(dependencies, "pg_proc", 401).is_ok_and(|proc| {
        proc.get("proname").and_then(Value::as_str) == Some("text")
            && proc
                .get("proargtypes")
                .and_then(Value::as_array)
                .is_some_and(|args| args.len() == 1 && oid(args.first(), false).ok() == Some(1042))
            && oid(proc.get("prorettype"), false).ok() == Some(25)
            && proc.get("provolatile").and_then(Value::as_str) == Some("i")
            && proc.get("prosecdef").and_then(Value::as_bool) == Some(false)
    })
}

fn prove_expression_type(
    proof: &ExpressionProof,
    opclass_oid: u32,
    collation: u32,
    method_oid: u32,
    method: &str,
    context: &mut KeyProofContext<'_>,
) -> Result<(), Error> {
    let dependencies = context.dependencies;
    let enums = context.enums;
    let opclass = runtime_fields(dependencies, "pg_opclass", opclass_oid)?;
    let input_type = oid(opclass.get("opcintype"), false)?;
    let root_type = proof.root_type();
    prove_type_oid(root_type, dependencies, enums, &mut *context.enum_digests)?;
    if !opclass_accepts_type(
        input_type,
        root_type,
        method,
        dependencies,
        enums,
        &mut *context.enum_digests,
    )? {
        return Err(Error::TypeMismatch);
    }
    let expected_collation = type_collation_oid(root_type, dependencies, enums)?;
    if collation != expected_collation || !matches!(collation, 0 | 100 | 950 | 951) {
        return Err(Error::CollationMismatch);
    }
    prove_key(
        opclass_oid,
        collation,
        root_type,
        expected_collation,
        method_oid,
        method,
        context,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::schema::read_policy::{
            dependency_profile::DependencyProof, expression_proof, namespace_authority, node_tree,
            rows::RoleRow,
        },
        net::messages::DataRow,
    };
    use serde_json::{Value, json};

    const ACTOR: u32 = 20_001;

    #[expect(
        clippy::too_many_arguments,
        reason = "fixture tests deliberately vary each independent evidence input to make the tested trust boundary explicit"
    )]
    fn prove(
        index: &Value,
        index_relation: &Value,
        columns: &[ColumnRow],
        expression_proofs: &[ExpressionProof],
        predicate: Option<&ExpressionProof>,
        dependencies: &DependencyProof,
        enums: &BTreeMap<u32, EnumTypeProof>,
        role_oid: u32,
        authority: &NamespaceAuthorityProof,
        index_attribute_options: &[Option<Vec<String>>],
    ) -> Result<IndexProof, Error> {
        super::prove(
            index,
            index_relation,
            ProofContext {
                columns,
                expression_proofs,
                predicate,
                dependencies,
                enums,
                role_oid,
                authority,
                index_attribute_options,
            },
        )
    }

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

    fn authority() -> NamespaceAuthorityProof {
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

    fn column(proof: &DependencyProof, relation: u32, type_oid: u32) -> ColumnRow {
        column_at(proof, relation, type_oid, 1)
    }

    fn column_at(proof: &DependencyProof, relation: u32, type_oid: u32, attnum: u32) -> ColumnRow {
        let identity = proof
            .identity_for_runtime_oid("pg_type", type_oid)
            .expect("profile contains type");
        let fields = proof
            .row("pg_type", identity)
            .unwrap()
            .get("fields")
            .unwrap();
        let ns_oid = oid(&fields["typnamespace"]);
        let ns_identity = proof
            .identity_for_runtime_oid("pg_namespace", ns_oid)
            .unwrap();
        let namespace = proof.row("pg_namespace", ns_identity).unwrap()["fields"]["nspname"]
            .as_str()
            .unwrap();
        ColumnRow::from(DataRow::from_columns(vec![
            relation.to_string(),
            "value".to_owned(),
            type_oid.to_string(),
            namespace.to_owned(),
            fields["typname"].as_str().unwrap().to_owned(),
            fields["typtype"].as_str().unwrap().to_owned(),
            oid(&fields["typbasetype"]).to_string(),
            oid(&fields["typinput"]).to_string(),
            oid(&fields["typoutput"]).to_string(),
            oid(&fields["typreceive"]).to_string(),
            oid(&fields["typsend"]).to_string(),
            "f".to_owned(),
            String::new(),
            String::new(),
            oid(&fields["typcollation"]).to_string(),
            attnum.to_string(),
            "-1".to_owned(),
            "0".to_owned(),
        ]))
    }

    fn oid(value: &Value) -> u32 {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
            .unwrap() as u32
    }

    fn base_index(major: u32, relation: u32, index_oid: u32, method: u32, class: u32) -> Value {
        let mut fields = json!({
            "indexrelid": index_oid, "indrelid": relation,
            "indnatts": 1, "indnkeyatts": 1,
            "indisunique": false, "indisprimary": false,
            "indisexclusion": false, "indimmediate": true,
            "indisclustered": false, "indisvalid": true,
            "indcheckxmin": false, "indisready": true, "indislive": true,
            "indisreplident": false, "indkey": [1], "indcollation": [0],
            "indclass": [class], "indoption": [0], "indexprs": null, "indpred": null
        });
        if major >= 15 {
            fields["indnullsnotdistinct"] = json!(false);
        }
        let _ = method;
        fields
    }

    fn index_relation(index_oid: u32, method: u32) -> Value {
        json!({
            "oid": index_oid, "relname": "proof_test_idx", "relnamespace": 2200,
            "reltype": 0, "reloftype": 0, "relowner": 10, "relam": method,
            "relfilenode": 0, "reltablespace": 0, "relpages": 0, "reltuples": -1,
            "relallvisible": 0, "reltoastrelid": 0, "relhasindex": false,
            "relisshared": false, "relpersistence": "p", "relkind": "i",
            "relnatts": 1, "relchecks": 0, "relhasrules": false,
            "relhastriggers": false, "relhassubclass": false, "relrowsecurity": false,
            "relforcerowsecurity": false, "relispopulated": true, "relreplident": "n",
            "relispartition": false, "relrewrite": 0, "relfrozenxid": "0",
            "relminmxid": "0", "relacl": null, "reloptions": null, "relpartbound": null
        })
    }

    fn expression_source(proof: &DependencyProof) -> String {
        let lower = proof
            .rows("pg_proc")
            .unwrap()
            .find_map(|row| {
                let f = row.get("fields")?;
                (f["proname"].as_str()? == "lower"
                    && f["proargtypes"] == json!([25])
                    && oid(&f["prorettype"]) == 25)
                    .then(|| oid(&f["oid"]))
            })
            .unwrap();
        format!(
            "{{FUNCEXPR :funcid {lower} :funcresulttype 25 :funcretset false :funcvariadic false :funcformat 0 :funccollid 100 :inputcollid 100 :args ({{VAR :varno 1 :varattno 1 :vartype 25 :vartypmod -1 :varcollid 100 :varlevelsup 0 :varnullingrels (b) :varreturningtype 0 :varnosyn 1 :varattnosyn 1 :location -1}}) :location -1}}"
        )
    }

    fn expression(proof: &DependencyProof, relation: u32) -> ExpressionProof {
        let source = expression_source(proof);
        let tree = node_tree::parse_and_extract(
            &source,
            proof.major(),
            node_tree::Context::index(relation),
        )
        .unwrap();
        let column = column(proof, relation, 25);
        if proof.major() == 12 {
            // The fixture currently exercises PG18 expression layouts. PG12
            // nodes use the legacy VAR fields and are added below on demand.
            panic!("expression fixture helper expects PG18 node layout");
        }
        let checked = expression_proof::precheck(
            &tree,
            proof,
            std::slice::from_ref(&column),
            &BTreeMap::new(),
        )
        .unwrap();
        checked.finish(None).unwrap()
    }

    fn index_attribute_matrix(major: u32) -> Value {
        let directory = std::env::var("PGDOG_PROFILE_TEST_FIXTURE_DIR")
            .expect("owned dependency fixture path is set");
        serde_json::from_slice(
            &std::fs::read(format!("{directory}/index-attribute-matrix-pg{major}.json"))
                .expect("owned synthetic index metadata exists"),
        )
        .unwrap()
    }

    fn matrix_columns(proof: &DependencyProof, matrix: &Value) -> Vec<ColumnRow> {
        matrix["table_attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|attribute| {
                let type_oid = oid(attribute.get("atttypid").unwrap());
                let fields = runtime_fields(proof, "pg_type", type_oid).unwrap();
                let schema_oid = oid(fields.get("typnamespace").unwrap());
                let schema = namespace_name(proof, schema_oid).unwrap();
                ColumnRow::from_catalog_metadata(attribute, fields, &schema).unwrap()
            })
            .collect()
    }

    fn matrix_index_rows(matrix: &Value, index_oid: u32) -> Vec<Value> {
        matrix["index_attributes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|attribute| {
                attribute
                    .get("attrelid")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<u32>().ok())
                    .or_else(|| {
                        attribute
                            .get("attrelid")
                            .and_then(Value::as_u64)
                            .map(|v| v as u32)
                    })
                    == Some(index_oid)
            })
            .cloned()
            .collect()
    }

    fn prove_matrix_index(
        proof: &DependencyProof,
        matrix: &Value,
        columns: &[ColumnRow],
        name: &str,
    ) -> (IndexProof, Value, Vec<Value>) {
        let item = matrix["indexes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["relation"]["relname"] == name)
            .unwrap();
        let index = item["index"].clone();
        let relation = item["relation"].clone();
        let attributes = matrix_index_rows(matrix, oid(index.get("indexrelid").unwrap()));
        let options = attributes
            .iter()
            .map(|attribute| {
                attribute["attoptions"].as_array().map(|options| {
                    options
                        .iter()
                        .map(|value| value.as_str().unwrap().to_owned())
                        .collect()
                })
            })
            .collect::<Vec<Option<Vec<String>>>>();
        let proof_index = prove(
            &index,
            &relation,
            columns,
            &[],
            None,
            proof,
            &BTreeMap::new(),
            ACTOR,
            &authority(),
            &options,
        )
        .expect("owned synthetic index row proves");
        (proof_index, index, attributes)
    }

    #[test]
    fn validates_owned_pg12_and_pg18_index_attribute_storage_types() {
        for major in [12, 18] {
            let proof = fixture(major);
            let matrix = index_attribute_matrix(major);
            assert_eq!(matrix["major"], major);
            let columns = matrix_columns(&proof, &matrix);
            for name in [
                "matrix_btree_include",
                "matrix_btree_typmod",
                "matrix_hash_text",
                "matrix_gin_jsonb",
                "matrix_gin_array",
                "matrix_gist_range",
                "matrix_gist_trgm",
                "matrix_gist_btree_gist",
            ] {
                let (index_proof, raw_index, attributes) =
                    prove_matrix_index(&proof, &matrix, &columns, name);
                let attributes_digest = validate_attributes(
                    &index_proof,
                    &raw_index,
                    &attributes,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .unwrap_or_else(|error| panic!("PG{major} {name}: {error:?}"));
                assert_ne!(attributes_digest, [0; 32]);
            }
        }
    }

    #[test]
    fn rejects_wrong_index_attribute_type_collation_and_include_type() {
        for major in [12, 18] {
            let proof = fixture(major);
            let matrix = index_attribute_matrix(major);
            let columns = matrix_columns(&proof, &matrix);

            let (proof_index, raw_index, mut gin_array) =
                prove_matrix_index(&proof, &matrix, &columns, "matrix_gin_array");
            gin_array[0]["atttypid"] = json!(1009);
            assert!(
                validate_attributes(
                    &proof_index,
                    &raw_index,
                    &gin_array,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err()
            );

            let (proof_index, raw_index, mut btree) =
                prove_matrix_index(&proof, &matrix, &columns, "matrix_btree_include");
            btree[0]["attcollation"] = json!(0);
            assert!(
                validate_attributes(
                    &proof_index,
                    &raw_index,
                    &btree,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err()
            );
            btree[0]["attcollation"] = matrix_index_rows(
                &matrix,
                oid(raw_index.get("indexrelid").unwrap()),
            )[0]["attcollation"]
                .clone();
            btree[1]["atttypid"] = json!(25);
            assert!(
                validate_attributes(
                    &proof_index,
                    &raw_index,
                    &btree,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn preserves_varchar_numeric_and_array_modifiers_on_owned_pg12_and_pg18_indexes() {
        for major in [12, 18] {
            let proof = fixture(major);
            let matrix = index_attribute_matrix(major);
            let columns = matrix_columns(&proof, &matrix);
            let (index_proof, raw_index, attributes) =
                prove_matrix_index(&proof, &matrix, &columns, "matrix_btree_typmod");
            let source_attributes = matrix["table_attributes"].as_array().unwrap();
            assert_eq!(
                [
                    source_attributes
                        .iter()
                        .find(|row| row["attname"] == "short_label")
                        .unwrap()["atttypmod"]
                        .as_i64()
                        .unwrap(),
                    source_attributes
                        .iter()
                        .find(|row| row["attname"] == "amount")
                        .unwrap()["atttypmod"]
                        .as_i64()
                        .unwrap(),
                    source_attributes
                        .iter()
                        .find(|row| row["attname"] == "amounts")
                        .unwrap()["atttypmod"]
                        .as_i64()
                        .unwrap(),
                ],
                [40, 524_294, 524_294]
            );
            assert_eq!(
                [
                    source_attributes
                        .iter()
                        .find(|row| row["attname"] == "short_label")
                        .unwrap()["attndims"]
                        .as_i64()
                        .unwrap(),
                    source_attributes
                        .iter()
                        .find(|row| row["attname"] == "amount")
                        .unwrap()["attndims"]
                        .as_i64()
                        .unwrap(),
                    source_attributes
                        .iter()
                        .find(|row| row["attname"] == "amounts")
                        .unwrap()["attndims"]
                        .as_i64()
                        .unwrap(),
                ],
                [0, 0, 2]
            );
            for (index_position, source_name) in
                ["short_label", "amount", "amounts"].into_iter().enumerate()
            {
                let source = source_attributes
                    .iter()
                    .find(|row| row["attname"] == source_name)
                    .expect("source column metadata is captured");
                assert_eq!(
                    attributes[index_position]["atttypmod"], source["atttypmod"],
                    "PG{major} {source_name} modifier should match its logical column"
                );
                assert_eq!(
                    attributes[index_position]["attndims"], source["attndims"],
                    "PG{major} {source_name} dimensions should match its logical column"
                );
            }
            validate_attributes(
                &index_proof,
                &raw_index,
                &attributes,
                &columns,
                &proof,
                &BTreeMap::new(),
            )
            .unwrap_or_else(|error| panic!("PG{major} typmod index: {error:?}"));

            let (gin_proof, gin_index, gin_array) =
                prove_matrix_index(&proof, &matrix, &columns, "matrix_gin_array");
            assert_eq!(gin_array[0]["atttypmod"], json!(-1));
            assert_eq!(gin_array[0]["attndims"], json!(1));
            validate_attributes(
                &gin_proof,
                &gin_index,
                &gin_array,
                &columns,
                &proof,
                &BTreeMap::new(),
            )
            .unwrap_or_else(|error| panic!("PG{major} GIN array dimensions: {error:?}"));
        }
    }

    #[test]
    fn rejects_arbitrary_or_mismatched_physical_typmods() {
        for major in [12, 18] {
            let proof = fixture(major);
            let matrix = index_attribute_matrix(major);
            let columns = matrix_columns(&proof, &matrix);
            let (index_proof, raw_index, mut attributes) =
                prove_matrix_index(&proof, &matrix, &columns, "matrix_btree_typmod");

            attributes[0]["atttypmod"] = json!(-1);
            assert!(
                validate_attributes(
                    &index_proof,
                    &raw_index,
                    &attributes,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err()
            );

            attributes[0]["atttypmod"] = json!(259);
            assert!(
                validate_attributes(
                    &index_proof,
                    &raw_index,
                    &attributes,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err()
            );

            let (proof_index, raw_index, mut attributes) =
                prove_matrix_index(&proof, &matrix, &columns, "matrix_btree_typmod");
            attributes[2]["atttypmod"] = json!(-1);
            assert!(
                validate_attributes(
                    &proof_index,
                    &raw_index,
                    &attributes,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err(),
                "included numeric-array typmod must match its source column"
            );
            attributes[2]["atttypmod"] = json!(524294);
            attributes[2]["attndims"] = json!(0);
            assert!(
                validate_attributes(
                    &proof_index,
                    &raw_index,
                    &attributes,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err(),
                "included array rank must match its source column"
            );

            let (gin_proof, gin_index, mut gin_array) =
                prove_matrix_index(&proof, &matrix, &columns, "matrix_gin_array");
            gin_array[0]["attndims"] = json!(0);
            assert!(
                validate_attributes(
                    &gin_proof,
                    &gin_index,
                    &gin_array,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err(),
                "GIN storage type still preserves declared array rank"
            );
        }
    }

    #[test]
    fn rejects_index_attribute_inventory_options_and_metadata_replay() {
        for major in [12, 18] {
            let proof = fixture(major);
            let matrix = index_attribute_matrix(major);
            let columns = matrix_columns(&proof, &matrix);
            let (proof_index, raw_index, attributes) =
                prove_matrix_index(&proof, &matrix, &columns, "matrix_gin_jsonb");

            let mut stale_enum_proof = proof_index.clone();
            stale_enum_proof.enum_digests.insert(90_001, [7; 32]);
            assert!(
                validate_attributes(
                    &stale_enum_proof,
                    &raw_index,
                    &attributes,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err()
            );

            let mut missing = attributes.clone();
            missing.pop();
            assert!(
                validate_attributes(
                    &proof_index,
                    &raw_index,
                    &missing,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err()
            );

            let mut duplicate = attributes.clone();
            duplicate.push(attributes[0].clone());
            assert!(
                validate_attributes(
                    &proof_index,
                    &raw_index,
                    &duplicate,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err()
            );

            let mut option = attributes.clone();
            option[0]["attoptions"] = json!(["fastupdate=off"]);
            assert!(
                validate_attributes(
                    &proof_index,
                    &raw_index,
                    &option,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err()
            );

            let mut unknown_field = attributes.clone();
            unknown_field[0]["unreviewed_attribute_field"] = json!(true);
            assert!(
                validate_attributes(
                    &proof_index,
                    &raw_index,
                    &unknown_field,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err()
            );

            let mut replayed = raw_index.clone();
            replayed["indkey"] = json!([1]);
            assert!(
                validate_attributes(
                    &proof_index,
                    &replayed,
                    &attributes,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn accepts_safe_index_attribute_shape_and_rejects_legacy_missing_value() {
        for major in [12, 18] {
            let proof = fixture(major);
            let matrix = index_attribute_matrix(major);
            let columns = matrix_columns(&proof, &matrix);
            let (proof_index, raw_index, attributes) =
                prove_matrix_index(&proof, &matrix, &columns, "matrix_btree_include");

            assert!(
                validate_attributes(
                    &proof_index,
                    &raw_index,
                    &attributes,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_ok()
            );

            let mut legacy = attributes.clone();
            for attribute in &mut legacy {
                let object = attribute.as_object_mut().unwrap();
                object.remove("attmissingval_present");
                object.insert("attmissingval".into(), json!(["synthetic"]));
            }
            assert!(
                validate_attributes(
                    &proof_index,
                    &raw_index,
                    &legacy,
                    &columns,
                    &proof,
                    &BTreeMap::new(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn proves_profiled_jsonb_gin_and_expression_gist_cases() {
        let proof = fixture(18);
        let relation = 90_001;
        let index_oid = 90_002;
        let jsonb_class = proof
            .runtime_oid_for_identity("pg_opclass", "10090")
            .expect("profiled jsonb GIN class");
        let jsonb_index = base_index(18, relation, index_oid, 2742, jsonb_class);
        let jsonb_column = column(&proof, relation, 3802);
        let jsonb_proof = prove(
            &jsonb_index,
            &index_relation(index_oid, 2742),
            std::slice::from_ref(&jsonb_column),
            &[],
            None,
            &proof,
            &BTreeMap::new(),
            ACTOR,
            &authority(),
            &[None],
        )
        .unwrap();
        assert_eq!(jsonb_proof.key_types(), &[3802]);
        assert_eq!(jsonb_proof.key_attnums(), &[1]);
        assert!(!jsonb_proof.is_unique());
        assert!(!jsonb_proof.is_primary());
        assert!(!jsonb_proof.is_exclusion());
        assert!(jsonb_proof.is_immediate());
        assert!(!jsonb_proof.has_predicate());

        let predicate_source = "{VAR :varno 1 :varattno 2 :vartype 16 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnullingrels (b) :varreturningtype 0 :varnosyn 1 :varattnosyn 2 :location -1}";
        let predicate_tree = node_tree::parse_and_extract(
            predicate_source,
            18,
            node_tree::Context::predicate(relation),
        )
        .unwrap();
        let bool_column = column_at(&proof, relation, 16, 2);
        let predicate_checked = expression_proof::precheck(
            &predicate_tree,
            &proof,
            &[jsonb_column.clone(), bool_column.clone()],
            &BTreeMap::new(),
        )
        .unwrap();
        let predicate_proof = predicate_checked.finish(None).unwrap();
        let mut partial_index = jsonb_index.clone();
        partial_index["indpred"] = json!(predicate_source);
        assert!(
            prove(
                &partial_index,
                &index_relation(index_oid, 2742),
                &[jsonb_column.clone(), bool_column],
                &[],
                Some(&predicate_proof),
                &proof,
                &BTreeMap::new(),
                ACTOR,
                &authority(),
                &[None],
            )
            .is_ok()
        );
        let partial_proof = prove(
            &partial_index,
            &index_relation(index_oid, 2742),
            &[jsonb_column.clone(), column_at(&proof, relation, 16, 2)],
            &[],
            Some(&predicate_proof),
            &proof,
            &BTreeMap::new(),
            ACTOR,
            &authority(),
            &[None],
        )
        .unwrap();
        assert!(partial_proof.has_predicate());
        assert_eq!(partial_proof.key_types(), &[3802]);

        let index_oid = 90_003;
        let gist_class = proof
            .runtime_oid_for_identity(
                "pg_opclass",
                "$extension:pg_trgm:pg_opclass:public.gist_trgm_ops@gist",
            )
            .expect("profiled extension GiST trgm class");
        let mut gist_index = base_index(18, relation, index_oid, 783, gist_class);
        gist_index["indkey"] = json!([0]);
        gist_index["indcollation"] = json!([100]);
        let source = expression_source(&proof);
        gist_index["indexprs"] = json!(source);
        let expr = expression(&proof, relation);
        assert_eq!(expr.root_type(), 25);
        let mut debug_enum_digests = BTreeMap::new();
        let mut key_context = KeyProofContext {
            dependencies: &proof,
            enums: &BTreeMap::new(),
            role_oid: ACTOR,
            authority: &authority(),
            enum_digests: &mut debug_enum_digests,
        };
        assert_eq!(
            prove_expression_type(&expr, gist_class, 100, 783, "gist", &mut key_context,),
            Ok(()),
            "expression key type validation"
        );
        let text_column = column(&proof, relation, 25);
        let gist_result = prove(
            &gist_index,
            &index_relation(index_oid, 783),
            &[text_column],
            &[expr],
            None,
            &proof,
            &BTreeMap::new(),
            ACTOR,
            &authority(),
            &[None],
        );
        assert!(
            gist_result.is_ok(),
            "expression GiST proof: {gist_result:?}"
        );
        let expression_gist = gist_result.unwrap();
        assert_eq!(expression_gist.key_types(), &[25]);
        assert_eq!(expression_gist.key_attnums(), &[0]);
    }

    #[test]
    fn rejects_index_method_opclass_type_collation_option_and_source_mismatches() {
        let proof = fixture(18);
        let relation = 91_001;
        let index_oid = 91_002;
        let jsonb_class = proof
            .runtime_oid_for_identity("pg_opclass", "10090")
            .expect("profiled jsonb GIN class");
        let valid_index = base_index(18, relation, index_oid, 2742, jsonb_class);
        let valid_relation = index_relation(index_oid, 2742);
        let jsonb_column = column_at(&proof, relation, 3802, 1);
        let authority = authority();

        let mut wrong_method_relation = valid_relation.clone();
        wrong_method_relation["relam"] = json!(403);
        assert!(
            prove(
                &valid_index,
                &wrong_method_relation,
                std::slice::from_ref(&jsonb_column),
                &[],
                None,
                &proof,
                &BTreeMap::new(),
                ACTOR,
                &authority,
                &[None],
            )
            .is_err()
        );

        let mut wrong_class = valid_index.clone();
        wrong_class["indclass"] = json!([0]);
        assert!(
            prove(
                &wrong_class,
                &valid_relation,
                std::slice::from_ref(&jsonb_column),
                &[],
                None,
                &proof,
                &BTreeMap::new(),
                ACTOR,
                &authority,
                &[None],
            )
            .is_err()
        );

        assert!(
            prove(
                &valid_index,
                &valid_relation,
                &[column_at(&proof, relation, 25, 1)],
                &[],
                None,
                &proof,
                &BTreeMap::new(),
                ACTOR,
                &authority,
                &[None],
            )
            .is_err()
        );

        let mut wrong_collation = valid_index.clone();
        wrong_collation["indcollation"] = json!([100]);
        assert!(
            prove(
                &wrong_collation,
                &valid_relation,
                std::slice::from_ref(&jsonb_column),
                &[],
                None,
                &proof,
                &BTreeMap::new(),
                ACTOR,
                &authority,
                &[None],
            )
            .is_err()
        );

        let mut unsupported_option = valid_index.clone();
        unsupported_option["indoption"] = json!([4]);
        assert!(
            prove(
                &unsupported_option,
                &valid_relation,
                std::slice::from_ref(&jsonb_column),
                &[],
                None,
                &proof,
                &BTreeMap::new(),
                ACTOR,
                &authority,
                &[None],
            )
            .is_err()
        );

        let mut unproved_predicate = valid_index.clone();
        unproved_predicate["indpred"] = json!("{VAR :varno 1 :varattno 1}");
        assert!(
            prove(
                &unproved_predicate,
                &valid_relation,
                std::slice::from_ref(&jsonb_column),
                &[],
                None,
                &proof,
                &BTreeMap::new(),
                ACTOR,
                &authority,
                &[None],
            )
            .is_err()
        );

        let index_oid = 91_003;
        let gist_class = proof
            .runtime_oid_for_identity(
                "pg_opclass",
                "$extension:pg_trgm:pg_opclass:public.gist_trgm_ops@gist",
            )
            .unwrap();
        let source = expression_source(&proof);
        let expr = expression(&proof, relation);
        let mut gist_index = base_index(18, relation, index_oid, 783, gist_class);
        gist_index["indkey"] = json!([0]);
        gist_index["indcollation"] = json!([100]);
        gist_index["indexprs"] = json!(format!("{source} "));
        assert!(
            prove(
                &gist_index,
                &index_relation(index_oid, 783),
                &[column_at(&proof, relation, 25, 1)],
                &[expr],
                None,
                &proof,
                &BTreeMap::new(),
                ACTOR,
                &authority,
                &[None],
            )
            .is_err()
        );

        gist_index["indexprs"] = json!(source);
        let foreign_relation_expr = expression(&proof, relation + 1);
        assert!(
            prove(
                &gist_index,
                &index_relation(index_oid, 783),
                &[column_at(&proof, relation, 25, 1)],
                &[foreign_relation_expr],
                None,
                &proof,
                &BTreeMap::new(),
                ACTOR,
                &authority,
                &[None],
            )
            .is_err()
        );
    }
}
