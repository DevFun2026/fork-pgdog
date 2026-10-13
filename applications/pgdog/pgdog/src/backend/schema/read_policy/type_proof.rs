#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn enum_type() -> PgTypeMetadata {
        PgTypeMetadata {
            oid: 90_001,
            schema_oid: 90_002,
            owner_oid: 90_003,
            name: "status_kind".into(),
            kind: b'e',
            length: 4,
            by_value: true,
            category: b'E',
            preferred: false,
            defined: true,
            delimiter: b',',
            element_oid: 0,
            array_oid: 90_004,
            input_oid: 3_506,
            output_oid: 3_507,
            receive_oid: 3_532,
            send_oid: 3_533,
            typmod_input_oid: 0,
            typmod_output_oid: 0,
            analyze_oid: 0,
            align: b'i',
            storage: b'p',
            not_null: false,
            base_type_oid: 0,
            type_modifier: -1,
            dimensions: 0,
            collation_oid: 0,
            relation_oid: 0,
            default: None,
            default_bin: None,
            acl: None,
            subscript_oid: None,
        }
    }

    fn reviewed_io() -> ReviewedCoreIoProfile {
        ReviewedCoreIoProfile {
            server_major: 12,
            core_namespace_oid: 11,
            input_oid: 3_506,
            output_oid: 3_507,
            receive_oid: 3_532,
            send_oid: 3_533,
        }
    }

    fn permissions() -> TypePermissions {
        TypePermissions {
            role_oid: 90_010,
            superuser: false,
            schemas_with_create: BTreeSet::new(),
            owner_role_memberships: BTreeSet::new(),
        }
    }

    fn labels() -> Vec<EnumLabel> {
        vec![
            EnumLabel {
                enum_type_oid: 90_001,
                oid: 90_101,
                sort_order: 1.0,
                value: "draft".into(),
            },
            EnumLabel {
                enum_type_oid: 90_001,
                oid: 90_102,
                sort_order: 2.0,
                value: "published".into(),
            },
        ]
    }

    #[test]
    fn proves_enum_projection_io_without_granting_operator_capabilities() {
        let proof = prove_dynamic_enum(&enum_type(), &labels(), &permissions(), &reviewed_io())
            .expect("exact reviewed enum metadata should prove");

        assert!(proof.capabilities().text_output);
        assert!(proof.capabilities().binary_output);
        assert!(proof.capabilities().text_input);
        assert!(proof.capabilities().binary_input);
        assert!(!proof.capabilities().comparison);
        assert!(!proof.capabilities().ordering);
        assert!(!proof.capabilities().grouping);
        assert_ne!(proof.digest(), &[0; 32]);
    }

    #[test]
    fn rejects_unreviewed_io_and_mutable_or_invalid_enum_metadata() {
        let mut metadata = enum_type();
        metadata.output_oid += 1;
        assert!(prove_dynamic_enum(&metadata, &labels(), &permissions(), &reviewed_io()).is_err());

        let metadata = enum_type();
        let mut owner = permissions();
        owner.role_oid = metadata.owner_oid;
        assert!(prove_dynamic_enum(&metadata, &labels(), &owner, &reviewed_io()).is_err());

        let mut owner_member = permissions();
        owner_member
            .owner_role_memberships
            .insert(metadata.owner_oid);
        assert!(prove_dynamic_enum(&metadata, &labels(), &owner_member, &reviewed_io()).is_err());

        let mut mutable_schema = permissions();
        mutable_schema
            .schemas_with_create
            .insert(enum_type().schema_oid);
        assert!(
            prove_dynamic_enum(&enum_type(), &labels(), &mutable_schema, &reviewed_io()).is_err()
        );

        let mut unsorted = labels();
        unsorted[1].sort_order = unsorted[0].sort_order;
        assert!(
            prove_dynamic_enum(&enum_type(), &unsorted, &permissions(), &reviewed_io()).is_err()
        );

        let mut dangling_label = labels();
        dangling_label[1].enum_type_oid += 1;
        assert!(
            prove_dynamic_enum(
                &enum_type(),
                &dangling_label,
                &permissions(),
                &reviewed_io()
            )
            .is_err()
        );

        let mut duplicate_oid = labels();
        duplicate_oid[1].oid = duplicate_oid[0].oid;
        assert!(
            prove_dynamic_enum(&enum_type(), &duplicate_oid, &permissions(), &reviewed_io())
                .is_err()
        );

        let mut non_finite_order = labels();
        non_finite_order[1].sort_order = f32::NAN;
        assert!(
            prove_dynamic_enum(
                &enum_type(),
                &non_finite_order,
                &permissions(),
                &reviewed_io()
            )
            .is_err()
        );

        let mut domain = enum_type();
        domain.kind = b'd';
        assert!(prove_dynamic_enum(&domain, &labels(), &permissions(), &reviewed_io()).is_err());

        let mut superuser = permissions();
        superuser.superuser = true;
        assert!(prove_dynamic_enum(&enum_type(), &labels(), &superuser, &reviewed_io()).is_err());
    }

    #[test]
    fn enum_io_profile_must_bind_to_pg_catalog() {
        let mut unqualified_profile = reviewed_io();
        unqualified_profile.core_namespace_oid = 90_099;
        assert!(
            prove_dynamic_enum(
                &enum_type(),
                &labels(),
                &permissions(),
                &unqualified_profile
            )
            .is_err()
        );
    }

    fn enum_catalog_json(major: u32) -> serde_json::Value {
        let mut row = serde_json::json!({
            "oid": "17085",
            "typacl": null,
            "typalign": "i",
            "typanalyze": "0",
            "typarray": "17084",
            "typbasetype": "0",
            "typbyval": true,
            "typcategory": "E",
            "typcollation": "0",
            "typdefault": null,
            "typdefaultbin": null,
            "typdelim": ",",
            "typelem": "0",
            "typinput": "3506",
            "typisdefined": true,
            "typispreferred": false,
            "typlen": 4,
            "typmodin": "0",
            "typmodout": "0",
            "typname": "safe_state",
            "typnamespace": "2200",
            "typndims": 0,
            "typnotnull": false,
            "typoutput": "3507",
            "typowner": "10",
            "typreceive": "3532",
            "typrelid": "0",
            "typsend": "3533",
            "typstorage": "p",
            "typtype": "e",
            "typtypmod": -1
        });
        if major == 18 {
            row["typsubscript"] = serde_json::json!("0");
        }
        row
    }

    #[test]
    fn decodes_complete_major_specific_pg_type_rows_and_rejects_shape_drift() {
        let pg12 = PgTypeMetadata::from_catalog_json(&enum_catalog_json(12), 12).unwrap();
        assert_eq!(pg12.oid, 17_085);
        assert_eq!(pg12.subscript_oid, None);
        assert!(pg12.by_value);

        let pg18 = PgTypeMetadata::from_catalog_json(&enum_catalog_json(18), 18).unwrap();
        assert_eq!(pg18.subscript_oid, Some(0));

        let mut missing = enum_catalog_json(18);
        missing.as_object_mut().unwrap().remove("typinput");
        assert!(PgTypeMetadata::from_catalog_json(&missing, 18).is_err());

        let mut unexpected = enum_catalog_json(12);
        unexpected["future_field"] = serde_json::json!(1);
        assert!(PgTypeMetadata::from_catalog_json(&unexpected, 12).is_err());

        let mut wrong_type = enum_catalog_json(12);
        wrong_type["typbyval"] = serde_json::json!("true");
        assert!(PgTypeMetadata::from_catalog_json(&wrong_type, 12).is_err());

        assert!(PgTypeMetadata::from_catalog_json(&enum_catalog_json(18), 12).is_err());
        assert!(PgTypeMetadata::from_catalog_json(&enum_catalog_json(12), 18).is_err());
    }

    #[test]
    fn enum_digest_binds_labels_and_type_metadata() {
        let first =
            prove_dynamic_enum(&enum_type(), &labels(), &permissions(), &reviewed_io()).unwrap();
        let mut changed_labels = labels();
        changed_labels[1].value = "released".into();
        let changed = prove_dynamic_enum(
            &enum_type(),
            &changed_labels,
            &permissions(),
            &reviewed_io(),
        )
        .unwrap();
        assert_ne!(first.digest(), changed.digest());

        let mut changed_type = enum_type();
        changed_type.name = "other_kind".into();
        let changed =
            prove_dynamic_enum(&changed_type, &labels(), &permissions(), &reviewed_io()).unwrap();
        assert_ne!(first.digest(), changed.digest());
    }

    fn builtin(oid: u32, name: &str, element_oid: u32, array_oid: u32) -> PgTypeMetadata {
        PgTypeMetadata {
            oid,
            schema_oid: 11,
            owner_oid: 10,
            name: name.into(),
            kind: b'b',
            length: -1,
            by_value: false,
            category: if element_oid == 0 { b'S' } else { b'A' },
            preferred: false,
            defined: true,
            delimiter: b',',
            element_oid,
            array_oid,
            input_oid: 46,
            output_oid: 47,
            receive_oid: 2_414,
            send_oid: 2_415,
            typmod_input_oid: 0,
            typmod_output_oid: 0,
            analyze_oid: 0,
            align: b'i',
            storage: b'x',
            not_null: false,
            base_type_oid: 0,
            type_modifier: -1,
            dimensions: 0,
            collation_oid: 100,
            relation_oid: 0,
            default: None,
            default_bin: None,
            acl: None,
            subscript_oid: Some(0),
        }
    }

    fn capabilities() -> TypeCapabilities {
        TypeCapabilities {
            text_output: true,
            binary_output: true,
            text_input: true,
            binary_input: true,
            comparison: true,
            ordering: true,
            grouping: true,
        }
    }

    #[test]
    fn builtin_array_proof_recursively_requires_exact_approved_element_profile() {
        let text = builtin(25, "text", 0, 1009);
        let text_array = builtin(1009, "_text", 25, 0);
        let profiles = BTreeMap::from([
            (25, BuiltinTypeProfile::new(text.clone(), capabilities())),
            (
                1009,
                BuiltinTypeProfile::new(text_array.clone(), capabilities()),
            ),
        ]);
        let actual = BTreeMap::from([(25, text.clone()), (1009, text_array.clone())]);
        let granted = prove_builtin_type(1009, &actual, &profiles, &permissions()).unwrap();
        assert!(granted.text_output && granted.binary_input);

        let incomplete_profiles = BTreeMap::from([(
            1009,
            BuiltinTypeProfile::new(text_array.clone(), capabilities()),
        )]);
        assert!(prove_builtin_type(1009, &actual, &incomplete_profiles, &permissions()).is_err());

        let mut drifted_array = text_array;
        drifted_array.element_oid = 23;
        let drifted_actual = BTreeMap::from([(25, text), (1009, drifted_array)]);
        assert!(prove_builtin_type(1009, &drifted_actual, &profiles, &permissions()).is_err());

        let mut first = builtin(2000, "_first", 2001, 2001);
        first.category = b'A';
        let mut second = builtin(2001, "_second", 2000, 2000);
        second.category = b'A';
        let cycle = BTreeMap::from([
            (2000, BuiltinTypeProfile::new(first.clone(), capabilities())),
            (
                2001,
                BuiltinTypeProfile::new(second.clone(), capabilities()),
            ),
        ]);
        let cycle_actual = BTreeMap::from([(2000, first), (2001, second)]);
        assert!(matches!(
            prove_builtin_type(2000, &cycle_actual, &cycle, &permissions()),
            Err(TypeProofError::TypeGraphCycle)
        ));
    }
}

use std::collections::{BTreeMap, BTreeSet};

const MAX_TYPE_PROOF_DEPTH: usize = 16;
const MAX_ENUM_LABELS: usize = 4096;

/// Complete typed subset of one `pg_type` row used by the runtime proof.
/// OIDs remain numeric so text formatting and JSON number coercions cannot
/// silently change identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PgTypeMetadata {
    pub(crate) oid: u32,
    pub(crate) schema_oid: u32,
    pub(crate) owner_oid: u32,
    pub(crate) name: String,
    pub(crate) kind: u8,
    pub(crate) length: i16,
    pub(crate) by_value: bool,
    pub(crate) category: u8,
    pub(crate) preferred: bool,
    pub(crate) defined: bool,
    pub(crate) delimiter: u8,
    pub(crate) element_oid: u32,
    pub(crate) array_oid: u32,
    pub(crate) input_oid: u32,
    pub(crate) output_oid: u32,
    pub(crate) receive_oid: u32,
    pub(crate) send_oid: u32,
    pub(crate) typmod_input_oid: u32,
    pub(crate) typmod_output_oid: u32,
    pub(crate) analyze_oid: u32,
    pub(crate) align: u8,
    pub(crate) storage: u8,
    pub(crate) not_null: bool,
    pub(crate) base_type_oid: u32,
    pub(crate) type_modifier: i32,
    pub(crate) dimensions: i32,
    pub(crate) collation_oid: u32,
    pub(crate) relation_oid: u32,
    pub(crate) default: Option<String>,
    pub(crate) default_bin: Option<String>,
    pub(crate) acl: Option<Vec<String>>,
    /// PostgreSQL 12 predates `pg_type.typsubscript`; `None` is only valid
    /// when proving against a PG12 profile.
    pub(crate) subscript_oid: Option<u32>,
}

impl PgTypeMetadata {
    /// Decode the complete, major-specific JSON representation returned by
    /// `to_jsonb(pg_type)`. OIDs accept the numeric JSON form emitted by
    /// PostgreSQL and the canonical decimal strings used by pinned captures.
    pub(crate) fn from_catalog_json(
        row: &serde_json::Value,
        server_major: u32,
    ) -> Result<Self, TypeProofError> {
        const PG12_KEYS: &[&str] = &[
            "oid",
            "typacl",
            "typalign",
            "typanalyze",
            "typarray",
            "typbasetype",
            "typbyval",
            "typcategory",
            "typcollation",
            "typdefault",
            "typdefaultbin",
            "typdelim",
            "typelem",
            "typinput",
            "typisdefined",
            "typispreferred",
            "typlen",
            "typmodin",
            "typmodout",
            "typname",
            "typnamespace",
            "typndims",
            "typnotnull",
            "typoutput",
            "typowner",
            "typreceive",
            "typrelid",
            "typsend",
            "typstorage",
            "typtype",
            "typtypmod",
        ];
        const PG18_KEYS: &[&str] = &[
            "oid",
            "typacl",
            "typalign",
            "typanalyze",
            "typarray",
            "typbasetype",
            "typbyval",
            "typcategory",
            "typcollation",
            "typdefault",
            "typdefaultbin",
            "typdelim",
            "typelem",
            "typinput",
            "typisdefined",
            "typispreferred",
            "typlen",
            "typmodin",
            "typmodout",
            "typname",
            "typnamespace",
            "typndims",
            "typnotnull",
            "typoutput",
            "typowner",
            "typreceive",
            "typrelid",
            "typsend",
            "typstorage",
            "typsubscript",
            "typtype",
            "typtypmod",
        ];

        let expected_keys = match server_major {
            12 => PG12_KEYS,
            18 => PG18_KEYS,
            _ => return Err(TypeProofError::InvalidProfile),
        };
        let object = row.as_object().ok_or(TypeProofError::InvalidMetadata)?;
        if object.len() != expected_keys.len()
            || expected_keys.iter().any(|key| !object.contains_key(*key))
        {
            return Err(TypeProofError::InvalidMetadata);
        }

        let metadata = Self {
            oid: json_oid(object.get("oid"))?,
            schema_oid: json_oid(object.get("typnamespace"))?,
            owner_oid: json_oid(object.get("typowner"))?,
            name: json_string(object.get("typname"))?.to_owned(),
            kind: json_char(object.get("typtype"))?,
            length: json_i16(object.get("typlen"))?,
            by_value: json_bool(object.get("typbyval"))?,
            category: json_char(object.get("typcategory"))?,
            preferred: json_bool(object.get("typispreferred"))?,
            defined: json_bool(object.get("typisdefined"))?,
            delimiter: json_char(object.get("typdelim"))?,
            element_oid: json_oid(object.get("typelem"))?,
            array_oid: json_oid(object.get("typarray"))?,
            input_oid: json_oid(object.get("typinput"))?,
            output_oid: json_oid(object.get("typoutput"))?,
            receive_oid: json_oid(object.get("typreceive"))?,
            send_oid: json_oid(object.get("typsend"))?,
            typmod_input_oid: json_oid(object.get("typmodin"))?,
            typmod_output_oid: json_oid(object.get("typmodout"))?,
            analyze_oid: json_oid(object.get("typanalyze"))?,
            align: json_char(object.get("typalign"))?,
            storage: json_char(object.get("typstorage"))?,
            not_null: json_bool(object.get("typnotnull"))?,
            base_type_oid: json_oid(object.get("typbasetype"))?,
            type_modifier: json_i32(object.get("typtypmod"))?,
            dimensions: json_i32(object.get("typndims"))?,
            collation_oid: json_oid(object.get("typcollation"))?,
            relation_oid: json_oid(object.get("typrelid"))?,
            default: json_option_string(object.get("typdefault"))?,
            default_bin: json_option_string(object.get("typdefaultbin"))?,
            acl: json_option_string_list(object.get("typacl"))?,
            subscript_oid: match server_major {
                12 => None,
                18 => Some(json_oid(object.get("typsubscript"))?),
                _ => unreachable!("major was checked above"),
            },
        };
        if !metadata.is_well_formed() {
            return Err(TypeProofError::InvalidMetadata);
        }
        Ok(metadata)
    }

    fn is_well_formed(&self) -> bool {
        self.oid != 0
            && self.schema_oid != 0
            && self.owner_oid != 0
            && !self.name.is_empty()
            && self.name.len() <= 63
            && !self.name.as_bytes().contains(&0)
            && self.align.is_ascii()
            && self.storage.is_ascii()
            && self.category.is_ascii()
            && self.delimiter.is_ascii()
            && self.acl.as_ref().is_none_or(|acl| {
                acl.len() <= 64
                    && acl
                        .iter()
                        .all(|item| item.len() <= 4096 && !item.as_bytes().contains(&0))
            })
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.oid);
        encoder.u32(self.schema_oid);
        encoder.u32(self.owner_oid);
        encoder.string(&self.name);
        encoder.u8(self.kind);
        encoder.i16(self.length);
        encoder.bool(self.by_value);
        encoder.u8(self.category);
        encoder.bool(self.preferred);
        encoder.bool(self.defined);
        encoder.u8(self.delimiter);
        encoder.u32(self.element_oid);
        encoder.u32(self.array_oid);
        encoder.u32(self.input_oid);
        encoder.u32(self.output_oid);
        encoder.u32(self.receive_oid);
        encoder.u32(self.send_oid);
        encoder.u32(self.typmod_input_oid);
        encoder.u32(self.typmod_output_oid);
        encoder.u32(self.analyze_oid);
        encoder.u8(self.align);
        encoder.u8(self.storage);
        encoder.bool(self.not_null);
        encoder.u32(self.base_type_oid);
        encoder.i32(self.type_modifier);
        encoder.i32(self.dimensions);
        encoder.u32(self.collation_oid);
        encoder.u32(self.relation_oid);
        encoder.option_string(self.default.as_deref());
        encoder.option_string(self.default_bin.as_deref());
        if let Some(acl) = &self.acl {
            encoder.tag(1);
            let mut canonical_acl = acl.clone();
            canonical_acl.sort();
            encoder.usize(canonical_acl.len());
            for item in canonical_acl {
                encoder.string(&item);
            }
        } else {
            encoder.tag(0);
        }
        match self.subscript_oid {
            Some(oid) => {
                encoder.tag(1);
                encoder.u32(oid);
            }
            None => encoder.tag(0),
        }
    }
}

fn json_oid(value: Option<&serde_json::Value>) -> Result<u32, TypeProofError> {
    match value.ok_or(TypeProofError::InvalidMetadata)? {
        serde_json::Value::Number(number) => number
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(TypeProofError::InvalidMetadata),
        serde_json::Value::String(text) => {
            let parsed = text
                .parse::<u32>()
                .map_err(|_| TypeProofError::InvalidMetadata)?;
            (parsed.to_string() == *text)
                .then_some(parsed)
                .ok_or(TypeProofError::InvalidMetadata)
        }
        _ => Err(TypeProofError::InvalidMetadata),
    }
}

fn json_i16(value: Option<&serde_json::Value>) -> Result<i16, TypeProofError> {
    value
        .and_then(serde_json::Value::as_i64)
        .and_then(|value| i16::try_from(value).ok())
        .ok_or(TypeProofError::InvalidMetadata)
}

fn json_i32(value: Option<&serde_json::Value>) -> Result<i32, TypeProofError> {
    value
        .and_then(serde_json::Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(TypeProofError::InvalidMetadata)
}

fn json_bool(value: Option<&serde_json::Value>) -> Result<bool, TypeProofError> {
    value
        .and_then(serde_json::Value::as_bool)
        .ok_or(TypeProofError::InvalidMetadata)
}

fn json_string(value: Option<&serde_json::Value>) -> Result<&str, TypeProofError> {
    value
        .and_then(serde_json::Value::as_str)
        .ok_or(TypeProofError::InvalidMetadata)
}

fn json_char(value: Option<&serde_json::Value>) -> Result<u8, TypeProofError> {
    let text = json_string(value)?;
    if text.len() != 1 || !text.as_bytes()[0].is_ascii() {
        return Err(TypeProofError::InvalidMetadata);
    }
    Ok(text.as_bytes()[0])
}

fn json_option_string(value: Option<&serde_json::Value>) -> Result<Option<String>, TypeProofError> {
    match value.ok_or(TypeProofError::InvalidMetadata)? {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(text) if text.len() <= 8192 => Ok(Some(text.clone())),
        _ => Err(TypeProofError::InvalidMetadata),
    }
}

fn json_option_string_list(
    value: Option<&serde_json::Value>,
) -> Result<Option<Vec<String>>, TypeProofError> {
    match value.ok_or(TypeProofError::InvalidMetadata)? {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(TypeProofError::InvalidMetadata)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err(TypeProofError::InvalidMetadata),
    }
}

/// Caller-supplied, pinned PG-major-specific profile for PostgreSQL's core
/// enum I/O functions. The caller must construct this from the reviewed core
/// catalog profile, never from the live enum's own catalog rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReviewedCoreIoProfile {
    pub(crate) server_major: u32,
    pub(crate) core_namespace_oid: u32,
    pub(crate) input_oid: u32,
    pub(crate) output_oid: u32,
    pub(crate) receive_oid: u32,
    pub(crate) send_oid: u32,
}

impl ReviewedCoreIoProfile {
    fn is_well_formed(&self) -> bool {
        matches!(self.server_major, 12 | 18)
            && self.core_namespace_oid == 11
            && self.input_oid != 0
            && self.output_oid != 0
            && self.receive_oid != 0
            && self.send_oid != 0
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.server_major);
        encoder.u32(self.core_namespace_oid);
        encoder.u32(self.input_oid);
        encoder.u32(self.output_oid);
        encoder.u32(self.receive_oid);
        encoder.u32(self.send_oid);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EnumLabel {
    pub(crate) enum_type_oid: u32,
    pub(crate) oid: u32,
    pub(crate) sort_order: f32,
    pub(crate) value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TypePermissions {
    pub(crate) role_oid: u32,
    pub(crate) superuser: bool,
    pub(crate) schemas_with_create: BTreeSet<u32>,
    pub(crate) owner_role_memberships: BTreeSet<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct TypeCapabilities {
    pub(crate) text_output: bool,
    pub(crate) binary_output: bool,
    pub(crate) text_input: bool,
    pub(crate) binary_input: bool,
    pub(crate) comparison: bool,
    pub(crate) ordering: bool,
    pub(crate) grouping: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnumTypeProof {
    type_oid: u32,
    metadata: PgTypeMetadata,
    digest: [u8; 32],
    capabilities: TypeCapabilities,
}

impl EnumTypeProof {
    pub(crate) fn type_oid(&self) -> u32 {
        self.type_oid
    }

    pub(crate) fn metadata(&self) -> &PgTypeMetadata {
        &self.metadata
    }

    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn capabilities(&self) -> TypeCapabilities {
        self.capabilities
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeProofError {
    InvalidProfile,
    InvalidMetadata,
    MutableType,
    UnreviewedIo,
    InvalidLabels,
    UnapprovedType,
    TypeGraphCycle,
    TypeGraphTooDeep,
}

pub(crate) fn prove_dynamic_enum(
    metadata: &PgTypeMetadata,
    labels: &[EnumLabel],
    permissions: &TypePermissions,
    core_io: &ReviewedCoreIoProfile,
) -> Result<EnumTypeProof, TypeProofError> {
    // `labels` must be the complete result of a fixed query over every
    // `pg_enum` row for this type, ordered by enumsortorder; callers must not
    // pass a filtered or capped subset.
    if !core_io.is_well_formed() || permissions.role_oid == 0 {
        return Err(TypeProofError::InvalidProfile);
    }
    if !metadata.is_well_formed()
        || metadata.kind != b'e'
        || metadata.length != 4
        || !metadata.by_value
        || metadata.category != b'E'
        || !metadata.defined
        || metadata.delimiter != b','
        || metadata.element_oid != 0
        || metadata.array_oid == 0
        || metadata.typmod_input_oid != 0
        || metadata.typmod_output_oid != 0
        || metadata.analyze_oid != 0
        || metadata.align != b'i'
        || metadata.storage != b'p'
        || metadata.not_null
        || metadata.base_type_oid != 0
        || metadata.type_modifier != -1
        || metadata.dimensions != 0
        || metadata.collation_oid != 0
        || metadata.relation_oid != 0
        || metadata.default.is_some()
        || metadata.default_bin.is_some()
    {
        return Err(TypeProofError::InvalidMetadata);
    }
    if metadata.owner_oid == permissions.role_oid
        || permissions.superuser
        || permissions
            .schemas_with_create
            .contains(&metadata.schema_oid)
        || permissions
            .owner_role_memberships
            .contains(&metadata.owner_oid)
    {
        return Err(TypeProofError::MutableType);
    }
    if metadata.input_oid != core_io.input_oid
        || metadata.output_oid != core_io.output_oid
        || metadata.receive_oid != core_io.receive_oid
        || metadata.send_oid != core_io.send_oid
        || metadata.subscript_oid
            != match core_io.server_major {
                12 => None,
                18 => Some(0),
                _ => return Err(TypeProofError::InvalidProfile),
            }
    {
        return Err(TypeProofError::UnreviewedIo);
    }
    if labels.is_empty() || labels.len() > MAX_ENUM_LABELS {
        return Err(TypeProofError::InvalidLabels);
    }
    let mut label_oids = BTreeSet::new();
    let mut label_values = BTreeSet::new();
    let mut previous_order = None;
    for label in labels {
        if label.enum_type_oid != metadata.oid
            || label.oid == 0
            || !label.sort_order.is_finite()
            || label.value.is_empty()
            || label.value.len() > 63
            || label.value.as_bytes().contains(&0)
            || !label_oids.insert(label.oid)
            || !label_values.insert(label.value.as_str())
            || previous_order.is_some_and(|previous| label.sort_order <= previous)
        {
            return Err(TypeProofError::InvalidLabels);
        }
        previous_order = Some(label.sort_order);
    }

    let mut encoder = CanonicalEncoder::new(b"pgdog.dynamic-enum-proof.v1");
    core_io.encode(&mut encoder);
    metadata.encode(&mut encoder);
    encoder.u32(permissions.role_oid);
    encoder.bool(permissions.superuser);
    encoder.bool(
        permissions
            .schemas_with_create
            .contains(&metadata.schema_oid),
    );
    encoder.bool(
        permissions
            .owner_role_memberships
            .contains(&metadata.owner_oid),
    );
    encoder.usize(labels.len());
    for label in labels {
        encoder.u32(label.enum_type_oid);
        encoder.u32(label.oid);
        encoder.u32(label.sort_order.to_bits());
        encoder.string(&label.value);
    }
    let digest = sha256(&encoder.bytes);
    Ok(EnumTypeProof {
        type_oid: metadata.oid,
        metadata: metadata.clone(),
        digest,
        capabilities: TypeCapabilities {
            text_output: true,
            binary_output: true,
            text_input: true,
            binary_input: true,
            // Enum metadata and I/O do not prove client comparisons, ordering,
            // grouping, or index operator support.
            comparison: false,
            ordering: false,
            grouping: false,
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuiltinTypeProfile {
    metadata: PgTypeMetadata,
    capabilities: TypeCapabilities,
}

impl BuiltinTypeProfile {
    pub(crate) fn new(metadata: PgTypeMetadata, capabilities: TypeCapabilities) -> Self {
        Self {
            metadata,
            capabilities,
        }
    }
}

pub(crate) fn prove_builtin_type(
    type_oid: u32,
    actual: &BTreeMap<u32, PgTypeMetadata>,
    approved: &BTreeMap<u32, BuiltinTypeProfile>,
    permissions: &TypePermissions,
) -> Result<TypeCapabilities, TypeProofError> {
    if permissions.role_oid == 0 {
        return Err(TypeProofError::InvalidProfile);
    }
    let mut visiting = BTreeSet::new();
    prove_builtin_type_inner(type_oid, actual, approved, permissions, &mut visiting, 0)
}

fn prove_builtin_type_inner(
    type_oid: u32,
    actual: &BTreeMap<u32, PgTypeMetadata>,
    approved: &BTreeMap<u32, BuiltinTypeProfile>,
    permissions: &TypePermissions,
    visiting: &mut BTreeSet<u32>,
    depth: usize,
) -> Result<TypeCapabilities, TypeProofError> {
    if depth >= MAX_TYPE_PROOF_DEPTH {
        return Err(TypeProofError::TypeGraphTooDeep);
    }
    if !visiting.insert(type_oid) {
        return Err(TypeProofError::TypeGraphCycle);
    }
    let result = (|| {
        let metadata = actual
            .get(&type_oid)
            .ok_or(TypeProofError::UnapprovedType)?;
        let profile = approved
            .get(&type_oid)
            .ok_or(TypeProofError::UnapprovedType)?;
        if !metadata.is_well_formed()
            || metadata.oid != type_oid
            || metadata != &profile.metadata
            || metadata.kind != b'b'
            || metadata.base_type_oid != 0
            || metadata.schema_oid != 11
            || metadata.owner_oid != 10
            || (metadata.element_oid != 0 && metadata.category != b'A')
            || (metadata.element_oid == 0 && metadata.category == b'A')
            || metadata.owner_oid == permissions.role_oid
            || permissions
                .owner_role_memberships
                .contains(&metadata.owner_oid)
            || permissions.superuser
            || permissions
                .schemas_with_create
                .contains(&metadata.schema_oid)
        {
            return Err(TypeProofError::UnapprovedType);
        }
        if metadata.element_oid != 0 {
            let element = actual
                .get(&metadata.element_oid)
                .ok_or(TypeProofError::UnapprovedType)?;
            if element.array_oid != metadata.oid {
                return Err(TypeProofError::UnapprovedType);
            }
            prove_builtin_type_inner(
                metadata.element_oid,
                actual,
                approved,
                permissions,
                visiting,
                depth + 1,
            )?;
        }
        Ok(profile.capabilities)
    })();
    visiting.remove(&type_oid);
    result
}

struct CanonicalEncoder {
    bytes: Vec<u8>,
}

impl CanonicalEncoder {
    fn new(domain: &[u8]) -> Self {
        let mut encoder = Self { bytes: Vec::new() };
        encoder.usize(domain.len());
        encoder.bytes.extend_from_slice(domain);
        encoder
    }

    fn tag(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn bool(&mut self, value: bool) {
        self.tag(u8::from(value));
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i16(&mut self, value: i16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn usize(&mut self, value: usize) {
        self.bytes.extend_from_slice(&(value as u64).to_le_bytes());
    }

    fn string(&mut self, value: &str) {
        self.usize(value.len());
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn option_string(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.tag(1);
                self.string(value);
            }
            None => self.tag(0),
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 always returns 32 bytes")
}
