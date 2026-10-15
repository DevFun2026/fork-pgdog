//! Immutable, version-bound dependency metadata used by the strict read proof.
//!
//! The profile is an artifact reviewed out of band. Runtime metadata can only
//! prove equality with that artifact; it can never create a new trusted row.

use std::collections::{BTreeMap, BTreeSet};

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

const FORMAT_V1: &str = "pgdog-read-dependency-profile/v1";
const FORMAT_V2: &str = "pgdog-read-dependency-profile/v2";
#[cfg(test)]
const FORMAT: &str = FORMAT_V1;
const EXTENSION_NAMES: &[&str] = &["btree_gist", "pg_trgm"];
const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ROWS: usize = 20_000;
const MAX_VALUE_DEPTH: usize = 64;
const MAX_STRING_BYTES: usize = 1_048_576;

const CATALOGS: &[&str] = &[
    "pg_aggregate",
    "pg_am",
    "pg_amop",
    "pg_amproc",
    "pg_cast",
    "pg_collation",
    "pg_enum",
    "pg_extension",
    "pg_namespace",
    "pg_opclass",
    "pg_operator",
    "pg_opfamily",
    "pg_proc",
    "pg_range",
    "pg_ts_config",
    "pg_ts_config_map",
    "pg_ts_dict",
    "pg_ts_parser",
    "pg_ts_template",
    "pg_type",
];

/// Profile whose trust comes from the caller's immutable artifact digest.
#[derive(Debug, Clone)]
pub(crate) struct ValidatedDependencyProfile {
    major: u32,
    digest: [u8; 32],
    document: Value,
    core_oid_identities: BTreeMap<(String, u32), String>,
    #[cfg(test)]
    identity_core_oids: BTreeMap<(String, String), u32>,
    enabled_extensions: Vec<String>,
}

/// Runtime equality proof. Its fields are private to prevent constructing a
/// proof from application-controlled or partially checked catalog values.
#[derive(Debug, Clone)]
pub(crate) struct DependencyProof {
    major: u32,
    digest: [u8; 32],
    profile_digest: [u8; 32],
    #[cfg(test)]
    core_oid_identities: BTreeMap<(String, u32), String>,
    extension_identities: BTreeSet<(String, String)>,
    direct_extension_identities: BTreeSet<(String, String)>,
    runtime_oid_identities: BTreeMap<(String, u32), String>,
    runtime_identity_oids: BTreeMap<(String, String), u32>,
    catalog: Value,
}

struct NormalizedCapture {
    document: Value,
    oid_identities: BTreeMap<(String, u32), String>,
    identity_oids: BTreeMap<(String, String), u32>,
}

impl ValidatedDependencyProfile {
    pub(crate) fn validate_live_authorized(
        &self,
        live: &Value,
        major: u32,
        authority: &super::namespace_authority::NamespaceAuthorityProof,
    ) -> Result<DependencyProof, ProfileError> {
        self.validate_live_inner(live, major, Some(authority))
    }
    /// Parse and validate exact profile bytes against a separately reviewed
    /// SHA-256, PostgreSQL major, and immutable image pin.
    pub(crate) fn load_profile(
        bytes: &[u8],
        expected_sha256: &str,
        expected_major: u32,
        pinned_image: &str,
    ) -> Result<Self, ProfileError> {
        if bytes.is_empty() || bytes.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::Invalid("profile size is outside bounds"));
        }
        let expected_digest = parse_digest(expected_sha256)?;
        let actual_digest = sha256(bytes);
        if actual_digest != expected_digest {
            return Err(ProfileError::Invalid(
                "profile digest does not match reviewed digest",
            ));
        }
        if !matches!(expected_major, 12 | 18) || !valid_pinned_image(pinned_image, expected_major) {
            return Err(ProfileError::Invalid(
                "unsupported major or malformed image pin",
            ));
        }

        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let document = UniqueValue::deserialize(&mut deserializer)
            .map_err(|_| ProfileError::Invalid("profile JSON is malformed or has duplicate keys"))?
            .0;
        deserializer
            .end()
            .map_err(|_| ProfileError::Invalid("profile has trailing JSON data"))?;
        validate_value_budget(&document, 0, &mut 0)?;
        validate_profile(&document, expected_major, pinned_image)?;
        let enabled_extensions = profile_enabled_extensions(&document)?;

        let mut core_oid_identities = BTreeMap::new();
        let mut identity_core_oids = BTreeMap::new();
        for (catalog, identity, fields) in profile_rows(&document)? {
            if let Some(oid) = core_oid(catalog, &identity)
                && (core_oid_identities
                    .insert((catalog.to_owned(), oid), identity.clone())
                    .is_some()
                    || identity_core_oids
                        .insert((catalog.to_owned(), identity.clone()), oid)
                        .is_some())
            {
                return Err(ProfileError::Invalid("duplicate core catalog identity"));
            }
            // A core identity is numeric, so `fields.oid` is an exact identity
            // assertion when present. Composite support rows use their stable
            // synthesized key and intentionally have no `oid` identity.
            if let Some(oid) = fields.get("oid")
                && let Some(identity_oid) = core_oid(catalog, &identity)
                && parse_oid(oid, true)? != identity_oid
            {
                return Err(ProfileError::Invalid("row OID disagrees with identity"));
            }
            let key_field = match catalog {
                "pg_range" => Some("rngtypid"),
                "pg_aggregate" => Some("aggfnoid"),
                _ => None,
            };
            if let (Some(key_field), Some(identity_oid)) = (key_field, core_oid(catalog, &identity))
                && parse_oid(required(fields, key_field)?, false)? != identity_oid
            {
                return Err(ProfileError::Invalid(
                    "catalog key disagrees with numeric identity",
                ));
            }
        }
        let digest = canonical_digest(&document)?;
        Ok(Self {
            major: expected_major,
            digest,
            document,
            core_oid_identities,
            #[cfg(test)]
            identity_core_oids,
            enabled_extensions,
        })
    }

    pub(crate) fn major(&self) -> u32 {
        self.major
    }

    pub(crate) fn enabled_extensions(&self) -> Vec<String> {
        self.enabled_extensions.clone()
    }

    #[cfg(test)]
    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[cfg(test)]
    pub(crate) fn identity_for_core_oid(&self, catalog: &str, oid: u32) -> Option<&str> {
        self.core_oid_identities
            .get(&(catalog.to_owned(), oid))
            .map(String::as_str)
    }

    #[cfg(test)]
    pub(crate) fn core_oid_for_identity(&self, catalog: &str, identity: &str) -> Option<u32> {
        self.identity_core_oids
            .get(&(catalog.to_owned(), identity.to_owned()))
            .copied()
    }

    pub(crate) fn core_oids_for_catalog(&self, catalog: &str) -> Vec<u32> {
        self.core_oid_identities
            .keys()
            .filter_map(|(table, oid)| (table == catalog).then_some(*oid))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn extension_member_identities(&self, extension: &str) -> Vec<&str> {
        let Some(extensions) = self.document.get("extensions").and_then(Value::as_array) else {
            return Vec::new();
        };
        extensions
            .iter()
            .filter_map(|entry| {
                let entry = entry.as_object()?;
                (entry.get("name")?.as_str()? == extension).then_some(entry.get("members")?)
            })
            .flat_map(|members| members.as_array().into_iter().flatten())
            .filter_map(Value::as_str)
            .collect()
    }

    /// Exact reviewed rows that must be located by qualified identity instead
    /// of a PostgreSQL OID that varies across initdb environments.
    pub(crate) fn expected_named_builtin_rows(&self, catalog: &str) -> Vec<(String, Value)> {
        self.catalog_rows(catalog)
            .into_iter()
            .filter_map(|row| {
                let identity = identity_string(row.get("identity")?).ok()?;
                if !identity.starts_with("$builtin:") {
                    return None;
                }
                Some((identity, row.get("fields")?.clone()))
            })
            .collect()
    }

    fn catalog_rows(&self, catalog: &str) -> Vec<&Value> {
        self.document
            .get("catalog")
            .and_then(|catalogs| catalogs.get(catalog))
            .and_then(Value::as_array)
            .map(|rows| rows.iter().collect())
            .unwrap_or_default()
    }

    /// Normalize a raw captured catalog and compare its full selected closure
    /// and extension membership with the reviewed profile.
    #[cfg(test)]
    pub(crate) fn validate_live(
        &self,
        live: &Value,
        live_major: u32,
    ) -> Result<DependencyProof, ProfileError> {
        self.validate_live_inner(live, live_major, None)
    }

    fn validate_live_inner(
        &self,
        live: &Value,
        live_major: u32,
        authority: Option<&super::namespace_authority::NamespaceAuthorityProof>,
    ) -> Result<DependencyProof, ProfileError> {
        validate_value_budget(live, 0, &mut 0)?;
        if live_major != self.major {
            return Err(ProfileError::Invalid(
                "runtime major does not match profile",
            ));
        }
        if let Err(error) = validate_live_provenance(live, self.major) {
            profile_diagnostic(
                "provenance",
                "",
                match error {
                    ProfileError::Invalid(reason) => reason,
                },
            );
            return Err(error);
        }
        let profile = object(&self.document, "profile")?;
        let live_object = object(live, "live capture")?;
        if let Some(authority) = authority
            && (profile.get("namespace_authority").and_then(Value::as_str)
                != Some("actor-namespace-authority/v1")
                || !authority.matches_catalog_rows(
                    live_object
                        .get("tables")
                        .and_then(|tables| tables.get("pg_namespace"))
                        .ok_or(ProfileError::Invalid(
                            "missing namespace authority metadata",
                        ))?,
                ))
        {
            return Err(ProfileError::Invalid("unbound namespace authority proof"));
        }
        let normalized = match normalize_capture(self, live) {
            Ok(normalized) => normalized,
            Err(error) => {
                profile_diagnostic(
                    "normalization",
                    "",
                    match error {
                        ProfileError::Invalid(reason) => reason,
                    },
                );
                return Err(error);
            }
        };
        let normalized_document = &normalized.document;
        let live_catalog = required(
            object(normalized_document, "normalized capture")?,
            "catalog",
        )?;
        let profile_catalog = required(profile, "catalog")?;
        let mut comparison_catalog = live_catalog.clone();
        if authority.is_some() {
            let expected = required(
                object(profile_catalog, "reference catalog")?,
                "pg_namespace",
            )?
            .as_array()
            .ok_or(ProfileError::Invalid(
                "namespace reference must be an array",
            ))?;
            let actual = comparison_catalog
                .get_mut("pg_namespace")
                .and_then(Value::as_array_mut)
                .ok_or(ProfileError::Invalid("namespace capture must be an array"))?;
            // Only this comparison substitutes the disposable reference ACL.
            // The original live ACL remains in the opaque proof and its digest;
            // the separate actor proof checked CREATE, USAGE, ownership and
            // the exact same complete live ACL before this point.
            for row in actual {
                let reference = expected
                    .iter()
                    .find(|reference| reference["identity"] == row["identity"])
                    .ok_or(ProfileError::Invalid("unreviewed namespace"))?;
                row["fields"]["nspacl"] = reference["fields"]
                    .get("nspacl")
                    .ok_or(ProfileError::Invalid("missing reference namespace ACL"))?
                    .clone();
            }
        }
        if canonical_bytes(&comparison_catalog)? != canonical_bytes(profile_catalog)? {
            if let (Some(actual), Some(expected)) =
                (comparison_catalog.as_object(), profile_catalog.as_object())
            {
                for table in CATALOGS {
                    let (Some(actual), Some(expected)) = (actual.get(*table), expected.get(*table))
                    else {
                        profile_diagnostic("catalog_mismatch", table, "table_presence");
                        return Err(ProfileError::Invalid(
                            "runtime catalog closure differs from profile",
                        ));
                    };
                    if actual != expected {
                        let path = first_json_difference_path(actual, expected, &mut Vec::new())
                            .unwrap_or_default()
                            .join(".");
                        profile_diagnostic("catalog_mismatch", table, &path);
                        return Err(ProfileError::Invalid(
                            "runtime catalog closure differs from profile",
                        ));
                    }
                }
            }
            profile_diagnostic("catalog_mismatch", "", "top_level_shape");
            return Err(ProfileError::Invalid(
                "runtime catalog closure differs from profile",
            ));
        }
        if required(
            object(normalized_document, "normalized capture")?,
            "extensions",
        )? != required(profile, "extensions")?
        {
            profile_diagnostic("extension_mismatch", "pg_extension", "metadata_or_members");
            return Err(ProfileError::Invalid(
                "runtime extension membership differs from profile",
            ));
        }
        if let Some(module_hashes) = live_object.get("module_sha256")
            && normalize_runtime_module_hashes(module_hashes, self.major, &self.enabled_extensions)?
                != *required(profile, "module_sha256")?
        {
            profile_diagnostic("module_mismatch", "", "hashes");
            return Err(ProfileError::Invalid(
                "runtime module provenance differs from profile",
            ));
        }

        // Re-validate dynamic JSON boundaries on the normalized object, including
        // explicit presence of every catalog and the empty static enum table.
        let normalized_object = object(normalized_document, "normalized capture")?;
        validate_catalog(required(normalized_object, "catalog")?)?;
        validate_extensions(
            required(normalized_object, "extensions")?,
            self.major,
            &self.enabled_extensions,
        )?;
        let extension_identities =
            extension_identity_set(required(normalized_object, "extensions")?)?;
        Ok(DependencyProof {
            major: self.major,
            digest: if let Some(authority) = authority {
                canonical_digest(&serde_json::json!({
                    "metadata":normalized_document, "namespace_authority":authority.digest(),
                }))?
            } else {
                canonical_digest(normalized_document)?
            },
            profile_digest: self.digest,
            #[cfg(test)]
            core_oid_identities: self.core_oid_identities.clone(),
            extension_identities,
            direct_extension_identities: array(required(normalized_object, "extensions")?)?
                .iter()
                .map(|entry| {
                    let extension = object(entry, "extension")?;
                    let name = string(required(extension, "name")?)?;
                    array(required(extension, "members")?)?
                        .iter()
                        .map(|member| Ok((name.to_owned(), string(member)?.to_owned())))
                        .collect::<Result<Vec<_>, ProfileError>>()
                })
                .collect::<Result<Vec<_>, ProfileError>>()?
                .into_iter()
                .flatten()
                .collect(),
            runtime_oid_identities: normalized.oid_identities,
            runtime_identity_oids: normalized.identity_oids,
            catalog: required(normalized_object, "catalog")?.clone(),
        })
    }
}

impl DependencyProof {
    #[cfg(test)]
    pub(crate) fn from_test_values(
        profile: &Value,
        capture: &Value,
        major: u32,
        pinned_image: &str,
    ) -> Result<Self, ProfileError> {
        let bytes = serde_json::to_vec(profile)
            .map_err(|_| ProfileError::Invalid("test profile serialization failed"))?;
        let digest = expected_sha256(&bytes);
        let reviewed =
            ValidatedDependencyProfile::load_profile(&bytes, &digest, major, pinned_image)?;
        reviewed.validate_live(capture, major)
    }

    pub(crate) fn major(&self) -> u32 {
        self.major
    }

    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }

    #[cfg(test)]
    pub(crate) fn identity_for_core_oid(&self, catalog: &str, oid: u32) -> Option<&str> {
        self.core_oid_identities
            .get(&(catalog.to_owned(), oid))
            .map(String::as_str)
    }

    pub(crate) fn has_direct_extension_member(
        &self,
        extension_oid: u32,
        catalog: &str,
        object_oid: u32,
    ) -> bool {
        let Some(extension) = self.identity_for_runtime_oid("pg_extension", extension_oid) else {
            return false;
        };
        let Some(member) = self.identity_for_runtime_oid(catalog, object_oid) else {
            return false;
        };
        self.direct_extension_identities
            .contains(&(extension.to_owned(), member.to_owned()))
    }

    pub(crate) fn has_extension_identity(&self, extension: &str, identity: &str) -> bool {
        self.extension_identities
            .contains(&(extension.to_owned(), identity.to_owned()))
    }

    /// Resolve an OID observed in the exact runtime capture to its approved
    /// core numeric identity or extension-stable token.
    pub(crate) fn identity_for_runtime_oid(&self, catalog: &str, oid: u32) -> Option<&str> {
        self.runtime_oid_identities
            .get(&(catalog.to_owned(), oid))
            .map(String::as_str)
    }

    pub(crate) fn runtime_oid_for_identity(&self, catalog: &str, identity: &str) -> Option<u32> {
        self.runtime_identity_oids
            .get(&(catalog.to_owned(), identity.to_owned()))
            .copied()
    }

    /// Return the complete normalized row only after the full capture matched
    /// the pinned profile.
    pub(crate) fn row(&self, catalog: &str, identity: &str) -> Option<&Value> {
        self.catalog.get(catalog)?.as_array()?.iter().find(|row| {
            row.get("identity")
                .and_then(|value| identity_string(value).ok())
                .as_deref()
                == Some(identity)
        })
    }

    /// Iterate the complete catalog table from the validated runtime snapshot.
    /// The caller must still select rows by exact typed fields; this accessor
    /// does not grant any catalog capability by itself.
    pub(crate) fn rows(&self, catalog: &str) -> Option<impl Iterator<Item = &Value>> {
        Some(self.catalog.get(catalog)?.as_array()?.iter())
    }
    /// Match a later relation/type capture to this exact closed snapshot,
    /// including extension-stable callback identities and every metadata field.
    pub(crate) fn matches_type_row(&self, row: &Value) -> bool {
        let Ok(oid) = field_oid(row, "oid", false) else {
            return false;
        };
        let Some(identity) = self.identity_for_runtime_oid("pg_type", oid) else {
            return false;
        };
        let Some(expected) = self.row("pg_type", identity) else {
            return false;
        };
        let mut ids: StableIds = CATALOGS
            .iter()
            .map(|table| ((*table).to_owned(), BTreeMap::new()))
            .collect();
        for ((table, id), identity) in &self.runtime_oid_identities {
            ids.entry(table.clone())
                .or_default()
                .insert(*id, identity.clone());
        }
        normalize_row("pg_type", row, oid, &ids)
            .is_ok_and(|fields| Value::Object(fields) == expected["fields"])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileError {
    Invalid(&'static str),
}

fn profile_diagnostic(stage: &str, table: &str, detail: &str) {
    #[cfg(test)]
    eprintln!("dependency_profile_diagnostic stage={stage} table={table} detail={detail}");
    let _ = (stage, table, detail);
}

/// Return the first structural path at which two JSON documents differ.
/// Callers log this path only for the normalized, fixed catalog schema; values
/// and identity strings are never included in diagnostics.
fn first_json_difference_path(
    actual: &Value,
    expected: &Value,
    path: &mut Vec<String>,
) -> Option<Vec<String>> {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => {
            let keys: BTreeSet<_> = actual.keys().chain(expected.keys()).collect();
            for key in keys {
                path.push(key.clone());
                match (actual.get(key), expected.get(key)) {
                    (Some(actual), Some(expected)) => {
                        if let Some(diff) = first_json_difference_path(actual, expected, path) {
                            return Some(diff);
                        }
                    }
                    _ => return Some(path.clone()),
                }
                path.pop();
            }
            None
        }
        (Value::Array(actual), Value::Array(expected)) => {
            if actual.len() != expected.len() {
                path.push("length".to_owned());
                return Some(path.clone());
            }
            for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
                path.push(format!("[{index}]"));
                if let Some(diff) = first_json_difference_path(actual, expected, path) {
                    return Some(diff);
                }
                path.pop();
            }
            None
        }
        _ if actual != expected => Some(path.clone()),
        _ => None,
    }
}

fn validate_profile(document: &Value, major: u32, pinned_image: &str) -> Result<(), ProfileError> {
    let root = object(document, "profile")?;
    let format = string(required(root, "format")?)?;
    let v2 = format == FORMAT_V2;
    if format != FORMAT_V1 && !v2 {
        return Err(ProfileError::Invalid("unsupported profile format"));
    }
    let mut keys = vec![
        "format",
        "provenance",
        "roots",
        "catalog",
        "extensions",
        "module_sha256",
        "client_functions",
        "projection_types",
    ];
    if v2 {
        keys.push("enabled_extensions");
    }
    if let Some(policy) = root.get("namespace_authority") {
        if policy.as_str() != Some("actor-namespace-authority/v1") {
            return Err(ProfileError::Invalid("unknown namespace authority policy"));
        }
        keys.push("namespace_authority");
    }
    exact_keys(root, &keys)?;
    let enabled = if v2 {
        validate_enabled_extensions(required(root, "enabled_extensions")?)?
    } else {
        EXTENSION_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    };
    validate_provenance(required(root, "provenance")?, major, pinned_image)?;
    validate_catalog(required(root, "catalog")?)?;
    validate_roots(required(root, "roots")?)?;
    validate_extensions(required(root, "extensions")?, major, &enabled)?;
    validate_module_hashes(required(root, "module_sha256")?, &enabled)?;
    validate_projection_types(required(root, "projection_types")?)?;
    validate_profile_references(root)?;
    if required(root, "client_functions")? != &Value::Array(Vec::new()) {
        return Err(ProfileError::Invalid(
            "profile cannot admit client functions",
        ));
    }
    Ok(())
}

fn validate_provenance(value: &Value, major: u32, pinned_image: &str) -> Result<(), ProfileError> {
    let p = object(value, "provenance")?;
    exact_keys(
        p,
        &[
            "postgres_major",
            "source_image",
            "server_version",
            "server_version_num",
            "platform",
            "capture_id",
        ],
    )?;
    if uint(required(p, "postgres_major")?)? != major as u64
        || string(required(p, "source_image")?)? != pinned_image
    {
        return Err(ProfileError::Invalid(
            "profile provenance is not bound to the pinned image",
        ));
    }
    let version = string(required(p, "server_version")?)?;
    if !(version.starts_with(&format!("{major}.")) || version == major.to_string()) {
        return Err(ProfileError::Invalid(
            "server version does not match profile major",
        ));
    }
    let version_num = uint(required(p, "server_version_num")?)?;
    if version_num / 10_000 != major as u64 {
        return Err(ProfileError::Invalid(
            "server version number does not match profile major",
        ));
    }
    if !matches!(
        string(required(p, "platform")?)?,
        "linux/amd64" | "linux/arm64"
    ) {
        return Err(ProfileError::Invalid("unsupported reference platform"));
    }
    if string(required(p, "capture_id")?)?.trim().is_empty() {
        return Err(ProfileError::Invalid("empty capture identifier"));
    }
    Ok(())
}

fn validate_live_provenance(value: &Value, major: u32) -> Result<(), ProfileError> {
    let root = object(value, "live capture")?;
    let observed_major = required(root, "postgres_major")?;
    if uint(observed_major)? != major as u64 {
        return Err(ProfileError::Invalid(
            "live provenance major does not match profile",
        ));
    }
    if uint(required(root, "server_version_num")?)? / 10_000 != major as u64 {
        return Err(ProfileError::Invalid(
            "live server version does not match profile major",
        ));
    }
    let capture_id = string(required(root, "capture_id")?)?;
    if capture_id.trim().is_empty() || capture_id.len() > 256 {
        return Err(ProfileError::Invalid("live provenance is incomplete"));
    }
    let version = string(required(root, "server_version")?)?;
    if !(version.starts_with(&format!("{major}.")) || version == major.to_string()) {
        return Err(ProfileError::Invalid(
            "live server version does not match profile major",
        ));
    }
    Ok(())
}

fn validate_catalog(value: &Value) -> Result<(), ProfileError> {
    let catalog = object(value, "catalog")?;
    if catalog.len() != CATALOGS.len() || CATALOGS.iter().any(|table| !catalog.contains_key(*table))
    {
        return Err(ProfileError::Invalid(
            "catalog table set is incomplete or unsupported",
        ));
    }
    let mut total_rows = 0usize;
    for table in CATALOGS {
        let rows = array(required(catalog, table)?)?;
        total_rows = total_rows
            .checked_add(rows.len())
            .ok_or(ProfileError::Invalid("row count overflow"))?;
        if total_rows > MAX_ROWS {
            return Err(ProfileError::Invalid("catalog row budget exceeded"));
        }
        let mut identities = BTreeSet::new();
        let mut prior: Option<String> = None;
        for row in rows {
            let row = object(row, "catalog row")?;
            exact_keys(row, &["identity", "fields"])?;
            let identity = identity_string(required(row, "identity")?)?;
            if !identities.insert(identity.clone()) {
                return Err(ProfileError::Invalid("duplicate catalog identity"));
            }
            if prior.as_ref().is_some_and(|value| value >= &identity) {
                return Err(ProfileError::Invalid(
                    "catalog rows are not canonically sorted",
                ));
            }
            prior = Some(identity);
            let fields = object(required(row, "fields")?, "catalog fields")?;
            if table == &"pg_proc" {
                for field in ["prosrc", "prosqlbody"] {
                    if let Some(source) = fields.get(field) {
                        validate_proc_source_marker(source)?;
                    }
                }
            }
        }
    }
    if !array(required(catalog, "pg_enum")?)?.is_empty() {
        return Err(ProfileError::Invalid(
            "enum rows are runtime data, not static dependencies",
        ));
    }
    Ok(())
}

fn validate_roots(value: &Value) -> Result<(), ProfileError> {
    let roots = array(value)?;
    if roots.len() > MAX_ROWS {
        return Err(ProfileError::Invalid("root budget exceeded"));
    }
    let mut previous: Option<(String, String)> = None;
    let mut seen = BTreeSet::new();
    for item in roots {
        let root = object(item, "root")?;
        exact_keys(root, &["catalog", "identity"])?;
        let catalog = string(required(root, "catalog")?)?.to_owned();
        if !CATALOGS.contains(&catalog.as_str()) || catalog == "pg_enum" {
            return Err(ProfileError::Invalid("unsupported dependency root"));
        }
        let identity = identity_string(required(root, "identity")?)?;
        let key = (catalog, identity);
        if previous.as_ref().is_some_and(|old| old >= &key) || !seen.insert(key.clone()) {
            return Err(ProfileError::Invalid("roots are duplicate or not sorted"));
        }
        previous = Some(key);
    }
    Ok(())
}

fn validate_enabled_extensions(value: &Value) -> Result<Vec<String>, ProfileError> {
    let values = array(value)?;
    if values.len() > EXTENSION_NAMES.len() {
        return Err(ProfileError::Invalid("enabled extension set is too large"));
    }
    let mut result = Vec::with_capacity(values.len());
    let mut previous: Option<&str> = None;
    for value in values {
        let name = string(value)?;
        if !EXTENSION_NAMES.contains(&name) || previous.is_some_and(|old| old >= name) {
            return Err(ProfileError::Invalid(
                "enabled extensions are unsupported, duplicate, or unsorted",
            ));
        }
        result.push(name.to_owned());
        previous = Some(name);
    }
    Ok(result)
}

fn profile_enabled_extensions(document: &Value) -> Result<Vec<String>, ProfileError> {
    let root = object(document, "profile")?;
    if string(required(root, "format")?)? == FORMAT_V1 {
        return Ok(EXTENSION_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect());
    }
    validate_enabled_extensions(required(root, "enabled_extensions")?)
}

fn validate_extensions(value: &Value, major: u32, enabled: &[String]) -> Result<(), ProfileError> {
    let rows = array(value)?;
    if rows.len() != enabled.len() {
        return Err(ProfileError::Invalid(
            "extension rows differ from the selected module set",
        ));
    }
    let mut names = BTreeSet::new();
    let mut previous = None;
    for item in rows {
        let ext = object(item, "extension")?;
        exact_keys(
            ext,
            &[
                "name",
                "version",
                "namespace",
                "members",
                "derived_members",
                "fields",
            ],
        )?;
        let name = string(required(ext, "name")?)?.to_owned();
        if !matches!(name.as_str(), "pg_trgm" | "btree_gist") || !names.insert(name.clone()) {
            return Err(ProfileError::Invalid("unsupported or duplicate extension"));
        }
        if previous
            .as_ref()
            .is_some_and(|prior: &String| prior >= &name)
        {
            return Err(ProfileError::Invalid("extensions are not sorted"));
        }
        previous = Some(name.clone());
        let version = string(required(ext, "version")?)?;
        let approved_version = match (major, name.as_str()) {
            (12, "pg_trgm") => "1.4",
            (18, "pg_trgm") => "1.6",
            (12, "btree_gist") => "1.5",
            (18, "btree_gist") => "1.8",
            _ => "",
        };
        if version != approved_version || string(required(ext, "namespace")?)?.trim().is_empty() {
            return Err(ProfileError::Invalid("extension identity is incomplete"));
        }
        let fields = object(required(ext, "fields")?, "extension fields")?;
        exact_keys(
            fields,
            &[
                "oid",
                "extname",
                "extowner",
                "extnamespace",
                "extrelocatable",
                "extversion",
                "extconfig",
                "extcondition",
            ],
        )?;
        if string(required(fields, "extname")?)? != name
            || string(required(fields, "extversion")?)? != version
            || string(required(fields, "extnamespace")?)? != string(required(ext, "namespace")?)?
            || string(required(fields, "oid")?)? != name
        {
            return Err(ProfileError::Invalid(
                "normalized extension fields disagree with identity",
            ));
        }
        let members = array(required(ext, "members")?)?;
        if members.len() > MAX_ROWS {
            return Err(ProfileError::Invalid("extension member budget exceeded"));
        }
        let mut member_set = BTreeSet::new();
        let mut prior: Option<String> = None;
        for member in members {
            let member = identity_string(member)?;
            if !member.starts_with("$extension:")
                || !member.contains(&format!(
                    ":{}:",
                    required(ext, "name")?.as_str().unwrap_or_default()
                ))
                || prior.as_ref().is_some_and(|old| old >= &member)
                || !member_set.insert(member.clone())
            {
                return Err(ProfileError::Invalid(
                    "malformed, duplicate, or unsorted extension member",
                ));
            }
            prior = Some(member);
        }
        let derived_members = array(required(ext, "derived_members")?)?;
        let mut derived_previous: Option<String> = None;
        let mut derived_seen = BTreeSet::new();
        for member in derived_members {
            let member = identity_string(member)?;
            if !member.starts_with(&format!("$extension:{name}:"))
                || derived_previous.as_ref().is_some_and(|old| old >= &member)
                || !derived_seen.insert(member.clone())
            {
                return Err(ProfileError::Invalid(
                    "malformed, duplicate, or unsorted derived extension member",
                ));
            }
            derived_previous = Some(member);
        }
    }
    if names != enabled.iter().cloned().collect() {
        return Err(ProfileError::Invalid(
            "extension rows differ from selected modules",
        ));
    }
    Ok(())
}

fn validate_module_hashes(value: &Value, enabled: &[String]) -> Result<(), ProfileError> {
    let hashes = object(value, "module hashes")?;
    if hashes
        .keys()
        .any(|name| !EXTENSION_NAMES.contains(&name.as_str()))
    {
        return Err(ProfileError::Invalid("unsupported extension module hash"));
    }
    let expected: BTreeSet<_> = enabled.iter().cloned().collect();
    if hashes.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(ProfileError::Invalid(
            "module hashes differ from selected extensions",
        ));
    }
    for name in enabled {
        let digest = string(required(hashes, name)?)?;
        parse_digest(digest)?;
    }
    Ok(())
}

fn normalize_runtime_module_hashes(
    value: &Value,
    major: u32,
    enabled: &[String],
) -> Result<Value, ProfileError> {
    if value.is_object() {
        validate_module_hashes(value, enabled)?;
        return Ok(value.clone());
    }
    let rows = array(value)?;
    let mut output = Map::new();
    for value in rows {
        let line = string(value)?;
        let mut parts = line.split_whitespace();
        let digest = parts
            .next()
            .ok_or(ProfileError::Invalid("module hash is malformed"))?;
        let path = parts
            .next()
            .ok_or(ProfileError::Invalid("module hash path is missing"))?;
        if parts.next().is_some() {
            return Err(ProfileError::Invalid("module hash has extra fields"));
        }
        parse_digest(digest)?;
        let expected_prefix = format!("/usr/lib/postgresql/{major}/lib/");
        let name = path
            .strip_prefix(&expected_prefix)
            .and_then(|name| name.strip_suffix(".so"))
            .ok_or(ProfileError::Invalid(
                "module hash path does not match runtime major",
            ))?;
        if !matches!(name, "pg_trgm" | "btree_gist")
            || output
                .insert(name.to_owned(), Value::String(digest.to_owned()))
                .is_some()
        {
            return Err(ProfileError::Invalid(
                "unsupported or duplicate module hash",
            ));
        }
    }
    let output = Value::Object(output);
    validate_module_hashes(&output, enabled)?;
    Ok(output)
}

fn validate_projection_types(value: &Value) -> Result<(), ProfileError> {
    let values = array(value)?;
    if values.len() > MAX_ROWS {
        return Err(ProfileError::Invalid("projection type budget exceeded"));
    }
    let mut previous = 0u32;
    for value in values {
        let oid = u32::try_from(uint(value)?)
            .map_err(|_| ProfileError::Invalid("invalid projection OID"))?;
        if oid == 0 || oid <= previous {
            return Err(ProfileError::Invalid(
                "projection OIDs are zero, duplicate, or unsorted",
            ));
        }
        previous = oid;
    }
    Ok(())
}

fn validate_profile_references(profile: &Map<String, Value>) -> Result<(), ProfileError> {
    let catalog = object(required(profile, "catalog")?, "catalog")?;
    let mut row_ids = BTreeSet::new();
    for table in CATALOGS {
        for row in array(required(catalog, table)?)? {
            let row = object(row, "catalog row")?;
            row_ids.insert((
                (*table).to_owned(),
                identity_string(required(row, "identity")?)?,
            ));
        }
    }
    for item in array(required(profile, "roots")?)? {
        let root = object(item, "root")?;
        let key = (
            string(required(root, "catalog")?)?.to_owned(),
            identity_string(required(root, "identity")?)?,
        );
        if !row_ids.contains(&key) {
            return Err(ProfileError::Invalid(
                "root identity is absent from selected catalog",
            ));
        }
    }
    for value in array(required(profile, "projection_types")?)? {
        let oid = uint(value)?;
        if !row_ids.contains(&("pg_type".to_owned(), oid.to_string())) {
            return Err(ProfileError::Invalid(
                "projection type is absent from static type closure",
            ));
        }
    }
    for extension in array(required(profile, "extensions")?)? {
        let extension = object(extension, "extension")?;
        let name = string(required(extension, "name")?)?;
        for key in ["members", "derived_members"] {
            for member in array(required(extension, key)?)? {
                if !row_ids
                    .iter()
                    .any(|(_, identity)| identity == member.as_str().unwrap_or_default())
                {
                    return Err(ProfileError::Invalid(
                        "extension member is absent from static closure",
                    ));
                }
                if !member
                    .as_str()
                    .unwrap_or_default()
                    .starts_with(&format!("$extension:{name}:"))
                {
                    return Err(ProfileError::Invalid(
                        "extension member belongs to another extension",
                    ));
                }
            }
        }
    }
    Ok(())
}

type ProfileCatalogRow<'a> = (&'a str, String, &'a Map<String, Value>);

fn profile_rows(document: &Value) -> Result<Vec<ProfileCatalogRow<'_>>, ProfileError> {
    let catalog = object(
        required(object(document, "profile")?, "catalog")?,
        "catalog",
    )?;
    let mut rows = Vec::new();
    for table in CATALOGS {
        for value in array(required(catalog, table)?)? {
            let row = object(value, "row")?;
            let identity_value = required(row, "identity")?;
            let identity = identity_string(identity_value)?;
            rows.push((
                *table,
                identity,
                object(required(row, "fields")?, "fields")?,
            ));
        }
    }
    Ok(rows)
}

fn extension_identity_set(value: &Value) -> Result<BTreeSet<(String, String)>, ProfileError> {
    let mut output = BTreeSet::new();
    for item in array(value)? {
        let extension = object(item, "extension")?;
        let name = string(required(extension, "name")?)?.to_owned();
        for key in ["members", "derived_members"] {
            for member in array(required(extension, key)?)? {
                output.insert((name.clone(), string(member)?.to_owned()));
            }
        }
    }
    Ok(output)
}

type RawRows = BTreeMap<String, BTreeMap<u32, Value>>;
type StableIds = BTreeMap<String, BTreeMap<u32, String>>;
type ExtensionMembers = BTreeMap<(String, u32), String>;

/// Convert the raw, bounded catalog snapshot to the profile's canonical row
/// representation. Identity synthesis is done from captured catalog rows, not
/// from names supplied by a client or from a live-generated allowlist.
fn normalize_capture(
    profile: &ValidatedDependencyProfile,
    capture: &Value,
) -> Result<NormalizedCapture, ProfileError> {
    let root = object(capture, "capture")?;
    let tables = object(required(root, "tables")?, "capture tables")?;
    if tables.len() != CATALOGS.len() || CATALOGS.iter().any(|table| !tables.contains_key(*table)) {
        return Err(ProfileError::Invalid(
            "raw capture table inventory is incomplete",
        ));
    }
    let mut total_rows = 0usize;
    let mut rows = RawRows::new();
    for table in CATALOGS {
        let values = array(required(tables, table)?)?;
        total_rows = total_rows
            .checked_add(values.len())
            .ok_or(ProfileError::Invalid("row count overflow"))?;
        if total_rows > MAX_ROWS {
            return Err(ProfileError::Invalid("raw catalog row budget exceeded"));
        }
        let mut indexed = BTreeMap::new();
        for (ordinal, row) in values.iter().enumerate() {
            let row = object(row, "raw catalog row")?;
            let key = if table == &"pg_ts_config_map" {
                u32::try_from(ordinal + 1)
                    .map_err(|_| ProfileError::Invalid("text search map count overflow"))?
            } else {
                raw_identity_key(table, row).inspect_err(|_error| {
                    let key_field = match *table {
                        "pg_aggregate" => "aggfnoid",
                        "pg_range" => "rngtypid",
                        _ => "oid",
                    };
                    profile_diagnostic("raw_identity", table, key_field);
                })?
            };
            // Enum labels are dynamic data. Validate their shape/size, but do
            // not promote them to static dependencies here.
            if table == &"pg_enum" {
                continue;
            }
            if indexed.insert(key, Value::Object(row.clone())).is_some() {
                return Err(ProfileError::Invalid("duplicate raw catalog identity"));
            }
        }
        rows.insert((*table).to_owned(), indexed);
    }
    let members = parse_extension_members(required(root, "extension_members")?)?;
    if members
        .values()
        .any(|name| name != "plpgsql" && !profile.enabled_extensions.contains(name))
    {
        return Err(ProfileError::Invalid(
            "capture contains membership for an unselected extension",
        ));
    }
    let identities = build_stable_identities(&rows, &members)?;
    let profile_doc = object(&profile.document, "profile")?;
    let profile_catalog = object(required(profile_doc, "catalog")?, "profile catalog")?;
    let mut normalized_catalog = Map::new();
    let mut oid_identities = BTreeMap::new();
    let mut identity_oids = BTreeMap::new();
    for table in CATALOGS {
        let expected_rows = array(required(profile_catalog, table)?)?;
        if table == &"pg_enum" {
            normalized_catalog.insert((*table).to_owned(), Value::Array(Vec::new()));
            continue;
        }
        let mut selected = Vec::new();
        let mut wanted_family_oids = BTreeSet::new();
        if table == &"pg_ts_config_map" {
            let mut wanted_config_oids = BTreeSet::new();
            for (oid, row) in &rows["pg_ts_config"] {
                let identity = emitted_identity("pg_ts_config", *oid, row, &identities)?;
                if profile_has_identity(profile_catalog, "pg_ts_config", &identity)? {
                    wanted_config_oids.insert(*oid);
                }
            }
            for (oid, row) in &rows["pg_ts_config_map"] {
                let config_oid = field_oid(row, "mapcfg", false)?;
                if wanted_config_oids.contains(&config_oid) {
                    selected.push((*oid, row));
                }
            }
        } else if table == &"pg_amop" || table == &"pg_amproc" {
            let family_field = if table == &"pg_amop" {
                "amopfamily"
            } else {
                "amprocfamily"
            };
            for oid in identities["pg_opfamily"].keys() {
                let row = rows["pg_opfamily"]
                    .get(oid)
                    .ok_or(ProfileError::Invalid("operator family row is missing"))?;
                let identity = emitted_identity("pg_opfamily", *oid, row, &identities)?;
                if profile_has_identity(profile_catalog, "pg_opfamily", &identity)? {
                    wanted_family_oids.insert(*oid);
                }
            }
            for (oid, row) in &rows[*table] {
                let family_oid = field_oid(row, family_field, false)?;
                if wanted_family_oids.contains(&family_oid) {
                    selected.push((*oid, row));
                }
            }
        } else {
            for expected in expected_rows {
                let expected = object(expected, "profile row")?;
                let identity = identity_string(required(expected, "identity")?)?;
                let row_oid = raw_oid_for_identity(table, &identity, &rows[*table], &identities)?
                    .ok_or({
                    ProfileError::Invalid("required profiled row is missing at runtime")
                })?;
                let row = rows[*table]
                    .get(&row_oid)
                    .ok_or(ProfileError::Invalid("profile row lookup failed"))?;
                selected.push((row_oid, row));
            }
        }
        for (oid, row) in selected {
            let stable_identity = emitted_identity(table, oid, row, &identities)?;
            if table != &"pg_ts_config_map" {
                let key = ((*table).to_owned(), oid);
                if oid_identities
                    .insert(key, stable_identity.clone())
                    .is_some()
                    || identity_oids
                        .insert(((*table).to_owned(), stable_identity.clone()), oid)
                        .is_some()
                {
                    return Err(ProfileError::Invalid("runtime OID identity is duplicated"));
                }
            }
            let identity = encoded_identity(table, oid, row, &identities)?;
            let fields = normalize_row(table, row, oid, &identities)?;
            selected_rows_push(&mut normalized_catalog, table, identity, fields)?;
        }
        let mut table_rows = normalized_catalog
            .remove(*table)
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default();
        table_rows.sort_by_key(|row| identity_string(&row["identity"]).unwrap_or_default());
        normalized_catalog.insert((*table).to_owned(), Value::Array(table_rows));
    }

    // Extension metadata is compared in full, including owner/security fields
    // from pg_extension and every supported direct member identity.
    let extension_rows =
        normalize_extensions(&rows, &members, &identities, &profile.enabled_extensions)?;
    let mut normalized = Map::new();
    normalized.insert("catalog".into(), Value::Object(normalized_catalog));
    normalized.insert("extensions".into(), Value::Array(extension_rows));
    Ok(NormalizedCapture {
        document: Value::Object(normalized),
        oid_identities,
        identity_oids,
    })
}

fn selected_rows_push(
    catalog: &mut Map<String, Value>,
    table: &str,
    identity: Value,
    fields: Map<String, Value>,
) -> Result<(), ProfileError> {
    let rows = catalog
        .entry(table.to_owned())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or(ProfileError::Invalid("normalized table is not an array"))?;
    rows.push(serde_json::json!({"identity":identity,"fields":fields}));
    if rows.len() > MAX_ROWS {
        return Err(ProfileError::Invalid(
            "normalized table row budget exceeded",
        ));
    }
    Ok(())
}

fn raw_identity_key(table: &str, row: &Map<String, Value>) -> Result<u32, ProfileError> {
    let field = match table {
        "pg_aggregate" => "aggfnoid",
        "pg_range" => "rngtypid",
        // pg_ts_config_map uses a synthetic three-column identity. The raw map
        // remains indexed separately by a stable hash below; this sentinel is
        // only used for row-shape validation and duplicate detection.
        "pg_ts_config_map" => "mapcfg",
        _ => "oid",
    };
    field_oid(&Value::Object(row.clone()), field, false)
}

fn parse_extension_members(value: &Value) -> Result<ExtensionMembers, ProfileError> {
    let rows = array(value)?;
    if rows.len() > MAX_ROWS {
        return Err(ProfileError::Invalid("extension member budget exceeded"));
    }
    let mut members = ExtensionMembers::new();
    for item in rows {
        let row = object(item, "extension member")?;
        let extname = string(required(row, "extname")?)?.to_owned();
        if !matches!(extname.as_str(), "plpgsql" | "pg_trgm" | "btree_gist") {
            return Err(ProfileError::Invalid("unsupported installed extension"));
        }
        let catalog = string(required(row, "catalog")?)?.to_owned();
        if !CATALOGS.contains(&catalog.as_str()) {
            // The captured plpgsql language member is outside the modeled
            // closure; the two explicitly profiled extensions may not omit it.
            if extname == "plpgsql" {
                continue;
            }
            return Err(ProfileError::Invalid(
                "extension member catalog is unsupported",
            ));
        }
        let subid = parse_oid(required(row, "objsubid")?, true)?;
        if subid != 0 {
            return Err(ProfileError::Invalid(
                "extension subobject membership is unsupported",
            ));
        }
        let oid = parse_oid(required(row, "objid")?, false)?;
        if members.insert((catalog, oid), extname).is_some() {
            return Err(ProfileError::Invalid("duplicate extension member"));
        }
    }
    Ok(members)
}

fn build_stable_identities(
    rows: &RawRows,
    members: &ExtensionMembers,
) -> Result<StableIds, ProfileError> {
    let mut ids: StableIds = CATALOGS
        .iter()
        .map(|table| ((*table).to_owned(), BTreeMap::new()))
        .collect();
    let namespaces = string_field_map(&rows["pg_namespace"], "oid", "nspname")?;
    let methods = string_field_map(&rows["pg_am"], "oid", "amname")?;
    for (oid, row) in &rows["pg_namespace"] {
        ids.get_mut("pg_namespace")
            .unwrap()
            .insert(*oid, field_string(row, "nspname")?.to_owned());
    }
    for (oid, row) in &rows["pg_extension"] {
        ids.get_mut("pg_extension")
            .unwrap()
            .insert(*oid, field_string(row, "extname")?.to_owned());
    }
    for (oid, row) in &rows["pg_am"] {
        ids.get_mut("pg_am")
            .unwrap()
            .insert(*oid, field_string(row, "amname")?.to_owned());
    }
    for (oid, row) in &rows["pg_type"] {
        let ns = namespaces
            .get(&field_oid(row, "typnamespace", false)?)
            .ok_or(ProfileError::Invalid("type namespace is missing"))?;
        ids.get_mut("pg_type")
            .unwrap()
            .insert(*oid, format!("{ns}.{}", field_string(row, "typname")?));
    }
    for (oid, row) in &rows["pg_proc"] {
        let ns = namespaces
            .get(&field_oid(row, "pronamespace", false)?)
            .ok_or(ProfileError::Invalid("function namespace is missing"))?;
        let args = oid_vector(row.get("proargtypes"))?
            .into_iter()
            .map(|oid| signature_type(&ids, oid))
            .collect::<Vec<_>>()
            .join(",");
        let ret = signature_type(&ids, field_oid(row, "prorettype", true)?);
        ids.get_mut("pg_proc").unwrap().insert(
            *oid,
            format!(
                "{ns}.{}({args})->{ret}/{}",
                field_string(row, "proname")?,
                field_string(row, "prokind")?
            ),
        );
    }
    for (oid, row) in &rows["pg_operator"] {
        let ns = namespaces
            .get(&field_oid(row, "oprnamespace", false)?)
            .ok_or(ProfileError::Invalid("operator namespace is missing"))?;
        let left = signature_type(&ids, field_oid(row, "oprleft", true)?);
        let right = signature_type(&ids, field_oid(row, "oprright", true)?);
        ids.get_mut("pg_operator").unwrap().insert(
            *oid,
            format!("{ns}.{}({left},{right})", field_string(row, "oprname")?),
        );
    }
    for (table, nfield, namefield, methodfield) in [
        ("pg_opclass", "opcnamespace", "opcname", "opcmethod"),
        ("pg_opfamily", "opfnamespace", "opfname", "opfmethod"),
    ] {
        for (oid, row) in &rows[table] {
            let ns =
                namespaces
                    .get(&field_oid(row, nfield, false)?)
                    .ok_or(ProfileError::Invalid(
                        "operator family namespace is missing",
                    ))?;
            let method =
                methods
                    .get(&field_oid(row, methodfield, false)?)
                    .ok_or(ProfileError::Invalid(
                        "operator family access method is missing",
                    ))?;
            ids.get_mut(table).unwrap().insert(
                *oid,
                format!("{ns}.{}@{method}", field_string(row, namefield)?),
            );
        }
    }
    for (oid, row) in &rows["pg_amop"] {
        let family = ids["pg_opfamily"]
            .get(&field_oid(row, "amopfamily", false)?)
            .ok_or(ProfileError::Invalid("amop family is missing"))?
            .clone();
        let left = signature_type(&ids, field_oid(row, "amoplefttype", false)?);
        let right = signature_type(&ids, field_oid(row, "amoprighttype", false)?);
        let method = methods
            .get(&field_oid(row, "amopmethod", false)?)
            .ok_or(ProfileError::Invalid("amop method is missing"))?;
        ids.get_mut("pg_amop").unwrap().insert(
            *oid,
            format!(
                "{family}/{left}/{right}/{}/{}/{method}",
                field_string(row, "amoppurpose")?,
                field_value_string(row, "amopstrategy")?
            ),
        );
    }
    for (oid, row) in &rows["pg_amproc"] {
        let family = ids["pg_opfamily"]
            .get(&field_oid(row, "amprocfamily", false)?)
            .ok_or(ProfileError::Invalid("amproc family is missing"))?
            .clone();
        let left = signature_type(&ids, field_oid(row, "amproclefttype", false)?);
        let right = signature_type(&ids, field_oid(row, "amprocrighttype", false)?);
        ids.get_mut("pg_amproc").unwrap().insert(
            *oid,
            format!(
                "{family}/{left}/{right}/{}",
                field_value_string(row, "amprocnum")?
            ),
        );
    }
    for (oid, row) in &rows["pg_cast"] {
        let source = signature_type(&ids, field_oid(row, "castsource", false)?);
        let target = signature_type(&ids, field_oid(row, "casttarget", false)?);
        ids.get_mut("pg_cast").unwrap().insert(
            *oid,
            format!(
                "{source}->{target}/{}/{}",
                field_string(row, "castcontext")?,
                field_string(row, "castmethod")?
            ),
        );
    }
    for (oid, row) in &rows["pg_collation"] {
        let ns = namespaces
            .get(&field_oid(row, "collnamespace", false)?)
            .ok_or(ProfileError::Invalid("collation namespace is missing"))?;
        ids.get_mut("pg_collation").unwrap().insert(
            *oid,
            format!(
                "{ns}.{}/{}/{}",
                field_string(row, "collname")?,
                field_value_string(row, "collprovider")?,
                field_value_string(row, "collencoding")?
            ),
        );
    }
    for (oid, row) in &rows["pg_range"] {
        let typ = field_oid(row, "rngtypid", false)?;
        let name = ids["pg_type"]
            .get(&typ)
            .ok_or(ProfileError::Invalid("range type is missing"))?
            .clone();
        ids.get_mut("pg_range").unwrap().insert(*oid, name);
    }
    for (table, nsfield, namefield) in [
        ("pg_ts_config", "cfgnamespace", "cfgname"),
        ("pg_ts_dict", "dictnamespace", "dictname"),
        ("pg_ts_parser", "prsnamespace", "prsname"),
        ("pg_ts_template", "tmplnamespace", "tmplname"),
    ] {
        for (oid, row) in &rows[table] {
            let ns = namespaces
                .get(&field_oid(row, nsfield, false)?)
                .ok_or(ProfileError::Invalid("text search namespace is missing"))?;
            ids.get_mut(table)
                .unwrap()
                .insert(*oid, format!("{ns}.{}", field_string(row, namefield)?));
        }
    }
    for (table, nsfield, namefield, allowed_names) in [
        (
            "pg_ts_config",
            "cfgnamespace",
            "cfgname",
            &["simple", "english"][..],
        ),
        (
            "pg_ts_dict",
            "dictnamespace",
            "dictname",
            &["simple", "english_stem"][..],
        ),
        (
            "pg_ts_template",
            "tmplnamespace",
            "tmplname",
            &["simple", "snowball"][..],
        ),
    ] {
        for (oid, row) in &rows[table] {
            let namespace = namespaces
                .get(&field_oid(row, nsfield, false)?)
                .ok_or(ProfileError::Invalid("builtin namespace is missing"))?;
            if namespace == "pg_catalog" && allowed_names.contains(&field_string(row, namefield)?) {
                let stable = ids[table]
                    .get(oid)
                    .ok_or(ProfileError::Invalid("builtin identity is missing"))?
                    .clone();
                ids.get_mut(table)
                    .unwrap()
                    .insert(*oid, format!("$builtin:{table}:{stable}"));
            }
        }
    }
    for (oid, row) in &rows["pg_proc"] {
        let namespace = namespaces
            .get(&field_oid(row, "pronamespace", false)?)
            .ok_or(ProfileError::Invalid(
                "builtin function namespace is missing",
            ))?;
        if namespace == "pg_catalog"
            && matches!(
                field_string(row, "proname")?,
                "dsnowball_init" | "dsnowball_lexize"
            )
        {
            let stable = ids["pg_proc"]
                .get(oid)
                .ok_or(ProfileError::Invalid(
                    "builtin function identity is missing",
                ))?
                .clone();
            ids.get_mut("pg_proc")
                .unwrap()
                .insert(*oid, format!("$builtin:pg_proc:{stable}"));
        }
    }
    for (oid, row) in &rows["pg_aggregate"] {
        let proc_oid = field_oid(row, "aggfnoid", false)?;
        let name = ids["pg_proc"]
            .get(&proc_oid)
            .ok_or(ProfileError::Invalid("aggregate function is missing"))?
            .clone();
        ids.get_mut("pg_aggregate").unwrap().insert(*oid, name);
    }
    for (oid, row) in &rows["pg_ts_config_map"] {
        let config = ids["pg_ts_config"]
            .get(&field_oid(row, "mapcfg", false)?)
            .ok_or(ProfileError::Invalid(
                "text search config map parent is missing",
            ))?;
        // The composite map-row key keeps the qualified configuration name;
        // its actual `mapcfg` OID field is normalized separately to the
        // `$builtin` token so it remains stable across initdb environments.
        let config_identity = config
            .strip_prefix("$builtin:pg_ts_config:")
            .unwrap_or(config);
        let stable = format!(
            "{config_identity}/{}/{}",
            field_value_string(row, "maptokentype")?,
            field_value_string(row, "mapseqno")?
        );
        ids.get_mut("pg_ts_config_map")
            .unwrap()
            .insert(*oid, stable);
    }

    // Direct extension members get stable tokens after their qualified base
    // identity is known; extension auto-arrays inherit their element owner.
    for ((table, oid), extname) in members {
        if let Some(stable) = ids.get_mut(table).and_then(|rows| rows.get_mut(oid)) {
            if stable.starts_with("$builtin:") {
                return Err(ProfileError::Invalid(
                    "builtin dependency is also claimed by an extension",
                ));
            }
            *stable = format!("$extension:{extname}:{table}:{stable}");
        }
    }
    for (oid, row) in &rows["pg_type"] {
        let element = field_oid(row, "typelem", true)?;
        if element != 0
            && members.contains_key(&("pg_type".to_owned(), element))
            && !members.contains_key(&("pg_type".to_owned(), *oid))
        {
            let ext = &members[&(String::from("pg_type"), element)];
            let stable = ids["pg_type"][oid].clone();
            ids.get_mut("pg_type")
                .unwrap()
                .insert(*oid, format!("$extension:{ext}:pg_type:{stable}"));
        }
    }
    for (table, family_field) in [("pg_amop", "amopfamily"), ("pg_amproc", "amprocfamily")] {
        for (oid, row) in &rows[table] {
            let family = field_oid(row, family_field, false)?;
            if let Some(ext) = members.get(&("pg_opfamily".to_owned(), family)) {
                let stable = ids[table][oid].clone();
                ids.get_mut(table)
                    .unwrap()
                    .insert(*oid, format!("$extension:{ext}:{table}:{stable}"));
            }
        }
    }
    for table in CATALOGS {
        let mut stable = BTreeSet::new();
        for identity in ids[*table].values() {
            if !stable.insert(identity) {
                return Err(ProfileError::Invalid(
                    "duplicate canonical runtime catalog identity",
                ));
            }
        }
    }
    Ok(ids)
}

fn string_field_map(
    rows: &BTreeMap<u32, Value>,
    _key: &str,
    name: &str,
) -> Result<BTreeMap<u32, String>, ProfileError> {
    rows.iter()
        .map(|(oid, row)| Ok((*oid, field_string(row, name)?.to_owned())))
        .collect()
}

fn field_string<'a>(row: &'a Value, field: &str) -> Result<&'a str, ProfileError> {
    string(
        row.get(field)
            .ok_or(ProfileError::Invalid("catalog field is missing"))?,
    )
}

fn field_value_string(row: &Value, field: &str) -> Result<String, ProfileError> {
    let value = row
        .get(field)
        .ok_or(ProfileError::Invalid("catalog field is missing"))?;
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        _ => Err(ProfileError::Invalid("catalog identity field is malformed")),
    }
}

fn field_oid(row: &Value, field: &str, allow_zero: bool) -> Result<u32, ProfileError> {
    parse_oid(
        row.get(field)
            .ok_or(ProfileError::Invalid("catalog OID field is missing"))?,
        allow_zero,
    )
}

fn signature_type(ids: &StableIds, oid: u32) -> String {
    if oid == 0 {
        return "0".to_owned();
    }
    ids.get("pg_type")
        .and_then(|rows| rows.get(&oid))
        .cloned()
        .unwrap_or_else(|| format!("oid:{oid}"))
}

fn oid_vector(value: Option<&Value>) -> Result<Vec<u32>, ProfileError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    match value {
        Value::Array(items) => items.iter().map(|item| parse_oid(item, false)).collect(),
        Value::String(text) => {
            let text = text.trim();
            let values = if text.starts_with('{') && text.ends_with('}') {
                let inner = &text[1..text.len() - 1];
                if inner.is_empty() {
                    Vec::new()
                } else {
                    inner.split(',').map(str::trim).collect()
                }
            } else if text.is_empty() {
                Vec::new()
            } else {
                text.split_whitespace().collect()
            };
            values
                .iter()
                .map(|value| parse_oid(&Value::String((*value).to_owned()), false))
                .collect()
        }
        _ => Err(ProfileError::Invalid("OID vector is malformed")),
    }
}

fn raw_oid_for_identity(
    table: &str,
    identity: &str,
    rows: &BTreeMap<u32, Value>,
    ids: &StableIds,
) -> Result<Option<u32>, ProfileError> {
    if table == "pg_extension" {
        return Ok(rows.iter().find_map(|(oid, row)| {
            (row.get("extname").and_then(Value::as_str) == Some(identity)).then_some(*oid)
        }));
    }
    if let Ok(oid) = identity.parse::<u32>() {
        if table == "pg_ts_config_map" {
            return Ok(rows.iter().find_map(|(oid, _)| {
                (ids[table].get(oid).map(String::as_str) == Some(identity)).then_some(*oid)
            }));
        }
        return Ok(rows.contains_key(&oid).then_some(oid));
    }
    Ok(ids.get(table).and_then(|map| {
        map.iter()
            .find_map(|(oid, stable)| (stable == identity).then_some(*oid))
    }))
}

fn emitted_identity(
    table: &str,
    oid: u32,
    _row: &Value,
    identities: &StableIds,
) -> Result<String, ProfileError> {
    if table == "pg_extension" {
        return identities[table]
            .get(&oid)
            .cloned()
            .ok_or(ProfileError::Invalid("extension name identity is missing"));
    }
    if table == "pg_ts_config_map" {
        return identities[table]
            .get(&oid)
            .cloned()
            .ok_or(ProfileError::Invalid("text search map identity is missing"));
    }
    let stable = identities
        .get(table)
        .and_then(|rows| rows.get(&oid))
        .ok_or(ProfileError::Invalid("stable identity is missing"))?;
    if is_stable_token(stable) {
        return Ok(stable.clone());
    }
    if table == "pg_range" {
        return Ok(oid.to_string());
    }
    Ok(oid.to_string())
}

fn encoded_identity(
    table: &str,
    oid: u32,
    row: &Value,
    identities: &StableIds,
) -> Result<Value, ProfileError> {
    let stable = emitted_identity(table, oid, row, identities)?;
    if table != "pg_extension" && table != "pg_ts_config_map" && !is_stable_token(&stable) {
        return Ok(Value::from(oid));
    }
    Ok(Value::String(stable))
}

fn normalize_row(
    table: &str,
    row: &Value,
    oid: u32,
    ids: &StableIds,
) -> Result<Map<String, Value>, ProfileError> {
    let mut fields = object(row, "raw row")?.clone();
    let oid_fields: &[(&str, Option<&str>)] = match table {
        "pg_type" => &[
            ("typnamespace", Some("pg_namespace")),
            ("typelem", Some("pg_type")),
            ("typarray", Some("pg_type")),
            ("typbasetype", Some("pg_type")),
            ("typcollation", Some("pg_collation")),
            ("typinput", Some("pg_proc")),
            ("typoutput", Some("pg_proc")),
            ("typreceive", Some("pg_proc")),
            ("typsend", Some("pg_proc")),
            ("typmodin", Some("pg_proc")),
            ("typmodout", Some("pg_proc")),
            ("typanalyze", Some("pg_proc")),
            ("typsubscript", Some("pg_proc")),
            ("typrelid", None),
        ],
        "pg_proc" => &[
            ("pronamespace", Some("pg_namespace")),
            ("prorettype", Some("pg_type")),
            ("provariadic", Some("pg_type")),
            ("prosupport", Some("pg_proc")),
            ("prolang", None),
            ("proowner", None),
        ],
        "pg_operator" => &[
            ("oprnamespace", Some("pg_namespace")),
            ("oprleft", Some("pg_type")),
            ("oprright", Some("pg_type")),
            ("oprresult", Some("pg_type")),
            ("oprcode", Some("pg_proc")),
            ("oprrest", Some("pg_proc")),
            ("oprjoin", Some("pg_proc")),
            ("oprcom", Some("pg_operator")),
            ("oprnegate", Some("pg_operator")),
        ],
        "pg_aggregate" => &[
            ("aggfnoid", Some("pg_proc")),
            ("aggtransfn", Some("pg_proc")),
            ("aggfinalfn", Some("pg_proc")),
            ("aggcombinefn", Some("pg_proc")),
            ("aggserialfn", Some("pg_proc")),
            ("aggdeserialfn", Some("pg_proc")),
            ("aggmtransfn", Some("pg_proc")),
            ("aggminvtransfn", Some("pg_proc")),
            ("aggmfinalfn", Some("pg_proc")),
            ("aggsortop", Some("pg_operator")),
            ("aggtranstype", Some("pg_type")),
            ("aggmtranstype", Some("pg_type")),
        ],
        "pg_cast" => &[
            ("castsource", Some("pg_type")),
            ("casttarget", Some("pg_type")),
            ("castfunc", Some("pg_proc")),
        ],
        "pg_am" => &[("amhandler", Some("pg_proc"))],
        "pg_collation" => &[("collnamespace", Some("pg_namespace")), ("collowner", None)],
        "pg_opclass" => &[
            ("opcmethod", Some("pg_am")),
            ("opcfamily", Some("pg_opfamily")),
            ("opcintype", Some("pg_type")),
            ("opckeytype", Some("pg_type")),
            ("opcnamespace", Some("pg_namespace")),
            ("opcowner", None),
        ],
        "pg_opfamily" => &[
            ("opfmethod", Some("pg_am")),
            ("opfnamespace", Some("pg_namespace")),
            ("opfowner", None),
        ],
        "pg_amop" => &[
            ("amopfamily", Some("pg_opfamily")),
            ("amoplefttype", Some("pg_type")),
            ("amoprighttype", Some("pg_type")),
            ("amopopr", Some("pg_operator")),
            ("amopmethod", Some("pg_am")),
            ("amopsortfamily", Some("pg_opfamily")),
        ],
        "pg_amproc" => &[
            ("amprocfamily", Some("pg_opfamily")),
            ("amproclefttype", Some("pg_type")),
            ("amprocrighttype", Some("pg_type")),
            ("amproc", Some("pg_proc")),
        ],
        "pg_range" => &[
            ("rngtypid", Some("pg_type")),
            ("rngsubtype", Some("pg_type")),
            ("rngcollation", Some("pg_collation")),
            ("rngsubopc", Some("pg_opclass")),
            ("rngcanonical", Some("pg_proc")),
            ("rngsubdiff", Some("pg_proc")),
            ("rngmultitypid", Some("pg_type")),
        ],
        "pg_ts_config" => &[
            ("cfgnamespace", Some("pg_namespace")),
            ("cfgowner", None),
            ("cfgparser", Some("pg_ts_parser")),
        ],
        "pg_ts_config_map" => &[
            ("mapcfg", Some("pg_ts_config")),
            ("mapdict", Some("pg_ts_dict")),
        ],
        "pg_ts_dict" => &[
            ("dictnamespace", Some("pg_namespace")),
            ("dictowner", None),
            ("dicttemplate", Some("pg_ts_template")),
        ],
        "pg_ts_parser" => &[
            ("prsnamespace", Some("pg_namespace")),
            ("prsstart", Some("pg_proc")),
            ("prstoken", Some("pg_proc")),
            ("prsend", Some("pg_proc")),
            ("prsheadline", Some("pg_proc")),
            ("prslextype", Some("pg_proc")),
        ],
        "pg_ts_template" => &[
            ("tmplnamespace", Some("pg_namespace")),
            ("tmplinit", Some("pg_proc")),
            ("tmpllexize", Some("pg_proc")),
        ],
        "pg_extension" => &[("extnamespace", Some("pg_namespace")), ("extowner", None)],
        "pg_namespace" => &[("nspowner", None)],
        "pg_enum" => &[],
        _ => return Err(ProfileError::Invalid("unsupported catalog table")),
    };
    for (field, target) in oid_fields {
        let Some(value) = fields.get(*field).cloned() else {
            continue;
        };
        let value_oid = parse_oid(&value, true).inspect_err(|_error| {
            profile_diagnostic("oid_field_parse", table, field);
        })?;
        let normalized = if value_oid == 0 || target.is_none() {
            Value::from(value_oid)
        } else {
            let target = target.unwrap();
            let identity = ids
                .get(target)
                .and_then(|rows| rows.get(&value_oid))
                .ok_or_else(|| {
                    profile_diagnostic("oid_reference_lookup", table, field);
                    ProfileError::Invalid("catalog contains an unprofiled OID reference")
                })?;
            if is_stable_token(identity) {
                Value::String(identity.clone())
            } else {
                Value::from(value_oid)
            }
        };
        fields.insert((*field).to_owned(), normalized);
    }
    if table == "pg_proc" {
        for field in ["proargtypes", "proallargtypes", "protrftypes"] {
            let Some(value) = fields.get(field).cloned() else {
                continue;
            };
            if value.is_null() {
                continue;
            }
            let mut normalized = Vec::new();
            for oid in oid_vector(Some(&value))? {
                let identity = ids["pg_type"]
                    .get(&oid)
                    .ok_or(ProfileError::Invalid("function signature type is missing"))?;
                normalized.push(if is_stable_token(identity) {
                    Value::String(identity.clone())
                } else {
                    Value::from(oid)
                });
            }
            fields.insert(field.to_owned(), Value::Array(normalized));
        }
        for field in ["prosrc", "prosqlbody"] {
            if let Some(source) = fields.get(field).cloned() {
                fields.insert(field.to_owned(), normalize_proc_source(&source)?);
            }
        }
    }
    if table == "pg_extension" {
        let ext = field_string(row, "extname")?.to_owned();
        fields.insert("oid".to_owned(), Value::String(ext));
    }
    if table == "pg_namespace" {
        fields.insert("oid".to_owned(), Value::from(oid));
    } else if table != "pg_ts_config_map"
        && table != "pg_range"
        && table != "pg_aggregate"
        && table != "pg_extension"
    {
        let stable = ids[table]
            .get(&oid)
            .ok_or(ProfileError::Invalid("row identity is missing"))?;
        fields.insert(
            "oid".to_owned(),
            if is_stable_token(stable) {
                Value::String(stable.clone())
            } else {
                Value::from(oid)
            },
        );
    }
    Ok(fields)
}

fn profile_has_identity(
    profile_catalog: &Map<String, Value>,
    table: &str,
    identity: &str,
) -> Result<bool, ProfileError> {
    Ok(array(required(profile_catalog, table)?)?.iter().any(|row| {
        row.get("identity")
            .and_then(|value| identity_string(value).ok())
            .as_deref()
            == Some(identity)
    }))
}

fn normalize_extensions(
    rows: &RawRows,
    members: &ExtensionMembers,
    ids: &StableIds,
    enabled: &[String],
) -> Result<Vec<Value>, ProfileError> {
    let observed: BTreeSet<_> = rows["pg_extension"]
        .values()
        .map(|row| field_string(row, "extname").map(str::to_owned))
        .collect::<Result<_, _>>()?;
    let expected: BTreeSet<_> = enabled.iter().cloned().collect();
    if observed != expected {
        return Err(ProfileError::Invalid(
            "captured extensions differ from selected module set",
        ));
    }
    let mut output = Vec::new();
    for name in enabled {
        let (_oid, row) = rows["pg_extension"]
            .iter()
            .find(|(_, row)| row.get("extname").and_then(Value::as_str) == Some(name.as_str()))
            .ok_or(ProfileError::Invalid("reviewed extension is missing"))?;
        let version = field_string(row, "extversion")?;
        let ns_oid = field_oid(row, "extnamespace", false)?;
        let namespace = ids["pg_namespace"]
            .get(&ns_oid)
            .ok_or(ProfileError::Invalid("extension namespace is missing"))?
            .clone();
        let mut member_names = Vec::new();
        for ((catalog, member_oid), ext) in members {
            if ext == name {
                let stable = ids.get(catalog).and_then(|map| map.get(member_oid)).ok_or(
                    ProfileError::Invalid("extension member has no stable identity"),
                )?;
                member_names.push(stable.clone());
            }
        }
        member_names.sort();
        let mut derived_names = BTreeSet::new();
        let direct_family_oids: BTreeSet<u32> = members
            .iter()
            .filter_map(|((catalog, oid), ext)| {
                (catalog == "pg_opfamily" && ext == name).then_some(*oid)
            })
            .collect();
        for (oid, row) in &rows["pg_amop"] {
            if direct_family_oids.contains(&field_oid(row, "amopfamily", false)?) {
                derived_names.insert(
                    ids["pg_amop"]
                        .get(oid)
                        .ok_or(ProfileError::Invalid("derived amop identity is missing"))?
                        .clone(),
                );
            }
        }
        for (oid, row) in &rows["pg_amproc"] {
            if direct_family_oids.contains(&field_oid(row, "amprocfamily", false)?) {
                derived_names.insert(
                    ids["pg_amproc"]
                        .get(oid)
                        .ok_or(ProfileError::Invalid("derived amproc identity is missing"))?
                        .clone(),
                );
            }
        }
        let direct_types: BTreeSet<u32> = members
            .iter()
            .filter_map(|((catalog, oid), ext)| {
                (catalog == "pg_type" && ext == name).then_some(*oid)
            })
            .collect();
        for (oid, row) in &rows["pg_type"] {
            let element = field_oid(row, "typelem", true)?;
            if direct_types.contains(&element)
                && !members.contains_key(&("pg_type".to_owned(), *oid))
            {
                derived_names.insert(
                    ids["pg_type"]
                        .get(oid)
                        .ok_or(ProfileError::Invalid("derived array identity is missing"))?
                        .clone(),
                );
            }
        }
        let mut fields = object(row, "extension row")?.clone();
        fields.insert("oid".to_owned(), Value::String(name.to_owned()));
        fields.insert("extnamespace".to_owned(), Value::String(namespace.clone()));
        let fields = Value::Object(fields);
        output.push(serde_json::json!({
            "name":name,
            "version":version,
            "namespace":namespace,
            "members":member_names,
            "derived_members":derived_names,
            "fields":fields
        }));
    }
    Ok(output)
}

fn core_oid(catalog: &str, identity: &str) -> Option<u32> {
    let _ = catalog;
    identity.parse::<u32>().ok().filter(|oid| *oid != 0)
}

fn is_stable_token(identity: &str) -> bool {
    identity.starts_with("$extension:") || identity.starts_with("$builtin:")
}

fn valid_pinned_image(image: &str, major: u32) -> bool {
    let Some((repository_tag, digest)) = image.split_once("@sha256:") else {
        return false;
    };
    let Some(tag) = repository_tag.strip_prefix("postgres:") else {
        return false;
    };
    let major = major.to_string();
    let suffix = tag.strip_prefix(&major);
    let valid_major_tag = suffix.is_some_and(|suffix| {
        if suffix.is_empty() {
            true
        } else {
            (suffix.starts_with('.') || suffix.starts_with('-'))
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        }
    });
    valid_major_tag
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn parse_digest(value: &str) -> Result<[u8; 32], ProfileError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProfileError::Invalid(
            "SHA-256 must be 64 lowercase hexadecimal characters",
        ));
    }
    let mut digest = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0]).ok_or(ProfileError::Invalid("malformed SHA-256"))?;
        let lo = hex_nibble(pair[1]).ok_or(ProfileError::Invalid("malformed SHA-256"))?;
        digest[index] = (hi << 4) | lo;
    }
    Ok(digest)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .unwrap()
}

fn normalize_proc_source(value: &Value) -> Result<Value, ProfileError> {
    match value {
        Value::Null => Ok(Value::Null),
        Value::String(source) => {
            Ok(serde_json::json!({"sha256_utf8": expected_sha256(source.as_bytes())}))
        }
        Value::Object(marker) => {
            if marker.len() != 1 || !marker.contains_key("sha256_utf8") {
                return Err(ProfileError::Invalid(
                    "function source fingerprint has an invalid shape",
                ));
            }
            let digest = string(required(marker, "sha256_utf8")?)?;
            parse_digest(digest)?;
            Ok(value.clone())
        }
        _ => Err(ProfileError::Invalid(
            "function source fingerprint is malformed",
        )),
    }
}

fn validate_proc_source_marker(value: &Value) -> Result<(), ProfileError> {
    match value {
        Value::Null => Ok(()),
        Value::Object(_) => {
            let normalized = normalize_proc_source(value)?;
            if normalized != *value {
                return Err(ProfileError::Invalid(
                    "function source fingerprint is not canonical",
                ));
            }
            Ok(())
        }
        _ => Err(ProfileError::Invalid(
            "profile contains unredacted function source",
        )),
    }
}

fn expected_sha256(bytes: &[u8]) -> String {
    sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn canonical_digest(value: &Value) -> Result<[u8; 32], ProfileError> {
    Ok(sha256(&canonical_bytes(value)?))
}

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, ProfileError> {
    serde_json::to_vec(value).map_err(|_| ProfileError::Invalid("JSON canonicalization failed"))
}

fn validate_value_budget(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ProfileError> {
    *nodes = nodes
        .checked_add(1)
        .ok_or(ProfileError::Invalid("JSON node count overflow"))?;
    if depth > MAX_VALUE_DEPTH || *nodes > MAX_ROWS * 128 {
        return Err(ProfileError::Invalid("JSON shape budget exceeded"));
    }
    match value {
        Value::String(value) if value.len() > MAX_STRING_BYTES => {
            Err(ProfileError::Invalid("JSON string is too large"))
        }
        Value::Array(values) => {
            if values.len() > MAX_ROWS {
                return Err(ProfileError::Invalid("JSON array budget exceeded"));
            }
            for value in values {
                validate_value_budget(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, value) in values {
                if key.len() > 4096 {
                    return Err(ProfileError::Invalid("JSON object key is too large"));
                }
                validate_value_budget(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn parse_oid(value: &Value, allow_zero: bool) -> Result<u32, ProfileError> {
    let number = match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.parse::<u64>().ok(),
        _ => None,
    }
    .ok_or(ProfileError::Invalid("malformed OID"))?;
    if number > u32::MAX as u64 || (!allow_zero && number == 0) {
        return Err(ProfileError::Invalid("OID outside valid range"));
    }
    Ok(number as u32)
}

fn identity_string(value: &Value) -> Result<String, ProfileError> {
    match value {
        Value::String(value) if !value.is_empty() && value.len() <= 4096 => Ok(value.clone()),
        Value::Number(value)
            if value
                .as_u64()
                .is_some_and(|number| number > 0 && number <= u32::MAX as u64) =>
        {
            Ok(value.to_string())
        }
        _ => Err(ProfileError::Invalid("malformed catalog identity")),
    }
}

fn object<'a>(
    value: &'a Value,
    _label: &'static str,
) -> Result<&'a Map<String, Value>, ProfileError> {
    value
        .as_object()
        .ok_or(ProfileError::Invalid("expected JSON object"))
}

fn array(value: &Value) -> Result<&Vec<Value>, ProfileError> {
    value
        .as_array()
        .ok_or(ProfileError::Invalid("expected JSON array"))
}

fn required<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, ProfileError> {
    object
        .get(key)
        .ok_or(ProfileError::Invalid("required field is missing"))
}

fn exact_keys(object: &Map<String, Value>, keys: &[&str]) -> Result<(), ProfileError> {
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(ProfileError::Invalid(
            "object has missing or unsupported fields",
        ));
    }
    Ok(())
}

fn string(value: &Value) -> Result<&str, ProfileError> {
    value
        .as_str()
        .ok_or(ProfileError::Invalid("expected string"))
}

fn uint(value: &Value) -> Result<u64, ProfileError> {
    value
        .as_u64()
        .filter(|_| !value.is_boolean())
        .ok_or(ProfileError::Invalid("expected unsigned integer"))
}

/// A serde_json::Value decoder that rejects duplicate object keys instead of
/// silently keeping the last value.
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element::<UniqueValue>()? {
            if values.len() >= MAX_ROWS {
                return Err(serde::de::Error::custom("JSON array budget exceeded"));
            }
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate object key"));
            }
            let value = map.next_value::<UniqueValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE: &str =
        "postgres:18.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TRGM_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const GIST_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const EXT_TYPE: &str = "$extension:pg_trgm:pg_type:public.ext_type";

    #[test]
    fn local_owned_reference_profiles_round_trip_when_fixture_path_is_supplied() {
        let Ok(directory) = std::env::var("PGDOG_PROFILE_TEST_FIXTURE_DIR") else {
            eprintln!(
                "SKIP local owned-profile roundtrip: set PGDOG_PROFILE_TEST_FIXTURE_DIR to the private output of scripts/capture_read_dependency_reference.py"
            );
            return;
        };
        for major in [12, 18] {
            let profile_bytes = std::fs::read(format!(
                "{directory}/variants/read-dependency-profile-pg{major}-both.json"
            ))
            .unwrap();
            let profile_value: Value = serde_json::from_slice(&profile_bytes).unwrap();
            let pinned_image = profile_value["provenance"]["source_image"]
                .as_str()
                .unwrap();
            let digest = expected(&profile_bytes);
            let profile = ValidatedDependencyProfile::load_profile(
                &profile_bytes,
                &digest,
                major,
                pinned_image,
            )
            .unwrap();
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
            let normalized = normalize_capture(&profile, &capture).unwrap();
            for table in CATALOGS {
                let actual = normalized.document["catalog"][*table].as_array().unwrap();
                let expected = profile.document["catalog"][*table].as_array().unwrap();
                if actual != expected {
                    let mismatch = actual
                        .iter()
                        .zip(expected)
                        .find(|(left, right)| left != right);
                    let detail = mismatch
                        .map(|(left, right)| {
                            let left_fields = left["fields"].as_object().unwrap();
                            let right_fields = right["fields"].as_object().unwrap();
                            let keys: BTreeSet<_> =
                                left_fields.keys().chain(right_fields.keys()).collect();
                            keys.into_iter()
                                .filter(|&key| left_fields.get(key) != right_fields.get(key))
                                .map(|key| {
                                    format!(
                                        "{key}: {:?} != {:?}",
                                        left_fields.get(key),
                                        right_fields.get(key)
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_else(|| {
                            format!("row count {} != {}", actual.len(), expected.len())
                        });
                    panic!("catalog mismatch in {table} for PG{major}: {detail}");
                }
            }
            let proof = profile.validate_live(&capture, major).unwrap();
            for table in ["pg_ts_config", "pg_ts_dict", "pg_ts_template", "pg_proc"] {
                for (identity, _) in profile.expected_named_builtin_rows(table) {
                    let oid = proof.runtime_oid_for_identity(table, &identity).unwrap();
                    assert_eq!(
                        proof.identity_for_runtime_oid(table, oid),
                        Some(identity.as_str())
                    );
                }
            }
            let mut extra_map = capture.clone();
            let maps = extra_map["tables"]["pg_ts_config_map"]
                .as_array_mut()
                .unwrap();
            let mut extra = maps[0].clone();
            let old_sequence = parse_oid(&extra["mapseqno"], false).unwrap();
            extra["mapseqno"] = Value::from(old_sequence + 1);
            maps.push(extra);
            assert!(profile.validate_live(&extra_map, major).is_err());
        }
    }

    #[test]
    fn local_owned_v2_module_variants_round_trip_against_filtered_capture() {
        let Ok(directory) = std::env::var("PGDOG_PROFILE_TEST_FIXTURE_DIR") else {
            eprintln!(
                "SKIP v2 profile roundtrip: set PGDOG_PROFILE_TEST_FIXTURE_DIR to the private output of scripts/capture_read_dependency_reference.py and generate variants with write_profile_variants"
            );
            return;
        };
        let variants = [
            ("core", &[][..]),
            ("pg-trgm", &["pg_trgm"][..]),
            ("btree-gist", &["btree_gist"][..]),
            ("both", &["btree_gist", "pg_trgm"][..]),
        ];
        for major in [12, 18] {
            let reference: Value = serde_json::from_slice(
                &std::fs::read(format!("{directory}/reference-extended-pg{major}.json")).unwrap(),
            )
            .unwrap();
            for (suffix, enabled) in variants {
                let bytes = std::fs::read(format!(
                    "{directory}/variants/read-dependency-profile-pg{major}-{suffix}.json"
                ))
                .unwrap();
                let artifact: Value = serde_json::from_slice(&bytes).unwrap();
                let image = artifact["provenance"]["source_image"].as_str().unwrap();
                let reviewed = ValidatedDependencyProfile::load_profile(
                    &bytes,
                    &expected(&bytes),
                    major,
                    image,
                )
                .unwrap();
                assert_eq!(
                    reviewed.enabled_extensions(),
                    enabled
                        .iter()
                        .map(|name| (*name).to_owned())
                        .collect::<Vec<_>>(),
                );
                let mut capture = reference.clone();
                capture["tables"]["pg_extension"] = Value::Array(
                    capture["tables"]["pg_extension"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|row| enabled.contains(&row["extname"].as_str().unwrap()))
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
                                || enabled.contains(&row["extname"].as_str().unwrap())
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
                            enabled
                                .iter()
                                .any(|name| line.as_str().unwrap().contains(&format!("/{name}.so")))
                        })
                        .cloned()
                        .collect(),
                );
                let proof = reviewed.validate_live(&capture, major).unwrap();
                assert_eq!(proof.major(), major);
                for table in CATALOGS {
                    assert_eq!(
                        proof.catalog[*table], artifact["catalog"][*table],
                        "catalog mismatch for PG{major} {suffix} {table}"
                    );
                }
            }
        }
    }

    #[test]
    fn authorized_acl_variation_keeps_live_acl_in_digest_and_requires_exact_actor_proof() {
        let mut reference = profile();
        reference["namespace_authority"] = Value::String("actor-namespace-authority/v1".into());
        let validated = load(&reference).unwrap();
        let role = super::super::rows::RoleRow {
            valid: true,
            oid: 20001,
            superuser: false,
            create_role: false,
            create_database: false,
            replication: false,
            bypass_rls: false,
            inherit: true,
            has_memberships: false,
        };
        let expected = [(11, "pg_catalog".into()), (2200, "public".into())].into();
        let mut live = raw_capture();
        live["tables"]["pg_namespace"][1]["nspacl"] = serde_json::json!(["=U/postgres"]);
        let authority_rows = |capture: &Value| {
            Value::Array(
                capture["tables"]["pg_namespace"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| {
                        let mut row = row.clone();
                        row["actor_oid"] = Value::String("20001".into());
                        row["has_create"] = Value::Bool(false);
                        row["has_usage"] = Value::Bool(true);
                        row
                    })
                    .collect(),
            )
        };
        let authority =
            super::super::namespace_authority::prove(&role, &expected, &authority_rows(&live))
                .unwrap();
        assert!(validated.validate_live(&live, 18).is_err());
        let first = validated
            .validate_live_authorized(&live, 18, &authority)
            .unwrap();
        live["tables"]["pg_namespace"][1]["nspacl"] = serde_json::json!(["reader=U/postgres"]);
        assert!(
            validated
                .validate_live_authorized(&live, 18, &authority)
                .is_err()
        );
        let changed =
            super::super::namespace_authority::prove(&role, &expected, &authority_rows(&live))
                .unwrap();
        let second = validated
            .validate_live_authorized(&live, 18, &changed)
            .unwrap();
        assert_ne!(first.digest(), second.digest());
        assert!(
            load(&profile())
                .unwrap()
                .validate_live_authorized(&raw_capture(), 18, &changed)
                .is_err()
        );
        live["tables"]["pg_namespace"][1]["nspowner"] = Value::String("30".into());
        let new_owner =
            super::super::namespace_authority::prove(&role, &expected, &authority_rows(&live))
                .unwrap();
        assert!(
            validated
                .validate_live_authorized(&live, 18, &new_owner)
                .is_err()
        );
    }

    fn empty_catalog() -> Map<String, Value> {
        CATALOGS
            .iter()
            .map(|table| ((*table).to_owned(), Value::Array(Vec::new())))
            .collect()
    }

    fn namespace(oid: u32, name: &str) -> Value {
        serde_json::json!({"identity":oid,"fields":{"oid":oid,"nspname":name,"nspowner":10,"nspacl":null}})
    }

    fn extension(name: &str, version: &str) -> Value {
        serde_json::json!({
            "name":name,
            "version":version,
            "namespace":"public",
            "members":[],
            "derived_members":[],
            "fields":{
                "oid":name,
                "extname":name,
                "extowner":"10",
                "extnamespace":"public",
                "extrelocatable":true,
                "extversion":version,
                "extconfig":null,
                "extcondition":null
            }
        })
    }

    fn profile() -> Value {
        let mut catalog = empty_catalog();
        catalog.insert(
            "pg_namespace".into(),
            serde_json::json!([namespace(11, "pg_catalog"), namespace(2200, "public")]),
        );
        catalog.insert(
            "pg_type".into(),
            serde_json::json!([{
                "identity":23,
            "fields":{"oid":23,"typname":"int4","typnamespace":11,"typelem":0}
            }]),
        );
        catalog.insert("pg_extension".into(), serde_json::json!([
            {"identity":"btree_gist","fields":{"oid":"btree_gist","extname":"btree_gist","extowner":10,"extnamespace":2200,"extrelocatable":true,"extversion":"1.8","extconfig":null,"extcondition":null}},
            {"identity":"pg_trgm","fields":{"oid":"pg_trgm","extname":"pg_trgm","extowner":10,"extnamespace":2200,"extrelocatable":true,"extversion":"1.6","extconfig":null,"extcondition":null}}
        ]));
        serde_json::json!({
            "format":FORMAT,
            "provenance":{
                "postgres_major":18,
                "source_image":IMAGE,
                "server_version":"18.0",
                "server_version_num":180000,
                "platform":"linux/amd64",
                "capture_id":"owned-pg18-fixture"
            },
            "roots":[{"catalog":"pg_type","identity":23}],
            "catalog":catalog,
            "extensions":[extension("btree_gist","1.8"),extension("pg_trgm","1.6")],
            "module_sha256":{"pg_trgm":TRGM_HASH,"btree_gist":GIST_HASH},
            "client_functions":[],
            "projection_types":[23]
        })
    }

    fn profile_v2(enabled: &[&str]) -> Value {
        let mut value = profile();
        value["format"] = Value::String(FORMAT_V2.to_owned());
        value["enabled_extensions"] = serde_json::json!(enabled);
        value["extensions"] = Value::Array(
            value["extensions"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| enabled.contains(&row["name"].as_str().unwrap()))
                .cloned()
                .collect(),
        );
        value["catalog"]["pg_extension"] = Value::Array(
            value["catalog"]["pg_extension"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| enabled.contains(&row["identity"].as_str().unwrap()))
                .cloned()
                .collect(),
        );
        let mut hashes = Map::new();
        for name in enabled {
            hashes.insert(name.to_string(), value["module_sha256"][*name].clone());
        }
        value["module_sha256"] = Value::Object(hashes);
        value
    }

    fn capture_for_enabled(enabled: &[&str]) -> Value {
        let mut value = raw_capture();
        let extension_rows = value["tables"]["pg_extension"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| enabled.contains(&row["extname"].as_str().unwrap()))
            .cloned()
            .collect();
        value["tables"]["pg_extension"] = Value::Array(extension_rows);
        let hashes = value["module_sha256"].as_array().unwrap();
        value["module_sha256"] = Value::Array(
            hashes
                .iter()
                .filter(|line| {
                    enabled
                        .iter()
                        .any(|name| line.as_str().unwrap().contains(&format!("/{name}.so")))
                })
                .cloned()
                .collect(),
        );
        value
    }

    fn raw_capture() -> Value {
        let mut tables = empty_catalog();
        tables.insert(
            "pg_namespace".into(),
            serde_json::json!([
                {"oid":"11","nspname":"pg_catalog","nspowner":"10","nspacl":null},
                {"oid":"2200","nspname":"public","nspowner":"10","nspacl":null}
            ]),
        );
        tables.insert(
            "pg_type".into(),
            serde_json::json!([
            {"oid":"23","typname":"int4","typnamespace":"11","typelem":"0"}
            ]),
        );
        tables.insert("pg_extension".into(), serde_json::json!([
            {"oid":"1234","extname":"btree_gist","extowner":"10","extnamespace":"2200","extrelocatable":true,"extversion":"1.8","extconfig":null,"extcondition":null},
            {"oid":"1235","extname":"pg_trgm","extowner":"10","extnamespace":"2200","extrelocatable":true,"extversion":"1.6","extconfig":null,"extcondition":null}
        ]));
        serde_json::json!({
            "postgres_major":18,
            "server_version":"18.2",
            "server_version_num":180002,
            "capture_id":"runtime-catalog-capture",
            "tables":tables,
            "extension_members":[],
            "module_sha256":[
                format!("{TRGM_HASH}  /usr/lib/postgresql/18/lib/pg_trgm.so"),
                format!("{GIST_HASH}  /usr/lib/postgresql/18/lib/btree_gist.so")
            ]
        })
    }

    fn profile_with_extension_type() -> Value {
        let mut value = profile();
        value["catalog"]["pg_type"] = serde_json::json!([
            {"identity":EXT_TYPE,"fields":{"oid":EXT_TYPE,"typname":"ext_type","typnamespace":2200,"typelem":0}},
            {"identity":23,"fields":{"oid":23,"typname":"int4","typnamespace":11,"typelem":0}}
        ]);
        value["extensions"][1]["members"] = serde_json::json!([EXT_TYPE]);
        value
    }

    fn raw_capture_with_extension_type() -> Value {
        let mut value = raw_capture();
        value["tables"]["pg_type"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "oid":"90000","typname":"ext_type","typnamespace":"2200","typelem":"0"
            }));
        value["extension_members"] = serde_json::json!([
            {"extname":"pg_trgm","catalog":"pg_type","objid":"90000","objsubid":0}
        ]);
        value
    }

    fn profile_with_proc_fingerprint() -> Value {
        let mut value = profile();
        value["catalog"]["pg_proc"] = serde_json::json!([{
            "identity":100,
            "fields":{
                "oid":100,
                "proname":"safe_fn",
                "pronamespace":11,
                "proargtypes":[],
                "prorettype":23,
                "prokind":"f",
                "prosrc":{"sha256_utf8":expected(b"SELECT 1")},
                "prosqlbody":null
            }
        }]);
        value
    }

    fn raw_capture_with_proc_source(source: Value) -> Value {
        let mut value = raw_capture();
        value["tables"]["pg_proc"] = serde_json::json!([{
            "oid":"100",
            "proname":"safe_fn",
            "pronamespace":"11",
            "proargtypes":"",
            "prorettype":"23",
            "prokind":"f",
            "prosrc":source,
            "prosqlbody":null
        }]);
        value
    }

    fn encode(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }
    fn expected(bytes: &[u8]) -> String {
        sha256(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
    fn load(value: &Value) -> Result<ValidatedDependencyProfile, ProfileError> {
        let bytes = encode(value);
        ValidatedDependencyProfile::load_profile(&bytes, &expected(&bytes), 18, IMAGE)
    }

    #[test]
    fn loads_exact_reviewed_artifact_and_builds_core_oid_lookup() {
        let validated = load(&profile()).unwrap();
        assert_eq!(validated.major(), 18);
        assert_ne!(validated.digest(), &[0; 32]);
        assert_eq!(validated.identity_for_core_oid("pg_type", 23), Some("23"));
        assert_eq!(validated.core_oid_for_identity("pg_type", "23"), Some(23));
    }

    #[test]
    fn exposes_only_explicitly_profiled_named_builtin_rows_for_capture() {
        let mut value = profile();
        let identity = "$builtin:pg_ts_config:pg_catalog.english";
        value["catalog"]["pg_ts_config"] = serde_json::json!([{
            "identity":identity,
            "fields":{"cfgname":"english","cfgnamespace":11,"oid":identity}
        }]);
        let validated = load(&value).unwrap();
        assert_eq!(
            validated.expected_named_builtin_rows("pg_ts_config"),
            vec![(
                identity.to_owned(),
                serde_json::json!({
                    "cfgname":"english","cfgnamespace":11,"oid":identity
                })
            )]
        );
        assert!(validated.expected_named_builtin_rows("pg_type").is_empty());
    }

    #[test]
    fn duplicate_canonical_builtin_candidates_are_denied_even_if_unselected() {
        let validated = load(&profile()).unwrap();
        let mut capture = raw_capture();
        capture["tables"]["pg_ts_config"] = serde_json::json!([
            {"oid":"12001","cfgname":"english","cfgnamespace":"11"},
            {"oid":"12002","cfgname":"english","cfgnamespace":"11"}
        ]);
        assert!(normalize_capture(&validated, &capture).is_err());
    }

    #[test]
    fn artifact_digest_and_reference_provenance_are_separate_trust_inputs() {
        let value = profile();
        let bytes = encode(&value);
        assert!(
            ValidatedDependencyProfile::load_profile(&bytes, &"0".repeat(64), 18, IMAGE).is_err()
        );
        let mut changed = value.clone();
        changed["provenance"]["source_image"] = Value::String("postgres:18.0".into());
        assert!(load(&changed).is_err());
        assert!(
            ValidatedDependencyProfile::load_profile(&bytes, &expected(&bytes), 12, IMAGE).is_err()
        );
        let malformed_pin =
            "postgres:180@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut malformed_pin_profile = profile();
        malformed_pin_profile["provenance"]["source_image"] =
            Value::String(malformed_pin.to_owned());
        let malformed_pin_bytes = encode(&malformed_pin_profile);
        assert!(
            ValidatedDependencyProfile::load_profile(
                &malformed_pin_bytes,
                &expected(&malformed_pin_bytes),
                18,
                malformed_pin
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_missing_unsupported_and_static_enum_catalog_rows() {
        let mut missing = profile();
        missing["catalog"]
            .as_object_mut()
            .unwrap()
            .remove("pg_enum");
        assert!(load(&missing).is_err());
        let mut extra = profile();
        extra["catalog"]["pg_untrusted"] = serde_json::json!([]);
        assert!(load(&extra).is_err());
        let mut dynamic_enum = profile();
        dynamic_enum["catalog"]["pg_enum"] =
            serde_json::json!([{"identity":"unexpected","fields":{}}]);
        assert!(load(&dynamic_enum).is_err());
    }

    #[test]
    fn rejects_duplicate_json_keys_even_when_the_expected_hash_matches() {
        let bytes = encode(&profile());
        let text = String::from_utf8(bytes).unwrap();
        let duplicate = text.replacen("\"format\":", "\"format\":\"forged\",\"format\":", 1);
        assert!(
            ValidatedDependencyProfile::load_profile(
                duplicate.as_bytes(),
                &expected(duplicate.as_bytes()),
                18,
                IMAGE
            )
            .is_err()
        );
    }

    #[test]
    fn raw_runtime_rows_are_normalized_then_compared_as_a_complete_closure() {
        let reference = profile();
        let validated = load(&reference).unwrap();
        let raw = raw_capture();
        let normalized = normalize_capture(&validated, &raw).unwrap();
        assert_eq!(normalized.document["catalog"], reference["catalog"]);
        assert_eq!(normalized.document["extensions"], reference["extensions"]);
        let proof = validated.validate_live(&raw, 18).unwrap();
        assert_eq!(proof.major(), 18);
        assert_eq!(proof.profile_digest(), validated.digest());
        assert_ne!(proof.digest(), &[0; 32]);
        assert_eq!(proof.identity_for_core_oid("pg_type", 23), Some("23"));
        assert_eq!(proof.identity_for_runtime_oid("pg_type", 23), Some("23"));
        assert_eq!(proof.runtime_oid_for_identity("pg_type", "23"), Some(23));
        assert!(proof.row("pg_type", "23").is_some());

        let mut changed = raw_capture();
        changed["tables"]["pg_type"][0]["typname"] = Value::String("varchar".into());
        assert!(validated.validate_live(&changed, 18).is_err());

        let mut missing = raw_capture();
        missing["tables"]["pg_type"] = Value::Array(Vec::new());
        assert!(validated.validate_live(&missing, 18).is_err());

        assert!(validated.validate_live(&raw_capture(), 12).is_err());
    }

    #[test]
    fn v2_extension_subsets_are_explicit_and_match_live_membership_and_hashes() {
        for enabled in [
            &[][..],
            &["pg_trgm"][..],
            &["btree_gist"][..],
            &["btree_gist", "pg_trgm"][..],
        ] {
            let reviewed = load(&profile_v2(enabled)).unwrap();
            assert_eq!(
                reviewed.enabled_extensions(),
                enabled
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>()
            );
            let proof = reviewed
                .validate_live(&capture_for_enabled(enabled), 18)
                .unwrap_or_else(|error| panic!("enabled={enabled:?}: {error:?}"));
            assert_eq!(proof.major(), 18);
        }

        let mut missing_selector = profile_v2(&[]);
        missing_selector
            .as_object_mut()
            .unwrap()
            .remove("enabled_extensions");
        assert!(load(&missing_selector).is_err());

        let mut unselected_extension = profile_v2(&["pg_trgm"]);
        unselected_extension["extensions"]
            .as_array_mut()
            .unwrap()
            .push(extension("btree_gist", "1.8"));
        assert!(load(&unselected_extension).is_err());

        let mut unsorted = profile_v2(&["btree_gist", "pg_trgm"]);
        unsorted["enabled_extensions"] = serde_json::json!(["pg_trgm", "btree_gist"]);
        assert!(load(&unsorted).is_err());

        let reviewed = load(&profile_v2(&[])).unwrap();
        let mut unexpected_module = capture_for_enabled(&[]);
        unexpected_module["module_sha256"] = serde_json::json!([format!(
            "{TRGM_HASH}  /usr/lib/postgresql/18/lib/pg_trgm.so"
        )]);
        assert!(reviewed.validate_live(&unexpected_module, 18).is_err());
    }

    #[test]
    fn runtime_capture_requires_version_provenance_and_bounded_shape() {
        let validated = load(&profile()).unwrap();
        let mut missing_version = raw_capture();
        missing_version
            .as_object_mut()
            .unwrap()
            .remove("server_version");
        assert!(validated.validate_live(&missing_version, 18).is_err());

        let mut oversized = raw_capture();
        oversized["tables"]["pg_namespace"][0]["unexpected"] =
            Value::String("x".repeat(MAX_STRING_BYTES + 1));
        assert!(validated.validate_live(&oversized, 18).is_err());
    }

    #[test]
    fn function_source_is_compared_by_exact_sha256_marker_without_exporting_plaintext() {
        let mut unredacted_profile = profile_with_proc_fingerprint();
        unredacted_profile["catalog"]["pg_proc"][0]["fields"]["prosrc"] =
            Value::String("SELECT 1".into());
        assert!(load(&unredacted_profile).is_err());

        let validated = load(&profile_with_proc_fingerprint()).unwrap();
        let normalized = normalize_capture(
            &validated,
            &raw_capture_with_proc_source(Value::String("SELECT 1".into())),
        )
        .unwrap();
        assert_eq!(
            normalized.document["catalog"]["pg_proc"][0]["fields"]["prosrc"],
            serde_json::json!({"sha256_utf8":expected(b"SELECT 1")})
        );
        assert!(normalized.document["catalog"]["pg_proc"][0]["fields"]["prosqlbody"].is_null());
        assert!(
            normalize_capture(
                &validated,
                &raw_capture_with_proc_source(
                    serde_json::json!({"sha256_utf8":"bad","extra":true})
                ),
            )
            .is_err()
        );
        assert!(
            normalize_capture(
                &validated,
                &raw_capture_with_proc_source(serde_json::json!({"sha256_utf8":"A".repeat(64)})),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_added_extension_members_and_module_hash_claims() {
        let reference = profile();
        let validated = load(&reference).unwrap();
        let mut extra_member = raw_capture();
        extra_member["tables"]["pg_type"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "oid":"90001","typname":"new_type","typnamespace":"2200","typelem":"0"
            }));
        extra_member["extension_members"] = serde_json::json!([
            {"extname":"pg_trgm","catalog":"pg_type","objid":"90001","objsubid":0}
        ]);
        assert!(validated.validate_live(&extra_member, 18).is_err());

        let mut tampered_hash = raw_capture();
        tampered_hash["module_sha256"][0] = Value::String(format!(
            "{}  /usr/lib/postgresql/18/lib/pg_trgm.so",
            "d".repeat(64)
        ));
        assert!(validated.validate_live(&tampered_hash, 18).is_err());
    }

    #[test]
    fn maps_runtime_extension_oids_only_after_complete_membership_matches() {
        let reference = profile_with_extension_type();
        let validated = load(&reference).unwrap();
        assert_eq!(validated.extension_member_identities("pg_trgm"), [EXT_TYPE]);
        let proof = validated
            .validate_live(&raw_capture_with_extension_type(), 18)
            .unwrap();
        assert!(proof.has_extension_identity("pg_trgm", EXT_TYPE));
        assert_eq!(
            proof.identity_for_runtime_oid("pg_type", 90000),
            Some(EXT_TYPE)
        );
        assert_eq!(
            proof.runtime_oid_for_identity("pg_type", EXT_TYPE),
            Some(90000)
        );
        assert_eq!(
            proof.row("pg_type", EXT_TYPE).unwrap()["fields"]["typname"],
            "ext_type"
        );
    }

    #[test]
    fn dynamic_runtime_enum_rows_do_not_become_static_permissions() {
        let validated = load(&profile()).unwrap();
        let mut runtime = raw_capture();
        runtime["tables"]["pg_enum"] = serde_json::json!([
            {"oid":"90002","enumtypid":"90000","enumlabel":"safe","enumsortorder":1.0}
        ]);
        let proof = validated.validate_live(&runtime, 18).unwrap();
        assert!(
            !proof.has_extension_identity(
                "pg_trgm",
                "$extension:pg_trgm:pg_enum:public.dynamic_enum"
            )
        );
    }

    #[test]
    fn profile_rows_require_numeric_core_identity_and_exact_oid_fields() {
        let mut malformed = profile();
        malformed["catalog"]["pg_type"][0]["identity"] = serde_json::json!(true);
        assert!(load(&malformed).is_err());
        let mut mismatch = profile();
        mismatch["catalog"]["pg_type"][0]["fields"]["oid"] = serde_json::json!(25);
        assert!(load(&mismatch).is_err());
        let mut unsorted = profile();
        unsorted["catalog"]["pg_type"] = serde_json::json!([
            {"identity":25,"fields":{"oid":25}}, {"identity":23,"fields":{"oid":23}}
        ]);
        assert!(load(&unsorted).is_err());

        let mut bad_range = profile();
        bad_range["catalog"]["pg_range"] =
            serde_json::json!([{"identity":23,"fields":{"rngtypid":25}}]);
        assert!(load(&bad_range).is_err());
    }
}
