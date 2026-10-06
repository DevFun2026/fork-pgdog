use serde::Deserialize;
use std::collections::HashSet;

use super::PolicyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManifestDigest(pub(crate) [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadManifest {
    schema_revision: String,
    databases: Vec<DatabaseManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DatabaseManifest {
    name: String,
    relations: Vec<QualifiedName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct QualifiedName {
    schema: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    schema_revision: String,
    databases: Vec<RawDatabase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDatabase {
    name: String,
    relations: Vec<String>,
}

impl ReadManifest {
    /// Parse policy data as data only. Identifier strings are never passed to a SQL parser.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, PolicyError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| PolicyError::manifest("manifest_invalid_utf8"))?;
        let raw: RawManifest =
            toml::from_str(text).map_err(|_| PolicyError::manifest("manifest_invalid_toml"))?;
        if raw.schema_revision.trim().is_empty()
            || raw.schema_revision.trim() != raw.schema_revision
            || raw.schema_revision.chars().count() > 128
            || raw.schema_revision.chars().any(char::is_control)
        {
            return Err(PolicyError::manifest("manifest_blank_schema_revision"));
        }
        if raw.databases.is_empty() {
            return Err(PolicyError::manifest("manifest_empty_databases"));
        }

        let mut aliases = HashSet::new();
        let mut databases = Vec::with_capacity(raw.databases.len());
        for db in raw.databases {
            let alias_parts = parse_identifier(&db.name)?;
            if alias_parts.len() != 1 {
                return Err(PolicyError::manifest("manifest_invalid_database_alias"));
            }
            let name = alias_parts.into_iter().next().expect("length checked");
            if !aliases.insert(name.clone()) {
                return Err(PolicyError::manifest("manifest_duplicate_database"));
            }
            if db.relations.is_empty() {
                return Err(PolicyError::manifest("manifest_empty_relations"));
            }
            let mut relations = HashSet::new();
            let mut parsed_relations = Vec::with_capacity(db.relations.len());
            for relation in db.relations {
                let mut parts = parse_identifier(&relation)?;
                if parts.len() != 2 {
                    return Err(PolicyError::manifest("manifest_relation_must_be_qualified"));
                }
                let relation = QualifiedName {
                    schema: parts.remove(0),
                    name: parts.remove(0),
                };
                if !relations.insert(relation.clone()) {
                    return Err(PolicyError::manifest("manifest_duplicate_relation"));
                }
                parsed_relations.push(relation);
            }
            databases.push(DatabaseManifest {
                name,
                relations: parsed_relations,
            });
        }
        Ok(Self {
            schema_revision: raw.schema_revision,
            databases,
        })
    }

    pub(crate) fn schema_revision(&self) -> &str {
        &self.schema_revision
    }

    pub(crate) fn databases(&self) -> &[DatabaseManifest] {
        &self.databases
    }
}

impl DatabaseManifest {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn relations(&self) -> &[QualifiedName] {
        &self.relations
    }
}

impl QualifiedName {
    pub(crate) fn schema(&self) -> &str {
        &self.schema
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

/// Parse a one- or two-part PostgreSQL identifier, including SQL double-quoted
/// identifier escaping. Wildcards, whitespace outside quotes, and SQL syntax fail.
fn parse_identifier(input: &str) -> Result<Vec<String>, PolicyError> {
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut parts = Vec::new();
    while i < bytes.len() {
        let part = if bytes[i] == b'"' {
            i += 1;
            let mut value = String::new();
            let mut closed = false;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' if bytes.get(i + 1) == Some(&b'"') => {
                        value.push('"');
                        i += 2;
                    }
                    b'"' => {
                        i += 1;
                        closed = true;
                        break;
                    }
                    _ => {
                        let ch = input[i..].chars().next().ok_or_else(invalid_identifier)?;
                        value.push(ch);
                        i += ch.len_utf8();
                    }
                }
            }
            if !closed || value.is_empty() || value == "*" || value.chars().any(char::is_control) {
                return Err(invalid_identifier());
            }
            value
        } else {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
            {
                i += 1;
            }
            if start == i || !((bytes[start].is_ascii_alphabetic()) || bytes[start] == b'_') {
                return Err(invalid_identifier());
            }
            input[start..i].to_ascii_lowercase()
        };
        // PostgreSQL stores at most NAMEDATALEN - 1 bytes (64 by default).
        // Reject longer manifest identities instead of silently matching a
        // server-truncated name to a different configured object.
        if part.len() > 63 {
            return Err(invalid_identifier());
        }
        parts.push(part);
        if i == bytes.len() {
            break;
        }
        if bytes[i] != b'.' || parts.len() == 2 {
            return Err(invalid_identifier());
        }
        i += 1;
        if i == bytes.len() {
            return Err(invalid_identifier());
        }
    }
    if parts.is_empty() {
        return Err(invalid_identifier());
    }
    Ok(parts)
}

fn invalid_identifier() -> PolicyError {
    PolicyError::manifest("manifest_invalid_identifier")
}
