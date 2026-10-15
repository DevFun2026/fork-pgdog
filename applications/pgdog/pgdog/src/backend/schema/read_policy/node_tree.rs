//! Bounded parser for PostgreSQL's serialized expression trees (`pg_node_tree`).
//!
//! This module recognizes only a small, explicit set of expression node layouts.
//! It extracts identities; it does not decide whether any catalog object is safe.

use std::collections::BTreeSet;

pub(crate) const MAX_BYTES: usize = 256 * 1024;
pub(crate) const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 4096;
const MAX_LIST_ITEMS: usize = 1024;
const MAX_USER_ATTRIBUTE_NUMBER: i64 = 1600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExpressionKind {
    Check,
    IndexExpression,
    Predicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Context {
    pub(crate) relation_oid: u32,
    pub(crate) kind: ExpressionKind,
}

impl Context {
    pub(crate) fn check(relation_oid: u32) -> Self {
        Self {
            relation_oid,
            kind: ExpressionKind::Check,
        }
    }

    pub(crate) fn index(relation_oid: u32) -> Self {
        Self {
            relation_oid,
            kind: ExpressionKind::IndexExpression,
        }
    }

    pub(crate) fn predicate(relation_oid: u32) -> Self {
        Self {
            relation_oid,
            kind: ExpressionKind::Predicate,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Requirements {
    pub(crate) types: Vec<u32>,
    pub(crate) functions: Vec<u32>,
    pub(crate) operators: Vec<u32>,
    pub(crate) casts: Vec<CastRequirement>,
    pub(crate) collations: Vec<u32>,
    pub(crate) constants: Vec<ConstantRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CastRequirement {
    pub(crate) source_type: u32,
    pub(crate) target_type: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConstantRequirement {
    pub(crate) type_oid: u32,
    pub(crate) type_len: i32,
    pub(crate) by_value: bool,
    pub(crate) is_null: bool,
    /// Exact nodeToString datum bytes. Interpretation requires matching the
    /// type OID to the version-pinned catalog proof.
    pub(crate) bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VarRequirement {
    /// PostgreSQL's range-table index. Stored relation expressions must use 1.
    pub(crate) varno: u32,
    pub(crate) relation_oid: u32,
    /// Positive user attribute number. Whole-row and system attributes are denied.
    pub(crate) attno: i32,
    pub(crate) type_oid: u32,
    pub(crate) collation_oid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TreeProof {
    pub(crate) major: u32,
    pub(crate) relation_oid: u32,
    pub(crate) kind: ExpressionKind,
    pub(crate) root_type: Option<u32>,
    pub(crate) requirements: Requirements,
    pub(crate) vars: Vec<VarRequirement>,
    /// FUNCEXPR calls in child-first expression traversal order.
    pub(crate) function_calls: Vec<FunctionCall>,
    /// OPEXPR calls paired with their implementation function and exact input
    /// and result types, in child-first expression traversal order.
    pub(crate) operator_calls: Vec<OperatorCall>,
    /// SCALARARRAYOPEXPR calls paired with the scalar LHS type and RHS array
    /// type. The array's element type must be resolved by catalog proof.
    pub(crate) scalar_array_calls: Vec<ScalarArrayCall>,
    source_digest: [u8; 32],
    source_ordinal: usize,
    #[cfg(test)]
    root: Value,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ExpressionLineage {
    /// Runtime relation OIDs mapped to one stable source-to-synthetic identity.
    pub(crate) relations: std::collections::BTreeMap<u32, String>,
    /// Runtime `(relation OID, attribute number)` mapped to a stable column identity.
    pub(crate) columns: std::collections::BTreeMap<(u32, i32), String>,
    /// Runtime enum type OIDs mapped to a stable source-to-synthetic identity.
    pub(crate) enum_types: std::collections::BTreeMap<u32, String>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompareError {
    ProofMismatch,
    MissingLineage,
    MissingCatalogIdentity,
    InvalidRegconfig,
    InvalidTree,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalExpression {
    kind: ExpressionKind,
    ordinal: usize,
    relation: String,
    root: Value,
    digest: [u8; 32],
}

#[cfg(test)]
impl CanonicalExpression {
    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[cfg(test)]
pub(crate) fn canonical_expression(
    tree: &TreeProof,
    proof: &super::expression_proof::ExpressionProof,
    dependencies: &super::dependency_profile::DependencyProof,
    lineage: &ExpressionLineage,
    regconfig_identity: Option<&str>,
) -> Result<CanonicalExpression, CompareError> {
    if !matches!(tree.major, 12 | 18)
        || tree.major != dependencies.major()
        || tree.source_digest() != proof.source_digest()
        || tree.source_ordinal() != proof.source_ordinal()
        || tree.relation_oid != proof.relation_oid()
        || tree.kind != proof.kind()
        || tree.root_type != Some(proof.root_type())
        || !proof.matches_dependencies(dependencies)
        || tree.vars.len() > MAX_NODES
        || lineage.relations.len() > MAX_NODES
        || lineage.columns.len() > MAX_NODES
        || lineage.enum_types.len() > MAX_NODES
    {
        return Err(CompareError::ProofMismatch);
    }
    let relation = lineage
        .relations
        .get(&tree.relation_oid)
        .filter(|identity| valid_lineage_identity(identity))
        .cloned()
        .ok_or(CompareError::MissingLineage)?;

    let regconfig_oid = proof.regconfig_oid();
    let regconfig_constants = tree
        .requirements
        .constants
        .iter()
        .filter(|constant| constant.type_oid == 3734)
        .count();
    if regconfig_constants != usize::from(regconfig_oid.is_some()) {
        return Err(CompareError::InvalidRegconfig);
    }
    match (regconfig_oid, regconfig_identity) {
        (Some(oid), Some(identity))
            if valid_lineage_identity(identity)
                && dependencies.identity_for_runtime_oid("pg_ts_config", oid) == Some(identity)
                && dependencies.runtime_oid_for_identity("pg_ts_config", identity) == Some(oid) => {
        }
        (None, None) => {}
        _ => return Err(CompareError::InvalidRegconfig),
    }
    for identity in lineage.enum_types.values() {
        if !valid_lineage_identity(identity) {
            return Err(CompareError::MissingLineage);
        }
    }

    for var in &tree.vars {
        if var.relation_oid != tree.relation_oid
            || !lineage
                .columns
                .get(&(var.relation_oid, var.attno))
                .is_some_and(|identity| valid_lineage_identity(identity))
        {
            return Err(CompareError::MissingLineage);
        }
    }
    let root_type = tree.root_type.ok_or(CompareError::InvalidTree)?;
    canonical_oid("pg_type", root_type, proof, dependencies, lineage)?;
    let root = canonicalize_value(
        &tree.root,
        tree.major,
        tree,
        proof,
        dependencies,
        lineage,
        regconfig_identity,
    )?;
    let mut encoder = CanonicalEncoder::default();
    encoder.tag(b"pgdog.canonical-expression.v1");
    encoder.tag(match tree.kind {
        ExpressionKind::Check => b"check",
        ExpressionKind::IndexExpression => b"index-expression",
        ExpressionKind::Predicate => b"predicate",
    });
    encoder.u64(tree.source_ordinal as u64);
    encoder.string(&relation);
    encoder.value(&root);
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &encoder.bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 digest length is fixed");
    Ok(CanonicalExpression {
        kind: tree.kind,
        ordinal: tree.source_ordinal,
        relation,
        root,
        digest,
    })
}

#[cfg(test)]
fn canonicalize_value(
    value: &Value,
    major: u32,
    tree: &TreeProof,
    proof: &super::expression_proof::ExpressionProof,
    dependencies: &super::dependency_profile::DependencyProof,
    lineage: &ExpressionLineage,
    regconfig_identity: Option<&str>,
) -> Result<Value, CompareError> {
    match value {
        Value::Atom(value) => Ok(Value::Atom(value.clone())),
        Value::Quoted(value) => Ok(Value::Quoted(value.clone())),
        Value::List(items) => Ok(Value::List(
            items
                .iter()
                .map(|item| {
                    canonicalize_value(
                        item,
                        major,
                        tree,
                        proof,
                        dependencies,
                        lineage,
                        regconfig_identity,
                    )
                })
                .collect::<Result<_, _>>()?,
        )),
        Value::Struct(tag, fields) => {
            let normalized_tag = match (major, tag.as_str()) {
                (18, "ARRAYEXPR") => "ARRAY".to_owned(),
                (18, "COALESCEEXPR") => "COALESCE".to_owned(),
                (12 | 18, _) => tag.clone(),
                _ => return Err(CompareError::InvalidTree),
            };
            let field = |name: &str| fields.iter().find(|(key, _)| key == name).map(|(_, v)| v);
            let is_regconfig_const = if normalized_tag == "CONST" {
                field("consttype")
                    .and_then(value_u32)
                    .filter(|oid| *oid == 3734)
                    .is_some()
            } else {
                false
            };
            let mut canonical_fields = Vec::with_capacity(fields.len());
            for (name, child) in fields {
                if name == "location" {
                    continue;
                }
                if normalized_tag == "VAR"
                    && matches!(
                        (major, name.as_str()),
                        (12, "varnoold" | "varoattno")
                            | (
                                18,
                                "varnullingrels" | "varreturningtype" | "varnosyn" | "varattnosyn"
                            )
                    )
                {
                    continue;
                }
                if normalized_tag == "ARRAY"
                    && major == 18
                    && matches!(name.as_str(), "list_start" | "list_end")
                {
                    if value_i64(child) != Some(-1) {
                        return Err(CompareError::InvalidTree);
                    }
                    continue;
                }
                if normalized_tag == "SCALARARRAYOPEXPR"
                    && major == 18
                    && matches!(name.as_str(), "hashfuncid" | "negfuncid")
                    && value_u32(child) == Some(0)
                {
                    continue;
                }
                let converted = if normalized_tag == "VAR" && name == "varattno" {
                    let attno = value_i64(child)
                        .and_then(|number| i32::try_from(number).ok())
                        .ok_or(CompareError::InvalidTree)?;
                    let identity = lineage
                        .columns
                        .get(&(tree.relation_oid, attno))
                        .filter(|identity| valid_lineage_identity(identity))
                        .ok_or(CompareError::MissingLineage)?;
                    Value::Quoted(format!("$column:{identity}"))
                } else if let Some(catalog) = oid_catalog(&normalized_tag, name) {
                    let oid = value_u32(child).ok_or(CompareError::InvalidTree)?;
                    canonical_oid(catalog, oid, proof, dependencies, lineage)?
                } else if normalized_tag == "CONST" && name == "constvalue" && is_regconfig_const {
                    let oid = proof
                        .regconfig_oid()
                        .ok_or(CompareError::InvalidRegconfig)?;
                    Value::Quoted(canonical_regconfig_datum(
                        fields,
                        oid,
                        regconfig_identity.ok_or(CompareError::InvalidRegconfig)?,
                    )?)
                } else {
                    canonicalize_value(
                        child,
                        major,
                        tree,
                        proof,
                        dependencies,
                        lineage,
                        regconfig_identity,
                    )?
                };
                canonical_fields.push((name.clone(), converted));
            }
            if normalized_tag == "VAR" {
                let attno = field("varattno")
                    .and_then(value_i64)
                    .and_then(|number| i32::try_from(number).ok())
                    .ok_or(CompareError::InvalidTree)?;
                if !lineage.columns.contains_key(&(tree.relation_oid, attno)) {
                    return Err(CompareError::MissingLineage);
                }
            }
            canonical_fields.sort_by(|left, right| left.0.cmp(&right.0));
            Ok(Value::Struct(normalized_tag, canonical_fields))
        }
    }
}

#[cfg(test)]
fn oid_catalog(node: &str, field: &str) -> Option<&'static str> {
    Some(match (node, field) {
        ("VAR", "vartype")
        | ("CONST", "consttype")
        | ("OPEXPR", "opresulttype")
        | ("FUNCEXPR", "funcresulttype")
        | ("COALESCE", "coalescetype")
        | ("ARRAY", "array_typeid" | "element_typeid")
        | ("RELABELTYPE", "resulttype") => "pg_type",
        ("VAR", "varcollid")
        | ("CONST", "constcollid")
        | ("OPEXPR", "opcollid" | "inputcollid")
        | ("SCALARARRAYOPEXPR", "inputcollid")
        | ("FUNCEXPR", "funccollid" | "inputcollid")
        | ("COALESCE", "coalescecollid")
        | ("ARRAY", "array_collid")
        | ("RELABELTYPE", "resultcollid") => "pg_collation",
        ("OPEXPR" | "SCALARARRAYOPEXPR", "opno") => "pg_operator",
        ("OPEXPR" | "SCALARARRAYOPEXPR", "opfuncid")
        | ("FUNCEXPR", "funcid")
        | ("SCALARARRAYOPEXPR", "hashfuncid" | "negfuncid") => "pg_proc",
        _ => return None,
    })
}

#[cfg(test)]
fn canonical_oid(
    catalog: &str,
    oid: u32,
    proof: &super::expression_proof::ExpressionProof,
    dependencies: &super::dependency_profile::DependencyProof,
    lineage: &ExpressionLineage,
) -> Result<Value, CompareError> {
    if oid == 0 {
        return Ok(Value::Atom("0".to_owned()));
    }
    if catalog == "pg_type"
        && let Some(identity) = lineage.enum_types.get(&oid)
    {
        if !valid_lineage_identity(identity) || !proof.enum_digests().contains_key(&oid) {
            return Err(CompareError::MissingLineage);
        }
        return Ok(Value::Quoted(format!("$enum:{identity}")));
    }
    let identity = dependencies
        .identity_for_runtime_oid(catalog, oid)
        .ok_or(CompareError::MissingCatalogIdentity)?;
    Ok(Value::Quoted(format!("${catalog}:{identity}")))
}

#[cfg(test)]
fn canonical_regconfig_datum(
    fields: &[(String, Value)],
    expected_oid: u32,
    identity: &str,
) -> Result<String, CompareError> {
    let field = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    };
    if field("constlen").and_then(value_i64) != Some(4)
        || field("constbyval").and_then(value_bool) != Some(true)
        || field("constisnull").and_then(value_bool) != Some(false)
        || !valid_lineage_identity(identity)
    {
        return Err(CompareError::InvalidRegconfig);
    }
    let Some(Value::List(pair)) = field("constvalue") else {
        return Err(CompareError::InvalidRegconfig);
    };
    if pair.len() != 2 || value_i64(&pair[0]) != Some(4) {
        return Err(CompareError::InvalidRegconfig);
    }
    let Value::List(bytes) = &pair[1] else {
        return Err(CompareError::InvalidRegconfig);
    };
    if bytes.len() != 8 {
        return Err(CompareError::InvalidRegconfig);
    }
    let bytes = bytes
        .iter()
        .map(|value| value_u32(value).and_then(|n| u8::try_from(n).ok()))
        .collect::<Option<Vec<_>>>()
        .ok_or(CompareError::InvalidRegconfig)?;
    let little = u32::from_le_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| CompareError::InvalidRegconfig)?,
    );
    let big = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| CompareError::InvalidRegconfig)?,
    );
    if (little != expected_oid && big != expected_oid) || bytes[4..] != [0, 0, 0, 0] {
        return Err(CompareError::InvalidRegconfig);
    }
    Ok(format!("$regconfig:{identity}"))
}

#[cfg(test)]
fn valid_lineage_identity(identity: &str) -> bool {
    !identity.is_empty() && identity.len() <= 256 && !identity.as_bytes().contains(&0)
}

#[cfg(test)]
fn value_u32(value: &Value) -> Option<u32> {
    match value {
        Value::Atom(value) => value.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
fn value_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Atom(value) => value.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
fn value_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Atom(value) if value == "true" => Some(true),
        Value::Atom(value) if value == "false" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
#[derive(Default)]
struct CanonicalEncoder {
    bytes: Vec<u8>,
}

#[cfg(test)]
impl CanonicalEncoder {
    fn tag(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    fn string(&mut self, value: &str) {
        self.tag(value.as_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn value(&mut self, value: &Value) {
        match value {
            Value::Atom(value) => {
                self.tag(b"atom");
                self.string(value);
            }
            Value::Quoted(value) => {
                self.tag(b"quoted");
                self.string(value);
            }
            Value::List(items) => {
                self.tag(b"list");
                self.u64(items.len() as u64);
                for item in items {
                    self.value(item);
                }
            }
            Value::Struct(tag, fields) => {
                self.tag(b"struct");
                self.string(tag);
                self.u64(fields.len() as u64);
                for (key, value) in fields {
                    self.string(key);
                    self.value(value);
                }
            }
        }
    }
}

impl TreeProof {
    pub(crate) fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }

    pub(crate) fn source_ordinal(&self) -> usize {
        self.source_ordinal
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FunctionCall {
    pub(crate) funcid: u32,
    pub(crate) format: u32,
    pub(crate) argument_types: Vec<u32>,
    pub(crate) result_type: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OperatorCall {
    pub(crate) opno: u32,
    pub(crate) opfuncid: u32,
    pub(crate) argument_types: [u32; 2],
    pub(crate) result_type: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScalarArrayCall {
    pub(crate) opno: u32,
    pub(crate) opfuncid: u32,
    pub(crate) left_type: u32,
    pub(crate) array_type: u32,
    pub(crate) result_type: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Atom(String),
    Quoted(String),
    List(Vec<Value>),
    Struct(String, Vec<(String, Value)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Open(char),
    Close(char),
    Colon,
    Atom(String),
    Quoted(String),
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    nodes: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Result<Self, Error> {
        if input.is_empty() || input.len() > MAX_BYTES || !input.is_ascii() {
            return Err(Error);
        }
        Ok(Self {
            input: input.as_bytes(),
            pos: 0,
            nodes: 0,
        })
    }

    fn whitespace(&mut self) {
        while self.pos < self.input.len() && self.input[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn token(&mut self) -> Result<Option<Token>, Error> {
        self.whitespace();
        let Some(&byte) = self.input.get(self.pos) else {
            return Ok(None);
        };
        self.pos += 1;
        Ok(Some(match byte {
            b'(' | b'{' | b'[' => Token::Open(byte as char),
            b')' | b'}' | b']' => Token::Close(byte as char),
            b':' => Token::Colon,
            b'"' => Token::Quoted(self.quoted()?),
            b if b.is_ascii_graphic() => {
                let start = self.pos - 1;
                while self.pos < self.input.len()
                    && !self.input[self.pos].is_ascii_whitespace()
                    && !matches!(
                        self.input[self.pos],
                        b'(' | b')' | b'{' | b'}' | b'[' | b']' | b':' | b'"'
                    )
                {
                    self.pos += 1;
                }
                Token::Atom(
                    std::str::from_utf8(&self.input[start..self.pos])
                        .map_err(|_| Error)?
                        .to_owned(),
                )
            }
            _ => return Err(Error),
        }))
    }

    fn quoted(&mut self) -> Result<String, Error> {
        let mut out = Vec::new();
        loop {
            let byte = *self.input.get(self.pos).ok_or(Error)?;
            self.pos += 1;
            match byte {
                b'"' => return String::from_utf8(out).map_err(|_| Error),
                b'\\' => {
                    let escaped = *self.input.get(self.pos).ok_or(Error)?;
                    self.pos += 1;
                    match escaped {
                        b'\\' | b'"' => out.push(escaped),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        _ => return Err(Error),
                    }
                }
                b if b.is_ascii() && !b.is_ascii_control() => out.push(b),
                _ => return Err(Error),
            }
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error);
        }
        let token = self.token()?.ok_or(Error)?;
        match token {
            Token::Atom(atom) => Ok(Value::Atom(atom)),
            Token::Quoted(value) => Ok(Value::Quoted(value)),
            Token::Open('(') => self.sequence(depth, ')'),
            Token::Open('[') => self.sequence(depth, ']'),
            Token::Open('{') => self.structure(depth),
            _ => Err(Error),
        }
    }

    fn sequence(&mut self, depth: usize, close: char) -> Result<Value, Error> {
        let mut items = Vec::new();
        loop {
            let save = self.pos;
            let token = self.token()?.ok_or(Error)?;
            if token == Token::Close(close) {
                return Ok(Value::List(items));
            }
            self.pos = save;
            if items.len() >= MAX_LIST_ITEMS {
                return Err(Error);
            }
            items.push(self.value(depth + 1)?);
        }
    }

    fn structure(&mut self, depth: usize) -> Result<Value, Error> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(Error);
        }
        let name = match self.token()?.ok_or(Error)? {
            Token::Atom(name) if !name.is_empty() => name,
            _ => return Err(Error),
        };
        let mut fields = Vec::new();
        loop {
            let save = self.pos;
            let token = self.token()?.ok_or(Error)?;
            if token == Token::Close('}') {
                return Ok(Value::Struct(name, fields));
            }
            if token != Token::Colon {
                return Err(Error);
            }
            let key = match self.token()?.ok_or(Error)? {
                Token::Atom(key) if !key.is_empty() => key,
                _ => return Err(Error),
            };
            if fields.iter().any(|(seen, _)| seen == &key) {
                return Err(Error);
            }
            if fields.len() >= 64 {
                return Err(Error);
            }
            let value = self.value(depth + 1)?;
            // nodeToString writes Const's byte count and payload as a pair after
            // the single `constvalue` field label.
            let value = if name == "CONST" && key == "constvalue" {
                if matches!(&value, Value::Atom(s) if s == "<>") {
                    Value::List(vec![Value::Atom("-1".into()), value])
                } else {
                    Value::List(vec![value, self.value(depth + 1)?])
                }
            } else {
                value
            };
            fields.push((key, value));
            if self.pos <= save {
                return Err(Error);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn parse_and_extract(
    input: &str,
    major: u32,
    context: Context,
) -> Result<TreeProof, Error> {
    let mut proofs = parse_and_extract_all(input, major, context)?;
    if proofs.len() != 1 {
        return Err(Error);
    }
    proofs.pop().ok_or(Error)
}

/// Parse a stored index-expression list and return a proof for each key in
/// order. A bare node is treated as a one-expression list.
pub(crate) fn parse_and_extract_all(
    input: &str,
    major: u32,
    context: Context,
) -> Result<Vec<TreeProof>, Error> {
    if !matches!(major, 12 | 18) || context.relation_oid == 0 {
        return Err(Error);
    }
    let mut parser = Parser::new(input)?;
    let source_digest = source_digest(input);
    let root = parser.value(0)?;
    if parser.token()?.is_some() {
        return Err(Error);
    }
    let roots = match root {
        Value::Struct(_, _) => vec![root],
        Value::List(items) => items,
        _ => return Err(Error),
    };
    if roots.len() > MAX_LIST_ITEMS || roots.is_empty() {
        return Err(Error);
    }
    if matches!(
        context.kind,
        ExpressionKind::Check | ExpressionKind::Predicate
    ) && roots.len() != 1
    {
        return Err(Error);
    }
    roots
        .into_iter()
        .enumerate()
        .map(|(source_ordinal, root)| {
            let mut extractor = Extractor {
                major,
                context,
                requirements: Requirements::default(),
                vars: Vec::new(),
                function_calls: Vec::new(),
                operator_calls: Vec::new(),
                scalar_array_calls: Vec::new(),
            };
            let root_type = extractor.expression(&root)?;
            if matches!(
                context.kind,
                ExpressionKind::Check | ExpressionKind::Predicate
            ) && root_type != Some(16)
            {
                return Err(Error);
            }
            let requirements = extractor.finish();
            Ok(TreeProof {
                major,
                relation_oid: context.relation_oid,
                kind: context.kind,
                root_type,
                requirements,
                vars: extractor.vars,
                function_calls: extractor.function_calls,
                operator_calls: extractor.operator_calls,
                scalar_array_calls: extractor.scalar_array_calls,
                source_digest,
                source_ordinal,
                #[cfg(test)]
                root,
            })
        })
        .collect()
}

fn source_digest(input: &str) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, input.as_bytes());
    let mut output = [0; 32];
    output.copy_from_slice(digest.as_ref());
    output
}

struct Extractor {
    major: u32,
    context: Context,
    requirements: Requirements,
    vars: Vec<VarRequirement>,
    function_calls: Vec<FunctionCall>,
    operator_calls: Vec<OperatorCall>,
    scalar_array_calls: Vec<ScalarArrayCall>,
}

impl Extractor {
    fn finish(&mut self) -> Requirements {
        for values in [
            &mut self.requirements.types,
            &mut self.requirements.functions,
            &mut self.requirements.operators,
            &mut self.requirements.collations,
        ] {
            *values = values
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
        }
        self.requirements.casts.sort();
        self.requirements.casts.dedup();
        self.requirements.constants.sort();
        self.requirements.constants.dedup();
        self.vars.sort_by_key(|v| {
            (
                v.relation_oid,
                v.varno,
                v.attno,
                v.type_oid,
                v.collation_oid,
            )
        });
        self.vars.dedup();
        std::mem::take(&mut self.requirements)
    }

    fn expression(&mut self, value: &Value) -> Result<Option<u32>, Error> {
        let Value::Struct(name, fields) = value else {
            return Err(Error);
        };
        let schema = schema(self.major, name).ok_or(Error)?;
        if fields.len() != schema.len()
            || fields
                .iter()
                .any(|(field, _)| !schema.contains(&field.as_str()))
        {
            return Err(Error);
        }
        for required in schema {
            if !fields.iter().any(|(field, _)| field == required) {
                return Err(Error);
            }
        }
        for (field, value) in fields {
            match field.as_str() {
                "args" | "elements" | "arg" | "varnullingrels" => {}
                "boolop" => {
                    atom_string(value)?;
                }
                "constvalue" => {
                    if !matches!(value, Value::List(pair) if pair.len() == 2) {
                        return Err(Error);
                    }
                }
                "constbyval" | "constisnull" | "funcvariadic" | "funcretset" | "opretset"
                | "argisrow" | "useOr" | "multidims" => {
                    atom_bool(value)?;
                }
                _ => {
                    atom_i64(value)?;
                }
            }
        }
        let f = |name: &str| {
            fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value)
                .ok_or(Error)
        };
        let oid = |name: &str| -> Result<u32, Error> {
            let value = atom_i64(f(name)?)?;
            if !(0..=u32::MAX as i64).contains(&value) {
                return Err(Error);
            }
            let value = value as u32;
            Ok(value)
        };
        match name.as_str() {
            "VAR" => {
                let varno = atom_u32(f("varno")?)?;
                let attno = atom_i64(f("varattno")?)?;
                let typ = oid("vartype")?;
                self.requirements.types.push(typ);
                let coll = oid("varcollid")?;
                if coll != 0 {
                    self.requirements.collations.push(coll)
                }
                if varno != 1
                    || atom_i64(f("varlevelsup")?)? != 0
                    || !(1..=MAX_USER_ATTRIBUTE_NUMBER).contains(&attno)
                    || typ == 0
                {
                    return Err(Error);
                }
                if self.major == 12 {
                    if atom_u32(f("varnoold")?)? != varno || atom_i64(f("varoattno")?)? != attno {
                        return Err(Error);
                    }
                } else {
                    if atom_u32(f("varnosyn")?)? != varno || atom_i64(f("varattnosyn")?)? != attno {
                        return Err(Error);
                    }
                    if !matches!(f("varnullingrels")?, Value::List(v) if v.as_slice() == [Value::Atom("b".into())])
                        || atom_u32(f("varreturningtype")?)? != 0
                    {
                        return Err(Error);
                    }
                }
                self.vars.push(VarRequirement {
                    varno,
                    relation_oid: self.context.relation_oid,
                    attno: i32::try_from(attno).map_err(|_| Error)?,
                    type_oid: typ,
                    collation_oid: coll,
                });
                Ok(Some(typ))
            }
            "CONST" => {
                let typ = oid("consttype")?;
                self.requirements.types.push(typ);
                let coll = oid("constcollid")?;
                if coll != 0 {
                    self.requirements.collations.push(coll)
                }
                if typ == 0 {
                    return Err(Error);
                }
                let len = atom_i64(f("constlen")?)?;
                let byval = atom_bool(f("constbyval")?)?;
                let isnull = atom_bool(f("constisnull")?)?;
                let Value::List(pair) = f("constvalue")? else {
                    return Err(Error);
                };
                if pair.len() != 2 {
                    return Err(Error);
                }
                let bytes = atom_i64(&pair[0])?;
                let payload = &pair[1];
                let mut constant_bytes = Vec::new();
                if isnull {
                    if !matches!(payload, Value::Atom(s) if s == "<>") || bytes != -1 {
                        return Err(Error);
                    }
                    if len == 0 || len < -1 || (byval && !matches!(len, 1 | 2 | 4 | 8)) {
                        return Err(Error);
                    }
                } else {
                    let Value::List(values) = payload else {
                        return Err(Error);
                    };
                    let expected_payload = if byval {
                        8
                    } else {
                        usize::try_from(bytes).map_err(|_| Error)?
                    };
                    if bytes < 0
                        || values.len() != expected_payload
                        || values
                            .iter()
                            .any(|v| !matches!(v, Value::Atom(s) if s.parse::<u8>().is_ok()))
                    {
                        return Err(Error);
                    }
                    if byval && !matches!(len, 1 | 2 | 4 | 8) {
                        return Err(Error);
                    }
                    if len >= 0 && !byval && len != bytes {
                        return Err(Error);
                    }
                    if len >= 0 && byval && len != bytes {
                        return Err(Error);
                    }
                    constant_bytes = values
                        .iter()
                        .map(|v| {
                            let Value::Atom(byte) = v else {
                                return Err(Error);
                            };
                            byte.parse::<u8>().map_err(|_| Error)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    if len == 0 || len < -1 || (len == -1 && byval) {
                        return Err(Error);
                    }
                }
                if coll != 0 {
                    self.requirements.collations.push(coll)
                }
                self.requirements.constants.push(ConstantRequirement {
                    type_oid: typ,
                    type_len: i32::try_from(len).map_err(|_| Error)?,
                    by_value: byval,
                    is_null: isnull,
                    bytes: constant_bytes,
                });
                Ok(Some(typ))
            }
            "BOOLEXPR" => {
                self.requirements.types.push(16);
                let op = atom_string(f("boolop")?)?;
                let Value::List(args) = f("args")? else {
                    return Err(Error);
                };
                if args.is_empty()
                    || args.len() > MAX_LIST_ITEMS
                    || !matches!(op.as_str(), "and" | "or" | "not")
                    || (op == "not" && args.len() != 1)
                {
                    return Err(Error);
                }
                for arg in args {
                    if self.expression(arg)? != Some(16) {
                        return Err(Error);
                    }
                }
                Ok(Some(16))
            }
            "NULLTEST" => {
                self.requirements.types.push(16);
                if atom_i64(f("nulltesttype")?)? < 0
                    || atom_i64(f("nulltesttype")?)? > 1
                    || atom_bool(f("argisrow")?)?
                {
                    return Err(Error);
                }
                self.expression(f("arg")?)?;
                Ok(Some(16))
            }
            "OPEXPR" => {
                let opno = atom_u32(f("opno")?)?;
                let func = atom_u32(f("opfuncid")?)?;
                let result = oid("opresulttype")?;
                self.requirements.types.push(result);
                let coll = oid("opcollid")?;
                let input_coll = oid("inputcollid")?;
                if opno == 0 || func == 0 || result == 0 || atom_bool(f("opretset")?)? {
                    return Err(Error);
                }
                self.requirements.operators.push(opno);
                self.requirements.functions.push(func);
                if coll != 0 {
                    self.requirements.collations.push(coll)
                }
                if input_coll != 0 {
                    self.requirements.collations.push(input_coll)
                }
                let Value::List(args) = f("args")? else {
                    return Err(Error);
                };
                if args.len() != 2 {
                    return Err(Error);
                }
                let mut argument_types = [0; 2];
                for (index, arg) in args.iter().enumerate() {
                    argument_types[index] = self.expression(arg)?.ok_or(Error)?;
                }
                self.operator_calls.push(OperatorCall {
                    opno,
                    opfuncid: func,
                    argument_types,
                    result_type: result,
                });
                Ok(Some(result))
            }
            "SCALARARRAYOPEXPR" => {
                self.requirements.types.push(16);
                let opno = atom_u32(f("opno")?)?;
                let func = atom_u32(f("opfuncid")?)?;
                if opno == 0 || func == 0 {
                    return Err(Error);
                }
                self.requirements.operators.push(opno);
                self.requirements.functions.push(func);
                for key in ["hashfuncid", "negfuncid"] {
                    if self.major == 18 {
                        let id = atom_u32(f(key)?)?;
                        if id != 0 {
                            self.requirements.functions.push(id)
                        }
                    }
                }
                let coll = oid("inputcollid")?;
                if coll != 0 {
                    self.requirements.collations.push(coll)
                }
                atom_bool(f("useOr")?)?;
                let Value::List(args) = f("args")? else {
                    return Err(Error);
                };
                if args.len() != 2 {
                    return Err(Error);
                }
                let left_type = self.expression(&args[0])?.ok_or(Error)?;
                let array_type = self.expression(&args[1])?.ok_or(Error)?;
                self.scalar_array_calls.push(ScalarArrayCall {
                    opno,
                    opfuncid: func,
                    left_type,
                    array_type,
                    result_type: 16,
                });
                Ok(Some(16))
            }
            "FUNCEXPR" => {
                let func = atom_u32(f("funcid")?)?;
                let result = oid("funcresulttype")?;
                self.requirements.types.push(result);
                let format = atom_i64(f("funcformat")?)?;
                if func == 0
                    || result == 0
                    || atom_bool(f("funcretset")?)?
                    || atom_bool(f("funcvariadic")?)?
                    || !(0..=max_coercion_form(self.major)).contains(&format)
                {
                    return Err(Error);
                }
                self.requirements.functions.push(func);
                for key in ["funccollid", "inputcollid"] {
                    let id = oid(key)?;
                    if id != 0 {
                        self.requirements.collations.push(id)
                    }
                }
                let Value::List(args) = f("args")? else {
                    return Err(Error);
                };
                if args.len() > MAX_LIST_ITEMS {
                    return Err(Error);
                }
                let argument_types = args
                    .iter()
                    .map(|arg| self.expression(arg)?.ok_or(Error))
                    .collect::<Result<Vec<_>, _>>()?;
                self.function_calls.push(FunctionCall {
                    funcid: func,
                    format: u32::try_from(format).map_err(|_| Error)?,
                    argument_types,
                    result_type: result,
                });
                Ok(Some(result))
            }
            "COALESCE" | "COALESCEEXPR" => {
                let result = oid("coalescetype")?;
                self.requirements.types.push(result);
                if result == 0 {
                    return Err(Error);
                }
                let collation = oid("coalescecollid")?;
                if collation != 0 {
                    self.requirements.collations.push(collation);
                }
                let Value::List(args) = f("args")? else {
                    return Err(Error);
                };
                if args.len() < 2 || args.len() > MAX_LIST_ITEMS {
                    return Err(Error);
                }
                for arg in args {
                    if self.expression(arg)? != Some(result) {
                        return Err(Error);
                    }
                }
                Ok(Some(result))
            }
            "ARRAY" | "ARRAYEXPR" => {
                let array_type = oid("array_typeid")?;
                self.requirements.types.push(array_type);
                let coll = oid("array_collid")?;
                let element_type = oid("element_typeid")?;
                self.requirements.types.push(element_type);
                if array_type == 0 || element_type == 0 {
                    return Err(Error);
                }
                if self.major == 18
                    && (atom_i64(f("list_start")?)? != -1 || atom_i64(f("list_end")?)? != -1)
                {
                    return Err(Error);
                }
                let Value::List(elements) = f("elements")? else {
                    return Err(Error);
                };
                if elements.is_empty() || elements.len() > MAX_LIST_ITEMS {
                    return Err(Error);
                }
                for element in elements {
                    if self.expression(element)? != Some(element_type) {
                        return Err(Error);
                    }
                }
                if coll != 0 {
                    self.requirements.collations.push(coll)
                }
                atom_bool(f("multidims")?)?;
                Ok(Some(array_type))
            }
            "RELABELTYPE" => {
                let result = oid("resulttype")?;
                self.requirements.types.push(result);
                let coll = oid("resultcollid")?;
                if result == 0 {
                    return Err(Error);
                }
                if coll != 0 {
                    self.requirements.collations.push(coll)
                }
                let source = self.expression(f("arg")?)?.ok_or(Error)?;
                self.requirements.casts.push(CastRequirement {
                    source_type: source,
                    target_type: result,
                });
                if !(0..=max_coercion_form(self.major)).contains(&atom_i64(f("relabelformat")?)?) {
                    return Err(Error);
                }
                Ok(Some(result))
            }
            _ => Err(Error),
        }
    }
}

fn schema(major: u32, name: &str) -> Option<&'static [&'static str]> {
    Some(match (major, name) {
        (12, "VAR") => &[
            "varno",
            "varattno",
            "vartype",
            "vartypmod",
            "varcollid",
            "varlevelsup",
            "varnoold",
            "varoattno",
            "location",
        ],
        (18, "VAR") => &[
            "varno",
            "varattno",
            "vartype",
            "vartypmod",
            "varcollid",
            "varnullingrels",
            "varlevelsup",
            "varreturningtype",
            "varnosyn",
            "varattnosyn",
            "location",
        ],
        (12 | 18, "CONST") => &[
            "consttype",
            "consttypmod",
            "constcollid",
            "constlen",
            "constbyval",
            "constisnull",
            "location",
            "constvalue",
        ],
        (12 | 18, "BOOLEXPR") => &["boolop", "args", "location"],
        (12 | 18, "NULLTEST") => &["arg", "nulltesttype", "argisrow", "location"],
        (12 | 18, "OPEXPR") => &[
            "opno",
            "opfuncid",
            "opresulttype",
            "opretset",
            "opcollid",
            "inputcollid",
            "args",
            "location",
        ],
        (12, "SCALARARRAYOPEXPR") => &[
            "opno",
            "opfuncid",
            "useOr",
            "inputcollid",
            "args",
            "location",
        ],
        (18, "SCALARARRAYOPEXPR") => &[
            "opno",
            "opfuncid",
            "hashfuncid",
            "negfuncid",
            "useOr",
            "inputcollid",
            "args",
            "location",
        ],
        (12 | 18, "FUNCEXPR") => &[
            "funcid",
            "funcresulttype",
            "funcretset",
            "funcvariadic",
            "funcformat",
            "funccollid",
            "inputcollid",
            "args",
            "location",
        ],
        (12, "COALESCE") => &["coalescetype", "coalescecollid", "args", "location"],
        (18, "COALESCEEXPR") => &["coalescetype", "coalescecollid", "args", "location"],
        (12, "ARRAY") => &[
            "array_typeid",
            "array_collid",
            "element_typeid",
            "elements",
            "multidims",
            "location",
        ],
        (18, "ARRAYEXPR") => &[
            "array_typeid",
            "array_collid",
            "element_typeid",
            "elements",
            "multidims",
            "list_start",
            "list_end",
            "location",
        ],
        (12 | 18, "RELABELTYPE") => &[
            "arg",
            "resulttype",
            "resulttypmod",
            "resultcollid",
            "relabelformat",
            "location",
        ],
        _ => return None,
    })
}

fn max_coercion_form(major: u32) -> i64 {
    match major {
        12 => 2,
        18 => 3,
        _ => -1,
    }
}

fn atom_string(value: &Value) -> Result<String, Error> {
    match value {
        Value::Atom(s) | Value::Quoted(s) => Ok(s.clone()),
        _ => Err(Error),
    }
}
fn atom_i64(value: &Value) -> Result<i64, Error> {
    match value {
        Value::Atom(s) => s.parse().map_err(|_| Error),
        _ => Err(Error),
    }
}
fn atom_u32(value: &Value) -> Result<u32, Error> {
    let n = atom_i64(value)?;
    u32::try_from(n).map_err(|_| Error)
}
fn atom_bool(value: &Value) -> Result<bool, Error> {
    match value {
        Value::Atom(s) if s == "true" => Ok(true),
        Value::Atom(s) if s == "false" => Ok(false),
        _ => Err(Error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_pg12_check_operator_dependencies_and_same_relation_vars() {
        let tree = r#"{OPEXPR :opno 521 :opfuncid 147 :opresulttype 16 :opretset false :opcollid 0 :inputcollid 0 :args ({VAR :varno 1 :varattno 1 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnoold 1 :varoattno 1 :location 217} {CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location 222 :constvalue 4 [ 0 0 0 0 0 0 0 0 ]}) :location 220}"#;
        let proof = parse_and_extract(tree, 12, Context::check(17089)).unwrap();
        assert_eq!(proof.root_type, Some(16));
        assert_eq!(proof.requirements.operators, [521]);
        assert_eq!(proof.requirements.functions, [147]);
        assert_eq!(proof.requirements.types, [16, 23]);
        assert_eq!(
            proof.operator_calls,
            [OperatorCall {
                opno: 521,
                opfuncid: 147,
                argument_types: [23, 23],
                result_type: 16,
            }]
        );
        assert!(proof.function_calls.is_empty());
        assert_eq!(proof.vars[0].relation_oid, 17089);
        assert_eq!(proof.vars[0].attno, 1);
    }

    #[test]
    fn rejects_out_of_range_var_attnos_for_pg12_and_pg18() {
        for major in [12, 18] {
            for attno in [1601_i64, 65537, i64::MAX] {
                let legacy = if major == 12 {
                    format!(":varnoold 1 :varoattno {attno}")
                } else {
                    format!(
                        ":varnullingrels (b) :varreturningtype 0 :varnosyn 1 :varattnosyn {attno}"
                    )
                };
                let tree = format!(
                    "{{VAR :varno 1 :varattno {attno} :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 {legacy} :location -1}}"
                );
                assert!(
                    parse_and_extract(&tree, major, Context::index(17089)).is_err(),
                    "PG{major} accepted out-of-range Var attno {attno}"
                );
            }

            let legacy = if major == 12 {
                ":varnoold 1 :varoattno 1600"
            } else {
                ":varnullingrels (b) :varreturningtype 0 :varnosyn 1 :varattnosyn 1600"
            };
            let valid = format!(
                "{{VAR :varno 1 :varattno 1600 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 {legacy} :location -1}}"
            );
            let proof = parse_and_extract(&valid, major, Context::index(17089))
                .expect("attnum 1600 is valid structurally");
            assert_eq!(proof.vars[0].attno, 1600);
        }
    }

    #[test]
    fn extracts_pg12_scalar_array_types_and_pg12_coalesce() {
        let check = r#"{SCALARARRAYOPEXPR :opno 96 :opfuncid 65 :useOr true :inputcollid 0 :args ({VAR :varno 1 :varattno 1 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnoold 1 :varoattno 1 :location 92} {ARRAY :array_typeid 1007 :array_collid 0 :element_typeid 23 :elements ({CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location 107 :constvalue 4 [ 1 0 0 0 0 0 0 0 ]}) :multidims false :location 101}) :location 95}"#;
        let proof = parse_and_extract(check, 12, Context::check(17089)).unwrap();
        assert!(proof.requirements.types.contains(&1007));
        assert!(proof.requirements.types.contains(&23));
        assert_eq!(
            proof.scalar_array_calls,
            [ScalarArrayCall {
                opno: 96,
                opfuncid: 65,
                left_type: 23,
                array_type: 1007,
                result_type: 16,
            }]
        );

        let wrong_arity = r#"{SCALARARRAYOPEXPR :opno 96 :opfuncid 65 :useOr true :inputcollid 0 :args ({VAR :varno 1 :varattno 1 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnoold 1 :varoattno 1 :location 0}) :location 0}"#;
        assert!(parse_and_extract(wrong_arity, 12, Context::check(17089)).is_err());
        let no_operator_function = check.replace("opfuncid 65", "opfuncid 0");
        assert!(parse_and_extract(&no_operator_function, 12, Context::check(17089)).is_err());
        let unverified_function = check.replace("opfuncid 65", "opfuncid 99999");
        let extracted = parse_and_extract(&unverified_function, 12, Context::check(17089)).unwrap();
        assert_eq!(extracted.scalar_array_calls[0].opfuncid, 99999);

        let coalesce = r#"({COALESCE :coalescetype 25 :coalescecollid 100 :args ({VAR :varno 1 :varattno 2 :vartype 25 :vartypmod -1 :varcollid 100 :varlevelsup 0 :varnoold 1 :varoattno 2 :location 59} {CONST :consttype 25 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval false :constisnull false :location 64 :constvalue 5 [ 20 0 0 0 120 ]}) :location 50})"#;
        let proof = parse_and_extract(coalesce, 12, Context::index(17089)).unwrap();
        assert_eq!(proof.root_type, Some(25));
        assert_eq!(proof.requirements.collations, [100]);
    }

    #[test]
    fn parses_pg18_layout_and_rejects_wrong_root_for_predicate() {
        let predicate = r#"{OPEXPR :opno 91 :opfuncid 60 :opresulttype 16 :opretset false :opcollid 0 :inputcollid 0 :args ({VAR :varno 1 :varattno 11 :vartype 16 :vartypmod -1 :varcollid 0 :varnullingrels (b) :varlevelsup 0 :varreturningtype 0 :varnosyn 1 :varattnosyn 11 :location -1} {CONST :consttype 16 :consttypmod -1 :constcollid 0 :constlen 1 :constbyval true :constisnull false :location -1 :constvalue 1 [ 0 0 0 0 0 0 0 0 ]}) :location -1}"#;
        assert_eq!(
            parse_and_extract(predicate, 18, Context::predicate(17197))
                .unwrap()
                .root_type,
            Some(16)
        );
        let wrong = predicate.replace("opresulttype 16", "opresulttype 23");
        assert!(parse_and_extract(&wrong, 18, Context::predicate(17197)).is_err());
        let set_result = predicate.replace("opretset false", "opretset true");
        assert!(parse_and_extract(&set_result, 18, Context::predicate(17197)).is_err());
        let no_operator = predicate.replace("opno 91", "opno 0");
        assert!(parse_and_extract(&no_operator, 18, Context::predicate(17197)).is_err());
        let no_operator_function = predicate.replace("opfuncid 60", "opfuncid 0");
        assert!(parse_and_extract(&no_operator_function, 18, Context::predicate(17197)).is_err());
    }

    #[test]
    fn extracts_jsonb_operator_function_collation_and_relabel_casts() {
        let jsonb = r#"({OPEXPR :opno 3477 :opfuncid 3214 :opresulttype 25 :opretset false :opcollid 100 :inputcollid 100 :args ({VAR :varno 1 :varattno 3 :vartype 3802 :vartypmod -1 :varcollid 0 :varnoold 1 :varoattno 3 :varlevelsup 0 :location 57} {CONST :consttype 25 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval false :constisnull false :location 69 :constvalue 9 [ 36 0 0 0 116 111 107 101 110 ]}) :location 65})"#;
        let proof = parse_and_extract(jsonb, 12, Context::index(17089)).unwrap();
        assert_eq!(proof.requirements.operators, [3477]);
        assert_eq!(proof.requirements.functions, [3214]);
        assert_eq!(
            proof.operator_calls,
            [OperatorCall {
                opno: 3477,
                opfuncid: 3214,
                argument_types: [3802, 25],
                result_type: 25,
            }]
        );
        assert_eq!(proof.requirements.collations, [100]);
        assert_eq!(proof.requirements.constants[0].type_oid, 25);
        assert_eq!(
            proof.requirements.constants[0].bytes,
            [36, 0, 0, 0, 116, 111, 107, 101, 110]
        );

        let relabel = r#"{RELABELTYPE :arg {VAR :varno 1 :varattno 1 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnoold 1 :varoattno 1 :location -1} :resulttype 25 :resulttypmod -1 :resultcollid 100 :relabelformat 1 :location -1}"#;
        let proof = parse_and_extract(relabel, 12, Context::index(17089)).unwrap();
        assert_eq!(
            proof.requirements.casts,
            [CastRequirement {
                source_type: 23,
                target_type: 25
            }]
        );
    }

    #[test]
    fn parses_nested_catalog_function_expressions_without_marking_them_safe() {
        let nested = r#"{FUNCEXPR :funcid 1218 :funcresulttype 1186 :funcretset false :funcvariadic false :funcformat 0 :funccollid 0 :inputcollid 100 :args ({CONST :consttype 25 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval false :constisnull false :location -1 :constvalue 4 [ 40 0 0 0 ]} {FUNCEXPR :funcid 1370 :funcresulttype 1186 :funcretset false :funcvariadic false :funcformat 1 :funccollid 0 :inputcollid 0 :args ({VAR :varno 1 :varattno 9 :vartype 1184 :vartypmod -1 :varcollid 0 :varnoold 1 :varoattno 9 :varlevelsup 0 :location -1}) :location -1}) :location -1}"#;
        let proof = parse_and_extract(nested, 12, Context::index(17089)).unwrap();
        assert!(proof.requirements.functions.contains(&1218));
        assert!(proof.requirements.functions.contains(&1370));
        assert_eq!(proof.root_type, Some(1186));
        assert_eq!(
            proof.function_calls,
            [
                FunctionCall {
                    funcid: 1370,
                    format: 1,
                    argument_types: vec![1184],
                    result_type: 1186,
                },
                FunctionCall {
                    funcid: 1218,
                    format: 0,
                    argument_types: vec![25, 1186],
                    result_type: 1186,
                },
            ]
        );
    }

    #[test]
    fn returns_each_expression_from_a_multi_key_index_list_in_order() {
        let input = r#"({VAR :varno 1 :varattno 2 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnoold 1 :varoattno 2 :location -1} {FUNCEXPR :funcid 870 :funcresulttype 25 :funcretset false :funcvariadic false :funcformat 0 :funccollid 100 :inputcollid 100 :args ({VAR :varno 1 :varattno 3 :vartype 25 :vartypmod -1 :varcollid 100 :varlevelsup 0 :varnoold 1 :varoattno 3 :location -1}) :location -1})"#;
        let proofs = parse_and_extract_all(input, 12, Context::index(17089)).unwrap();
        assert_eq!(proofs.len(), 2);
        assert_eq!(proofs[0].root_type, Some(23));
        assert_eq!(proofs[1].root_type, Some(25));
        assert_eq!(proofs[0].vars[0].attno, 2);
        assert_eq!(proofs[1].vars[0].attno, 3);
    }

    #[test]
    fn source_digest_binds_exact_input_bytes_even_when_tree_shape_is_unchanged() {
        let tree = r#"{VAR :varno 1 :varattno 2 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnoold 1 :varoattno 2 :location -1}"#;
        let with_whitespace = format!(" {tree}");
        let first = parse_and_extract(tree, 12, Context::index(17089)).unwrap();
        let second = parse_and_extract(&with_whitespace, 12, Context::index(17089)).unwrap();
        assert_eq!(first.vars, second.vars);
        assert_ne!(first.source_digest(), second.source_digest());
    }

    #[test]
    fn multi_root_proofs_share_full_source_digest_and_keep_ordered_ordinals() {
        let input = r#"({VAR :varno 1 :varattno 2 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnoold 1 :varoattno 2 :location -1} {VAR :varno 1 :varattno 2 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnoold 1 :varoattno 2 :location -1})"#;
        let proofs = parse_and_extract_all(input, 12, Context::index(17089)).unwrap();
        assert_eq!(proofs.len(), 2);
        assert_eq!(proofs[0].source_digest(), proofs[1].source_digest());
        assert_eq!(proofs[0].source_ordinal(), 0);
        assert_eq!(proofs[1].source_ordinal(), 1);
        let one = parse_and_extract(
            r#"{VAR :varno 1 :varattno 2 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnoold 1 :varoattno 2 :location -1}"#,
            12,
            Context::index(17089),
        )
        .unwrap();
        assert_ne!(proofs[0].source_digest(), one.source_digest());
    }

    #[test]
    fn rejects_unknown_duplicate_malformed_and_cross_relation_nodes() {
        let unknown = r#"{VAR :varno 1 :varattno 2 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnosyn 1 :varattnosyn 2 :location -1 :surprise 1 :varnullingrels (b) :varreturningtype 0}"#;
        assert!(parse_and_extract(unknown, 18, Context::index(42)).is_err());
        let duplicate = r#"{VAR :varno 1 :varno 1 :varattno 2 :vartype 23 :vartypmod -1 :varcollid 0 :varnullingrels (b) :varlevelsup 0 :varreturningtype 0 :varnosyn 1 :varattnosyn 2 :location -1}"#;
        assert!(parse_and_extract(duplicate, 18, Context::index(42)).is_err());
        let cross = r#"{VAR :varno 2 :varattno 2 :vartype 23 :vartypmod -1 :varcollid 0 :varnullingrels (b) :varlevelsup 0 :varreturningtype 0 :varnosyn 2 :varattnosyn 2 :location -1}"#;
        assert!(parse_and_extract(cross, 18, Context::index(42)).is_err());
        let unknown_node = "{NEWNODE :x 1}";
        assert!(parse_and_extract(unknown_node, 12, Context::index(42)).is_err());
        let malformed_const = r#"{CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location -1 :constvalue 4 [ 999 0 0 0 0 0 0 0 ]}"#;
        assert!(parse_and_extract(malformed_const, 12, Context::index(42)).is_err());
        let deep = format!(
            "{}0{}",
            "(".repeat(MAX_DEPTH + 2),
            ")".repeat(MAX_DEPTH + 2)
        );
        assert!(parse_and_extract(&deep, 18, Context::index(42)).is_err());
    }

    #[test]
    fn validates_major_specific_coercion_form_ranges() {
        for (major, valid_max, invalid) in [(12, 2, 3), (18, 3, 4)] {
            let function = |format| {
                format!(
                    "{{FUNCEXPR :funcid 870 :funcresulttype 25 :funcretset false :funcvariadic false :funcformat {format} :funccollid 100 :inputcollid 100 :args () :location -1}}"
                )
            };
            assert!(
                parse_and_extract(&function(valid_max), major, Context::index(42)).is_ok(),
                "PG{major} rejected its maximum CoercionForm value"
            );
            assert!(
                parse_and_extract(&function(invalid), major, Context::index(42)).is_err(),
                "PG{major} accepted an out-of-range FuncExpr CoercionForm"
            );

            let legacy = if major == 12 {
                ":varnoold 1 :varoattno 1"
            } else {
                ":varnullingrels (b) :varreturningtype 0 :varnosyn 1 :varattnosyn 1"
            };
            let relabel = |format| {
                format!(
                    "{{RELABELTYPE :arg {{VAR :varno 1 :varattno 1 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 {legacy} :location -1}} :resulttype 23 :resulttypmod -1 :resultcollid 0 :relabelformat {format} :location -1}}"
                )
            };
            assert!(
                parse_and_extract(&relabel(valid_max), major, Context::index(42)).is_ok(),
                "PG{major} rejected its maximum RelabelType CoercionForm value"
            );
            assert!(
                parse_and_extract(&relabel(invalid), major, Context::index(42)).is_err(),
                "PG{major} accepted an out-of-range RelabelType CoercionForm"
            );
        }
    }
}

#[cfg(test)]
mod canonical_comparison_tests {
    use super::*;
    use crate::backend::schema::read_policy::{
        dependency_profile::DependencyProof, expression_proof, rows::ColumnRow,
    };
    use crate::net::messages::DataRow;
    use serde_json::Value as JsonValue;
    use std::collections::{BTreeMap, BTreeSet};

    fn fixture(major: u32) -> Option<DependencyProof> {
        let directory = std::env::var("PGDOG_PROFILE_TEST_FIXTURE_DIR").ok()?;
        let profile: JsonValue = serde_json::from_slice(
            &std::fs::read(format!(
                "{directory}/variants/read-dependency-profile-pg{major}-both.json"
            ))
            .ok()?,
        )
        .ok()?;
        let pin = profile["provenance"]["source_image"].as_str()?.to_owned();
        let mut capture: JsonValue = serde_json::from_slice(
            &std::fs::read(format!("{directory}/reference-extended-pg{major}.json")).ok()?,
        )
        .ok()?;
        let selected = profile["enabled_extensions"].as_array()?;
        let selected = selected
            .iter()
            .filter_map(JsonValue::as_str)
            .collect::<BTreeSet<_>>();
        capture["tables"]["pg_extension"] = JsonValue::Array(
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
        capture["extension_members"] = JsonValue::Array(
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
        capture["module_sha256"] = JsonValue::Array(
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
        DependencyProof::from_test_values(&profile, &capture, major, &pin).ok()
    }

    fn field_oid(row: &JsonValue, field: &str) -> u32 {
        row[field]
            .as_u64()
            .or_else(|| row[field].as_str().and_then(|value| value.parse().ok()))
            .expect("owned fixture field is an OID") as u32
    }

    fn column(proof: &DependencyProof, relation: u32, attnum: i16) -> ColumnRow {
        let ty = proof.row("pg_type", "23").expect("fixture int4 row");
        let fields = &ty["fields"];
        let namespace_oid = field_oid(fields, "typnamespace");
        let namespace_identity = proof
            .identity_for_runtime_oid("pg_namespace", namespace_oid)
            .expect("fixture int4 namespace");
        let namespace = proof
            .row("pg_namespace", namespace_identity)
            .expect("fixture namespace");
        ColumnRow::from(DataRow::from_columns(vec![
            relation.to_string(),
            "value".to_owned(),
            "23".to_owned(),
            namespace["fields"]["nspname"].as_str().unwrap().to_owned(),
            fields["typname"].as_str().unwrap().to_owned(),
            fields["typtype"].as_str().unwrap().to_owned(),
            field_oid(fields, "typbasetype").to_string(),
            field_oid(fields, "typinput").to_string(),
            field_oid(fields, "typoutput").to_string(),
            field_oid(fields, "typreceive").to_string(),
            field_oid(fields, "typsend").to_string(),
            "f".to_owned(),
            String::new(),
            String::new(),
            field_oid(fields, "typcollation").to_string(),
            attnum.to_string(),
            "-1".to_owned(),
            "0".to_owned(),
        ]))
    }

    fn var_tree(major: u32, relation: u32, attnum: i16) -> TreeProof {
        let legacy = if major == 12 {
            format!(":varnoold 1 :varoattno {attnum}")
        } else {
            format!(":varnullingrels (b) :varreturningtype 0 :varnosyn 1 :varattnosyn {attnum}")
        };
        parse_and_extract(
            &format!(
                "{{VAR :varno 1 :varattno {attnum} :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 {legacy} :location -1}}"
            ),
            major,
            Context::index(relation),
        )
        .expect("synthetic Var is structurally valid")
    }

    fn checked_var(
        tree: &TreeProof,
        dependencies: &DependencyProof,
        relation: u32,
        attnum: i16,
    ) -> expression_proof::ExpressionProof {
        expression_proof::precheck(
            tree,
            dependencies,
            &[column(dependencies, relation, attnum)],
            &BTreeMap::new(),
        )
        .expect("profiled int4 Var is semantically valid")
        .finish(None)
        .expect("no regconfig is required")
    }

    fn checked_tree(
        tree: &TreeProof,
        dependencies: &DependencyProof,
    ) -> expression_proof::ExpressionProof {
        expression_proof::precheck(tree, dependencies, &[], &BTreeMap::new())
            .expect("constant expression should be semantically valid")
            .finish(None)
            .expect("no regconfig is required")
    }

    fn typed_column(
        proof: &DependencyProof,
        relation: u32,
        attnum: i16,
        type_oid: u32,
    ) -> ColumnRow {
        let ty = proof
            .row("pg_type", &type_oid.to_string())
            .expect("fixture type row");
        let fields = &ty["fields"];
        let namespace_oid = field_oid(fields, "typnamespace");
        let namespace_identity = proof
            .identity_for_runtime_oid("pg_namespace", namespace_oid)
            .expect("fixture type namespace");
        let namespace = proof
            .row("pg_namespace", namespace_identity)
            .expect("fixture namespace");
        ColumnRow::from(DataRow::from_columns(vec![
            relation.to_string(),
            "value".to_owned(),
            type_oid.to_string(),
            namespace["fields"]["nspname"].as_str().unwrap().to_owned(),
            fields["typname"].as_str().unwrap().to_owned(),
            fields["typtype"].as_str().unwrap().to_owned(),
            field_oid(fields, "typbasetype").to_string(),
            field_oid(fields, "typinput").to_string(),
            field_oid(fields, "typoutput").to_string(),
            field_oid(fields, "typreceive").to_string(),
            field_oid(fields, "typsend").to_string(),
            "f".to_owned(),
            String::new(),
            String::new(),
            field_oid(fields, "typcollation").to_string(),
            attnum.to_string(),
            "-1".to_owned(),
            "0".to_owned(),
        ]))
    }

    fn checked_with_column(
        tree: &TreeProof,
        dependencies: &DependencyProof,
        column: ColumnRow,
    ) -> expression_proof::ExpressionProof {
        expression_proof::precheck(tree, dependencies, &[column], &BTreeMap::new())
            .expect("typed expression should be semantically valid")
            .finish(None)
            .expect("no regconfig is required")
    }

    fn nulltest_tree(major: u32, relation: u32, value: u8, test_type: u8) -> TreeProof {
        let var = format!(
            "{{CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location 7 :constvalue 4 [ {value} 0 0 0 0 0 0 0 ]}}"
        );
        parse_and_extract(
            &format!(
                "{{NULLTEST :arg {var} :nulltesttype {test_type} :argisrow false :location 11}}"
            ),
            major,
            Context::check(relation),
        )
        .expect("constant null-test is structurally valid")
    }

    fn coalesce_tree(major: u32, relation: u32) -> TreeProof {
        let tag = if major == 12 {
            "COALESCE"
        } else {
            "COALESCEEXPR"
        };
        let constant = "{CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location 3 :constvalue 4 [ 7 0 0 0 0 0 0 0 ]}";
        parse_and_extract(
            &format!(
                "{{{tag} :coalescetype 23 :coalescecollid 0 :args ({constant} {constant}) :location 8}}"
            ),
            major,
            Context::index(relation),
        )
        .expect("equivalent coalesce layouts are structurally valid")
    }

    fn array_tree(major: u32, relation: u32) -> TreeProof {
        let (tag, defaults) = if major == 12 {
            ("ARRAY", "")
        } else {
            ("ARRAYEXPR", " :list_start -1 :list_end -1")
        };
        let constant = "{CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location 3 :constvalue 4 [ 7 0 0 0 0 0 0 0 ]}";
        parse_and_extract(
            &format!(
                "{{{tag} :array_typeid 1007 :array_collid 0 :element_typeid 23 :elements ({constant}) :multidims false{defaults} :location 8}}"
            ),
            major,
            Context::index(relation),
        )
        .expect("equivalent array layouts are structurally valid")
    }

    fn bool_tree(major: u32, relation: u32, first: u8, second: u8) -> TreeProof {
        let make_nulltest = |value| {
            format!(
                "{{NULLTEST :arg {{CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location 3 :constvalue 4 [ {value} 0 0 0 0 0 0 0 ]}} :nulltesttype 0 :argisrow false :location 8}}"
            )
        };
        parse_and_extract(
            &format!(
                "{{BOOLEXPR :boolop and :args ({} {}) :location 13}}",
                make_nulltest(first),
                make_nulltest(second)
            ),
            major,
            Context::check(relation),
        )
        .expect("bounded boolean expression is structurally valid")
    }

    fn tsvector_tree(major: u32, relation: u32, config_oid: u32) -> TreeProof {
        let oid = config_oid.to_le_bytes();
        parse_and_extract(
            &format!(
                "{{FUNCEXPR :funcid 3745 :funcresulttype 3614 :funcretset false :funcvariadic false :funcformat 0 :funccollid 0 :inputcollid 100 :args ({{CONST :consttype 3734 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location 2 :constvalue 4 [ {} {} {} {} 0 0 0 0 ]}} {{CONST :consttype 25 :consttypmod -1 :constcollid 100 :constlen -1 :constbyval false :constisnull false :location 4 :constvalue 4 [ 116 101 120 116 ]}}) :location 9}}",
                oid[0], oid[1], oid[2], oid[3]
            ),
            major,
            Context::index(relation),
        )
        .expect("closed tsvector expression is structurally valid")
    }

    fn operator_tree(major: u32, relation: u32, opno: u32, opfuncid: u32) -> TreeProof {
        let legacy = if major == 12 {
            ":varnoold 1 :varoattno 1"
        } else {
            ":varnullingrels (b) :varreturningtype 0 :varnosyn 1 :varattnosyn 1"
        };
        let var = format!(
            "{{VAR :varno 1 :varattno 1 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 {legacy} :location 1}}"
        );
        let constant = "{CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location 2 :constvalue 4 [ 7 0 0 0 0 0 0 0 ]}";
        parse_and_extract(
            &format!(
                "{{OPEXPR :opno {opno} :opfuncid {opfuncid} :opresulttype 16 :opretset false :opcollid 0 :inputcollid 0 :args ({var} {constant}) :location 9}}"
            ),
            major,
            Context::check(relation),
        )
        .expect("typed operator expression is structurally valid")
    }

    fn text_function_tree(
        major: u32,
        relation: u32,
        function_oid: u32,
        takes_length: bool,
    ) -> TreeProof {
        let legacy = if major == 12 {
            ":varnoold 1 :varoattno 2"
        } else {
            ":varnullingrels (b) :varreturningtype 0 :varnosyn 1 :varattnosyn 2"
        };
        let var = format!(
            "{{VAR :varno 1 :varattno 2 :vartype 25 :vartypmod -1 :varcollid 100 :varlevelsup 0 {legacy} :location 1}}"
        );
        let args = if takes_length {
            format!(
                "{var} {{CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location 3 :constvalue 4 [ 2 0 0 0 0 0 0 0 ]}}"
            )
        } else {
            var
        };
        parse_and_extract(
            &format!(
                "{{FUNCEXPR :funcid {function_oid} :funcresulttype 25 :funcretset false :funcvariadic false :funcformat 0 :funccollid 100 :inputcollid 100 :args ({args}) :location 8}}"
            ),
            major,
            Context::index(relation),
        )
        .expect("reviewed text function expression is structurally valid")
    }

    fn int2_to_int4_cast_tree(
        major: u32,
        relation: u32,
        function_oid: u32,
        funcformat: u32,
    ) -> TreeProof {
        let legacy = if major == 12 {
            ":varnoold 1 :varoattno 1"
        } else {
            ":varnullingrels (b) :varreturningtype 0 :varnosyn 1 :varattnosyn 1"
        };
        let var = format!(
            "{{VAR :varno 1 :varattno 1 :vartype 21 :vartypmod -1 :varcollid 0 :varlevelsup 0 {legacy} :location 1}}"
        );
        parse_and_extract(
            &format!(
                "{{FUNCEXPR :funcid {function_oid} :funcresulttype 23 :funcretset false :funcvariadic false :funcformat {funcformat} :funccollid 0 :inputcollid 0 :args ({var}) :location 9}}"
            ),
            major,
            Context::index(relation),
        )
        .expect("cast expression is structurally valid")
    }

    fn field_u32(row: &JsonValue, field: &str) -> Option<u32> {
        row.get(field)
            .and_then(JsonValue::as_u64)
            .or_else(|| {
                row.get(field)
                    .and_then(JsonValue::as_str)
                    .and_then(|s| s.parse().ok())
            })
            .and_then(|oid| u32::try_from(oid).ok())
    }

    fn find_node_field<'a>(value: &'a Value, node: &str, field: &str) -> Option<&'a Value> {
        match value {
            Value::Struct(tag, fields) => {
                if tag == node
                    && let Some((_, value)) = fields.iter().find(|(name, _)| name == field)
                {
                    return Some(value);
                }
                fields
                    .iter()
                    .find_map(|(_, value)| find_node_field(value, node, field))
            }
            Value::List(items) => items
                .iter()
                .find_map(|value| find_node_field(value, node, field)),
            Value::Atom(_) | Value::Quoted(_) => None,
        }
    }

    fn checked_tsvector(
        tree: &TreeProof,
        dependencies: &DependencyProof,
        config_oid: u32,
    ) -> expression_proof::ExpressionProof {
        expression_proof::precheck(tree, dependencies, &[], &BTreeMap::new())
            .expect("profiled tsvector call should precheck")
            .finish(Some(config_oid))
            .expect("reviewed config closure should finish")
    }

    #[test]
    fn canonical_ast_matches_equivalent_pg12_and_pg18_vars_after_lineage_mapping() {
        let (Some(pg12), Some(pg18)) = (fixture(12), fixture(18)) else {
            eprintln!("SKIP canonical expression comparison: owned profile fixtures unavailable");
            return;
        };
        let source_relation = 90_101;
        let target_relation = 90_201;
        let source = var_tree(12, source_relation, 1);
        let target = var_tree(18, target_relation, 2);
        let source_proof = checked_var(&source, &pg12, source_relation, 1);
        let target_proof = checked_var(&target, &pg18, target_relation, 2);
        let lineage = ExpressionLineage {
            relations: BTreeMap::from([
                (source_relation, "relation:items".to_owned()),
                (target_relation, "relation:items".to_owned()),
            ]),
            columns: BTreeMap::from([
                ((source_relation, 1), "column:item_id".to_owned()),
                ((target_relation, 2), "column:item_id".to_owned()),
            ]),
            enum_types: BTreeMap::new(),
        };
        let left = canonical_expression(&source, &source_proof, &pg12, &lineage, None)
            .expect("source expression should canonicalize");
        let right = canonical_expression(&target, &target_proof, &pg18, &lineage, None)
            .expect("synthetic expression should canonicalize");
        assert_eq!(left, right);
        assert_eq!(left.digest(), right.digest());

        let missing_relation = ExpressionLineage {
            columns: lineage.columns.clone(),
            ..ExpressionLineage::default()
        };
        assert_eq!(
            canonical_expression(&target, &target_proof, &pg18, &missing_relation, None,),
            Err(CompareError::MissingLineage)
        );
        let missing_column = ExpressionLineage {
            relations: lineage.relations.clone(),
            ..ExpressionLineage::default()
        };
        assert_eq!(
            canonical_expression(&target, &target_proof, &pg18, &missing_column, None),
            Err(CompareError::MissingLineage)
        );
    }

    #[test]
    fn canonical_ast_ignores_locations_but_preserves_constant_and_boolean_semantics() {
        let Some(dependencies) = fixture(12) else {
            eprintln!("SKIP canonical expression mutation test: owned profile fixture unavailable");
            return;
        };
        let relation = 90_301;
        let lineage = ExpressionLineage {
            relations: BTreeMap::from([(relation, "relation:items".to_owned())]),
            ..ExpressionLineage::default()
        };
        let first = nulltest_tree(12, relation, 7, 0);
        let proof = checked_tree(&first, &dependencies);
        let location_only = parse_and_extract(
            "{NULLTEST :arg {CONST :consttype 23 :consttypmod -1 :constcollid 0 :constlen 4 :constbyval true :constisnull false :location 99 :constvalue 4 [ 7 0 0 0 0 0 0 0 ]} :nulltesttype 0 :argisrow false :location 123}",
            12,
            Context::check(relation),
        )
        .unwrap();
        let location_proof = checked_tree(&location_only, &dependencies);
        let canonical_first =
            canonical_expression(&first, &proof, &dependencies, &lineage, None).unwrap();
        let canonical_location = canonical_expression(
            &location_only,
            &location_proof,
            &dependencies,
            &lineage,
            None,
        )
        .unwrap();
        assert_eq!(canonical_first, canonical_location);

        for changed in [
            nulltest_tree(12, relation, 8, 0),
            nulltest_tree(12, relation, 7, 1),
        ] {
            let changed_proof = checked_tree(&changed, &dependencies);
            let canonical_changed =
                canonical_expression(&changed, &changed_proof, &dependencies, &lineage, None)
                    .unwrap();
            assert_ne!(canonical_first, canonical_changed);
            assert_ne!(canonical_first.digest(), canonical_changed.digest());
        }

        let ordered = bool_tree(12, relation, 3, 9);
        let reversed = bool_tree(12, relation, 9, 3);
        let ordered_proof = checked_tree(&ordered, &dependencies);
        let reversed_proof = checked_tree(&reversed, &dependencies);
        let ordered =
            canonical_expression(&ordered, &ordered_proof, &dependencies, &lineage, None).unwrap();
        let reversed =
            canonical_expression(&reversed, &reversed_proof, &dependencies, &lineage, None)
                .unwrap();
        assert_ne!(ordered, reversed);

        let changed_source = nulltest_tree(12, relation, 8, 0);
        let replayed_proof = checked_tree(&changed_source, &dependencies);
        assert_eq!(
            canonical_expression(&first, &replayed_proof, &dependencies, &lineage, None,),
            Err(CompareError::ProofMismatch)
        );
    }

    #[test]
    fn canonical_ast_maps_only_reviewed_cross_major_node_aliases() {
        let (Some(pg12), Some(pg18)) = (fixture(12), fixture(18)) else {
            eprintln!("SKIP canonical alias test: owned PG12/PG18 fixtures unavailable");
            return;
        };
        let source_relation = 90_401;
        let target_relation = 90_402;
        let lineage = ExpressionLineage {
            relations: BTreeMap::from([
                (source_relation, "relation:items".to_owned()),
                (target_relation, "relation:items".to_owned()),
            ]),
            ..ExpressionLineage::default()
        };
        for (source, target) in [
            (
                coalesce_tree(12, source_relation),
                coalesce_tree(18, target_relation),
            ),
            (
                array_tree(12, source_relation),
                array_tree(18, target_relation),
            ),
        ] {
            let source_proof = checked_tree(&source, &pg12);
            let target_proof = checked_tree(&target, &pg18);
            let left = canonical_expression(&source, &source_proof, &pg12, &lineage, None)
                .expect("PG12 tree should canonicalize");
            let right = canonical_expression(&target, &target_proof, &pg18, &lineage, None)
                .expect("PG18 tree should canonicalize");
            assert_eq!(left, right);
        }
    }

    #[test]
    fn canonical_regconfig_constant_binds_oid_bytes_to_reviewed_identity() {
        let (Some(pg12), Some(pg18)) = (fixture(12), fixture(18)) else {
            eprintln!("SKIP canonical regconfig test: owned PG12/PG18 fixtures unavailable");
            return;
        };
        let identity = "$builtin:pg_ts_config:pg_catalog.english";
        let source_config = pg12
            .runtime_oid_for_identity("pg_ts_config", identity)
            .expect("PG12 simple config fixture");
        let target_config = pg18
            .runtime_oid_for_identity("pg_ts_config", identity)
            .expect("PG18 simple config fixture");
        let source_relation = 90_501;
        let target_relation = 90_502;
        let source = tsvector_tree(12, source_relation, source_config);
        let target = tsvector_tree(18, target_relation, target_config);
        let source_proof = checked_tsvector(&source, &pg12, source_config);
        let target_proof = checked_tsvector(&target, &pg18, target_config);
        let lineage = ExpressionLineage {
            relations: BTreeMap::from([
                (source_relation, "relation:items".to_owned()),
                (target_relation, "relation:items".to_owned()),
            ]),
            ..ExpressionLineage::default()
        };
        let left = canonical_expression(&source, &source_proof, &pg12, &lineage, Some(identity))
            .expect("PG12 config bytes should resolve to reviewed identity");
        let right = canonical_expression(&target, &target_proof, &pg18, &lineage, Some(identity))
            .expect("PG18 config bytes should resolve to reviewed identity");
        assert_eq!(left, right);

        let wrong_config = source_config.wrapping_add(1);
        let tampered = tsvector_tree(12, source_relation, wrong_config);
        let tampered_proof = checked_tsvector(&tampered, &pg12, source_config);
        assert_eq!(
            canonical_expression(&tampered, &tampered_proof, &pg12, &lineage, Some(identity),),
            Err(CompareError::InvalidRegconfig)
        );
    }

    #[test]
    fn canonical_expression_ordinal_is_bound_to_ordered_index_key_roots() {
        let Some(dependencies) = fixture(12) else {
            eprintln!("SKIP canonical ordinal test: owned profile fixture unavailable");
            return;
        };
        let relation = 90_601;
        let var = "{VAR :varno 1 :varattno 1 :vartype 23 :vartypmod -1 :varcollid 0 :varlevelsup 0 :varnoold 1 :varoattno 1 :location 1}";
        let trees = parse_and_extract_all(&format!("({var} {var})"), 12, Context::index(relation))
            .expect("two ordered roots should parse");
        assert_eq!(trees.len(), 2);
        let proofs = trees
            .iter()
            .map(|tree| checked_var(tree, &dependencies, relation, 1))
            .collect::<Vec<_>>();
        let lineage = ExpressionLineage {
            relations: BTreeMap::from([(relation, "relation:items".to_owned())]),
            columns: BTreeMap::from([((relation, 1), "column:item_id".to_owned())]),
            ..ExpressionLineage::default()
        };
        let canonical = trees
            .iter()
            .zip(&proofs)
            .map(|(tree, proof)| {
                canonical_expression(tree, proof, &dependencies, &lineage, None).unwrap()
            })
            .collect::<Vec<_>>();
        assert_ne!(canonical[0], canonical[1]);
        assert_eq!(canonical[0].ordinal, 0);
        assert_eq!(canonical[1].ordinal, 1);
    }

    #[test]
    fn canonical_operator_function_and_cast_nodes_keep_exact_catalog_bindings() {
        let (Some(pg12), Some(pg18)) = (fixture(12), fixture(18)) else {
            eprintln!("SKIP canonical call-binding test: owned PG12/PG18 fixtures unavailable");
            return;
        };
        let relation = 90_701;
        let lineage = ExpressionLineage {
            relations: BTreeMap::from([(relation, "relation:items".to_owned())]),
            columns: BTreeMap::from([
                ((relation, 1), "column:item_id".to_owned()),
                ((relation, 2), "column:payload".to_owned()),
            ]),
            ..ExpressionLineage::default()
        };

        let equality = operator_tree(12, relation, 96, 65);
        let less_than = operator_tree(12, relation, 97, 66);
        let equality_proof =
            checked_with_column(&equality, &pg12, typed_column(&pg12, relation, 1, 23));
        let less_than_proof =
            checked_with_column(&less_than, &pg12, typed_column(&pg12, relation, 1, 23));
        let canonical_eq =
            canonical_expression(&equality, &equality_proof, &pg12, &lineage, None).unwrap();
        let canonical_lt =
            canonical_expression(&less_than, &less_than_proof, &pg12, &lineage, None).unwrap();
        assert_ne!(canonical_eq, canonical_lt);
        let mismatched_operator = operator_tree(12, relation, 96, 66);
        assert!(
            expression_proof::precheck(
                &mismatched_operator,
                &pg12,
                &[typed_column(&pg12, relation, 1, 23)],
                &BTreeMap::new(),
            )
            .is_err()
        );

        let lower = text_function_tree(18, relation, 870, false);
        let right = text_function_tree(18, relation, 3061, true);
        let lower_proof = checked_with_column(&lower, &pg18, typed_column(&pg18, relation, 2, 25));
        let right_proof = checked_with_column(&right, &pg18, typed_column(&pg18, relation, 2, 25));
        let lower = canonical_expression(&lower, &lower_proof, &pg18, &lineage, None).unwrap();
        let right = canonical_expression(&right, &right_proof, &pg18, &lineage, None).unwrap();
        assert_ne!(lower, right);

        let cast = pg12
            .rows("pg_cast")
            .expect("profile contains cast table")
            .find_map(|row| {
                let fields = row.get("fields")?;
                (field_u32(fields, "castsource") == Some(21)
                    && field_u32(fields, "casttarget") == Some(23)
                    && fields.get("castmethod").and_then(JsonValue::as_str) == Some("f"))
                .then(|| field_u32(fields, "castfunc"))
                .flatten()
            })
            .expect("owned profile includes a reviewed int2-to-int4 function cast");
        let cast_tree = int2_to_int4_cast_tree(12, relation, cast, 1);
        let cast_proof =
            checked_with_column(&cast_tree, &pg12, typed_column(&pg12, relation, 1, 21));
        let canonical_cast =
            canonical_expression(&cast_tree, &cast_proof, &pg12, &lineage, None).unwrap();
        assert_eq!(
            find_node_field(&canonical_cast.root, "FUNCEXPR", "funcformat"),
            Some(&Value::Atom("1".to_owned()))
        );
        let cast_as_plain_function = int2_to_int4_cast_tree(12, relation, cast, 0);
        assert!(
            expression_proof::precheck(
                &cast_as_plain_function,
                &pg12,
                &[typed_column(&pg12, relation, 1, 21)],
                &BTreeMap::new(),
            )
            .is_err()
        );
    }
}
