use std::{
    collections::{BTreeMap, BTreeSet},
    ops::ControlFlow,
    panic::AssertUnwindSafe,
};

use crate::net::{Protocol, ProtocolMessage};
use pg_raw_parse::{
    ConstValue, Node, nodes,
    walk::{self, Recurse},
};

use super::PolicyError;

const MAX_AST_DEPTH: usize = 128;
const MAX_AST_NODES: usize = 65_536;
const MAX_STATEMENTS: usize = 1_024;
pub(super) const MAX_SQL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadIsolation {
    ReadUncommitted,
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadAction {
    Select,
    Begin(ReadIsolation),
    Commit,
    Rollback,
    ShowReadOnly,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CatalogRequirements {
    pub(crate) relations: BTreeSet<String>,
    /// Unqualified references resolved within the current WITH/CTE scope.
    pub(crate) cte_references: BTreeSet<String>,
    pub(crate) functions: BTreeSet<String>,
    pub(crate) operators: BTreeSet<String>,
    pub(crate) types: BTreeSet<String>,
    /// Bare references are ambiguous between a scalar column and a whole-row
    /// relation alias; catalog proof must resolve or deny them.
    pub(crate) column_refs: BTreeSet<String>,
    pub(crate) possible_whole_row_refs: BTreeSet<String>,
    /// Placeholder indexes are references, not resolved PostgreSQL OIDs.
    pub(crate) parameter_refs: BTreeSet<u32>,
    /// Explicit `$n::type` requirements captured from the original AST.
    pub(crate) parameter_type_requirements: BTreeMap<u32, BTreeSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedSql {
    pub(crate) original_sql: String,
    pub(crate) fingerprint: [u8; 32],
    pub(crate) actions: Vec<ReadAction>,
    pub(crate) catalog: CatalogRequirements,
}

#[derive(Clone, Default)]
struct CteScope {
    visible: BTreeSet<String>,
    forbidden: BTreeSet<String>,
}

pub(crate) fn admit_sql(sql: &str) -> Result<AdmittedSql, PolicyError> {
    if sql.len() > MAX_SQL_BYTES {
        return Err(PolicyError::unsupported());
    }
    let parsed = pg_raw_parse::parse(sql).map_err(|_| PolicyError::syntax())?;
    let mut actions = Vec::new();
    let mut catalog = CatalogRequirements::default();
    let mut nodes_seen = 0usize;
    for stmt in parsed.stmts() {
        if actions.len() >= MAX_STATEMENTS {
            return Err(PolicyError::unsupported());
        }
        let action = match stmt {
            Node::SelectStmt(select) => {
                if select.into_clause().is_some() || !select.locking_clause().is_empty() {
                    return Err(PolicyError::write());
                }
                ReadAction::Select
            }
            Node::TransactionStmt(transaction) => transaction_action(transaction)?,
            Node::VariableShowStmt(show)
                if show.name().is_some_and(|n| {
                    n.eq_ignore_ascii_case("transaction_read_only")
                        || n.eq_ignore_ascii_case("default_transaction_read_only")
                }) =>
            {
                ReadAction::ShowReadOnly
            }
            Node::VariableShowStmt(_) => return Err(PolicyError::unsupported()),
            Node::InsertStmt(_)
            | Node::UpdateStmt(_)
            | Node::DeleteStmt(_)
            | Node::MergeStmt(_) => {
                return Err(PolicyError::write());
            }
            _ => return Err(PolicyError::unsupported()),
        };
        if matches!(stmt, Node::TransactionStmt(_) | Node::VariableShowStmt(_)) {
            nodes_seen = nodes_seen.saturating_add(1);
            if policy_limit_exceeded(nodes_seen, MAX_AST_NODES) {
                return Err(PolicyError::unsupported());
            }
            actions.push(action);
            continue;
        }
        let mut todo = vec![(stmt, 1usize, CteScope::default())];
        while let Some((node, depth, inherited_scope)) = todo.pop() {
            if policy_limit_exceeded(depth, MAX_AST_DEPTH) {
                return Err(PolicyError::unsupported());
            }
            nodes_seen = nodes_seen.saturating_add(1);
            if policy_limit_exceeded(nodes_seen, MAX_AST_NODES) {
                return Err(PolicyError::unsupported());
            }
            let cte_scope = match node {
                Node::SelectStmt(select) => {
                    let mut scope = inherited_scope.clone();
                    if let Some(with_clause) = select.with_clause() {
                        if with_clause.recursive {
                            return Err(PolicyError::unsupported());
                        }
                        let mut local_names = BTreeSet::new();
                        for cte in with_clause.ctes().iter() {
                            if let Some(name) = cte.ctename()
                                && !local_names.insert(name.to_owned())
                            {
                                return Err(PolicyError::unsupported());
                            }
                        }
                        scope.visible.extend(local_names);
                    }
                    scope
                }
                _ => inherited_scope.clone(),
            };
            match inspect_node(node, &mut catalog, &cte_scope.visible, &cte_scope.forbidden) {
                NodeDisposition::Allowed => {
                    if let Node::WithClause(with_clause) = node {
                        if with_clause.recursive {
                            return Err(PolicyError::unsupported());
                        }
                        let ctes = with_clause.ctes().iter().collect::<Vec<_>>();
                        let all_names = ctes
                            .iter()
                            .filter_map(|cte| cte.ctename())
                            .map(str::to_owned)
                            .collect::<BTreeSet<_>>();
                        let mut preceding = inherited_scope.visible.clone();
                        for cte in ctes {
                            let Some(name) = cte.ctename() else {
                                return Err(PolicyError::unsupported());
                            };
                            let mut forbidden = inherited_scope.forbidden.clone();
                            forbidden.extend(all_names.difference(&preceding).cloned());
                            todo.push((
                                Node::from(cte),
                                depth + 1,
                                CteScope {
                                    visible: preceding.clone(),
                                    forbidden,
                                },
                            ));
                            preceding.insert(name.to_owned());
                        }
                        continue;
                    }
                    let mut limit_exceeded = false;
                    let walked = std::panic::catch_unwind(AssertUnwindSafe(|| {
                        walk::walk_manual::<()>(node, |child| {
                            if policy_limit_exceeded(depth + 1, MAX_AST_DEPTH)
                                || policy_limit_exceeded(
                                    nodes_seen.saturating_add(todo.len()).saturating_add(1),
                                    MAX_AST_NODES,
                                )
                            {
                                limit_exceeded = true;
                                return ControlFlow::Break(());
                            }
                            match node {
                                Node::SelectStmt(_) => {
                                    let child_scope = if matches!(child, Node::WithClause(_)) {
                                        inherited_scope.clone()
                                    } else {
                                        cte_scope.clone()
                                    };
                                    todo.push((child, depth + 1, child_scope));
                                }
                                _ => todo.push((child, depth + 1, cte_scope.clone())),
                            }
                            Recurse::no()
                        });
                    }));
                    if walked.is_err() || limit_exceeded {
                        return Err(PolicyError::unsupported());
                    }
                }
                NodeDisposition::Write => return Err(PolicyError::write()),
                NodeDisposition::Unsupported => return Err(PolicyError::unsupported()),
            }
        }
        actions.push(action);
    }
    if actions.is_empty() {
        return Err(PolicyError::unsupported());
    }
    // Transaction commands and SHOW are standalone protocol actions. A simple
    // Query batch mixing one with other statements has surprising partial
    // execution semantics, so strict mode admits only a single control action.
    if actions.len() > 1
        && actions
            .iter()
            .any(|action| !matches!(action, ReadAction::Select))
    {
        return Err(PolicyError::unsupported());
    }
    Ok(AdmittedSql {
        original_sql: sql.to_owned(),
        fingerprint: sha256(sql.as_bytes()),
        actions,
        catalog,
    })
}

enum NodeDisposition {
    Allowed,
    Write,
    Unsupported,
}

fn inspect_node(
    node: Node<'_>,
    catalog: &mut CatalogRequirements,
    cte_scope: &BTreeSet<String>,
    forbidden_ctes: &BTreeSet<String>,
) -> NodeDisposition {
    use Node::*;
    match node {
        SelectStmt(select) => {
            if select.into_clause().is_some() || !select.locking_clause().is_empty() {
                return NodeDisposition::Write;
            }
            NodeDisposition::Allowed
        }
        InsertStmt(_) | UpdateStmt(_) | DeleteStmt(_) | MergeStmt(_) | CopyStmt(_)
        | NextValueExpr(_) => NodeDisposition::Write,
        RangeVar(relation) => {
            let rel = relation.relname().unwrap_or_default();
            let schema = relation.schemaname();
            if relation.catalogname().is_some() {
                return NodeDisposition::Unsupported;
            }
            if schema.is_none() && forbidden_ctes.contains(rel) {
                return NodeDisposition::Unsupported;
            }
            if schema.is_none() && cte_scope.contains(rel) {
                catalog.cte_references.insert(quote_ident(rel));
                return NodeDisposition::Allowed;
            }
            if rel.is_empty() {
                return NodeDisposition::Unsupported;
            }
            catalog.relations.insert(match schema {
                Some(s) => format!("{}.{}", quote_ident(s), quote_ident(rel)),
                std::option::Option::None => quote_ident(rel),
            });
            NodeDisposition::Allowed
        }
        FuncCall(function) => {
            if !function.agg_order().is_empty()
                || !matches!(function.agg_filter(), Node::None)
                || function.over().is_some()
            {
                return NodeDisposition::Unsupported;
            }
            let parts = function
                .funcname()
                .into_iter()
                .filter_map(Node::as_str)
                .collect::<Vec<_>>();
            if parts.is_empty() || parts.len() > 2 {
                return NodeDisposition::Unsupported;
            }
            let (namespace, name) = if parts.len() == 1 {
                (std::option::Option::None, parts[0])
            } else {
                (Some(parts[0]), parts[1])
            };
            if namespace.is_some_and(|ns| ns != "pg_catalog")
                || !matches!(name, "count" | "sum" | "avg" | "min" | "max")
            {
                return NodeDisposition::Unsupported;
            }
            catalog.functions.insert(match namespace {
                Some(ns) => format!("{}.{}", quote_ident(ns), quote_ident(name)),
                std::option::Option::None => quote_ident(name),
            });
            NodeDisposition::Allowed
        }
        A_Expr(expr) => {
            if expr.kind != nodes::A_Expr_Kind::AEXPR_OP
                && expr.kind != nodes::A_Expr_Kind::AEXPR_NULLIF
            {
                return NodeDisposition::Unsupported;
            }
            let name = expr
                .name()
                .into_iter()
                .filter_map(Node::as_str)
                .collect::<Vec<_>>();
            if expr.kind == nodes::A_Expr_Kind::AEXPR_NULLIF {
                if !matches!(name.as_slice(), ["="]) {
                    return NodeDisposition::Unsupported;
                }
                catalog.operators.insert(quote_ident("="));
                return NodeDisposition::Allowed;
            }
            let (namespace, symbol) = match name.as_slice() {
                [symbol] => (std::option::Option::None, *symbol),
                [namespace, symbol] if *namespace == "pg_catalog" => (Some(*namespace), *symbol),
                _ => return NodeDisposition::Unsupported,
            };
            if !matches!(
                symbol,
                "=" | "<>" | "!=" | "<" | "<=" | ">" | ">=" | "+" | "-" | "*" | "/" | "%" | "||"
            ) {
                return NodeDisposition::Unsupported;
            }
            catalog.operators.insert(match namespace {
                Some(ns) => format!("{}.{}", quote_ident(ns), quote_ident(symbol)),
                std::option::Option::None => quote_ident(symbol),
            });
            NodeDisposition::Allowed
        }
        ColumnRef(reference) => {
            let fields = reference.fields().into_iter().collect::<Vec<_>>();
            let names = fields
                .iter()
                .filter_map(|node| match node {
                    Node::String(value) => value.sval(),
                    Node::A_Star(_) => Some("*"),
                    _ => std::option::Option::None,
                })
                .collect::<Vec<_>>();
            if names.len() == fields.len() && !names.is_empty() {
                let name = names
                    .iter()
                    .map(|part| {
                        if *part == "*" {
                            "*".to_owned()
                        } else {
                            quote_ident(part)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(".");
                catalog.column_refs.insert(name.clone());
                if names.len() == 1 && names[0] != "*" {
                    catalog.possible_whole_row_refs.insert(name);
                }
            } else {
                return NodeDisposition::Unsupported;
            }
            NodeDisposition::Allowed
        }
        TypeName(ty) => {
            let name = type_name(ty);
            if !supported_type_name(ty) {
                return NodeDisposition::Unsupported;
            }
            if !name.is_empty() {
                catalog.types.insert(name);
            }
            NodeDisposition::Allowed
        }
        TypeCast(cast) => {
            if let (Node::ParamRef(param), Some(ty)) = (cast.arg(), cast.type_name()) {
                if param.number <= 0 {
                    return NodeDisposition::Unsupported;
                }
                catalog
                    .parameter_type_requirements
                    .entry(param.number as u32)
                    .or_default()
                    .insert(type_name(ty));
            }
            NodeDisposition::Allowed
        }
        ParamRef(param) => {
            if param.number <= 0 {
                return NodeDisposition::Unsupported;
            }
            catalog.parameter_refs.insert(param.number as u32);
            NodeDisposition::Allowed
        }
        CaseExpr(expression) => {
            // Simple CASE resolves an equality operator for each WHEN even
            // though there is no explicit A_Expr in the raw syntax tree.
            if !matches!(expression.arg(), Node::None) {
                catalog.operators.insert(quote_ident("="));
            }
            NodeDisposition::Allowed
        }
        // Only the raw-parser SELECT surface reviewed for this policy is
        // accepted. All analyzed, procedural, JSON, window, array, and coercion
        // nodes remain denied even if a parent SELECT is otherwise safe.
        NodeList(_) | None | Alias(_) | ResTarget(_) | A_Const(_) | A_Star(_) | BoolExpr(_)
        | SortBy(_) | RangeSubselect(_) | JoinExpr(_) | SubLink(_) | CaseWhen(_)
        | CoalesceExpr(_) | NullTest(_) | BooleanTest(_) | SetOperationStmt(_)
        | CommonTableExpr(_) | WithClause(_) | Integer(_) | Float(_) | Boolean(_) | String(_)
        | BitString(_) | TransactionStmt(_) | VariableShowStmt(_) => NodeDisposition::Allowed,
        LockingClause(_) => NodeDisposition::Write,
        _ => NodeDisposition::Unsupported,
    }
}

fn transaction_action(stmt: &nodes::TransactionStmt) -> Result<ReadAction, PolicyError> {
    use nodes::TransactionStmtKind::*;
    if stmt.chain {
        return Err(PolicyError::unsupported());
    }
    match stmt.kind {
        TRANS_STMT_BEGIN | TRANS_STMT_START => {
            let mut isolation = ReadIsolation::ReadCommitted;
            for option in stmt.options().iter() {
                if let Node::DefElem(def) = option {
                    match def.defname() {
                        Some("transaction_read_only") => {
                            let Some(Node::A_Const(value)) = Some(def.arg()) else {
                                return Err(PolicyError::write());
                            };
                            if value.val().and_then(|v| v.numeric_value::<i32>()) != Some(1) {
                                return Err(PolicyError::write());
                            }
                        }
                        Some("transaction_isolation") => {
                            let Node::A_Const(value) = def.arg() else {
                                return Err(PolicyError::unsupported());
                            };
                            isolation = match value.val() {
                                Some(ConstValue::String("read uncommitted")) => {
                                    ReadIsolation::ReadUncommitted
                                }
                                Some(ConstValue::String("read committed")) => {
                                    ReadIsolation::ReadCommitted
                                }
                                Some(ConstValue::String("repeatable read")) => {
                                    ReadIsolation::RepeatableRead
                                }
                                Some(ConstValue::String("serializable")) => {
                                    ReadIsolation::Serializable
                                }
                                _ => return Err(PolicyError::unsupported()),
                            };
                        }
                        Some("transaction_deferrable") => return Err(PolicyError::unsupported()),
                        _ => return Err(PolicyError::unsupported()),
                    }
                } else {
                    return Err(PolicyError::unsupported());
                }
            }
            Ok(ReadAction::Begin(isolation))
        }
        TRANS_STMT_COMMIT => Ok(ReadAction::Commit),
        TRANS_STMT_ROLLBACK => Ok(ReadAction::Rollback),
        _ => Err(PolicyError::unsupported()),
    }
}

fn type_name(ty: &nodes::TypeName) -> String {
    ty.names()
        .into_iter()
        .filter_map(|part| part.sval())
        .map(quote_ident)
        .collect::<Vec<_>>()
        .join(".")
}

fn quote_ident(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn supported_type_name(ty: &nodes::TypeName) -> bool {
    if ty.pct_type || ty.setof || !ty.array_bounds().is_empty() {
        return false;
    }
    let parts = ty
        .names()
        .into_iter()
        .filter_map(|part| part.sval())
        .collect::<Vec<_>>();
    let name = match parts.as_slice() {
        [name] => *name,
        ["pg_catalog", name] => *name,
        _ => return false,
    };
    matches!(
        name,
        "bool"
            | "boolean"
            | "int2"
            | "smallint"
            | "int4"
            | "integer"
            | "int8"
            | "bigint"
            | "numeric"
            | "decimal"
            | "float4"
            | "real"
            | "float8"
            | "text"
            | "varchar"
            | "bpchar"
            | "char"
            | "bytea"
            | "date"
            | "time"
            | "timetz"
            | "timestamp"
            | "timestamptz"
            | "interval"
            | "uuid"
    )
}

#[inline]
pub(super) fn policy_limit_exceeded(value: usize, limit: usize) -> bool {
    value > limit
}

pub(crate) fn gate_message(message: &ProtocolMessage) -> Result<(), PolicyError> {
    use ProtocolMessage::*;
    match message {
        Query(query) => admit_sql(query.query()).map(|_| ()),
        Parse(parse) => admit_sql(parse.query()).map(|_| ()),
        Bind(_) | Describe(_) | Execute(_) | Close(_) | Sync(_) => Ok(()),
        EnsurePrepared(_) | PrepareFromClient(_) | Fastpath(_) | CopyData(_) | CopyDone(_)
        | CopyFail(_) => Err(PolicyError::protocol()),
        Other(message) if message.code() == 'H' => Ok(()),
        Other(message) if matches!(message.code(), 'd' | 'c' | 'f' | 'F') => {
            Err(PolicyError::protocol())
        }
        Other(_) => Err(PolicyError::protocol()),
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut output = [0; 32];
    output.copy_from_slice(digest.as_ref());
    output
}
