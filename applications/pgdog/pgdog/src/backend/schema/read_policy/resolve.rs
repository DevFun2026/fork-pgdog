//! Conservative local type resolution. No client SQL is prepared to obtain this proof.
use super::{CatalogSnapshot, registry};
use crate::frontend::read_policy::session::MAX_DECLARED_PARAMETERS;
use crate::frontend::read_policy::{AdmittedSql, PolicyError, ReadAction};
use pg_raw_parse::{ConstValue, Node, nodes};
use std::collections::BTreeMap;

type Result<T> = std::result::Result<T, PolicyError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Known(u32),
    Unknown,
    Parameter(usize),
}
#[derive(Debug, Clone)]
struct Source {
    name: String,
    columns: Vec<(String, u32)>,
}
#[derive(Default, Clone)]
struct Scope {
    sources: Vec<Source>,
    outer: Vec<Vec<Source>>,
    ctes: BTreeMap<String, Vec<(String, u32)>>,
}
struct Resolver<'a> {
    catalog: &'a CatalogSnapshot,
    parameters: Vec<Option<u32>>,
}

pub(super) fn prove(
    admitted: &AdmittedSql,
    catalog: &CatalogSnapshot,
    declared: &[u32],
) -> Result<()> {
    // Bind decodes every declared parameter, including parameters a SHOW or
    // SELECT does not reference. Never authorize an unreviewed input function.
    if declared.len() > MAX_DECLARED_PARAMETERS
        || declared
            .iter()
            .any(|oid| *oid != 0 && !registry::scalar_type(*oid))
    {
        return Err(PolicyError::unsupported());
    }
    if admitted.actions.iter().all(|a| {
        matches!(
            a,
            ReadAction::Begin(_)
                | ReadAction::Commit
                | ReadAction::Rollback
                | ReadAction::ShowReadOnly
        )
    }) {
        return Ok(());
    }
    let highest = admitted.catalog.parameter_refs.last().copied().unwrap_or(0) as usize;
    if highest > MAX_DECLARED_PARAMETERS {
        return Err(PolicyError::unsupported());
    }
    let mut parameters = vec![None; highest.max(declared.len())];
    for (index, oid) in declared.iter().enumerate() {
        if *oid != 0 {
            if !registry::scalar_type(*oid) {
                return Err(PolicyError::unsupported());
            }
            parameters[index] = Some(*oid);
        }
    }
    let mut resolver = Resolver {
        catalog,
        parameters,
    };
    let parsed = pg_raw_parse::parse(&admitted.original_sql).map_err(|_| PolicyError::syntax())?;
    for node in parsed.stmts() {
        let Node::SelectStmt(select) = node else {
            return Err(PolicyError::unsupported());
        };
        resolver.select(select, Scope::default())?;
    }
    if admitted
        .catalog
        .parameter_refs
        .iter()
        .any(|index| resolver.parameters[*index as usize - 1].is_none())
    {
        return Err(PolicyError::unsupported());
    }
    Ok(())
}

impl Resolver<'_> {
    fn known(&self, ty: Ty) -> Option<u32> {
        match ty {
            Ty::Known(oid) => Some(oid),
            Ty::Parameter(index) => self.parameters.get(index).copied().flatten(),
            Ty::Unknown => None,
        }
    }
    fn constrain(&mut self, ty: Ty, target: u32, implicit: bool) -> Result<u32> {
        if !registry::scalar_type(target) {
            return Err(PolicyError::unsupported());
        }
        match ty {
            Ty::Parameter(index) if self.parameters[index].is_none() => {
                self.parameters[index] = Some(target);
                Ok(target)
            }
            _ => match self.known(ty) {
                None if ty == Ty::Unknown => Ok(target),
                Some(source)
                    if source == target || registry::cast_allowed(source, target, implicit) =>
                {
                    Ok(target)
                }
                _ => Err(PolicyError::unsupported()),
            },
        }
    }
    fn output(&mut self, ty: Ty) -> Result<u32> {
        match self.known(ty) {
            Some(oid) if registry::scalar_type(oid) => Ok(oid),
            None if ty == Ty::Unknown => Ok(25),
            _ => Err(PolicyError::unsupported()),
        }
    }
    fn comparison(&mut self, name: &str, left: Ty, right: Ty) -> Result<u32> {
        let (mut l, mut r) = (self.known(left), self.known(right));
        match (l, r) {
            (Some(a), None) => {
                r = Some(self.constrain(right, a, true)?);
            }
            (None, Some(b)) => {
                l = Some(self.constrain(left, b, true)?);
            }
            (None, None)
                if left == Ty::Unknown
                    && right == Ty::Unknown
                    && matches!(name, "=" | "<>" | "<" | "<=" | ">" | ">=" | "||") =>
            {
                l = Some(25);
                r = Some(25);
            }
            _ => (),
        }
        let (l, r) = (
            l.ok_or_else(PolicyError::unsupported)?,
            r.ok_or_else(PolicyError::unsupported)?,
        );
        if let Some(result) = registry::operator_result(name, Some(l), r) {
            return Ok(result);
        }
        // varchar is binary-coercible to text; no function executes in this step.
        let (new_l, new_r) = (
            if l == 1043 { 25 } else { l },
            if r == 1043 { 25 } else { r },
        );
        if (l, r) != (new_l, new_r)
            && (l == new_l || registry::cast_allowed(l, new_l, true))
            && (r == new_r || registry::cast_allowed(r, new_r, true))
        {
            return registry::operator_result(name, Some(new_l), new_r)
                .ok_or_else(PolicyError::unsupported);
        }
        Err(PolicyError::unsupported())
    }
    fn common(&mut self, types: &[Ty]) -> Result<u32> {
        let known: Vec<_> = types.iter().filter_map(|ty| self.known(*ty)).collect();
        let target = known.first().copied().unwrap_or(25);
        if known.iter().any(|oid| *oid != target) {
            return Err(PolicyError::unsupported());
        }
        for ty in types {
            self.constrain(*ty, target, true)?;
        }
        Ok(target)
    }
    fn column(&self, node: &nodes::ColumnRef, scope: &Scope) -> Result<u32> {
        let parts = node
            .fields()
            .into_iter()
            .map(|part| part.as_str().ok_or_else(PolicyError::unsupported))
            .collect::<Result<Vec<_>>>()?;
        let (qualifier, name) = match parts.as_slice() {
            [name] => (None, *name),
            [source, name] => (Some(*source), *name),
            _ => return Err(PolicyError::unsupported()),
        };
        for sources in std::iter::once(&scope.sources).chain(scope.outer.iter()) {
            let found: Vec<_> = sources
                .iter()
                .filter(|source| qualifier.is_none_or(|q| source.name == q))
                .flat_map(|source| source.columns.iter())
                .filter(|(n, _)| n == name)
                .map(|(_, oid)| *oid)
                .collect();
            match found.as_slice() {
                [oid] => return Ok(*oid),
                [] => (),
                _ => return Err(PolicyError::unsupported()),
            }
            if qualifier.is_some_and(|q| sources.iter().any(|source| source.name == q)) {
                return Err(PolicyError::unsupported());
            }
        }
        Err(PolicyError::unsupported())
    }
    fn expression(&mut self, node: Node<'_>, scope: &Scope) -> Result<Ty> {
        let oid = match node {
            Node::A_Const(value) => match value.val() {
                None | Some(ConstValue::String(_)) => return Ok(Ty::Unknown),
                Some(ConstValue::Integer(_)) => 23,
                Some(ConstValue::Float(text)) => {
                    if text.parse::<i32>().is_ok() {
                        23
                    } else if text.parse::<i64>().is_ok() {
                        20
                    } else {
                        1700
                    }
                }
                Some(ConstValue::Boolean(_)) => 16,
                _ => return Err(PolicyError::unsupported()),
            },
            Node::ColumnRef(column) => self.column(column, scope)?,
            Node::ParamRef(param)
                if param.number > 0 && (param.number as usize) <= self.parameters.len() =>
            {
                return Ok(Ty::Parameter(param.number as usize - 1));
            }
            Node::TypeCast(cast) => {
                let target = cast.type_name().ok_or_else(PolicyError::unsupported)?;
                if !target.array_bounds().is_empty() || target.pct_type {
                    return Err(PolicyError::unsupported());
                }
                for modifier in target.typmods().iter() {
                    if !matches!(modifier, Node::A_Const(c) if c.val().and_then(|v| v.numeric_value::<i32>()).is_some())
                    {
                        return Err(PolicyError::unsupported());
                    }
                }
                let parts: Vec<_> = target
                    .names()
                    .iter()
                    .filter_map(|name| name.sval())
                    .collect();
                let name = match parts.as_slice() {
                    [name] | ["pg_catalog", name] => *name,
                    _ => return Err(PolicyError::unsupported()),
                };
                let target = registry::type_oid(name).ok_or_else(PolicyError::unsupported)?;
                let source = self.expression(cast.arg(), scope)?;
                self.constrain(source, target, false)?
            }
            Node::A_Expr(expr) => {
                let parts: Vec<_> = expr.name().iter().filter_map(Node::as_str).collect();
                let name = match parts.as_slice() {
                    [name] | ["pg_catalog", name] => *name,
                    _ => return Err(PolicyError::unsupported()),
                };
                let right = self.expression(expr.rexpr(), scope)?;
                if matches!(expr.lexpr(), Node::None) {
                    let right = self.output(right)?;
                    registry::operator_result(name, None, right)
                        .ok_or_else(PolicyError::unsupported)?
                } else {
                    let left = self.expression(expr.lexpr(), scope)?;
                    let result = self.comparison(name, left, right)?;
                    if expr.kind == nodes::A_Expr_Kind::AEXPR_NULLIF {
                        if result != 16 {
                            return Err(PolicyError::unsupported());
                        }
                        let left = self.known(left).or_else(|| self.known(right)).unwrap_or(25);
                        let right = self.known(right).unwrap_or(left);
                        if left == 1043
                            && registry::operator_result(name, Some(left), right).is_none()
                        {
                            25
                        } else {
                            left
                        }
                    } else if expr.kind == nodes::A_Expr_Kind::AEXPR_OP {
                        result
                    } else {
                        return Err(PolicyError::unsupported());
                    }
                }
            }
            Node::FuncCall(function) => {
                let parts: Vec<_> = function
                    .funcname()
                    .iter()
                    .filter_map(Node::as_str)
                    .collect();
                let name = match parts.as_slice() {
                    [name] | ["pg_catalog", name] => *name,
                    _ => return Err(PolicyError::unsupported()),
                };
                let mut arguments = Vec::new();
                for arg in function.args().iter() {
                    let ty = self.expression(arg, scope)?;
                    arguments.push(self.output(ty)?);
                }
                registry::aggregate_result(name, &arguments, function.agg_star)
                    .ok_or_else(PolicyError::unsupported)?
            }
            Node::BoolExpr(expr) => {
                for arg in expr.args().iter() {
                    let ty = self.expression(arg, scope)?;
                    self.constrain(ty, 16, true)?;
                }
                16
            }
            Node::NullTest(expr) => {
                let ty = self.expression(expr.arg(), scope)?;
                self.output(ty)?;
                16
            }
            Node::BooleanTest(expr) => {
                let ty = self.expression(expr.arg(), scope)?;
                self.constrain(ty, 16, true)?;
                16
            }
            Node::CoalesceExpr(expr) => {
                let mut types = Vec::new();
                for arg in expr.args().iter() {
                    types.push(self.expression(arg, scope)?);
                }
                self.common(&types)?
            }
            Node::CaseExpr(expr) => {
                let test = if matches!(expr.arg(), Node::None) {
                    None
                } else {
                    Some(self.expression(expr.arg(), scope)?)
                };
                let mut results = Vec::new();
                for branch in expr.args().iter() {
                    let Node::CaseWhen(branch) = branch else {
                        return Err(PolicyError::unsupported());
                    };
                    let when = self.expression(branch.expr(), scope)?;
                    if let Some(test) = test {
                        if self.comparison("=", test, when)? != 16 {
                            return Err(PolicyError::unsupported());
                        }
                    } else {
                        self.constrain(when, 16, true)?;
                    }
                    results.push(self.expression(branch.result(), scope)?);
                }
                if !matches!(expr.defresult(), Node::None) {
                    results.push(self.expression(expr.defresult(), scope)?);
                }
                self.common(&results)?
            }
            Node::SubLink(link) => {
                let Node::SelectStmt(select) = link.subselect() else {
                    return Err(PolicyError::unsupported());
                };
                let mut child = Scope {
                    ctes: scope.ctes.clone(),
                    ..Default::default()
                };
                child.outer.push(scope.sources.clone());
                child.outer.extend(scope.outer.clone());
                let output = self.select(select, child)?;
                match link.sub_link_type {
                    nodes::SubLinkType::EXISTS_SUBLINK => 16,
                    nodes::SubLinkType::EXPR_SUBLINK if output.len() == 1 => output[0].1,
                    _ => return Err(PolicyError::unsupported()),
                }
            }
            _ => return Err(PolicyError::unsupported()),
        };
        if !registry::scalar_type(oid) {
            return Err(PolicyError::unsupported());
        }
        Ok(Ty::Known(oid))
    }

    fn resolve_source(&mut self, node: Node<'_>, scope: &Scope) -> Result<Vec<Source>> {
        match node {
            Node::RangeVar(table) => {
                let name = table.relname().ok_or_else(PolicyError::unsupported)?;
                let columns = if table.schemaname().is_none() && scope.ctes.contains_key(name) {
                    scope.ctes[name].clone()
                } else {
                    let key = table
                        .schemaname()
                        .map(|schema| format!("{}.{}", quote(schema), quote(name)))
                        .unwrap_or_else(|| quote(name));
                    self.catalog
                        .relations
                        .get(&key)
                        .ok_or_else(PolicyError::unsupported)?
                        .columns
                        .iter()
                        .map(|column| (column.name.clone(), column.type_oid))
                        .collect()
                };
                let mut source = Source {
                    name: name.to_owned(),
                    columns,
                };
                if let Some(alias) = table.alias() {
                    alias_source(&mut source, alias)?;
                }
                Ok(vec![source])
            }
            Node::RangeSubselect(subselect) => {
                let Node::SelectStmt(select) = subselect.subquery() else {
                    return Err(PolicyError::unsupported());
                };
                let mut child = Scope {
                    ctes: scope.ctes.clone(),
                    outer: scope.outer.clone(),
                    ..Default::default()
                };
                if subselect.lateral {
                    child.outer.insert(0, scope.sources.clone());
                }
                let mut source = Source {
                    name: String::new(),
                    columns: self.select(select, child)?,
                };
                if let Some(alias) = subselect.alias() {
                    alias_source(&mut source, alias)?;
                }
                Ok(vec![source])
            }
            Node::JoinExpr(join) => {
                if join.is_natural
                    || !join.using_clause().is_empty()
                    || join.join_using_alias().is_some()
                {
                    return Err(PolicyError::unsupported());
                }
                let mut joined = self.resolve_source(join.larg(), scope)?;
                let mut right_scope = scope.clone();
                right_scope.sources.extend(joined.clone());
                joined.extend(self.resolve_source(join.rarg(), &right_scope)?);
                let mut proof_scope = scope.clone();
                proof_scope.sources.extend(joined.clone());
                if !matches!(join.quals(), Node::None) {
                    let condition = self.expression(join.quals(), &proof_scope)?;
                    self.constrain(condition, 16, true)?;
                }
                if let Some(alias) = join.alias() {
                    let mut source = Source {
                        name: String::new(),
                        columns: joined
                            .into_iter()
                            .flat_map(|source| source.columns)
                            .collect(),
                    };
                    alias_source(&mut source, alias)?;
                    Ok(vec![source])
                } else {
                    Ok(joined)
                }
            }
            _ => Err(PolicyError::unsupported()),
        }
    }

    fn select(
        &mut self,
        select: &nodes::SelectStmt,
        mut scope: Scope,
    ) -> Result<Vec<(String, u32)>> {
        if let Some(with) = select.with_clause() {
            if with.recursive {
                return Err(PolicyError::unsupported());
            }
            for cte in with.ctes().iter() {
                let name = cte.ctename().ok_or_else(PolicyError::unsupported)?;
                let Node::SelectStmt(query) = cte.ctequery() else {
                    return Err(PolicyError::unsupported());
                };
                let mut columns = self.select(
                    query,
                    Scope {
                        ctes: scope.ctes.clone(),
                        outer: scope.outer.clone(),
                        ..Default::default()
                    },
                )?;
                for (index, alias) in cte.aliascolnames().iter().enumerate() {
                    columns
                        .get_mut(index)
                        .ok_or_else(PolicyError::unsupported)?
                        .0 = alias.as_str().ok_or_else(PolicyError::unsupported)?.into();
                }
                if scope.ctes.insert(name.to_owned(), columns).is_some() {
                    return Err(PolicyError::unsupported());
                }
            }
        }
        let mut output = Vec::new();
        if select.op != nodes::SetOperation::SETOP_NONE {
            let left = self.select(
                select.larg().ok_or_else(PolicyError::unsupported)?,
                scope.clone(),
            )?;
            let right = self.select(
                select.rarg().ok_or_else(PolicyError::unsupported)?,
                scope.clone(),
            )?;
            if left.len() != right.len() {
                return Err(PolicyError::unsupported());
            }
            for ((name, l), (_, r)) in left.into_iter().zip(right) {
                if l != r {
                    return Err(PolicyError::unsupported());
                }
                output.push((name, l));
            }
        } else {
            if !select.values_lists().is_empty() {
                return Err(PolicyError::unsupported());
            }
            for from in select.from_clause().iter() {
                let sources = self.resolve_source(from, &scope)?;
                scope.sources.extend(sources);
            }
            for target in select.target_list().iter() {
                if let Node::ColumnRef(column) = target.val() {
                    let fields: Vec<_> = column.fields().iter().collect();
                    if matches!(fields.last(), Some(Node::A_Star(_))) {
                        let sources: Vec<_> = match fields.as_slice() {
                            [Node::A_Star(_)] => scope.sources.iter().collect(),
                            [Node::String(name), Node::A_Star(_)] => scope
                                .sources
                                .iter()
                                .filter(|source| Some(source.name.as_str()) == name.sval())
                                .collect(),
                            _ => return Err(PolicyError::unsupported()),
                        };
                        if sources.is_empty() {
                            return Err(PolicyError::unsupported());
                        }
                        output.extend(sources.iter().flat_map(|source| source.columns.clone()));
                        continue;
                    }
                }
                let ty = self.expression(target.val(), &scope)?;
                let name = target
                    .name()
                    .map(str::to_owned)
                    .unwrap_or_else(|| match target.val() {
                        Node::ColumnRef(column) => column
                            .fields()
                            .iter()
                            .next_back()
                            .and_then(Node::as_str)
                            .unwrap_or("?column?")
                            .to_owned(),
                        Node::FuncCall(function) => function
                            .funcname()
                            .iter()
                            .next_back()
                            .and_then(Node::as_str)
                            .unwrap_or("?column?")
                            .to_owned(),
                        _ => "?column?".to_owned(),
                    });
                output.push((name, self.output(ty)?));
            }
            for condition in [select.where_clause(), select.having_clause()] {
                if !matches!(condition, Node::None) {
                    let ty = self.expression(condition, &scope)?;
                    self.constrain(ty, 16, true)?;
                }
            }
            for group in select.group_clause().iter() {
                self.sort_expression(group, &scope, &output, false)?;
            }
            for distinct in select.distinct_clause().iter() {
                if !matches!(distinct, Node::None) {
                    self.sort_expression(distinct, &scope, &output, true)?;
                }
            }
        }
        for sort in select.sort_clause().iter() {
            if !sort.use_op().is_empty() {
                return Err(PolicyError::unsupported());
            }
            self.sort_expression(sort.node(), &scope, &output, true)?;
        }
        for limit in [select.limit_offset(), select.limit_count()] {
            if !matches!(limit, Node::None) {
                let ty = self.expression(limit, &scope)?;
                self.constrain(ty, 20, true)?;
            }
        }
        Ok(output)
    }
    fn sort_expression(
        &mut self,
        node: Node<'_>,
        scope: &Scope,
        output: &[(String, u32)],
        prefer_output: bool,
    ) -> Result<()> {
        if let Node::A_Const(constant) = node
            && let Some(ConstValue::Integer(index)) = constant.val()
        {
            if index > 0 && index as usize <= output.len() {
                return Ok(());
            }
            return Err(PolicyError::unsupported());
        }
        if let Node::ColumnRef(column) = node {
            let fields: Vec<_> = column.fields().iter().collect();
            if let [Node::String(name)] = fields.as_slice() {
                let candidates: Vec<_> = output
                    .iter()
                    .filter(|(column, _)| Some(column.as_str()) == name.sval())
                    .collect();
                if prefer_output || self.column(column, scope).is_err() {
                    if candidates.len() == 1 {
                        return Ok(());
                    }
                    if candidates.len() > 1 {
                        return Err(PolicyError::unsupported());
                    }
                }
            }
        }
        let ty = self.expression(node, scope)?;
        self.output(ty)?;
        Ok(())
    }
}
fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
fn alias_source(source: &mut Source, alias: &nodes::Alias) -> Result<()> {
    source.name = alias
        .aliasname()
        .ok_or_else(PolicyError::unsupported)?
        .into();
    for (index, name) in alias.colnames().iter().enumerate() {
        source
            .columns
            .get_mut(index)
            .ok_or_else(PolicyError::unsupported)?
            .0 = name.as_str().ok_or_else(PolicyError::unsupported)?.into();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::read_policy::admit_sql;
    fn catalog() -> CatalogSnapshot {
        CatalogSnapshot {
            server_major: 18,
            transaction_generation: 1,
            database_oid: 1,
            role_oid: 2,
            connection: crate::net::BackendPid::for_test(3),
            search_path: vec!["pg_catalog".into(), "public".into()],
            role: super::super::rows::RoleRow::from(crate::net::DataRow::new()),
            relations: BTreeMap::new(),
        }
    }
    #[test]
    fn strict_read_typed_resolution_accepts_closed_scalar_operations_and_scopes() {
        for sql in [
            "SELECT 1",
            "SELECT 1+2",
            "SELECT 'a'::text || 'b'::text",
            "SELECT -2147483648",
            "SELECT COALESCE(NULL::int4, 2)",
            "SELECT NULLIF(NULL, 1)",
            "SELECT CASE WHEN 1=1 THEN 2 ELSE 3 END",
            "SELECT CASE 1 WHEN 1 THEN 2 ELSE 3 END",
            "SELECT count(*)",
            "SELECT sum(1)",
            "SELECT avg(1)",
            "SELECT min(1), max(2)",
            "WITH q AS (SELECT 1 AS id) SELECT id FROM q",
            "SELECT x.id FROM (SELECT 1 AS id) x",
            "SELECT (SELECT 1)",
            "SELECT EXISTS(SELECT 1)",
            "SELECT 1 UNION SELECT 2",
            "SELECT $1::int4",
            "SELECT $1::int4 + $2::int4",
            "SELECT 1 WHERE 1=$1",
            "SELECT 1 LIMIT 1 OFFSET 0",
            "SELECT 1::integer, 1::smallint, 1::bigint, 1::decimal, 1::real, true::boolean",
            "SELECT $1::integer",
            "SELECT 'a'::char(1)",
        ] {
            let admitted = admit_sql(sql).unwrap();
            assert!(
                prove(&admitted, &catalog(), &[]).is_ok(),
                "did not resolve {sql}"
            );
        }
    }
    #[test]
    fn strict_read_typed_resolution_denies_unknown_and_ambiguous_type_inference() {
        for (sql, oids) in [
            ("SELECT $1", vec![]),
            ("SELECT $1 + $2", vec![]),
            ("SELECT $1::int4", vec![50_001]),
            ("SHOW transaction_read_only", vec![50_001]),
            (
                "SELECT id FROM (SELECT 1 AS id) a JOIN (SELECT 2 AS id) b ON a.id=b.id",
                vec![],
            ),
            ("SELECT a FROM (SELECT 1 AS id) a", vec![]),
            ("SELECT sum('untyped')", vec![]),
            ("SELECT $1025::int4", vec![]),
            ("SELECT 1", vec![23; 1_025]),
            ("SHOW transaction_read_only", vec![23; 1_025]),
        ] {
            assert!(
                prove(&admit_sql(sql).unwrap(), &catalog(), &oids).is_err(),
                "accepted {sql}"
            );
        }
    }
}
