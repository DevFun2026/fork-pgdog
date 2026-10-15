//! AST-aware remapping for private, already-proven stored-expression fixtures.
//!
//! This is test support only. Callers must first verify the source expression
//! against the source catalog proof and use a `pg_catalog`-only search path.

use pg_raw_parse::{Node, make, nodes, transform};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Error;

pub(super) fn remap(
    sql: &str,
    column_names: &BTreeMap<String, String>,
    type_names: &BTreeMap<Vec<String>, Vec<String>>,
) -> Result<String, Error> {
    if sql.is_empty() || sql.len() > 256 * 1024 || sql.contains('\0') {
        return Err(Error);
    }
    let wrapped = format!("SELECT {sql}");
    let parsed = pg_raw_parse::parse(&wrapped).map_err(|_| Error)?;
    let mut statements = parsed.stmts();
    let Some(Node::SelectStmt(select)) = statements.next() else {
        return Err(Error);
    };
    if statements.next().is_some() {
        return Err(Error);
    }
    let targets = select.target_list();
    if targets.len() != 1
        || !select.from_clause().is_empty()
        || !select.distinct_clause().is_empty()
        || select.into_clause().is_some()
        || !matches!(select.where_clause(), Node::None)
        || !select.group_clause().is_empty()
        || !matches!(select.having_clause(), Node::None)
        || !select.window_clause().is_empty()
        || !select.values_lists().is_empty()
        || !select.sort_clause().is_empty()
        || !matches!(select.limit_offset(), Node::None)
        || !matches!(select.limit_count(), Node::None)
        || !select.locking_clause().is_empty()
        || select.with_clause().is_some()
        || select.larg().is_some()
        || select.rarg().is_some()
    {
        return Err(Error);
    }
    let target = targets.first().ok_or(Error)?;
    if target.name().is_some() {
        return Err(Error);
    }

    let mut transform_error = false;
    let rewritten = make::owned(|mem| {
        let mut root = mem.make_unique(select);
        let mut remapper = AstRemapper {
            mem,
            column_names,
            type_names,
            error: false,
        };
        transform::transform_node(root.as_mut().into(), &mut remapper);
        transform_error = remapper.error;
        root
    });
    if transform_error {
        return Err(Error);
    }

    let deparsed = pg_raw_parse::deparse(&*rewritten)
        .map_err(|_| Error)?
        .as_str()
        .to_owned();
    let expression = deparsed.strip_prefix("SELECT").ok_or(Error)?.trim_start();
    if expression.is_empty() {
        return Err(Error);
    }
    Ok(expression.to_owned())
}

struct AstRemapper<'map, 'mem> {
    mem: pg_raw_parse::make::MemoryToken<'mem>,
    column_names: &'map BTreeMap<String, String>,
    type_names: &'map BTreeMap<Vec<String>, Vec<String>>,
    error: bool,
}

impl<'map, 'mem> transform::Transform<'mem> for AstRemapper<'map, 'mem> {
    fn transform_column_ref<'mutref>(&mut self, mut column: nodes::ColumnRefMut<'mem, 'mutref>) {
        let names = column
            .fields()
            .iter()
            .map(|node| match node {
                Node::String(value) => value.sval().map(str::to_owned).ok_or(Error),
                _ => Err(Error),
            })
            .collect::<Result<Vec<_>, _>>();
        let mapped = names.and_then(|names| {
            if names.is_empty() || names.iter().any(|name| name.is_empty()) {
                return Err(Error);
            }
            // A dotted single identifier would be ambiguous with an explicitly
            // qualified reference in the String-keyed remapping contract.
            if names.iter().any(|name| name.contains('.')) {
                return Err(Error);
            }
            let replacement = self.column_names.get(&names.join(".")).ok_or(Error)?;
            split_mapped_name(replacement)
        });
        match mapped {
            Ok(names) => {
                let fields = names
                    .iter()
                    .map(|name| self.mem.make_string(Some(name)).uncast())
                    .collect::<Vec<_>>();
                column.set_fields(self.mem.make_list(&fields));
            }
            Err(_) => self.error = true,
        }
    }

    fn transform_type_name<'mutref>(&mut self, mut ty: nodes::TypeNameMut<'mem, 'mutref>) {
        let names = ty
            .names()
            .iter()
            .map(|part| part.sval().map(str::to_owned).ok_or(Error))
            .collect::<Result<Vec<_>, _>>();
        let mapped = names.and_then(|names| {
            if names.is_empty()
                || names.iter().any(|name| name.is_empty())
                || ty.pct_type
                || ty.setof
            {
                return Err(Error);
            }
            if builtin_type(&names) {
                return Ok(None);
            }
            let mapped = self.type_names.get(&names).cloned().ok_or(Error)?;
            if mapped.iter().any(|name| !valid_identifier(name)) {
                return Err(Error);
            }
            Ok(Some(mapped))
        });
        match mapped {
            Ok(Some(names)) if !names.is_empty() && names.iter().all(|name| !name.is_empty()) => {
                let mut parts = self.mem.cast_empty::<nodes::String>();
                for name in &names {
                    parts
                        .as_mut()
                        .push(self.mem, self.mem.make_string(Some(name)));
                }
                ty.set_names(parts);
            }
            Ok(None) => {}
            _ => self.error = true,
        }
        transform::transform_type_name(ty, self);
    }

    fn transform_sub_link<'mutref>(&mut self, _node: nodes::SubLinkMut<'mem, 'mutref>) {
        self.error = true;
    }
}

fn split_mapped_name(name: &str) -> Result<Vec<String>, Error> {
    let parts = name.split('.').map(str::to_owned).collect::<Vec<_>>();
    if parts.is_empty() || parts.iter().any(|part| !valid_identifier(part)) {
        Err(Error)
    } else {
        Ok(parts)
    }
}

fn valid_identifier(part: &str) -> bool {
    !part.is_empty() && part.len() <= 63 && !part.contains('\0')
}

fn builtin_type(names: &[String]) -> bool {
    let name = match names {
        [name] => name.as_str(),
        [schema, name] if schema == "pg_catalog" => name.as_str(),
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
            | "json"
            | "jsonb"
            | "tsvector"
            | "tsquery"
            | "regconfig"
            | "oid"
            | "name"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maps() -> (BTreeMap<String, String>, BTreeMap<Vec<String>, Vec<String>>) {
        (
            BTreeMap::from([
                ("source_name".to_owned(), "fixture_name".to_owned()),
                (
                    "source_table.source_name".to_owned(),
                    "fixture_table.fixture_name".to_owned(),
                ),
            ]),
            BTreeMap::from([(
                vec!["private_schema".to_owned(), "status_enum".to_owned()],
                vec!["fixture_schema".to_owned(), "status_enum".to_owned()],
            )]),
        )
    }

    #[test]
    fn remaps_identifiers_but_preserves_literal_contents() {
        let (columns, types) = maps();
        let result = remap(
            "lower(source_name::text) = 'source_name private_schema.status_enum' AND source_name::private_schema.status_enum = 'active'",
            &columns,
            &types,
        )
        .expect("known identifiers should remap");

        assert!(result.contains("fixture_name"), "{result}");
        assert!(result.contains("fixture_schema.status_enum"), "{result}");
        assert!(
            result.contains("'source_name private_schema.status_enum'"),
            "{result}"
        );
    }

    #[test]
    fn rejects_unmapped_columns_and_types_and_non_expression_forms() {
        let (columns, types) = maps();
        for sql in [
            "unknown_column = 1",
            "source_name::private_schema.unknown_enum = 'x'",
            "(SELECT source_name FROM source_table)",
            "source_name = 1; SELECT 2",
            "source_name FROM pg_catalog.pg_class",
            "source_name, source_name",
        ] {
            assert!(remap(sql, &columns, &types).is_err(), "accepted {sql}");
        }
    }

    #[test]
    fn qualified_and_quoted_identifiers_require_exact_ast_mapping() {
        let mut columns = BTreeMap::from([
            (
                "source_table.source_name".to_owned(),
                "fixture_table.fixture_name".to_owned(),
            ),
            (
                "odd\"; DROP TABLE users--".to_owned(),
                "safe\"; SELECT pg_sleep(1)--".to_owned(),
            ),
        ]);
        let types = BTreeMap::new();
        let result = remap(
            "source_table.source_name = 'source_table.source_name' AND \"odd\"\"; DROP TABLE users--\" = 'odd\"; DROP TABLE users--'",
            &columns,
            &types,
        )
        .expect("exact mapped identifiers should be rewritten structurally");
        assert!(result.contains("fixture_table.fixture_name"), "{result}");
        assert!(result.contains("safe"), "{result}");
        assert!(result.contains("'source_table.source_name'"), "{result}");
        assert!(result.contains("'odd\"; DROP TABLE users--'"), "{result}");
        assert!(pg_raw_parse::parse(&format!("SELECT {result}")).is_ok());

        columns.remove("source_table.source_name");
        assert!(remap("source_table.source_name = 1", &columns, &types).is_err());
    }
}
