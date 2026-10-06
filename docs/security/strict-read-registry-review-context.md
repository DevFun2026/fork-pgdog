# Source-bound registry review context

This supplemental context links the pinned PostgreSQL catalog snapshot to the
strict endpoint's type gates. Catalog rows are not an allowlist for every
function or operator they describe. The `PUBLIC_SCALARS` list excludes `inet`
(OID 869) and `tid` (OID 27); parameter, cast, result and relation-column checks
use the same type gate.

The complete implementation remains in the review's full diff and child ranges;
these excerpts supplement that review rather than replace its source coverage.
Each entry below binds a full source file SHA-256 and inclusive line ranges.
`test_registry_review_context.py` checks both the complete source hashes and the
exact excerpt bytes, so any source change requires refreshing this context.

```json
[
  {
    "path": "applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs",
    "sha256": "86706d01ce1095b8f34cbb51a334244f2ebb5f893d99a72843566c06dc935f45",
    "ranges": [
      {
        "start": 190,
        "end": 241
      }
    ]
  },
  {
    "path": "applications/pgdog/pgdog/src/backend/schema/read_policy/resolve.rs",
    "sha256": "6c59b7895e998ee9d0717f7250791b2fb0d871846ab49ed8671be469917729ed",
    "ranges": [
      {
        "start": 31,
        "end": 89
      },
      {
        "start": 119,
        "end": 126
      },
      {
        "start": 230,
        "end": 253
      }
    ]
  },
  {
    "path": "applications/pgdog/pgdog/src/backend/schema/read_policy/rows.rs",
    "sha256": "34e8f55f0047a7f0832ce52bf0e137f094229273bcc4200ec2f8f5b510f8b3ab",
    "ranges": [
      {
        "start": 114,
        "end": 134
      }
    ]
  },
  {
    "path": "applications/pgdog/pgdog/src/backend/schema/read_policy/mod.rs",
    "sha256": "d49c48e41df5d42fbac3b0303d0ff6a077c5d53f46ad04c5265e27e5d4f89506",
    "ranges": [
      {
        "start": 339,
        "end": 349
      },
      {
        "start": 466,
        "end": 472
      }
    ]
  }
]
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs:190-241

```rust
pub(crate) fn scalar_type(oid: u32) -> bool {
    const PUBLIC_SCALARS: &[u32] = &[
        16, 17, 20, 21, 23, 25, 700, 701, 1042, 1043, 1082, 1083, 1114, 1184, 1186, 1266, 1700,
        2950,
    ];
    PUBLIC_SCALARS.contains(&oid)
        && row_by_oid("pg_type", oid).is_some_and(|row| {
            field_number(row, "typnamespace") == Some(11)
                && row.get("typtype").and_then(Value::as_str) == Some("b")
                && field_number(row, "typbasetype") == Some(0)
        })
}

pub(crate) fn trusted_type_io(
    oid: u32,
    name: &str,
    input: u32,
    output: u32,
    receive: u32,
    send: u32,
    collation: u32,
) -> bool {
    scalar_type(oid)
        && row_by_oid("pg_type", oid).is_some_and(|row| {
            row.get("typname").and_then(Value::as_str) == Some(name)
                && field_number(row, "typinput") == Some(input)
                && field_number(row, "typoutput") == Some(output)
                && field_number(row, "typreceive") == Some(receive)
                && field_number(row, "typsend") == Some(send)
                && field_number(row, "typcollation") == Some(collation)
        })
}

pub(crate) fn type_oid(name: &str) -> Option<u32> {
    let mut parts = name.split('.').map(|part| part.trim_matches('"'));
    let (schema, name) = match (parts.next()?, parts.next(), parts.next()) {
        (name, None, None) => ("pg_catalog", name),
        ("pg_catalog", Some(name), None) => ("pg_catalog", name),
        _ => return None,
    };
    if schema != "pg_catalog" {
        return None;
    }
    table("pg_type")?
        .iter()
        .find(|row| {
            row.get("typname").and_then(Value::as_str) == Some(name)
                && field_number(row, "typnamespace") == Some(11)
                && field_number(row, "oid").is_some_and(scalar_type)
        })
        .and_then(|row| field_number(row, "oid"))
}
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/resolve.rs:31-89

```rust
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
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/resolve.rs:119-126

```rust
    fn output(&mut self, ty: Ty) -> Result<u32> {
        match self.known(ty) {
            Some(oid) if registry::scalar_type(oid) => Ok(oid),
            None if ty == Ty::Unknown => Ok(25),
            _ => Err(PolicyError::unsupported()),
        }
    }
    fn comparison(&mut self, name: &str, left: Ty, right: Ty) -> Result<u32> {
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/resolve.rs:230-253

```rust
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
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/rows.rs:114-134

```rust
impl ColumnRow {
    pub(crate) fn is_supported(&self) -> bool {
        self.valid
            && !self.name.is_empty()
            && self.type_schema == "pg_catalog"
            && self.type_kind == "b"
            && self.base_type_oid == 0
            && self.generated.is_empty()
            && self.identity.is_empty()
            && crate::backend::schema::read_policy::registry::trusted_type_io(
                self.type_oid,
                &self.type_name,
                self.type_input_oid,
                self.type_output_oid,
                self.type_receive_oid,
                self.type_send_oid,
                self.collation_oid,
            )
            && (self.collation_oid == 0 || matches!(self.collation_oid, 100 | 950 | 951))
    }
}
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/mod.rs:339-349

```rust
            let relation_id = BindParameter::new(relation.oid.to_string().as_bytes());
            let columns = server
                .fetch_all::<ColumnRow>(ServerRequest::strict_internal(
                    catalog_query(3),
                    std::slice::from_ref(&relation_id),
                ))
                .await
                .map_err(|_| PolicyError::unsupported())?;
            if columns.is_empty() || columns.iter().any(|column| !column.is_supported()) {
                return Err(PolicyError::unsupported());
            }
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/mod.rs:466-472

```rust
        // Every column is checked, not just referenced columns: row/tuple
        // expansion and planner dependency paths cannot hide custom types.
        if relation.columns.iter().any(|column| !column.is_supported()) {
            return Err(PolicyError::unsupported());
        }
    }
    resolve::prove(admitted, catalog, parameter_oids)?;
```
