# Source-bound registry review context

This supplemental context links the separately pinned PostgreSQL 12/18 catalog snapshots to the
strict endpoint's type gates. Catalog rows are not an allowlist for every
function or operator they describe. The `PUBLIC_SCALARS` list excludes `inet`
(OID 869) and `tid` (OID 27); parameter, cast, result and relation-column checks
use the same type gate. The snapshot also retains unsupported geometric and
internal catalog rows; those rows are not authorized operations.

SQL admission checks structured TypeName components against exact built-in
names before catalog resolution. A quoted single identifier containing a dot
is rejected; two separately qualified pg_catalog/type components remain valid.
The resolver helper receives an exact base identifier and does not reparse it.
Parameter references are held in a BTreeSet, so last() is the maximum index
regardless of AST traversal order.

The complete implementation remains in the review's full diff and child ranges;
these excerpts supplement that review rather than replace its source coverage.
Each entry below binds a full source file SHA-256 and inclusive line ranges.
`test_registry_review_context.py` checks both the complete source hashes and the
exact excerpt bytes, so any source change requires refreshing this context.

```json
[
  {
    "path": "applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs",
    "sha256": "ae11d01c544fa50a4b1fb72c8931b45ff1a71f34281dec55ad4dab6ec25e2ae4",
    "ranges": [
      {
        "start": 33,
        "end": 65
      },
      {
        "start": 185,
        "end": 228
      }
    ]
  },
  {
    "path": "applications/pgdog/pgdog/src/backend/schema/read_policy/resolve.rs",
    "sha256": "fec51b7c5708f16c0cece3223d0da0b62fba0ed6c6f17986f7db39078cac8819",
    "ranges": [
      {
        "start": 31,
        "end": 89
      },
      {
        "start": 99,
        "end": 125
      },
      {
        "start": 245,
        "end": 259
      }
    ]
  },
  {
    "path": "applications/pgdog/pgdog/src/backend/schema/read_policy/rows.rs",
    "sha256": "2003ff60ab68e4cf7ea29e322105a92a33821e478dac2f4b025b6959f01b94e4",
    "ranges": [
      {
        "start": 115,
        "end": 132
      }
    ]
  },
  {
    "path": "applications/pgdog/pgdog/src/backend/schema/read_policy/mod.rs",
    "sha256": "bdb4f958b8b7c20f8e41fabcf00d846b64f5f0962a9dccb1468612328fc04165",
    "ranges": [
      {
        "start": 417,
        "end": 443
      },
      {
        "start": 447,
        "end": 467
      }
    ]
  },
  {
    "path": "applications/pgdog/pgdog/src/frontend/read_policy/admission.rs",
    "sha256": "6942e77283d48a9bb6e2dbd9447b099a03fb3d9c2ef230a7e16de0b0c916410d",
    "ranges": [
      {
        "start": 38,
        "end": 55
      },
      {
        "start": 373,
        "end": 382
      },
      {
        "start": 491,
        "end": 533
      }
    ]
  }
]
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs:33-65

```rust
    pub(crate) fn for_major(major: u32) -> Option<Self> {
        let data = match major {
            12 => REGISTRY_PG12
                .get_or_init(|| serde_json::from_str(REGISTRY_PG12_JSON).ok())
                .as_ref()?,
            18 => REGISTRY_PG18
                .get_or_init(|| serde_json::from_str(REGISTRY_PG18_JSON).ok())
                .as_ref()?,
            _ => return None,
        };
        let registry = Self { major, data };
        registry.is_complete().then_some(registry)
    }

    pub(crate) fn major(&self) -> u32 {
        self.major
    }

    fn is_complete(&self) -> bool {
        self.data.get("postgres_major").and_then(Value::as_u64) == Some(self.major.into())
            && self
                .data
                .get("source_image")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            && CATALOG_TABLES.iter().all(|name| {
                self.data
                    .get("tables")
                    .and_then(|t| t.get(name))
                    .and_then(Value::as_array)
                    .is_some_and(|rows| !rows.is_empty())
            })
    }
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs:185-228

```rust
    pub(crate) fn scalar_type(&self, oid: u32) -> bool {
        const PUBLIC_SCALARS: &[u32] = &[
            16, 17, 20, 21, 23, 25, 700, 701, 1042, 1043, 1082, 1083, 1114, 1184, 1186, 1266, 1700,
            2950,
        ];
        PUBLIC_SCALARS.contains(&oid)
            && self.row_by_oid("pg_type", oid).is_some_and(|row| {
                field_number(row, "typnamespace") == Some(11)
                    && row.get("typtype").and_then(Value::as_str) == Some("b")
                    && field_number(row, "typbasetype") == Some(0)
            })
    }

    pub(crate) fn trusted_type_io(
        &self,
        oid: u32,
        name: &str,
        input: u32,
        output: u32,
        receive: u32,
        send: u32,
        collation: u32,
    ) -> bool {
        self.scalar_type(oid)
            && self.row_by_oid("pg_type", oid).is_some_and(|row| {
                row.get("typname").and_then(Value::as_str) == Some(name)
                    && field_number(row, "typinput") == Some(input)
                    && field_number(row, "typoutput") == Some(output)
                    && field_number(row, "typreceive") == Some(receive)
                    && field_number(row, "typsend") == Some(send)
                    && field_number(row, "typcollation") == Some(collation)
            })
    }

    pub(crate) fn type_oid(&self, name: &str) -> Option<u32> {
        self.table("pg_type")?
            .iter()
            .find(|row| {
                row.get("typname").and_then(Value::as_str) == Some(name)
                    && field_number(row, "typnamespace") == Some(11)
                    && field_number(row, "oid").is_some_and(|oid| self.scalar_type(oid))
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
            .any(|oid| *oid != 0 && !catalog.registry.scalar_type(*oid))
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
            if !catalog.registry.scalar_type(*oid) {
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

## applications/pgdog/pgdog/src/backend/schema/read_policy/resolve.rs:99-125

```rust
    fn constrain(&mut self, ty: Ty, target: u32, implicit: bool) -> Result<u32> {
        if !self.catalog.registry.scalar_type(target) {
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
                    if source == target
                        || self.catalog.registry.cast_allowed(source, target, implicit) =>
                {
                    Ok(target)
                }
                _ => Err(PolicyError::unsupported()),
            },
        }
    }
    fn output(&mut self, ty: Ty) -> Result<u32> {
        match self.known(ty) {
            Some(oid) if self.catalog.registry.scalar_type(oid) => Ok(oid),
            None if ty == Ty::Unknown => Ok(25),
            _ => Err(PolicyError::unsupported()),
        }
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/resolve.rs:245-259

```rust
                let parts: Vec<_> = target
                    .names()
                    .iter()
                    .filter_map(|name| name.sval())
                    .collect();
                let name = match parts.as_slice() {
                    [name] | ["pg_catalog", name] => *name,
                    _ => return Err(PolicyError::unsupported()),
                };
                let target = self
                    .catalog
                    .registry
                    .type_oid(name)
                    .ok_or_else(PolicyError::unsupported)?;
                let source = self.expression(cast.arg(), scope)?;
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/rows.rs:115-132

```rust
    pub(crate) fn is_supported(&self, registry: &super::registry::ReadRegistry) -> bool {
        self.valid
            && !self.name.is_empty()
            && self.type_schema == "pg_catalog"
            && self.type_kind == "b"
            && self.base_type_oid == 0
            && self.generated.is_empty()
            && self.identity.is_empty()
            && registry.trusted_type_io(
                self.type_oid,
                &self.type_name,
                self.type_input_oid,
                self.type_output_oid,
                self.type_receive_oid,
                self.type_send_oid,
                self.collation_oid,
            )
            && (self.collation_oid == 0 || matches!(self.collation_oid, 100 | 950 | 951))
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/mod.rs:417-443

```rust
    pub(crate) fn identity(
        &self,
        policy: &ProcessPolicy,
        database_alias: &str,
        transaction_generation: u64,
    ) -> Result<CatalogIdentity, PolicyError> {
        let manifest = policy.manifest().ok_or_else(PolicyError::unsupported)?;
        let database = manifest
            .databases()
            .iter()
            .find(|db| db.name() == database_alias)
            .ok_or_else(PolicyError::unsupported)?;
        Ok(CatalogIdentity {
            backend_database_oid: self.database_oid,
            backend_role_oid: self.role_oid,
            backend_server_major: self.registry.major(),
            connection: self.connection,
            transaction_generation: {
                if transaction_generation != self.transaction_generation {
                    return Err(PolicyError::unsupported());
                }
                self.transaction_generation
            },
            manifest_digest: policy.digest().0,
            schema_revision: manifest.schema_revision().to_owned(),
            database_alias: database.name().to_owned(),
        })
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/mod.rs:447-467

```rust
pub(crate) fn verify_parse(
    policy: &ProcessPolicy,
    admitted: &AdmittedSql,
    catalog: &CatalogSnapshot,
    identity: CatalogIdentity,
    parameter_oids: &[u32],
) -> Result<CatalogProof, PolicyError> {
    if identity.backend_database_oid != catalog.database_oid
        || identity.backend_role_oid != catalog.role_oid
        || identity.backend_server_major != catalog.registry.major()
        || identity.connection != catalog.connection
        || identity.transaction_generation != catalog.transaction_generation
        || identity.manifest_digest != policy.digest().0
        || identity.schema_revision
            != policy
                .manifest()
                .ok_or_else(PolicyError::unsupported)?
                .schema_revision()
    {
        return Err(PolicyError::unsupported());
    }
```

## applications/pgdog/pgdog/src/frontend/read_policy/admission.rs:38-55

```rust
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
```

## applications/pgdog/pgdog/src/frontend/read_policy/admission.rs:373-382

```rust
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
```

## applications/pgdog/pgdog/src/frontend/read_policy/admission.rs:491-533

```rust
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
```
