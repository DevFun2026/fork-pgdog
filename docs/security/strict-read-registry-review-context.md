# Source-bound registry review context

This supplemental context links the separately pinned PostgreSQL 12 and 18 catalog snapshots to strict-read admission, catalog proof, and result handling. Catalog rows provide reference facts; they do not authorize every function or operator they describe. The `PUBLIC_SCALARS` set remains a narrow client-facing type gate for declared parameter OIDs and scalar cast/constraint resolution. The excerpted scalar-column helper also requires an allowed base type with matching catalog I/O OIDs and collation. The full-table relation proof separately validates complete catalog dependencies for expanded projection types, including JSONB, arrays and enums.

Projection has a distinct output check. A result type is allowed when it is in `PUBLIC_SCALARS` or when catalog proof establishes both text and binary output capability. That broader output capability does not widen SQL admission or permit arbitrary catalog functions: admission still restricts type syntax and callable names, and catalog resolution checks the reviewed operator or aggregate implementation.

For `pg_proc` record comparison, the embedded reference contains function-source strings while captured catalog rows carry opaque SHA-256 markers. The reference strings are hashed locally as UTF-8; live `prosrc` and `prosqlbody` values must already be null or a single-field `sha256_utf8` marker with 64 lowercase hexadecimal characters. The captured source is validated as a marker and is never re-hashed as though it were function text.

SQL admission checks structured TypeName components against exact built-in names before catalog resolution. A quoted single identifier containing a dot is rejected; two separately qualified `pg_catalog` and type components remain valid. The resolver receives an exact base identifier and does not reparse it. Parameter references are held in a `BTreeSet`, so `last()` is the maximum index regardless of AST traversal order.

The snapshots retain unsupported geometric and internal catalog rows; their presence does not authorize those types or operations. The excerpts below supplement the review's full source coverage. Each entry binds a complete source-file SHA-256 and inclusive line ranges. `test_registry_review_context.py` checks the complete hashes and exact excerpt bytes, so any source change requires refreshing this context.

```json
[
  {
    "path": "applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs",
    "sha256": "4975618c13ca79d0a14d436539f4013ebe804e1cfad1b26e9913d4098f3c7e78",
    "ranges": [
      {
        "start": 31,
        "end": 36
      },
      {
        "start": 41,
        "end": 53
      },
      {
        "start": 59,
        "end": 73
      },
      {
        "start": 157,
        "end": 167
      },
      {
        "start": 204,
        "end": 215
      },
      {
        "start": 217,
        "end": 227
      },
      {
        "start": 229,
        "end": 238
      },
      {
        "start": 357,
        "end": 406
      }
    ]
  },
  {
    "path": "applications/pgdog/pgdog/src/backend/schema/read_policy/resolve.rs",
    "sha256": "4fae4cd360a2f053777108d81c9ff4f983492938c9c9c55d79f7d078ffb879b1",
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
    "sha256": "560319c5a3c11026f570e3819f9f3cff850486362912d5e84cbfc66b57840ce6",
    "ranges": [
      {
        "start": 216,
        "end": 236
      }
    ]
  },
  {
    "path": "applications/pgdog/pgdog/src/backend/schema/read_policy/mod.rs",
    "sha256": "89ad0d2be46f90cb0ba0d4aaa107e763c0d782de2dc138c1a8dd38361e5ed8b1",
    "ranges": [
      {
        "start": 184,
        "end": 190
      },
      {
        "start": 584,
        "end": 612
      },
      {
        "start": 614,
        "end": 690
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

## applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs:31-36

```rust
pub(crate) struct TypeIo {
    pub(crate) input: u32,
    pub(crate) output: u32,
    pub(crate) receive: u32,
    pub(crate) send: u32,
}
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs:41-53

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
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs:59-73

```rust
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

## applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs:157-167

```rust
    pub(crate) fn exact_catalog_record(&self, table_name: &str, oid: u32, actual: &Value) -> bool {
        self.row_by_oid(table_name, oid).is_some_and(|expected| {
            let Some(expected) = normalize_catalog_record(table_name, expected, true) else {
                return false;
            };
            let Some(actual) = normalize_catalog_record(table_name, actual, false) else {
                return false;
            };
            expected == actual
        })
    }
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs:204-215

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
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs:217-227

```rust
    pub(crate) fn trusted_type_io(&self, oid: u32, name: &str, io: TypeIo, collation: u32) -> bool {
        self.scalar_type(oid)
            && self.row_by_oid("pg_type", oid).is_some_and(|row| {
                row.get("typname").and_then(Value::as_str) == Some(name)
                    && field_number(row, "typinput") == Some(io.input)
                    && field_number(row, "typoutput") == Some(io.output)
                    && field_number(row, "typreceive") == Some(io.receive)
                    && field_number(row, "typsend") == Some(io.send)
                    && field_number(row, "typcollation") == Some(collation)
            })
    }
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs:229-238

```rust
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

## applications/pgdog/pgdog/src/backend/schema/read_policy/registry.rs:357-406

```rust
/// Normalize only the embedded reference's function-source strings. Live rows
/// must already carry the exact opaque hash marker returned by the catalog SQL.
fn normalize_catalog_record(table_name: &str, row: &Value, reference: bool) -> Option<Value> {
    let mut normalized = row.clone();
    if table_name == "pg_proc" {
        let fields = normalized.as_object_mut()?;
        for field in ["prosrc", "prosqlbody"] {
            let Some(value) = fields.get(field) else {
                continue;
            };
            let marker = normalize_source_field(value, reference)?;
            fields.insert(field.to_owned(), marker);
        }
    }
    Some(normalize(&normalized))
}

fn normalize_source_field(value: &Value, reference: bool) -> Option<Value> {
    match value {
        Value::Null => Some(Value::Null),
        Value::String(source) if reference => Some(serde_json::json!({
            "sha256_utf8": sha256_hex(source.as_bytes())
        })),
        Value::Object(marker) if valid_source_marker(marker) => Some(value.clone()),
        _ => None,
    }
}

fn valid_source_marker(marker: &serde_json::Map<String, Value>) -> bool {
    if marker.len() != 1 {
        return false;
    }
    marker
        .get("sha256_utf8")
        .and_then(Value::as_str)
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn sha256_hex(bytes: &[u8]) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
            Some(oid) if self.catalog.output_type(oid) => Ok(oid),
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

## applications/pgdog/pgdog/src/backend/schema/read_policy/rows.rs:216-236

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
                super::registry::TypeIo {
                    input: self.type_input_oid,
                    output: self.type_output_oid,
                    receive: self.type_receive_oid,
                    send: self.type_send_oid,
                },
                self.collation_oid,
            )
            && (self.collation_oid == 0 || matches!(self.collation_oid, 100 | 950 | 951))
    }
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/mod.rs:184-190

```rust
    fn output_type(&self, oid: u32) -> bool {
        self.registry.scalar_type(oid)
            || self
                .proven_types
                .get(&oid)
                .is_some_and(|capability| capability.text_output && capability.binary_output)
    }
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/mod.rs:584-612

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
    }
}
```

## applications/pgdog/pgdog/src/backend/schema/read_policy/mod.rs:614-690

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
    let database = policy
        .manifest()
        .and_then(|manifest| {
            manifest
                .databases()
                .iter()
                .find(|db| db.name() == identity.database_alias)
        })
        .ok_or_else(PolicyError::unsupported)?;
    if !catalog.role.is_safe_application_role()
        || catalog.search_path.first().map(String::as_str) != Some("pg_catalog")
    {
        return Err(PolicyError::unsupported());
    }
    for name in &admitted.catalog.relations {
        let relation = catalog
            .relations
            .get(name)
            .ok_or_else(PolicyError::unsupported)?;
        let fully_proved = catalog
            .full_relations
            .get(&relation.relation.oid)
            .is_some_and(|proof| {
                proof.matches(&relation.relation, &relation.columns)
                    && catalog
                        .dependency_metadata
                        .get("full")
                        .is_some_and(|metadata| proof.matches_metadata(metadata))
            });
        if (!fully_proved && !relation.relation.is_supported_base_table())
            || !relation.indexes_safe
            || !database.relations().iter().any(|expected| {
                expected.schema() == relation.relation.schema
                    && expected.name() == relation.relation.name
            })
        {
            return Err(PolicyError::unsupported());
        }
        // Every column is checked, not just referenced columns: row/tuple
        // expansion and planner dependency paths cannot hide custom types.
        if relation
            .columns
            .iter()
            .any(|column| !fully_proved && !column.is_supported(&catalog.registry))
        {
            return Err(PolicyError::unsupported());
        }
    }
    resolve::prove(admitted, catalog, parameter_oids)?;
    Ok(CatalogProof {
        fingerprint: admitted.fingerprint,
        parameter_oids: parameter_oids.to_vec(),
        identity,
        metadata_digest: catalog.metadata_digest()?,
    })
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
