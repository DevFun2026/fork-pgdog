# Prepare the `icondo` PG12 read and write values

This folder contains a deliberately incomplete operator input for the planned
`0.2.1` chart and a local generator. The input targets namespace `database`,
database and alias `icondo`, and backend
`staging-postgres.database.svc.cluster.local:5432`. It leaves the Kubernetes
context, exact eligible ordinary-table list, controlled schema revision,
backend CA key name, and immutable `0.2.1` image digest as placeholders. The
generator rejects those placeholders until an operator supplies real values.

Copy the input to a protected working directory, fill each placeholder, and
generate the paired values and closed read-policy manifest:

```sh
cp charts/fork-pgdog/examples/strict-read/icondo/operator-input.example.json ./operator-input.json
python3 scripts/generate-strict-read-deploy.py --input ./operator-input.json --output ./generated
```

The output directory must be empty or absent. Generation is local and only
writes `read-values.yaml`, `write-values.yaml`, and `read-policy.toml` there. It
does not inspect or change a Kubernetes context, create resources, contact a
registry, or install a chart. Do not put application passwords, tokens, or
private keys in the JSON input. Authentication passes through to PostgreSQL;
the users Secret can contain only `users = []`.

The input requires PostgreSQL major `12` or `18`, an immutable
`sha256:<64 lowercase hex>` image digest, a concrete context, and a nonempty
unique list of schema-qualified ordinary tables. Use the exact reviewed
inventory for `protected_relations`; do not enter wildcards or views. The
`schema_revision` must identify the controlled migration state reviewed with
that inventory. The backend CA filename must name a key in the client TLS
Secret. That Secret must contain `tls.crt`, `tls.key`, and the CA file; the CA
must validate the configured backend hostname. Client TLS is required and
backend TLS verifies the hostname and CA.

The generator creates disjoint policy values: the read release references the
strict-read ConfigMap and manifest, while the write release is unrestricted.
Both use the same digest, backend, database identity, Secret references, and
TLS configuration. PostgreSQL grants continue to govern write access.

After filling the input, validate both files locally against the chart:

```sh
python3 scripts/verify-artifacts chart --chart charts/fork-pgdog --values ./generated/read-values.yaml
python3 scripts/verify-artifacts chart --chart charts/fork-pgdog --values ./generated/write-values.yaml
```

The `0.2.1` version here is a preparation target. This guide does not publish
an image or chart, create Secrets, apply Kubernetes resources, or install Helm
releases. Perform deployment only after the `0.2.1` artifacts and operator
inputs are reviewed and approved for the explicitly selected cluster context.
