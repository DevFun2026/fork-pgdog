# Fork container and Helm operations

The source Dockerfile is `applications/pgdog/Dockerfile`, the chart is
`charts/fork-pgdog`, the image destination is `ghcr.io/devfun2026/fork-pgdog`,
and the chart destination is `oci://ghcr.io/devfun2026/charts/fork-pgdog`.
Registry distribution requires the first approved publication; local source
builds and chart installation with a locally available image work beforehand.
No official PgDog image, base package or chart is required. PostgreSQL backends
remain operator-owned. Rust crates/Git dependencies and OS/PGDG package repositories
are still build dependencies; this change does not vendor them.

## Build and verify locally

From the repository root:

```sh
docker build -f applications/pgdog/Dockerfile -t fork-pgdog:local .
python3 -m pip install -r tests/artifacts/requirements.txt
python3 scripts/verify-artifacts chart --values charts/fork-pgdog/examples/values.yaml
bash scripts/helm-smoke.sh --image fork-pgdog:local
```

For an immutable source build, supply `--build-arg PGDOG_BUILD_REVISION=<full-40-hex-SHA>`.
Docker excludes Git and private host files. Version falls back to Cargo's package
version without a supplied revision. Use a clean committed candidate for release;
a dirty checkout with a HEAD label is only a local test image. The full-LTO release
build exceeded Docker's 4 GB limit locally and passed with 12 GB. The image runs
UID/GID 10001, includes CA certificates, PostgreSQL 18 client tools and the native
primary-only-tables plugin, and uses SIGINT for graceful drain. `FEATURES=fips`
is supported as a build input, but FIPS runtime validation remains separate.

Linux amd64 and arm64 are the published platform targets. The inherited arm64
`+lse` compiler flag requires a CPU supporting Arm LSE. Native CI must verify
each platform; a local arm64 result does not establish an amd64 result.
The smoke harness creates a unique Kind cluster with a private kubeconfig and
loopback-only API server, then deletes only that cluster. It never selects or
changes the user's existing Kubernetes context. Do not run upstream database
fixture setup against shared databases.

## Operator inputs and installation

Use an explicit context/namespace chosen by your operator process. Prepare
`users.toml` as a protected local file. Its Secret must contain the key
`users.toml`; configuration objects must contain `pgdog.toml`.

```sh
kubectl --context YOUR_CONTEXT --namespace pgdog create secret generic pgdog-users --from-file=users.toml=/protected/path/users.toml
```

Copy `charts/fork-pgdog/examples/values.yaml` into your protected operator values,
replace the synthetic backend with your own primary/replica/shard topology,
and set `users.existingSecret` to your Secret. Exactly one of
`config.pgdogToml`, `config.existingConfigMap` or `config.existingSecret` is required.
Unknown values fail schema validation. Plaintext passwords/tokens belong in
existing Secrets; the local TOML validator rejects credential-bearing inline
configuration. Avoid credentials in command arguments, committed values or logs.

```sh
python3 scripts/verify-artifacts chart --values operator-values.yaml
helm upgrade --install pgdog ./charts/fork-pgdog --kube-context YOUR_CONTEXT --namespace pgdog -f operator-values.yaml --wait --timeout 5m
```

The image must be available to the cluster. Before registry publication, load
`fork-pgdog:local` into your development Kind cluster and set
`image.repository=fork-pgdog`, `image.tag=local`, `image.pullPolicy=Never`.
For production use the approved published chart version; published charts pin
the combined image digest, which overrides `image.tag` for PgDog and configcheck.
Changing the tag alone cannot change a digest-pinned deployment.

```sh
helm upgrade --install pgdog oci://ghcr.io/devfun2026/charts/fork-pgdog --version APPROVED_CHART_VERSION --kube-context YOUR_CONTEXT --namespace pgdog -f operator-values.yaml --wait --timeout 5m
```

For private charts, use `helm registry login ghcr.io --password-stdin` with your
registry credential handling process. For private images, provision an existing
registry Secret and set `imagePullSecrets: [{name: your-pull-secret}]` in values.
An authenticated Helm client does not automatically authenticate Kubernetes image pulls.
Public visibility is an explicit registry administration decision.

## TLS, networking and resource policy

An optional `tls.existingSecret` mounts its files at `/etc/pgdog/tls`, read-only,
with group access for UID/GID 10001. Configure PgDog certificate/key file paths
against that mount, and backend TLS verification in your protected TOML.
The chart does not issue certificates or enforce production NetworkPolicies.
Operators own client/backend TLS, certificate rotation, Secret RBAC, network
isolation, ingress and any external Service exposure. Default Service is
ClusterIP:6432; HTTP health port 9090 is not exposed by the Service.

Pod/root/init hardening includes read-only root, all capabilities dropped,
RuntimeDefault seccomp, no privilege escalation and no ServiceAccount token.
Only `/tmp` is writable via a bounded 64Mi emptyDir. Configuration/users/TLS
are read-only mounts. Resource defaults are requests 100m/128Mi and limits 1 CPU/512Mi;
size them against measured connections and workloads. Linux scheduling,
replicas, affinity/tolerations and bounded probe timings are configurable.
Fixed selector/checksum metadata cannot be overridden.

## Probes, drain and configuration rollout

The configcheck initContainer uses the same image, arguments and mounts as PgDog.
Malformed TOML or missing Secrets prevent startup. Helm cannot inspect the contents
of an external Secret/ConfigMap; configcheck and actual runtime tests cover that boundary.
Align TOML `general.port` and `healthcheck_port` with container ports and bind
`general.host = "0.0.0.0"`. Startup and liveness check the TCP listener;
readiness checks the HTTP backend-aware endpoint. Backend outages remove readiness
while keeping liveness stable, permitting recovery without a restart loop.

The example uses shutdown_timeout=120000 ms plus a finite
shutdown_termination_timeout=10000 ms. Pod termination grace is 150 seconds,
leaving a margin. Set an explicit finite termination timeout and keep their sum
below the Pod grace. Kubernetes must honor the image SIGINT stop signal; compatibility
outside tested versions needs runtime verification. Force deletion bypasses drain.

Inline configuration changes alter `checksum/config` and roll Pods on Helm upgrade.
External Secret/ConfigMap content changes require an explicit operator rollout:

```sh
kubectl --context YOUR_CONTEXT --namespace pgdog rollout restart deployment/pgdog-fork-pgdog
kubectl --context YOUR_CONTEXT --namespace pgdog rollout status deployment/pgdog-fork-pgdog --timeout=5m
```

Helm rollback restores chart-managed values/configuration. It does not restore
externally owned Secret/ConfigMap contents or database changes. Preserve previous
external object versions through your Secret/configuration management process.
This stateless Deployment does not provide durable per-replica 2PC WAL or
storage recovery guarantees. Do not rely on it for durable 2PC recovery; that
requires a separate storage/deployment design. Back up databases through your
existing database process; the chart creates no database/schema migration.
