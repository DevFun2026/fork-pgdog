#!/usr/bin/env bash
# Exercise paired strict-read and unrestricted PgDog Services in an owned Kind cluster.
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
image=''
chart="$root/charts/fork-pgdog"
task_dir=''
cluster=''
namespace=''
config=''
context=''
cluster_owned=false
smoke_report=${STRICT_READ_SMOKE_REPORT:-$root/.agent/.runs/artifacts/strict-read-helm-smoke.json}
cleanup() {
  code=$1
  trap - EXIT
  if [[ "$code" != 0 && "$cluster_owned" == true && -n "$task_dir" && -f "$config" && -n "$namespace" ]]; then
    timeout 10s kubectl --kubeconfig "$config" --context "$context" --namespace "$namespace" \
      get pods,endpointslices -o wide > "$task_dir/endpoint-state.log" 2>&1 || true
    for release in pgdog-read pgdog-write; do
      timeout 10s kubectl --kubeconfig "$config" --context "$context" --namespace "$namespace" \
        logs "deployment/$release-fork-pgdog" -c pgdog --tail=60 \
        > "$task_dir/$release.log" 2>&1 || true
    done
  fi
  if [[ "$cluster_owned" == true ]]; then
    if ! timeout 150s kind delete cluster --name "$cluster" --kubeconfig "$config" >/dev/null 2>&1; then
      echo "Cleanup failed for owned cluster $cluster" >&2
      code=1
    fi
  fi
  if [[ "$code" != 0 ]]; then
    mkdir -p "$(dirname "$smoke_report")"
    printf '{"status":"failed","cluster":"%s","exit_code":%s}\n' "$cluster" "$code" \
      > "$smoke_report"
    if [[ -n "$task_dir" && -d "$task_dir" ]]; then
      for log in "$task_dir"/*.log; do
        [[ -f "$log" ]] && { echo "--- $(basename "$log") (last 40 lines) ---" >&2; tail -40 "$log" >&2; }
      done
    fi
  fi
  for child in $(jobs -pr); do kill "$child" 2>/dev/null || true; done
  if [[ -n "$task_dir" ]]; then rm -rf -- "$task_dir"; fi
  exit "$code"
}
trap 'cleanup "$?"' EXIT
while (($#)); do
  case "$1" in
    --image) image=${2:?}; shift 2 ;;
    --chart) chart=${2:?}; shift 2 ;;
    *) echo 'Usage: strict-read-helm-smoke.sh --image IMAGE [--chart PATH]' >&2; exit 2 ;;
  esac
done
[[ -n "$image" && "$image" != -* && "$image" != *@* && "$image" == *:* ]] || {
  echo 'A local tagged image is required' >&2; exit 2;
}
image_repository=${image%:*}
image_tag=${image##*:}
[[ -n "$image_repository" && -n "$image_tag" ]] || { echo 'Image must include a tag' >&2; exit 2; }
[[ -d "$chart" ]] || { echo "Chart directory is missing: $chart" >&2; exit 2; }
for tool in docker kind kubectl helm timeout openssl python3; do
  command -v "$tool" >/dev/null || { echo "Required smoke tool is missing: $tool" >&2; exit 1; }
done
baseline_bin=${STRICT_READ_BASELINE_BIN:-$root/.agent/.runs/strict-read/pgdog-baseline}
baseline_source_sha=${STRICT_READ_BASELINE_SOURCE_SHA:-960942d4254a547d459d44545151f30380ae3173}
[[ "$baseline_source_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'Baseline source must be a full commit SHA' >&2; exit 2; }
[[ -x "$baseline_bin" ]] || { echo "Baseline-source binary is missing: $baseline_bin" >&2; exit 1; }
if baseline_output=$("$baseline_bin" --config /dev/null --users /dev/null \
  --query-policy strict-read --read-policy-file /dev/null configcheck 2>&1); then
  echo 'Baseline-source binary unexpectedly accepted strict-read arguments' >&2
  exit 1
fi
grep -Eqi '(unexpected argument|unknown argument|unrecognized option).*query-policy|query-policy.*(unexpected argument|unknown argument|unrecognized option)' \
  <<<"$baseline_output" || { echo 'Baseline-source binary did not reject the strict-read CLI option specifically' >&2; exit 1; }
docker image inspect "$image" >/dev/null

task_dir=$(mktemp -d "${TMPDIR:-/tmp}/fork-pgdog-strict-kind.XXXXXX")
cluster="fork-pgdog-strict-smoke-$(python3 -c 'import uuid; print(uuid.uuid4().hex[:24])')"
namespace="${cluster}-ns"
config="$task_dir/kubeconfig"
context="kind-$cluster"
export KUBECONFIG="$config"
k() { kubectl --kubeconfig "$config" --context "$context" --namespace "$namespace" "$@"; }
h() { helm --kubeconfig "$config" --kube-context "$context" --namespace "$namespace" "$@"; }

postgres_pinned=$(python3 - "$root/tests/artifacts/kubernetes/postgres.yaml" <<'PY'
import sys, yaml
documents = list(yaml.safe_load_all(open(sys.argv[1])))
deployment = next(d for d in documents if d.get("kind") == "Deployment")
print(deployment["spec"]["template"]["spec"]["containers"][0]["image"])
PY
)
[[ "$postgres_pinned" == postgres:18@sha256:* ]] || { echo 'PostgreSQL fixture image is not digest-pinned' >&2; exit 1; }
docker pull "$postgres_pinned" >/dev/null
postgres_image_id=$(docker image inspect --format '{{.Id}}' "$postgres_pinned")
docker tag "$postgres_image_id" postgres:18-strict-read-smoke

kind create cluster --name "$cluster" --kubeconfig "$config" \
  --config "$root/tests/artifacts/kubernetes/kind.yaml" \
  --image kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed --wait 180s
# Kind handles its own failed-create cleanup. Our trap owns only a successfully
# created cluster; a collision or refused create must never delete another one.
cluster_owned=true
kind load docker-image "$image" postgres:18-strict-read-smoke --name "$cluster"
k apply -f - <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
  labels: {app.kubernetes.io/part-of: fork-pgdog-strict-read-smoke}
YAML
python3 - "$root/tests/artifacts/kubernetes/postgres.yaml" "$task_dir/postgres.yaml" <<'PY'
import sys, yaml
documents = list(yaml.safe_load_all(open(sys.argv[1])))
for document in documents:
    if document.get("kind") == "Deployment":
        document["spec"]["template"]["spec"]["containers"][0]["image"] = "postgres:18-strict-read-smoke"
with open(sys.argv[2], "w") as stream:
    yaml.safe_dump_all(documents, stream, sort_keys=False)
PY
k apply -f "$task_dir/postgres.yaml"
k rollout status deployment/postgres --timeout=180s

app_password=$(openssl rand -hex 24)
owner_exec() {
  k exec deployment/postgres -- env PGPASSWORD=fixture-password \
    psql -h 127.0.0.1 -p 5432 -U postgres -d "$1" -v ON_ERROR_STOP=1 -Atc "$2"
}
owner_exec postgres "CREATE ROLE strict_app LOGIN PASSWORD '$app_password'" >/dev/null
owner_exec postgres 'CREATE DATABASE app' >/dev/null
owner_exec app 'REVOKE CREATE ON SCHEMA public FROM PUBLIC; CREATE TABLE public.strict_smoke(value integer NOT NULL); GRANT USAGE ON SCHEMA public TO strict_app; GRANT SELECT, INSERT, UPDATE, DELETE ON public.strict_smoke TO strict_app' >/dev/null
role_info=$(owner_exec app "SELECT r.rolsuper::text || ':' || (pg_get_userbyid(c.relowner) <> r.rolname)::text FROM pg_roles r CROSS JOIN pg_class c WHERE r.rolname = 'strict_app' AND c.oid = 'public.strict_smoke'::regclass")
[[ "$role_info" == false:true ]] || { echo 'Fixture app role must be non-superuser and not own the protected table' >&2; exit 1; }

cat > "$task_dir/users.toml" <<'TOML'
users = []
TOML
k create secret generic pgdog-users --from-file="users.toml=$task_dir/users.toml" --dry-run=client -o yaml | k apply -f - >/dev/null
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 -subj /CN=strict-read-smoke \
  -addext 'subjectAltName=DNS:pgdog-read-fork-pgdog,DNS:pgdog-write-fork-pgdog' \
  -keyout "$task_dir/tls.key" -out "$task_dir/tls.crt" >/dev/null 2>&1
k create secret generic pgdog-client-tls --from-file="tls.key=$task_dir/tls.key" \
  --from-file="tls.crt=$task_dir/tls.crt" --dry-run=client -o yaml | k apply -f - >/dev/null

cat > "$task_dir/read-policy-v1.toml" <<'TOML'
schema_revision = "strict-smoke-v1"

[[databases]]
name = "app"
relations = ["public.strict_smoke"]
TOML
cat > "$task_dir/read-policy-v2.toml" <<'TOML'
schema_revision = "strict-smoke-v2"

[[databases]]
name = "app"
relations = ["public.strict_smoke", "public.strict_extra"]
TOML
k create configmap pgdog-read-policy --from-file="read-policy.toml=$task_dir/read-policy-v1.toml" \
  --dry-run=client -o yaml | k apply -f - >/dev/null

pgdog_config=$(printf '%s\n' \
  '[general]' 'host = "0.0.0.0"' 'port = 6432' 'healthcheck_port = 9090' \
  'shutdown_timeout = 120000' 'shutdown_termination_timeout = 10000' \
  'tls_certificate = "/etc/pgdog/tls/tls.crt"' 'tls_private_key = "/etc/pgdog/tls/tls.key"' \
  'passthrough_auth = "enabled"' 'auth_type = "plain"' 'pooler_mode = "session"' '' \
  '[[databases]]' 'name = "app"' 'database_name = "app"' 'host = "postgres"' 'port = 5432' 'role = "primary"')
python3 - "$task_dir" "$image_repository" "$image_tag" "$pgdog_config" <<'PY'
import pathlib, sys, yaml
task, repository, tag, config = sys.argv[1:]
root = pathlib.Path(task)
common = {
    "image": {"repository": repository, "tag": tag, "pullPolicy": "Never"},
    "users": {"existingSecret": "pgdog-users"},
    "tls": {"existingSecret": "pgdog-client-tls"},
    "config": {"pgdogToml": config},
    "replicaCount": 1,
}
for release, mode in (("pgdog-read", "strict-read"), ("pgdog-write", "unrestricted")):
    values = dict(common)
    values["queryPolicy"] = mode
    values["readPolicy"] = {"existingConfigMap": "pgdog-read-policy" if mode == "strict-read" else ""}
    (root / f"{release}.yaml").write_text(yaml.safe_dump(values, sort_keys=False))
PY
h upgrade --install pgdog-read "$chart" --values "$task_dir/pgdog-read.yaml" --wait --timeout 240s
h upgrade --install pgdog-write "$chart" --values "$task_dir/pgdog-write.yaml" --wait --timeout 240s

k get deployments pgdog-read-fork-pgdog pgdog-write-fork-pgdog -o json > "$task_dir/deployments.json"
k get services pgdog-read-fork-pgdog pgdog-write-fork-pgdog -o json > "$task_dir/services.json"
python3 - "$task_dir/deployments.json" "$task_dir/services.json" "$image" <<'PY'
import json, sys
deployments = json.load(open(sys.argv[1]))["items"]
services = json.load(open(sys.argv[2]))["items"]
image = sys.argv[3]
deployments_by_name = {resource["metadata"]["name"]: resource for resource in deployments}
services_by_name = {resource["metadata"]["name"]: resource for resource in services}
read_name, write_name = "pgdog-read-fork-pgdog", "pgdog-write-fork-pgdog"
read = deployments_by_name[read_name]["spec"]["selector"]["matchLabels"]
write = deployments_by_name[write_name]["spec"]["selector"]["matchLabels"]
assert read != write and any(k in write and read[k] != write[k] for k in read), "read/write selectors overlap"
for name in (read_name, write_name):
    deployment = deployments_by_name[name]
    pod = deployment["spec"]["template"]["spec"]
    images = {c["image"] for c in pod["containers"] + pod.get("initContainers", [])}
    assert images == {image}, f"{name} uses inconsistent PgDog images: {images}"
    service = services_by_name[name]
    assert service["spec"]["selector"] == deployment["spec"]["selector"]["matchLabels"], f"{name} Service selector mismatch"
assert "--query-policy" in deployments_by_name[read_name]["spec"]["template"]["spec"]["containers"][0]["args"]
assert "--query-policy" not in deployments_by_name[write_name]["spec"]["template"]["spec"]["containers"][0]["args"]
PY

pgdog_pod() {
  k get pods -l "app.kubernetes.io/instance=$1" -o json | python3 -c '
import json,sys
pods=[p for p in json.load(sys.stdin)["items"] if not p["metadata"].get("deletionTimestamp") and p.get("status",{}).get("phase")=="Running" and any(c.get("type")=="Ready" and c.get("status")=="True" for c in p.get("status",{}).get("conditions",[]))]
assert pods, "no live Ready PgDog Pod"
print(sorted(pods,key=lambda p:p["metadata"]["creationTimestamp"])[-1]["metadata"]["name"])'
}
strict_sql() {
  local release=$1 host=$2 statement=$3
  k exec "$(pgdog_pod "$release")" -- env "PGPASSWORD=$app_password" PGCONNECT_TIMEOUT=5 \
    PGSSLMODE=verify-full PGSSLROOTCERT=/etc/pgdog/tls/tls.crt \
    psql -h "$host" -p 6432 -U strict_app -d app -v ON_ERROR_STOP=1 -Atc "$statement"
}
# Deployment readiness and Service endpoint propagation are independent. Wait
# for the real SQL connection after replacing a Pod; never retry a SQL denial.
read_after_rollout() {
  local statement=$1 expected=$2 result attempt
  for ((attempt=1; attempt<=12; attempt++)); do
    if result=$(strict_sql pgdog-read pgdog-read-fork-pgdog "$statement" 2> "$task_dir/rollout-connect.log"); then
      [[ "$result" == "$expected" ]] || { echo "Unexpected post-rollout result: $result" >&2; return 1; }
      return 0
    fi
    if ! grep -Eq '(timeout expired|Connection refused|server closed the connection unexpectedly|could not translate host name)' "$task_dir/rollout-connect.log"; then
      cat "$task_dir/rollout-connect.log" >&2
      return 1
    fi
    echo "Post-rollout SQL connection not ready (attempt $attempt/12)" >&2
    cat "$task_dir/rollout-connect.log" >&2
    k get pods,endpointslices -o wide >&2 || true
    sleep 2
  done
  return 1
}
backend_snapshot() {
  owner_exec app 'SELECT count(*)::text || '"'"':'"'"' || COALESCE(sum(value), 0)::text FROM public.strict_smoke'
}
assert_strict_denied_without_change() {
  local statement=$1 before after
  before=$(backend_snapshot)
  if strict_sql pgdog-read pgdog-read-fork-pgdog "$statement" > "$task_dir/query.log" 2>&1; then
    echo "Strict-read accepted a mutation: $statement" >&2
    exit 1
  fi
  grep -Fq 'strict-read: write_statement' "$task_dir/query.log" || {
    echo 'Mutation was not rejected by the strict SQL policy' >&2; exit 1;
  }
  after=$(backend_snapshot)
  [[ "$after" == "$before" ]] || { echo "Rejected strict-read SQL changed backend state: $statement" >&2; exit 1; }
}

read_value=$(strict_sql pgdog-read pgdog-read-fork-pgdog 'SELECT count(*) FROM public.strict_smoke')
[[ "$read_value" == 0 ]] || { echo "Unexpected initial read result: $read_value" >&2; exit 1; }
assert_strict_denied_without_change "INSERT INTO public.strict_smoke(value) VALUES (9001)"
assert_strict_denied_without_change "UPDATE public.strict_smoke SET value = 9002"
assert_strict_denied_without_change "DELETE FROM public.strict_smoke"
strict_sql pgdog-write pgdog-write-fork-pgdog 'INSERT INTO public.strict_smoke(value) VALUES (42)' >/dev/null
[[ "$(backend_snapshot)" == 1:42 ]] || { echo 'Unrestricted write Service did not mutate the shared backend' >&2; exit 1; }
[[ "$(strict_sql pgdog-read pgdog-read-fork-pgdog 'SELECT value FROM public.strict_smoke')" == 42 ]] || {
  echo 'Strict-read Service did not observe the write Service backend row' >&2; exit 1;
}

# Drain the owned reader before DDL. Restart on v1 to prove that ConfigMap edits
# alone do not mutate a running process's immutable policy snapshot.
k scale deployment/pgdog-read-fork-pgdog --replicas=0
k wait --for=delete pod -l app.kubernetes.io/instance=pgdog-read --timeout=180s
owner_exec app 'CREATE TABLE public.strict_extra(value integer NOT NULL); GRANT SELECT, INSERT, UPDATE, DELETE ON public.strict_extra TO strict_app; INSERT INTO public.strict_extra VALUES (77)' >/dev/null
k scale deployment/pgdog-read-fork-pgdog --replicas=1
k rollout status deployment/pgdog-read-fork-pgdog --timeout=240s
read_after_rollout 'SELECT value FROM public.strict_smoke' 42
if strict_sql pgdog-read pgdog-read-fork-pgdog 'SELECT value FROM public.strict_extra' > "$task_dir/query.log" 2>&1; then
  echo 'Strict-read admitted a relation absent from the v1 manifest' >&2
  exit 1
fi
grep -Fq 'strict-read: unsupported_statement' "$task_dir/query.log" || {
  echo 'Missing-relation probe failed outside the strict policy' >&2; exit 1;
}
old_read_pod=$(pgdog_pod pgdog-read)
old_read_uid=$(k get pod "$old_read_pod" -o jsonpath='{.metadata.uid}')
k create configmap pgdog-read-policy --from-file="read-policy.toml=$task_dir/read-policy-v2.toml" \
  --dry-run=client -o yaml | k apply -f - >/dev/null
[[ "$(k get pod "$old_read_pod" -o jsonpath='{.metadata.uid}')" == "$old_read_uid" ]] || {
  echo 'External manifest edit unexpectedly restarted the strict-read release' >&2; exit 1;
}
if strict_sql pgdog-read pgdog-read-fork-pgdog 'SELECT value FROM public.strict_extra' > "$task_dir/query.log" 2>&1; then
  echo 'Running strict-read process observed a manifest edit without restart' >&2
  exit 1
fi
grep -Fq 'strict-read: unsupported_statement' "$task_dir/query.log" || {
  echo 'Immutable-manifest probe failed outside the strict policy' >&2; exit 1;
}
k rollout restart deployment/pgdog-read-fork-pgdog
k rollout status deployment/pgdog-read-fork-pgdog --timeout=240s
new_read_pod=$(pgdog_pod pgdog-read)
[[ "$(k get pod "$new_read_pod" -o jsonpath='{.metadata.uid}')" != "$old_read_uid" ]] || {
  echo 'Explicit strict-read rollout did not replace its process' >&2; exit 1;
}
read_after_rollout 'SELECT value FROM public.strict_extra' 77 || {
  echo 'Strict-read did not read the newly manifested relation after controlled restart' >&2; exit 1;
}

# Invalid strict manifests must fail init configcheck instead of serving a
# permissive endpoint.
printf '[broken\n' > "$task_dir/read-policy-invalid.toml"
k create configmap pgdog-read-policy-invalid --from-file="read-policy.toml=$task_dir/read-policy-invalid.toml" \
  --dry-run=client -o yaml | k apply -f - >/dev/null
python3 - "$task_dir/pgdog-read.yaml" "$task_dir/pgdog-read-invalid.yaml" <<'PY'
import pathlib, sys, yaml
values = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
values["readPolicy"]["existingConfigMap"] = "pgdog-read-policy-invalid"
pathlib.Path(sys.argv[2]).write_text(yaml.safe_dump(values, sort_keys=False))
PY
h upgrade --install pgdog-read-invalid "$chart" --values "$task_dir/pgdog-read-invalid.yaml"
invalid_failed=false
for ((attempt=0; attempt<30; attempt++)); do
  if k get pods -l app.kubernetes.io/instance=pgdog-read-invalid -o json | python3 -c '
import json,sys
pods=json.load(sys.stdin)["items"]
sys.exit(0 if any(any(s.get(state,{}).get("terminated",{}).get("exitCode",0)>0 for state in ("state","lastState")) for p in pods for s in p.get("status",{}).get("initContainerStatuses",[])) else 1)'; then
    invalid_failed=true
    break
  fi
  sleep 2
done
[[ "$invalid_failed" == true ]] || { echo 'Invalid strict manifest did not fail configcheck' >&2; exit 1; }
k logs deployment/pgdog-read-invalid-fork-pgdog -c configcheck > "$task_dir/invalid-manifest.log"
grep -Fq 'manifest_invalid_toml' "$task_dir/invalid-manifest.log" || {
  echo 'Invalid-manifest init failed for an unrelated reason' >&2; exit 1;
}
k get pods -o json | python3 -c '
import json,sys
pods=[p for p in json.load(sys.stdin)["items"] if p["metadata"].get("labels",{}).get("app.kubernetes.io/instance") in ("pgdog-read","pgdog-write") and not p["metadata"].get("deletionTimestamp")]
assert len(pods)==2, "missing final read/write Pods"
assert {p["metadata"]["labels"]["app.kubernetes.io/instance"] for p in pods}=={"pgdog-read","pgdog-write"}, "missing paired releases"
for p in pods:
 status=p.get("status",{})
 assert status.get("phase")=="Running" and any(c.get("type")=="Ready" and c.get("status")=="True" for c in status.get("conditions",[])), "final Pod is not Ready"
 runtime=[s for s in status.get("containerStatuses",[]) if s.get("name")=="pgdog"]
 assert len(runtime)==1 and runtime[0].get("ready") is True and runtime[0].get("restartCount",0)==0, "PgDog is missing, not ready or restarted"'

mkdir -p "$(dirname "$smoke_report")"
printf '{"status":"passed","cluster":"%s","baseline_source_sha":"%s","baseline_evidence":"source_binary_rejected_strict_cli","strict_read":"read_only","write_endpoint":"dml_succeeded","manifest":"explicit_restart_only","selectors":"disjoint"}\n' \
  "$cluster" "$baseline_source_sha" > "$smoke_report"
echo 'PASS paired strict-read/unrestricted Services, DML-capable role, backend snapshots, immutable manifest restart and configcheck failure'
