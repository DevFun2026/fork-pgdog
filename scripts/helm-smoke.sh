#!/usr/bin/env bash
# Every cluster operation is bound to a disposable cluster and private kubeconfig.
set -euo pipefail
umask 077
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=''; chart="$root/charts/fork-pgdog"
while (($#)); do
  case "$1" in
    --image) image=${2:?}; shift 2 ;;
    --chart) chart=${2:?}; shift 2 ;;
    *) echo 'Usage: helm-smoke.sh --image IMAGE [--chart PATH]' >&2; exit 2 ;;
  esac
done
[[ -n "$image" && "$image" != -* && "$image" != *@* && "$image" == *:* ]] || { echo 'A local tagged image is required' >&2; exit 2; }
task_dir=$(mktemp -d "${TMPDIR:-/tmp}/fork-pgdog-kind.XXXXXX")
cluster="fork-pgdog-smoke-$(date +%s)-${RANDOM}"
namespace=fork-pgdog-smoke
config="$task_dir/kubeconfig"
context="kind-$cluster"
created=false
cleanup() {
  code=$1
  trap - EXIT
  if [[ "$created" == true ]]; then
    if ! kind delete cluster --name "$cluster" >/dev/null 2>&1; then
      echo "Cleanup failed for owned cluster $cluster" >&2; code=1
    fi
  fi
  if [[ "$code" != 0 ]]; then
    mkdir -p "$root/.agent/.runs/artifacts"
    printf '{"status":"failed","cluster":"%s","exit_code":%s}\n' "$cluster" "$code" > "$root/.agent/.runs/artifacts/kubernetes-smoke.json"
    if [[ -f "$task_dir/query.log" ]]; then tail -20 "$task_dir/query.log" >&2; fi
    if [[ -f "$task_dir/drain.log" ]]; then
      tail -40 "$task_dir/drain.log" > "$root/.agent/.runs/artifacts/failed-drain.log"
    fi
  fi
  for child in $(jobs -pr); do kill "$child" 2>/dev/null || true; done
  rm -rf -- "$task_dir"
  exit "$code"
}
trap 'cleanup "$?"' EXIT
export KUBECONFIG="$config"
k() { kubectl --kubeconfig "$config" --context "$context" --namespace "$namespace" "$@"; }
h() { helm --kubeconfig "$config" --kube-context "$context" --namespace "$namespace" "$@"; }
# Set before creation so a partly created cluster is still cleaned up by its exact name.
created=true
kind create cluster --name "$cluster" --kubeconfig "$config" --config "$root/tests/artifacts/kubernetes/kind.yaml" \
  --image kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed --wait 180s
kind load docker-image "$image" --name "$cluster"
k apply -f - <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
  labels: {app.kubernetes.io/part-of: fork-pgdog-smoke}
YAML
k apply -f "$root/tests/artifacts/kubernetes/postgres.yaml"
k rollout status deployment/postgres --timeout=180s
cat > "$task_dir/users.toml" <<'TOML'
[[users]]
name = "postgres"
database = "postgres"
password = "fixture-password"
TOML
k create secret generic pgdog-users --from-file="users.toml=$task_dir/users.toml" --dry-run=client -o yaml | k apply -f - >/dev/null
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 -subj /CN=fixture-fork-pgdog \
  -addext subjectAltName=DNS:fixture-fork-pgdog -keyout "$task_dir/tls.key" -out "$task_dir/tls.crt" >/dev/null 2>&1
k create secret generic pgdog-tls --from-file="tls.key=$task_dir/tls.key" --from-file="tls.crt=$task_dir/tls.crt" --dry-run=client -o yaml | k apply -f - >/dev/null
python3 - "$root/tests/artifacts/kubernetes/values.yaml" "$task_dir/base.yaml" <<'PY'
import sys,yaml
values=yaml.safe_load(open(sys.argv[1])); values['tls']={'existingSecret':'pgdog-tls'}
values['config']['pgdogToml']=values['config']['pgdogToml'].replace('host = "0.0.0.0"','host = "0.0.0.0"\ntls_certificate = "/etc/pgdog/tls/tls.crt"\ntls_private_key = "/etc/pgdog/tls/tls.key"')
open(sys.argv[2],'w').write(yaml.safe_dump(values))
PY
repo=${image%:*}; tag=${image##*:}
h upgrade --install fixture "$chart" --values "$task_dir/base.yaml" \
  --set-string "image.repository=$repo" --set-string "image.tag=$tag" --wait --timeout 240s
deployment=fixture-fork-pgdog
pod() {
  k get pods -l app.kubernetes.io/instance=fixture -o json | python3 -c 'import json,sys; pods=[p for p in json.load(sys.stdin)["items"] if not p["metadata"].get("deletionTimestamp") and p.get("status",{}).get("phase")=="Running" and any(c.get("type")=="Ready" and c.get("status")=="True" for c in p.get("status",{}).get("conditions",[]))]; assert pods,"No live Ready PgDog Pod"; print(sorted(pods,key=lambda p:p["metadata"]["creationTimestamp"])[-1]["metadata"]["name"])'
}
current_password=fixture-password
sql() { k exec "$(pod)" -- env "PGPASSWORD=$current_password" PGCONNECT_TIMEOUT=5 PGSSLMODE=verify-full PGSSLROOTCERT=/etc/pgdog/tls/tls.crt psql -h "$deployment" -p 6432 -U postgres -d postgres -v ON_ERROR_STOP=1 -Atc "$1"; }
sql_ready() {
  for ((sql_attempt=0; sql_attempt<30; sql_attempt++)); do
    if sql_result=$(sql 'SELECT 1' 2>/dev/null) && [[ "$sql_result" == 1 ]]; then return 0; fi
    sleep 2
  done
  echo 'SQL did not recover within the bounded transition window' >&2; return 1
}
sql_ready
sql 'CREATE TABLE smoke(value int); INSERT INTO smoke VALUES (42);' >/dev/null
[[ "$(sql 'SELECT value FROM smoke')" == 42 ]] || { echo 'SQL round trip failed' >&2; exit 1; }
if k exec "$(pod)" -- env PGPASSWORD=wrong psql -h "$deployment" -p 6432 -U postgres -d postgres -Atc 'SELECT 1' >/dev/null 2>&1; then
  echo 'Wrong password was accepted' >&2; exit 1
fi
k exec "$(pod)" -- /bin/sh -ec '
  test "$(id -u)" = 10001
  test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token
  if touch /usr/local/bin/write-check 2>/dev/null; then exit 1; fi
  if touch /etc/pgdog/config/write-check 2>/dev/null; then exit 1; fi
  if touch /etc/pgdog/users/write-check 2>/dev/null; then exit 1; fi
  test -r /etc/pgdog/tls/tls.key
  if touch /etc/pgdog/tls/write-check 2>/dev/null; then exit 1; fi
  touch /tmp/write-check
'
outage_pod=$(pod)
before=$(k get pod "$outage_pod" -o jsonpath='{.status.containerStatuses[0].restartCount}')
k scale deployment/postgres --replicas=0 >/dev/null
k rollout status deployment/postgres --timeout=120s
k wait --for=condition=Ready=false "pod/$outage_pod" --timeout=120s
sleep 35
after=$(k get pod "$outage_pod" -o jsonpath='{.status.containerStatuses[0].restartCount}')
[[ "$before" == "$after" ]] || { echo 'Backend outage restarted PgDog' >&2; exit 1; }
k scale deployment/postgres --replicas=1 >/dev/null
k rollout status deployment/postgres --timeout=180s
k wait --for=condition=Ready "pod/$outage_pod" --timeout=120s
sql_ready
old=$(pod)
k logs -f "$old" > "$task_dir/drain.log" 2>&1 & log_pid=$!
k exec deployment/postgres -- env PGPASSWORD=fixture-password PGSSLMODE=require PGCONNECT_TIMEOUT=5 psql -h "$deployment" -p 6432 -U postgres -d postgres -v ON_ERROR_STOP=1 -c 'SELECT pg_sleep(8)' > "$task_dir/query.log" 2>&1 & query_pid=$!
active=false
for ((attempt=0; attempt<20; attempt++)); do
  count=$(k exec deployment/postgres -- psql -U postgres -Atc "SELECT count(*) FROM pg_stat_activity WHERE query = 'SELECT pg_sleep(8)' AND state = 'active'")
  if [[ "$count" == 1 ]]; then active=true; break; fi
  sleep 0.2
done
[[ "$active" == true ]] || { echo 'Drain query never became active' >&2; exit 1; }
k delete pod "$old" --wait=false >/dev/null
wait "$query_pid"
wait "$log_pid" || true
grep -Eqi 'SIGINT|interrupt|shutting down' "$task_dir/drain.log"
if grep -qi 'SIGTERM' "$task_dir/drain.log"; then echo 'Drain received SIGTERM' >&2; exit 1; fi
k wait --for=delete "pod/$old" --timeout=180s
k rollout status "deployment/$deployment" --timeout=240s
sql_ready
uid=$(k get pod "$(pod)" -o jsonpath='{.metadata.uid}')
python3 - "$task_dir/base.yaml" "$task_dir/upgrade.yaml" <<'PY'
import sys,yaml
values=yaml.safe_load(open(sys.argv[1]))
values['config']['pgdogToml'] += '\n# changed inline configuration\n'
open(sys.argv[2],'w').write(yaml.safe_dump(values))
PY
h upgrade fixture "$chart" --values "$task_dir/upgrade.yaml" --set-string "image.repository=$repo" --set-string "image.tag=$tag" --wait --timeout 240s
[[ "$(k get pod "$(pod)" -o jsonpath='{.metadata.uid}')" != "$uid" ]] || { echo 'Inline config did not roll Pods' >&2; exit 1; }
h rollback fixture 1 --wait --timeout 240s
sql_ready
# Updating an external Secret requires an explicit rollout and is not Helm history.
k exec deployment/postgres -- psql -U postgres -v ON_ERROR_STOP=1 -c "ALTER USER postgres PASSWORD 'rotated-fixture-password'" >/dev/null
python3 - "$task_dir/users.toml" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); p.write_text(p.read_text().replace('fixture-password','rotated-fixture-password'))
PY
k create secret generic pgdog-users --from-file="users.toml=$task_dir/users.toml" --dry-run=client -o yaml | k apply -f - >/dev/null
current_password=rotated-fixture-password
k rollout restart "deployment/$deployment"
k rollout status "deployment/$deployment" --timeout=240s
sql_ready
python3 - "$task_dir/base.yaml" "$task_dir/pgdog.toml" "$task_dir/external.yaml" <<'PY'
import pathlib,sys,yaml
values=yaml.safe_load(open(sys.argv[1])); pathlib.Path(sys.argv[2]).write_text(values['config']['pgdogToml'])
values['config']={'pgdogToml':'','existingSecret':'pgdog-config'}
pathlib.Path(sys.argv[3]).write_text(yaml.safe_dump(values))
PY
k create secret generic pgdog-config --from-file="pgdog.toml=$task_dir/pgdog.toml" --dry-run=client -o yaml | k apply -f - >/dev/null
h upgrade fixture "$chart" --values "$task_dir/external.yaml" --set-string "image.repository=$repo" --set-string "image.tag=$tag" --wait --timeout 240s
sql_ready
printf '\n# rotated external config\n' >> "$task_dir/pgdog.toml"
k create secret generic pgdog-config --from-file="pgdog.toml=$task_dir/pgdog.toml" --dry-run=client -o yaml | k apply -f - >/dev/null
external_version=$(k get secret pgdog-config -o jsonpath='{.metadata.resourceVersion}')
k rollout restart "deployment/$deployment"
k rollout status "deployment/$deployment" --timeout=240s
sql_ready
[[ "$(k exec "$(pod)" -- tail -1 /etc/pgdog/config/pgdog.toml)" == '# rotated external config' ]] || { echo 'External config update not mounted' >&2; exit 1; }
h rollback fixture 1 --wait --timeout 240s
sql_ready
[[ "$(k get secret pgdog-config -o jsonpath='{.metadata.resourceVersion}')" == "$external_version" ]] || { echo 'Helm changed external config Secret' >&2; exit 1; }
# Negative runtime cases: invalid external TOML must fail configcheck; missing users must fail mount.
printf '[broken\n' > "$task_dir/invalid.toml"
k create secret generic invalid-config --from-file="pgdog.toml=$task_dir/invalid.toml" >/dev/null
h install invalid "$chart" --values "$task_dir/external.yaml" --set-string config.existingSecret=invalid-config --set-string "image.repository=$repo" --set-string "image.tag=$tag" >/dev/null
invalid_failed=false
for ((attempt=0; attempt<30; attempt++)); do
  code=$(k get pods -l app.kubernetes.io/instance=invalid -o json | python3 -c 'import json,sys; statuses=[s for p in json.load(sys.stdin)["items"] for s in p.get("status",{}).get("initContainerStatuses",[])]; codes=[s.get("state",{}).get("terminated",s.get("lastState",{}).get("terminated",{})).get("exitCode",0) for s in statuses]; print(max(codes,default=0))')
  if [[ "$code" -gt 0 ]]; then invalid_failed=true; break; fi
  sleep 2
done
[[ "$invalid_failed" == true ]] || { echo 'Invalid TOML did not fail configcheck' >&2; exit 1; }
h install missing "$chart" --values "$task_dir/base.yaml" --set-string users.existingSecret=missing-users --set-string "image.repository=$repo" --set-string "image.tag=$tag" >/dev/null
missing_failed=false
for ((attempt=0; attempt<30; attempt++)); do
  missing_pod=$(k get pods -l app.kubernetes.io/instance=missing -o jsonpath='{.items[0].metadata.name}')
  if k get events --field-selector "involvedObject.name=$missing_pod" -o json | python3 -c 'import json,sys; sys.exit(0 if any(e.get("reason")=="FailedMount" for e in json.load(sys.stdin)["items"]) else 1)'; then missing_failed=true; break; fi
  sleep 2
done
[[ "$missing_failed" == true ]] || { echo 'Missing Secret did not prevent mounting' >&2; exit 1; }
mkdir -p "$root/.agent/.runs/artifacts"
printf '{"status":"passed","cluster":"%s","outage_restarts_before":%s,"outage_restarts_after":%s,"sql":"passed","drain":"passed","upgrade_rollback":"passed"}\n' "$cluster" "$before" "$after" > "$root/.agent/.runs/artifacts/kubernetes-smoke.json"
echo 'PASS isolated Kubernetes SQL/auth/TLS, hardening, outage probes, drain, config rejection, missing Secret, upgrade/rollback and external object rollout'
