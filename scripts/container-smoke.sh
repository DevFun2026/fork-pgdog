#!/usr/bin/env bash
# Exercise a built image, using only synthetic local configuration.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo 'Usage: bash scripts/container-smoke.sh IMAGE EXPECTED_VERSION' >&2
  exit 2
fi
image=$1
expected=$2
case "$image" in -*|'') echo 'Invalid image reference' >&2; exit 2 ;; esac
task_dir=$(mktemp -d "${TMPDIR:-/tmp}/fork-pgdog-container-smoke.XXXXXX")
container_id=''
cleanup() {
  if [[ -n "$container_id" ]]; then docker rm -f "$container_id" >/dev/null 2>&1 || true; fi
  # Only our own mktemp directory is removed.
  rm -rf -- "$task_dir"
}
trap cleanup EXIT

docker image inspect "$image" --format '{{json .Config}}' > "$task_dir/image.json"
python3 - "$task_dir/image.json" <<'PY'
import json, sys
with open(sys.argv[1]) as stream:
    config = json.load(stream)
assert config['User'] == '10001:10001', 'image is not running as the expected non-root user'
assert config['StopSignal'] == 'SIGINT', 'image has lost the drain stop signal'
assert config['Entrypoint'] == ['/usr/local/bin/pgdog'], 'PgDog must run directly as PID 1'
assert config['WorkingDir'] == '/pgdog'
assert not any('TOKEN=' in value or 'PASSWORD=' in value for value in config.get('Env', []))
PY
security=(--read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,noexec,size=64m)
version=$(docker run --rm --network none "${security[@]}" "$image" --version)
[[ "${version# }" == "PgDog v${expected}" ]] || { echo "Unexpected version: $version" >&2; exit 1; }
docker run --rm --network none "${security[@]}" --entrypoint /bin/sh "$image" -ec '
  test "$(id -u)" = 10001
  pg_dump --version
  psql --version
  test -s /etc/ssl/certs/ca-certificates.crt
  test -s /usr/lib/libpgdog_primary_only_tables.so
  test ! -e /build
  test ! -e /pgdog/.git
  if touch /usr/local/bin/forbidden-write 2>/dev/null; then echo "Root filesystem allowed writes" >&2; exit 1; fi
  touch /tmp/write-check
'
cat > "$task_dir/pgdog.toml" <<'TOML'
[general]
host = "0.0.0.0"
port = 6432
healthcheck_port = 9090
shutdown_timeout = 1000
shutdown_termination_timeout = 1000

[[plugins]]
name = "pgdog_primary_only_tables"
TOML
printf 'users = []\n' > "$task_dir/users.toml"
chmod 755 "$task_dir"
chmod 644 "$task_dir/pgdog.toml" "$task_dir/users.toml"
mounts=(--mount "type=bind,src=$task_dir/pgdog.toml,dst=/etc/pgdog/pgdog.toml,readonly"
        --mount "type=bind,src=$task_dir/users.toml,dst=/etc/pgdog/users.toml,readonly")
args=(--config /etc/pgdog/pgdog.toml --users /etc/pgdog/users.toml)
docker run --rm --network none "${security[@]}" "${mounts[@]}" "$image" "${args[@]}" configcheck
container_id=$(docker run -d --network none "${security[@]}" "${mounts[@]}" "$image" "${args[@]}")
ready=false
for ((attempt=0; attempt<30; attempt++)); do
  if docker exec "$container_id" curl --fail --silent http://127.0.0.1:9090/ >/dev/null; then
    ready=true; break
  fi
  sleep 1
done
[[ "$ready" == true ]] || { docker logs "$container_id"; echo 'Image never became healthy' >&2; exit 1; }
docker logs "$container_id" > "$task_dir/startup.log" 2>&1
grep -Eq 'pgdog_primary_only_tables.*loaded|loaded.*pgdog_primary_only_tables' "$task_dir/startup.log" || {
  cat "$task_dir/startup.log"; echo 'Plugin was not loaded' >&2; exit 1;
}
docker stop --time 10 "$container_id" >/dev/null
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$container_id")" == 0 ]]
echo "PASS non-root image, version, tools, config, plugin and SIGINT stop: $image"
