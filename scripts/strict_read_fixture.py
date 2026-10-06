#!/usr/bin/env python3
"""Own a loopback-only PostgreSQL/PgDog fixture for strict-read tests."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
APPLICATION = ROOT / "applications/pgdog"
FIXTURES = APPLICATION / "integration/strict_read"
BASELINE_BINARY = ROOT / ".agent/.runs/strict-read/pgdog-baseline"
PIN_SOURCE = ROOT / "tests/artifacts/kubernetes/postgres.yaml"


def new_resource_name() -> str:
    return f"pgdog-strict-{uuid.uuid4()}"


def available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def child_environment(parent: dict[str, str], config_json: str) -> dict[str, str]:
    result = dict(parent)
    for name in tuple(result):
        if name.startswith(("PGDOG_", "PG")) or name in ("DATABASE_URL", "KUBECONFIG"):
            result.pop(name, None)
    result["PGDOG_STRICT_TEST_CONFIG"] = config_json
    return result


class OwnedResources:
    """Track only exact child PIDs and Docker IDs created by this runner."""

    def __init__(self, docker=subprocess.run):
        self.docker = docker
        self.processes: list[subprocess.Popen] = []
        self.container_ids: list[str] = []
        self.log_handles = []

    def record_process(self, process: subprocess.Popen) -> None:
        self.processes.append(process)

    def record_container(self, container_id: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise ValueError("Docker returned an invalid container ID")
        self.container_ids.append(container_id)

    def cleanup(self) -> None:
        failures = []
        for process in reversed(self.processes):
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            except Exception as error:  # cleanup must continue across owned resources
                failures.append(f"pid {process.pid}: {error}")
        self.processes.clear()

        for container_id in reversed(self.container_ids):
            try:
                result = self.docker(["docker", "rm", "--force", container_id],
                                     capture_output=True, text=True, check=False)
                if result.returncode != 0:
                    failures.append(f"container {container_id}: {result.stderr.strip()}")
            except Exception as error:
                failures.append(f"container {container_id}: {error}")
        self.container_ids.clear()

        for handle in self.log_handles:
            try:
                handle.close()
            except Exception as error:
                failures.append(f"log handle: {error}")
        self.log_handles.clear()
        if failures:
            raise RuntimeError("fixture cleanup failed: " + "; ".join(failures))


def required_tools(postgres_mode: str = "docker") -> dict[str, str]:
    if postgres_mode not in ("docker", "native"):
        raise ValueError(f"unknown PostgreSQL fixture mode: {postgres_mode}")
    names = ("docker", "pg_isready", "cargo") if postgres_mode == "docker" else (
        "initdb", "postgres", "psql", "pg_isready", "cargo")
    paths = {name: shutil.which(name) for name in names}
    missing = [name for name, path in paths.items() if path is None]
    if missing:
        raise RuntimeError("missing required tools: " + ", ".join(missing))
    return paths


def verify_native_postgres_version(tools: dict[str, str]) -> None:
    for name in ("initdb", "postgres", "psql", "pg_isready"):
        version = run_checked([tools[name], "--version"]).stdout.strip()
        match = re.search(r"PostgreSQL\)\s+(\d+)(?:\.|\b)", version)
        if not match or match.group(1) != "18":
            raise RuntimeError(f"native fixture requires PostgreSQL 18 {name}; found: {version}")


def pinned_postgres_image() -> str:
    content = PIN_SOURCE.read_text()
    match = re.search(r"image:\s*(postgres:18@sha256:[0-9a-f]{64})\b", content)
    if not match:
        raise RuntimeError("could not resolve the pinned PostgreSQL 18 image")
    return match.group(1)


def run_checked(command: list[str], *, env=None, **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(command, env=env, text=True, capture_output=True, check=False, **kwargs)
    if result.returncode != 0:
        detail = (result.stdout.strip() + "\n" + result.stderr.strip())[-5000:]
        raise RuntimeError(f"command failed ({result.returncode}): {command[0]} {command[1:]}\n{detail}")
    return result


def wait_for_postgres(port: int, env: dict[str, str], process: subprocess.Popen | None = None) -> None:
    deadline = time.monotonic() + 90
    last = ""
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"owned PostgreSQL process exited with status {process.returncode}")
        check = subprocess.run(["pg_isready", "-h", "127.0.0.1", "-p", str(port),
                                "-U", "strict_app", "-d", "app"],
                               env=env, text=True, capture_output=True, check=False)
        if check.returncode == 0:
            return
        last = check.stderr.strip() or check.stdout.strip()
        time.sleep(0.25)
    raise RuntimeError(f"PostgreSQL readiness timed out on loopback port {port}: {last}")


def wait_for_pgdog(port: int, process: subprocess.Popen, env: dict[str, str]) -> None:
    deadline = time.monotonic() + 60
    last = ""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"PgDog pid {process.pid} exited with status {process.returncode}")
        check = subprocess.run(["pg_isready", "-h", "127.0.0.1", "-p", str(port),
                                "-U", "strict_app", "-d", "app"],
                               env=env, text=True, capture_output=True, check=False)
        if check.returncode == 0:
            return
        last = check.stderr.strip() or check.stdout.strip()
        time.sleep(0.2)
    raise RuntimeError(f"PgDog readiness timed out on loopback port {port}: {last}")


def write_private(path: Path, contents: str) -> None:
    path.write_text(contents)
    path.chmod(0o600)


def render_file(source: Path, target: Path, substitutions: dict[str, str]) -> None:
    content = source.read_text()
    for name, value in substitutions.items():
        content = content.replace(name, value)
    if re.search(r"__[A-Z][A-Z0-9_]*__", content):
        raise RuntimeError(f"unexpanded fixture placeholder in {source.name}")
    write_private(target, content)


def start_fixture(resources: OwnedResources, temp: Path, env: dict[str, str], app_password: str,
                  owner_password: str) -> int:
    bootstrap = (FIXTURES / "bootstrap.sql").read_text().replace("__APP_PASSWORD__", app_password)
    bootstrap_path = temp / "bootstrap.sql"
    write_private(bootstrap_path, bootstrap)
    cidfile = temp / "postgres.cid"
    command = [
        "docker", "run", "--pull=never", "--detach", "--name", new_resource_name(), "--cidfile", str(cidfile),
        "--publish", "127.0.0.1::5432", "--env", "POSTGRES_USER=fixture_owner",
        "--env", f"POSTGRES_PASSWORD={owner_password}", "--env", "POSTGRES_DB=app",
        "--mount", f"type=bind,source={bootstrap_path},target=/docker-entrypoint-initdb.d/001-bootstrap.sql,readonly",
        pinned_postgres_image(),
    ]
    created = subprocess.run(command, env=env, text=True, capture_output=True, check=False)
    if cidfile.exists():
        resources.record_container(cidfile.read_text().strip())
    if created.returncode != 0:
        raise RuntimeError(f"PostgreSQL fixture creation failed: {created.stderr.strip()[-3000:]}")
    if not resources.container_ids:
        raise RuntimeError("Docker started the fixture without recording its container ID")
    container_id = resources.container_ids[-1]
    inspect = run_checked(["docker", "inspect", "--format",
                           '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}',
                           container_id], env=env)
    try:
        port = int(inspect.stdout.strip())
    except ValueError as error:
        raise RuntimeError("Docker did not publish PostgreSQL on a loopback port") from error
    wait_for_postgres(port, env)
    return port


def start_native_fixture(resources: OwnedResources, temp: Path, env: dict[str, str], app_password: str,
                         owner_password: str, tools: dict[str, str]) -> int:
    native_env = child_environment(env, "{}")
    data_dir = temp / "postgres-data"
    data_dir.mkdir(mode=0o700)
    owner_password_path = temp / "fixture-owner.password"
    write_private(owner_password_path, owner_password + "\n")
    run_checked([
        tools["initdb"], "--no-instructions", "--auth-local=scram-sha-256",
        "--auth-host=scram-sha-256", "--username=fixture_owner",
        "--pwfile", str(owner_password_path), "--pgdata", str(data_dir),
    ], env=native_env)

    port = available_loopback_port()
    log = (temp / "postgres.log").open("w", encoding="utf-8")
    resources.log_handles.append(log)
    process = subprocess.Popen([
        tools["postgres"], "-D", str(data_dir), "-h", "127.0.0.1", "-p", str(port),
        "-c", "unix_socket_directories=",
    ], env=native_env, stdout=log, stderr=subprocess.STDOUT)
    resources.record_process(process)
    try:
        wait_for_postgres(port, native_env, process)
    except Exception as error:
        log.flush()
        detail = (temp / "postgres.log").read_text(encoding="utf-8", errors="replace")[-5000:]
        raise RuntimeError(f"{error}\nOwned native PostgreSQL log (bounded):\n{detail}") from error

    database_env = dict(native_env)
    database_env.update({
        "PGHOST": "127.0.0.1",
        "PGPORT": str(port),
        "PGUSER": "fixture_owner",
        "PGPASSWORD": owner_password,
        "PGDATABASE": "postgres",
    })
    endpoint = run_checked([
        tools["psql"], "--no-psqlrc", "--no-password", "--tuples-only", "--no-align",
        "--set=ON_ERROR_STOP=1", "-c",
        "SELECT current_setting('data_directory'), current_setting('port'), current_user",
    ], env=database_env)
    expected = f"{data_dir}|{port}|fixture_owner"
    if endpoint.stdout.strip() != expected:
        raise RuntimeError("native fixture endpoint did not match its owned PostgreSQL process")

    run_checked([tools["psql"], "--no-psqlrc", "--no-password", "--set=ON_ERROR_STOP=1",
                 "-c", "CREATE DATABASE app"], env=database_env)
    bootstrap = (FIXTURES / "bootstrap.sql").read_text().replace("__APP_PASSWORD__", app_password)
    bootstrap_path = temp / "bootstrap.sql"
    write_private(bootstrap_path, bootstrap)
    app_env = dict(database_env, PGDATABASE="app")
    run_checked([tools["psql"], "--no-psqlrc", "--no-password", "--set=ON_ERROR_STOP=1",
                 "--file", str(bootstrap_path)], env=app_env)
    return port


def json_config(temp: Path, postgres_port: int, read_port: int, write_port: int,
                app_password_path: Path, owner_password_path: Path) -> dict:
    return {
        "host": "127.0.0.1",
        "postgres_port": postgres_port,
        "read_port": read_port,
        "write_port": write_port,
        "database": "app",
        "application_role": "strict_app",
        "owner_role": "fixture_owner",
        "application_password_file": str(app_password_path),
        "owner_password_file": str(owner_password_path),
        "read_policy_file": str(temp / "read-policy.toml"),
        "read_config_file": str(temp / "read.toml"),
        "write_config_file": str(temp / "write.toml"),
        "users_file": str(temp / "users.toml"),
    }


def configcheck_old_cli(temp: Path, env: dict[str, str]) -> None:
    if not BASELINE_BINARY.is_file():
        raise RuntimeError(f"saved baseline PgDog binary is missing: {BASELINE_BINARY}")
    result = subprocess.run([
        str(BASELINE_BINARY), "--config", str(temp / "read.toml"), "--users", str(temp / "users.toml"),
        "--query-policy", "strict-read", "--read-policy-file", str(temp / "read-policy.toml"), "configcheck",
    ], env=env, text=True, capture_output=True, check=False)
    diagnostic = (result.stderr + "\n" + result.stdout).lower()
    if result.returncode == 0 or not any(token in diagnostic for token in ("unexpected argument", "unknown argument", "unrecognized option")):
        raise RuntimeError("saved baseline CLI did not fail specifically on the new strict-read argument")


def list_tests(root: Path, package: str, target_args: list[str], selection: str,
               env: dict[str, str]) -> list[str]:
    command = ["cargo", "test", "--offline", "--locked", "--manifest-path",
               str(root / "applications/pgdog/Cargo.toml"), "--package", package,
               *target_args, "--", "--list"]
    listed = run_checked(command, env=env, cwd=APPLICATION)
    all_tests = re.findall(r"(?m)^(\S+): test$", listed.stdout)
    if selection == "baseline":
        selected = [name for name in all_tests if name.startswith("strict_read_baseline_")]
    elif selection == "protocol":
        selected = [name for name in all_tests if not name.startswith("strict_read_baseline_")]
    elif selection == "core":
        selected = [name for name in all_tests if "strict_read" in name or "::read_policy::" in name]
    else:
        raise ValueError(f"unknown test selection: {selection}")
    if not selected:
        raise RuntimeError(f"selection discovered zero tests: {package} {selection}")
    print(f"Discovered {len(selected)} test(s): {package} {selection}")
    return selected


def run_tests(root: Path, package: str, target_args: list[str], selection: str,
              env: dict[str, str]) -> None:
    selected = list_tests(root, package, target_args, selection, env)
    command = ["cargo", "test", "--offline", "--locked", "--manifest-path",
               str(root / "applications/pgdog/Cargo.toml"), "--package", package, *target_args]
    if selection == "baseline":
        command.append("strict_read_baseline_")
        command.extend(["--", "--test-threads=1"])
    elif selection == "protocol":
        command.extend(["--", "--test-threads=1", "--skip", "strict_read_baseline_"])
    elif selection == "core":
        command.extend(["--", "--test-threads=1", "strict_read", "::read_policy::"])
    run_checked(command, env=env, cwd=APPLICATION)


def execute(pgdog_bin: Path, phase: str, pooler_mode: str = "session",
            query_parser: str = "auto", prepared_statements: str = "extended",
            postgres_mode: str = "docker") -> int:
    tools = required_tools(postgres_mode)
    if postgres_mode == "native":
        verify_native_postgres_version(tools)
    if not pgdog_bin.is_file() or not os.access(pgdog_bin, os.X_OK):
        raise RuntimeError(f"PgDog binary is missing or not executable: {pgdog_bin}")
    base_env = child_environment(dict(os.environ), "{}")
    resources = OwnedResources()
    temp_context = tempfile.TemporaryDirectory(prefix="pgdog-strict-read-")
    temp = Path(temp_context.name)
    temp.chmod(0o700)
    status = 0
    try:
        app_password = secrets.token_hex(24)
        owner_password = secrets.token_hex(24)
        app_password_path, owner_password_path = temp / "strict-app.password", temp / "fixture-owner.password"
        write_private(app_password_path, app_password + "\n")
        write_private(owner_password_path, owner_password + "\n")
        if postgres_mode == "native":
            postgres_port = start_native_fixture(resources, temp, base_env, app_password,
                                                 owner_password, tools)
        else:
            postgres_port = start_fixture(resources, temp, base_env, app_password,
                                          owner_password)

        ports = []
        while len(ports) < 4:
            port = available_loopback_port()
            if port not in ports:
                ports.append(port)
        read_port, write_port, read_health, write_health = ports

        substitutions = {"__APP_PASSWORD__": app_password}
        render_file(FIXTURES / "read.toml", temp / "read.toml", {
            "__PGDOG_PORT__": str(read_port), "__HEALTH_PORT__": str(read_health),
            "__POSTGRES_PORT__": str(postgres_port),
        })
        read_config = (temp / "read.toml").read_text(encoding="utf-8")
        read_config = read_config.replace('pooler_mode = "session"',
                                          f'pooler_mode = "{pooler_mode}"')
        read_config = read_config.replace("[general]", f'[general]\nquery_parser = "{query_parser}"\nprepared_statements = "{prepared_statements}"')
        write_private(temp / "read.toml", read_config)
        render_file(FIXTURES / "write.toml", temp / "write.toml", {
            "__PGDOG_PORT__": str(write_port), "__HEALTH_PORT__": str(write_health),
            "__POSTGRES_PORT__": str(postgres_port),
        })
        render_file(FIXTURES / "users.toml", temp / "users.toml", substitutions)
        render_file(FIXTURES / "read-policy.toml", temp / "read-policy.toml", {})

        config = json_config(temp, postgres_port, read_port, write_port, app_password_path, owner_password_path)
        config_json = json.dumps(config, sort_keys=True)
        test_env = child_environment(dict(os.environ), config_json)
        # The archived pre-change CLI is a one-time baseline experiment. Clean
        # CI checkouts run the current unrestricted endpoint's DML regressions
        # in `all` without depending on an ignored, machine-local executable.
        if phase == "baseline":
            configcheck_old_cli(temp, test_env)

        strict_read = phase in ("protocol", "core", "all")
        for name, port in (("read", read_port), ("write", write_port)):
            log = (temp / f"{name}.log").open("w", encoding="utf-8")
            resources.log_handles.append(log)
            command = [str(pgdog_bin), "--config", str(temp / f"{name}.toml"), "--users", str(temp / "users.toml")]
            if name == "read" and strict_read:
                command.extend(["--query-policy", "strict-read", "--read-policy-file", str(temp / "read-policy.toml")])
            process = subprocess.Popen(command, env=base_env, stdout=log, stderr=subprocess.STDOUT)
            resources.record_process(process)
            wait_for_pgdog(port, process, base_env)
            config[f"{name}_pid"] = process.pid

        test_env = child_environment(dict(os.environ), json.dumps(config, sort_keys=True))

        if phase in ("baseline", "all"):
            run_tests(ROOT, "integration_tests_rust", ["--test", "strict_read"],
                      "baseline", test_env)
        if phase in ("protocol", "all"):
            run_tests(ROOT, "integration_tests_rust", ["--test", "strict_read"],
                      "protocol", test_env)
        if phase in ("core", "all"):
            run_tests(ROOT, "pgdog", ["--bin", "pgdog"], "core", test_env)
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        for endpoint in ("read", "write"):
            log_path = temp / f"{endpoint}.log"
            if log_path.exists():
                print(f"Owned {endpoint} fixture log (bounded):\n{log_path.read_text()[-8000:]}", file=sys.stderr)
        status = 1
    finally:
        try:
            resources.cleanup()
        except Exception as error:
            print(f"FAIL: {error}", file=sys.stderr)
            status = 1
        try:
            temp_context.cleanup()
        except Exception as error:
            print(f"FAIL: temporary fixture cleanup failed: {error}", file=sys.stderr)
            status = 1
    if status == 0:
        print(f"PASS: strict-read fixture phase {phase}")
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pgdog-bin", required=True, type=Path)
    parser.add_argument("--phase", choices=("baseline", "protocol", "core", "all"), required=True)
    parser.add_argument("--pooler-mode", choices=("session", "transaction"), default="session")
    parser.add_argument("--query-parser", choices=("auto", "off"), default="auto")
    parser.add_argument("--prepared-statements", choices=("extended", "extended_anonymous", "full", "disabled"), default="extended")
    parser.add_argument("--postgres-mode", choices=("docker", "native"), default="docker")
    args = parser.parse_args()
    return execute(args.pgdog_bin.expanduser().resolve(), args.phase, args.pooler_mode,
                   args.query_parser, args.prepared_statements, args.postgres_mode)


if __name__ == "__main__":
    raise SystemExit(main())
