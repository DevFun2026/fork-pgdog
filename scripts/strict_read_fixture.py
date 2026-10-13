#!/usr/bin/env python3
"""Own a loopback-only PostgreSQL/PgDog fixture for strict-read tests."""
from __future__ import annotations

import argparse
import hashlib
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
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
from read_policy_profiles import write_profile_variants

APPLICATION = ROOT / "applications/pgdog"
FIXTURES = APPLICATION / "integration/strict_read"
BASELINE_BINARY = ROOT / ".agent/.runs/strict-read/pgdog-baseline"
PIN_SOURCES = {
    12: ROOT / "tests/artifacts/kubernetes/postgres-pg12.yaml",
    18: ROOT / "tests/artifacts/kubernetes/postgres.yaml",
}
SUPPORTED_MAJORS = (12, 18)


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


def verify_native_postgres_version(tools: dict[str, str], postgres_major: int = 18) -> None:
    if isinstance(postgres_major, bool) or postgres_major not in SUPPORTED_MAJORS:
        raise ValueError("PostgreSQL major must be 12 or 18")
    for name in ("initdb", "postgres", "psql", "pg_isready"):
        version = run_checked([tools[name], "--version"]).stdout.strip()
        match = re.search(r"PostgreSQL\)\s+(\d+)(?:\.|\b)", version)
        if not match or match.group(1) != str(postgres_major):
            raise RuntimeError(f"native fixture requires PostgreSQL {postgres_major} {name}; found: {version}")


def pinned_postgres_image(postgres_major: int = 18) -> str:
    if isinstance(postgres_major, bool) or postgres_major not in SUPPORTED_MAJORS:
        raise ValueError("PostgreSQL major must be 12 or 18")
    content = PIN_SOURCES[postgres_major].read_text(encoding="utf-8")
    image_lines = re.findall(r"(?m)^\s*image:\s*(postgres:[^\s#]+)", content)
    matching = [image for image in image_lines
                if re.match(rf"^postgres:{postgres_major}(?:[.@-])", image)]
    if len(matching) > 1:
        raise RuntimeError(f"repository PostgreSQL {postgres_major} image pin is ambiguous")
    if len(matching) != 1 or not re.fullmatch(
            rf"postgres:{postgres_major}(?:\.[0-9]+)?(?:-[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{{64}}",
            matching[0]):
        raise RuntimeError(f"repository PostgreSQL {postgres_major} immutable image pin is missing or malformed")
    return matching[0]


def run_checked(command: list[str], *, env=None, **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(command, env=env, text=True, capture_output=True, check=False, **kwargs)
    if result.returncode != 0:
        # Compiler warnings must not erase the test assertions on stdout.
        detail = "stdout:\n" + result.stdout.strip()[-3500:] + "\nstderr:\n" + result.stderr.strip()[-1500:]
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


def prepare_profile_fixtures(temp: Path, env: dict[str, str]) -> Path:
    """Capture owned pinned references and build private profile variants for core tests."""
    profile_dir = temp / "profile-fixtures"
    profile_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    profile_dir.chmod(0o700)
    producer = ROOT / "scripts/capture_read_dependency_reference.py"
    producer_env = child_environment(env, "{}")
    result = run_checked([
        sys.executable, str(producer), "--output-dir", str(profile_dir),
    ], env=producer_env, cwd=ROOT, timeout=900)
    try:
        captures = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("owned profile producer returned malformed provenance") from error
    if not isinstance(captures, list) or len(captures) != len(SUPPORTED_MAJORS):
        raise RuntimeError("owned profile producer did not capture both supported majors")
    by_major = {}
    for capture in captures:
        if not isinstance(capture, dict) or capture.get("major") not in SUPPORTED_MAJORS:
            raise RuntimeError("owned profile producer returned an unsupported major")
        major = capture["major"]
        if major in by_major:
            raise RuntimeError("owned profile producer returned a duplicate major")
        source = Path(capture.get("path", "")).resolve()
        expected_path = (profile_dir / f"reference-extended-pg{major}.json").resolve()
        if source != expected_path or not source.is_file():
            raise RuntimeError("owned profile producer returned a path outside its temporary fixture")
        raw = source.read_bytes()
        digest = capture.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) \
                or hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError(f"owned PG{major} reference digest did not verify")
        try:
            reference = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"owned PG{major} reference is malformed") from error
        if reference.get("postgres_major") != major \
                or reference.get("source_image") != pinned_postgres_image(major) \
                or not isinstance(reference.get("capture_id"), str) \
                or not reference["capture_id"] \
                or not str(reference.get("server_version", "")).startswith(f"{major}.") \
                or reference.get("platform") not in ("linux/amd64", "linux/arm64"):
            raise RuntimeError(f"owned PG{major} reference provenance does not match its immutable pin")
        if not isinstance(capture.get("catalog_rows"), int) or capture["catalog_rows"] <= 0 \
                or not isinstance(capture.get("extension_members"), int) or capture["extension_members"] <= 0:
            raise RuntimeError(f"owned PG{major} reference has empty catalog or extension inventory")
        by_major[major] = (capture, reference)
    if set(by_major) != set(SUPPORTED_MAJORS):
        raise RuntimeError("owned profile producer omitted a supported major")

    variants_dir = profile_dir / "variants"
    variants_dir.mkdir(mode=0o700, exist_ok=True)
    expected = {
        "core": [],
        "pg-trgm": ["pg_trgm"],
        "btree-gist": ["btree_gist"],
        "both": ["btree_gist", "pg_trgm"],
    }
    for major in SUPPORTED_MAJORS:
        capture, reference = by_major[major]
        variants = write_profile_variants(reference, variants_dir)
        if not isinstance(variants, list) or len(variants) != len(expected):
            raise RuntimeError(f"owned PG{major} profile generation did not produce four variants")
        seen = set()
        for variant in variants:
            if not isinstance(variant, dict):
                raise RuntimeError(f"owned PG{major} profile generator returned malformed metadata")
            path = Path(variant.get("path", "")).resolve()
            prefix = f"read-dependency-profile-pg{major}-"
            if path.parent != variants_dir.resolve() or not path.name.startswith(prefix) \
                    or path.suffix != ".json" or not path.is_file():
                raise RuntimeError(f"owned PG{major} variant path escaped the temporary fixture")
            suffix = path.stem[len(prefix):]
            if suffix not in expected or suffix in seen:
                raise RuntimeError(f"owned PG{major} profile variant set is ambiguous")
            data = path.read_bytes()
            digest = variant.get("sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) \
                    or hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError(f"owned PG{major} profile variant digest did not verify")
            artifact = json.loads(data)
            if artifact.get("format") != "pgdog-read-dependency-profile/v2" \
                    or artifact.get("enabled_extensions") != expected[suffix] \
                    or artifact.get("provenance", {}).get("postgres_major") != major \
                    or artifact.get("provenance", {}).get("source_image") != pinned_postgres_image(major):
                raise RuntimeError(f"owned PG{major} profile variant provenance or selector mismatch")
            counts = variant.get("catalog_row_counts")
            if not isinstance(counts, dict) or not counts or any(
                    not isinstance(count, int) or count < 0 for count in counts.values()):
                raise RuntimeError(f"owned PG{major} profile variant row counts are malformed")
            print(
                f"  {suffix}: sha256={digest} "
                f"catalog_rows={sum(counts.values())} enabled={','.join(expected[suffix]) or 'core'}"
            )
            seen.add(suffix)
        if seen != set(expected):
            raise RuntimeError(f"owned PG{major} profile variants are incomplete")
        print(
            f"Owned PG{major} profiles: image={pinned_postgres_image(major)} "
            f"platform={reference['platform']} capture_id={reference['capture_id']} "
            f"capture_sha256={capture['sha256']}"
        )
    return profile_dir


def core_test_environment(env: dict[str, str], profile_dir: Path) -> dict[str, str]:
    """Require the generated owned fixtures and explicitly pass them to Cargo."""
    profile_dir = profile_dir.resolve()
    if not profile_dir.is_dir() or any(
            not (profile_dir / f"reference-extended-pg{major}.json").is_file()
            for major in SUPPORTED_MAJORS):
        raise RuntimeError("owned profile fixtures are required for core Cargo tests")
    variants = profile_dir / "variants"
    expected = [f"read-dependency-profile-pg{major}-{suffix}.json"
                for major in SUPPORTED_MAJORS
                for suffix in ("core", "pg-trgm", "btree-gist", "both")]
    if any(not (variants / name).is_file() for name in expected):
        raise RuntimeError("owned profile fixture variants are incomplete for core Cargo tests")
    result = dict(env)
    result["PGDOG_PROFILE_TEST_FIXTURE_DIR"] = str(profile_dir)
    return result


def render_file(source: Path, target: Path, substitutions: dict[str, str]) -> None:
    content = source.read_text()
    for name, value in substitutions.items():
        content = content.replace(name, value)
    if re.search(r"__[A-Z][A-Z0-9_]*__", content):
        raise RuntimeError(f"unexpanded fixture placeholder in {source.name}")
    write_private(target, content)


def strict_read_bootstrap(app_password: str) -> str:
    """Add one safe cross-table FK used by the single-root capture regression."""
    bootstrap = (FIXTURES / "bootstrap.sql").read_text().replace(
        "__APP_PASSWORD__", app_password
    )
    return bootstrap + (
        "\nALTER TABLE public.strict_extended "
        "ADD COLUMN strict_item_id BIGINT REFERENCES public.strict_items(id);\n"
    )


def start_fixture(resources: OwnedResources, temp: Path, env: dict[str, str], app_password: str,
                  owner_password: str, postgres_major: int = 18) -> int:
    bootstrap = strict_read_bootstrap(app_password)
    cidfile = temp / "postgres.cid"
    command = [
        "docker", "run", "--pull=never", "--detach", "--name", new_resource_name(), "--cidfile", str(cidfile),
        "--publish", "127.0.0.1::5432", "--env", "POSTGRES_USER=fixture_owner",
        "--env", f"POSTGRES_PASSWORD={owner_password}", "--env", "POSTGRES_DB=app",
        pinned_postgres_image(postgres_major),
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

    # The official image runs initialization SQL as its postgres OS account.
    # A private host bind mount is owned by the runner and mode 0600, so that
    # account cannot read it on Linux. Keep the SQL private and stream it to a
    # psql process inside the already-recorded container instead.
    bootstrap_result = subprocess.run(
        ["docker", "exec", "--user", "postgres", "--interactive", container_id,
         "psql", "--username=fixture_owner", "--dbname=app", "--no-psqlrc",
         "--no-password", "--set=ON_ERROR_STOP=1", "--file", "-"],
        input=bootstrap, env=env, text=True, capture_output=True, check=False,
    )
    if bootstrap_result.returncode != 0:
        raise RuntimeError("PostgreSQL fixture bootstrap failed")
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
    bootstrap = strict_read_bootstrap(app_password)
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
    if selection == "core" and not env.get("PGDOG_PROFILE_TEST_FIXTURE_DIR"):
        raise RuntimeError("owned profile fixtures are mandatory for core Cargo tests")
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
    result = run_checked(command, env=env, cwd=APPLICATION)
    for line in (result.stdout or "").splitlines():
        if line.startswith("test result:"):
            print(line)


def execute(pgdog_bin: Path, phase: str, pooler_mode: str = "session",
            query_parser: str = "auto", prepared_statements: str = "extended",
            postgres_mode: str = "docker", postgres_major: int = 18) -> int:
    if isinstance(postgres_major, bool) or postgres_major not in SUPPORTED_MAJORS:
        raise ValueError("PostgreSQL major must be 12 or 18")
    tools = required_tools(postgres_mode)
    if postgres_mode == "native":
        verify_native_postgres_version(tools, postgres_major)
    if not pgdog_bin.is_file() or not os.access(pgdog_bin, os.X_OK):
        raise RuntimeError(f"PgDog binary is missing or not executable: {pgdog_bin}")
    base_env = child_environment(dict(os.environ), "{}")
    resources = OwnedResources()
    temp_context = tempfile.TemporaryDirectory(prefix="pgdog-strict-read-")
    temp = Path(temp_context.name)
    temp.chmod(0o700)
    status = 0
    try:
        profile_fixture_dir = None
        if phase in ("core", "all"):
            profile_fixture_dir = prepare_profile_fixtures(temp, base_env)
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
                                          owner_password, postgres_major)

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
            if profile_fixture_dir is None:
                raise RuntimeError("owned profile fixtures were not prepared for core tests")
            core_env = core_test_environment(test_env, profile_fixture_dir)
            run_tests(ROOT, "pgdog", ["--bin", "pgdog"], "core", core_env)
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
    parser.add_argument("--postgres-major", type=int, choices=SUPPORTED_MAJORS, default=18,
                        help="fixture PostgreSQL major (default: 18)")
    args = parser.parse_args()
    return execute(args.pgdog_bin.expanduser().resolve(), args.phase, args.pooler_mode,
                   args.query_parser, args.prepared_statements, args.postgres_mode,
                   args.postgres_major)


if __name__ == "__main__":
    raise SystemExit(main())
