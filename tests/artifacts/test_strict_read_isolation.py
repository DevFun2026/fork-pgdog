"""Safety contracts for the isolated strict-read integration fixture."""
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/strict_read_fixture.py"


def load_helper():
    if not HELPER.is_file():
        raise AssertionError("owned strict-read fixture helper has not been implemented")
    spec = importlib.util.spec_from_file_location("strict_read_fixture", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StrictReadFixtureIsolationTests(unittest.TestCase):
    def test_docker_bootstrap_uses_private_stdin_and_cleans_owned_container_on_failure(self):
        fixture = load_helper()
        commands = []
        container_id = "a1" * 32
        resources_class = fixture.OwnedResources

        def fake_run(command, *, input=None, **kwargs):
            commands.append((command, input, kwargs))
            if command[:2] == ["docker", "run"]:
                cidfile = Path(command[command.index("--cidfile") + 1])
                cidfile.write_text(container_id)
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
            if command[:2] == ["docker", "exec"]:
                self.assertIsNotNone(input)
                self.assertEqual(kwargs.get("text"), True)
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="permission denied")
            if command[:3] == ["docker", "rm", "--force"]:
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
            self.fail("unexpected Docker command")

        stderr = io.StringIO()
        with patch.object(fixture, "required_tools", return_value={"docker": "/usr/bin/docker"}), \
             patch.object(fixture.secrets, "token_hex",
                          side_effect=("app-password-sentinel", "owner-password-sentinel")), \
             patch.object(fixture, "OwnedResources",
                          side_effect=lambda: resources_class(docker=fake_run)), \
             patch.object(fixture.subprocess, "run", side_effect=fake_run), \
             patch.object(fixture, "run_checked", return_value=subprocess.CompletedProcess(
                 ["docker", "inspect"], 0, stdout="43130\n", stderr="")), \
             patch.object(fixture, "wait_for_postgres"), \
             redirect_stderr(stderr):
            status = fixture.execute(Path("/usr/bin/true"), "protocol", postgres_mode="docker")

        self.assertEqual(status, 1)
        run_command = next(command for command, _, _ in commands if command[:2] == ["docker", "run"])
        execs = [(command, value, kwargs) for command, value, kwargs in commands
                 if command[:2] == ["docker", "exec"]]
        self.assertEqual(len(execs), 1, "bootstrap must run through docker exec stdin")
        exec_command, bootstrap_sql, exec_kwargs = next(
            iter(execs)
        )
        self.assertNotIn("--mount", run_command)
        self.assertNotIn("bootstrap.sql", " ".join(run_command))
        self.assertEqual(exec_command[2:5], ["--user", "postgres", "--interactive"])
        self.assertEqual(exec_command[5], container_id)
        self.assertIn("--username=fixture_owner", exec_command)
        self.assertIn("--dbname=app", exec_command)
        self.assertEqual(exec_command[-2:], ["--file", "-"])
        self.assertIn("CREATE ROLE strict_app", bootstrap_sql)
        self.assertIn("app-password-sentinel", bootstrap_sql)
        self.assertNotIn("app-password-sentinel", " ".join(run_command + exec_command))
        self.assertNotIn("strict_app", " ".join(exec_command))
        self.assertNotIn("permission denied", stderr.getvalue())
        self.assertEqual(exec_kwargs.get("capture_output"), True)
        rm_commands = [command for command, _, _ in commands if command[:3] == ["docker", "rm", "--force"]]
        self.assertEqual(rm_commands, [["docker", "rm", "--force", container_id]])

    def test_native_mode_requires_postgres_18_tools_and_never_requires_docker(self):
        fixture = load_helper()
        with patch.object(fixture.shutil, "which", side_effect=lambda name: "/pg/bin/" + name):
            paths = fixture.required_tools("native")
            docker_paths = fixture.required_tools()
        self.assertNotIn("docker", paths)
        self.assertIn("docker", docker_paths)
        self.assertEqual(paths["initdb"], "/pg/bin/initdb")
        with patch.object(fixture, "run_checked", side_effect=[
            subprocess.CompletedProcess([], 0, stdout="initdb (PostgreSQL) 18.1\n"),
            subprocess.CompletedProcess([], 0, stdout="postgres (PostgreSQL) 17.6\n"),
        ]):
            with self.assertRaisesRegex(RuntimeError, "PostgreSQL 18"):
                fixture.verify_native_postgres_version(paths)

    def test_native_fixture_starts_only_owned_loopback_postgres_and_bootstraps_app(self):
        fixture = load_helper()
        resources = fixture.OwnedResources()
        process = _FakeProcess(31416)
        commands = []
        with tempfile.TemporaryDirectory(prefix="strict-native-test-") as directory:
            temp = Path(directory)
            def fake_checked(command, **kwargs):
                commands.append((command, kwargs))
                output = ""
                if "current_setting('data_directory')" in " ".join(command):
                    output = f"{temp / 'postgres-data'}|43130|fixture_owner\n"
                return subprocess.CompletedProcess(command, 0, stdout=output)
            with patch.object(fixture.subprocess, "Popen", return_value=process) as popen, \
                 patch.object(fixture, "available_loopback_port", return_value=43130), \
                 patch.object(fixture, "wait_for_postgres") as wait_ready, \
                 patch.object(fixture, "run_checked", side_effect=fake_checked):
                port = fixture.start_native_fixture(resources, temp, {
                    "PATH": "/pg/bin:/bin", "PGHOST": "unsafe", "DATABASE_URL": "unsafe",
                }, "app-secret", "owner-secret", {
                    "initdb": "/pg/bin/initdb", "postgres": "/pg/bin/postgres", "psql": "/pg/bin/psql",
                })
            self.assertEqual(port, 43130)
            self.assertEqual(resources.processes, [process])
            self.assertEqual(popen.call_args.args[0][1:6:2], ["-D", "-h", "-p"])
            self.assertEqual(popen.call_args.args[0][4], "127.0.0.1")
            self.assertIn("unix_socket_directories=", popen.call_args.args[0])
            resources.cleanup()
        self.assertIn("CREATE DATABASE app", [arg for command, _ in commands for arg in command])
        self.assertTrue(any("bootstrap.sql" in " ".join(command) for command, _ in commands))
        self.assertNotIn("docker", " ".join(arg for command, _ in commands for arg in command))
        self.assertEqual(wait_ready.call_args.args[0], port)
        database_env = next(kwargs["env"] for command, kwargs in commands
                            if "current_setting('data_directory')" in " ".join(command))
        self.assertEqual(database_env["PGHOST"], "127.0.0.1")
        self.assertEqual(database_env["PGPORT"], "43130")
        self.assertEqual(database_env["PGUSER"], "fixture_owner")
        self.assertNotIn("DATABASE_URL", database_env)

    def test_native_fixture_identity_failure_skips_bootstrap_and_cleans_owned_process(self):
        fixture = load_helper()
        resources = fixture.OwnedResources()
        process = _FakeProcess(31417)
        commands = []
        with tempfile.TemporaryDirectory(prefix="strict-native-failure-") as directory:
            temp = Path(directory)
            def fake_checked(command, **kwargs):
                commands.append(command)
                output = "other-cluster|43131|fixture_owner\n" if "current_setting" in " ".join(command) else ""
                return subprocess.CompletedProcess(command, 0, stdout=output)
            with patch.object(fixture.subprocess, "Popen", return_value=process), \
                 patch.object(fixture, "available_loopback_port", return_value=43131), \
                 patch.object(fixture, "wait_for_postgres"), \
                 patch.object(fixture, "run_checked", side_effect=fake_checked):
                with self.assertRaisesRegex(RuntimeError, "did not match its owned PostgreSQL process"):
                    fixture.start_native_fixture(resources, temp, {"PATH": "/pg/bin"},
                                                 "app-secret", "owner-secret", {
                        "initdb": "/pg/bin/initdb", "postgres": "/pg/bin/postgres", "psql": "/pg/bin/psql",
                    })
                self.assertEqual(resources.processes, [process])
                resources.cleanup()
        self.assertFalse(any("CREATE DATABASE app" in command for command in commands))
        self.assertEqual(process.terminated, 1)
        self.assertEqual(process.waited, 1)

    def test_verify_gate_propagates_the_selected_fixture_mode(self):
        gate = (ROOT / "scripts/verify-pgdog").read_text()
        self.assertIn("PGDOG_STRICT_POSTGRES_MODE", gate)
        self.assertEqual(gate.count("--postgres-mode"), 2)

    def test_verify_gate_rejects_unknown_fixture_mode_before_database_probe(self):
        env = dict(os.environ, PGDOG_STRICT_POSTGRES_MODE="ambient")
        result = subprocess.run(["bash", str(ROOT / "scripts/verify-pgdog"), "full"],
                                cwd=ROOT, env=env, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("expected docker or native", result.stderr)

    def test_core_discovery_recognizes_qualified_rust_test_names(self):
        fixture = load_helper()
        name = "frontend::read_policy::tests::strict_read_protocol"
        with patch.object(fixture, "run_checked", return_value=subprocess.CompletedProcess([], 0, stdout=name + ": test\n")):
            self.assertEqual(fixture.list_tests(ROOT, "pgdog", ["--bin", "pgdog"], "core", {}), [name])

    def test_resource_names_are_unique_and_docker_safe(self):
        fixture = load_helper()
        names = {fixture.new_resource_name() for _ in range(32)}
        self.assertEqual(len(names), 32)
        for name in names:
            self.assertRegex(name, r"^pgdog-strict-[a-f0-9-]{36}$")
            self.assertLessEqual(len(name), 63)

    def test_ephemeral_endpoint_ports_bind_only_to_loopback(self):
        fixture = load_helper()
        probe = _FakeSocket(43129)
        with patch.object(fixture.socket, "socket", return_value=probe):
            port = fixture.available_loopback_port()
        self.assertGreater(port, 0)
        self.assertLessEqual(port, 65535)
        self.assertEqual(probe.bound, ("127.0.0.1", 0))

    def test_child_environment_uses_generated_config_and_drops_overrides(self):
        fixture = load_helper()
        env = fixture.child_environment({
            "PATH": "/bin", "DATABASE_URL": "postgres://wrong/target",
            "PGDOG_TEST_CONFIG_DIR": "/repo/integration", "PGDOG_STRICT_TEST_CONFIG": "wrong",
        }, "/private/config.json")
        self.assertEqual(env["PATH"], "/bin")
        self.assertEqual(env["PGDOG_STRICT_TEST_CONFIG"], "/private/config.json")
        self.assertNotIn("DATABASE_URL", env)
        self.assertNotIn("PGDOG_TEST_CONFIG_DIR", env)

    def test_cleanup_targets_only_recorded_processes_and_container_ids(self):
        fixture = load_helper()
        runner = fixture.OwnedResources(docker=subprocess.run)
        process = _FakeProcess(31415)
        runner.record_process(process)
        runner.record_container("2f" * 32)
        commands = []

        def fake_docker(command, **kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0)

        runner.docker = fake_docker
        runner.cleanup()
        self.assertEqual(process.terminated, 1)
        self.assertEqual(process.waited, 1)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0], ["docker", "rm", "--force", "2f" * 32])

    def test_runner_has_no_cluster_or_ambient_database_target(self):
        runner = (ROOT / "scripts/strict-read-tests.sh").read_text()
        runner += HELPER.read_text()
        self.assertIn("PGDOG_STRICT_TEST_CONFIG", runner)
        self.assertNotIn("kubectl", runner)
        self.assertNotIn("docker system prune", runner)
        self.assertIn("--phase", runner)


class _FakeProcess:
    def __init__(self, pid):
        self.pid = pid
        self.terminated = 0
        self.waited = 0

    def poll(self):
        return None

    def terminate(self):
        self.terminated += 1

    def wait(self, timeout=None):
        self.waited += 1
        return 0


class _FakeSocket:
    def __init__(self, port):
        self.port = port
        self.bound = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def bind(self, address):
        self.bound = address

    def getsockname(self):
        return ("127.0.0.1", self.port)


if __name__ == "__main__":
    unittest.main()
