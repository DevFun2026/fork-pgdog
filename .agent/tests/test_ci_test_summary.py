import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class CiTestSummaryTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("ci_test_summary", ROOT / "scripts/ci-test-summary.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_failed_test_names_are_checked_against_public_source(self):
        log = " FAIL [ 5.000s] pgdog::bin/pgdog tests::known_test\n FAIL [ 1.0s] pgdog::bin/pgdog secret_value\n"
        result = self.module.summarize(log, {"known_test"})
        self.assertEqual(result["failed_tests"], ["known_test"])
        self.assertNotIn("secret_value", json.dumps(result))

    def test_arbitrary_logs_and_query_values_are_not_exported(self):
        log = "password=do-not-export\nSELECT 'private';\nthread panicked: private\n"
        self.assertEqual(self.module.summarize(log, set()), {"failed_tests": [], "failed_phases": []})

    def test_ansi_and_duplicate_nextest_failures(self):
        log = "\x1b[31m FAIL [ 1.0s] pgdog tests::known_test\x1b[0m\nFAIL [ 1.0s] pgdog tests::known_test\n"
        self.assertEqual(self.module.summarize(log, {"known_test"})["failed_tests"], ["known_test"])

    def test_phase_command_arguments_are_never_exported(self):
        log = "FAILED (1): cargo nextest run --profile integration --password=private\n"
        self.assertEqual(self.module.summarize(log, set())["failed_phases"], ["rust-integration"])

    def test_python_failure_identity(self):
        log = "FAIL: test_public (test_unit.Case.test_public)\nERROR: test_secret (module.Class.test_secret)\n"
        self.assertEqual(self.module.summarize(log, {"test_public"})["failed_tests"], ["test_public"])

    def test_libtest_failed_test_names_are_checked_against_public_source(self):
        log = (
            "test frontend::read_policy::tests::known_test ... FAILED\n"
            "test frontend::read_policy::tests::secret_value ... FAILED\n"
        )
        result = self.module.summarize(log, {"known_test"})
        self.assertEqual(result["failed_tests"], ["known_test"])
        self.assertNotIn("secret_value", json.dumps(result))

    def test_strict_read_fixture_failures_export_only_fixed_phase_labels(self):
        log = (
            "FAILED (1): bash ../../scripts/strict-read-tests.sh --pgdog-bin /private/token "
            "--postgres-mode docker --phase all\n"
            "FAILED (1): bash ../../scripts/strict-read-tests.sh --phase protocol "
            "--query-parser private-query-value\n"
        )
        result = self.module.summarize(log, set())
        self.assertEqual(result["failed_phases"], ["strict-read-all", "strict-read-protocol"])
        serialized = json.dumps(result)
        for private in ("/private/token", "private-query-value", "docker"):
            self.assertNotIn(private, serialized)

    def test_fatal_phase_markers_are_allowlisted_and_never_include_details(self):
        log = (
            "FATAL_PHASE: pgdog-build\n"
            "FATAL_PHASE: legacy-start\n"
            "FATAL_PHASE: legacy-ready\n"
            "FATAL_PHASE: password=private-value\n"
        )
        result = self.module.summarize(log, set())
        self.assertEqual(
            result["failed_phases"], ["legacy-ready", "legacy-start", "pgdog-build"]
        )
        self.assertNotIn("private-value", json.dumps(result))

    def test_fatal_unwrapped_commands_emit_phase_and_preserve_exit_cleanup(self):
        cases = (("pgdog-build", 17), ("legacy-start", 19), ("legacy-ready", 1))
        for phase, expected_exit in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                scripts = root / "scripts"
                applications = root / "applications/pgdog"
                fake_bin = root / "fake-bin"
                (scripts).mkdir(parents=True)
                (applications / "integration").mkdir(parents=True)
                fake_bin.mkdir()
                verify_script = (ROOT / "scripts/verify-pgdog").read_text()
                tee = "exec > >(tee .agent/.runs/gate-logs/full-tests.log) 2>&1"
                self.assertIn(tee, verify_script)
                isolated_script = scripts / "verify-pgdog"
                isolated_script.write_text(
                    verify_script.replace(tee, "exec > .agent/.runs/gate-logs/full-tests.log 2>&1")
                )
                isolated_script.chmod(0o755)
                (scripts / "agent").write_text("#!/usr/bin/env bash\nexit 0\n")
                (scripts / "agent").chmod(0o755)
                (scripts / "strict-read-tests.sh").write_text("#!/usr/bin/env bash\nexit 0\n")
                (scripts / "strict-read-tests.sh").chmod(0o755)
                common = applications / "integration/common.sh"
                common.write_text(
                    'COMMON_DIR="$PWD/integration"\n'
                    "run_pgdog() {\n"
                    '  trap \'printf "cleaned\\n" >> "$CLEANUP_MARKER"\' EXIT\n'
                    '  [[ "${FAIL_PHASE:-}" != legacy-start ]] || return 19\n'
                    "}\n"
                )
                (applications / "integration").mkdir(exist_ok=True)
                fakes = {
                    "env": "#!/usr/bin/env bash\nexit 0\n",
                    "cargo": (
                        "#!/usr/bin/env bash\n"
                        'if [[ "${FAIL_PHASE:-}" == pgdog-build && "${1:-}" == build ]]; then exit 17; fi\n'
                        "exit 0\n"
                    ),
                    "pg_isready": (
                        "#!/usr/bin/env bash\n"
                        'if [[ "${FAIL_PHASE:-}" == legacy-ready && " $* " == *" -p 6432 "* ]]; then exit 1; fi\n'
                        "exit 0\n"
                    ),
                    "seq": "#!/usr/bin/env bash\nprintf '1\\n'\n",
                    "sleep": "#!/usr/bin/env bash\nexit 0\n",
                }
                for name, source in fakes.items():
                    path = fake_bin / name
                    path.write_text(source)
                    path.chmod(0o755)
                cleanup_marker = root / "exit-cleanup.txt"
                env = dict(
                    os.environ,
                    PATH=f"{fake_bin}:{os.environ['PATH']}",
                    FAIL_PHASE=phase,
                    CLEANUP_MARKER=str(cleanup_marker),
                )
                result = subprocess.run(
                    ["bash", str(scripts / "verify-pgdog"), "full"],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
                log = (root / ".agent/.runs/gate-logs/full-tests.log").read_text()
                self.assertEqual(
                    result.returncode,
                    expected_exit,
                    f"stdout={result.stdout!r} stderr={result.stderr!r} log={log!r}",
                )
                self.assertEqual(
                    [line for line in log.splitlines() if line.startswith("FATAL_PHASE:")],
                    [f"FATAL_PHASE: {phase}"],
                )
                if phase != "pgdog-build":
                    self.assertEqual(cleanup_marker.read_text(), "cleaned\n")
