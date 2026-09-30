import importlib.util
import json
from pathlib import Path
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
