import tempfile
import unittest
from pathlib import Path

from agent_cli.process import run_command


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_metacharacters_are_literal_arguments(self):
        result = run_command(
            ["python3", "-c", "import sys; print(sys.argv[1])", "$(touch never)"],
            cwd=self.root,
            timeout=5,
        )
        self.assertEqual(result.stdout.strip(), "$(touch never)")
        self.assertFalse((self.root / "never").exists())
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(result.timed_out)

    def test_timeout_is_a_result_not_an_exception(self):
        result = run_command(
            ["python3", "-c", "import time; time.sleep(1)"],
            cwd=self.root,
            timeout=0.01,
        )
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.exit_code)


if __name__ == "__main__":
    unittest.main()
