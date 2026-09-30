import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class CliSmokeTests(unittest.TestCase):
    def test_version_reports_template_version(self):
        agent = ROOT / "scripts/agent"
        self.assertTrue(agent.exists(), "scripts/agent must exist")
        result = subprocess.run(
            [str(agent), "--version"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "agent-project-template 0.1.0")

    def test_unknown_command_is_usage_error(self):
        agent = ROOT / "scripts/agent"
        self.assertTrue(agent.exists(), "scripts/agent must exist")
        result = subprocess.run(
            [str(agent), "unknown"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)


if __name__ == "__main__":
    unittest.main()
