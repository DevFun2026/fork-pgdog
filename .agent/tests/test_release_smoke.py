import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class ReleaseSmokeTests(unittest.TestCase):
    @property
    def source_root(self):
        return Path(__file__).resolve().parents[2]

    @unittest.skipIf(
        os.environ.get("AGENT_RELEASE_SMOKE_INNER") == "1",
        "avoid recursive clean-export smoke",
    )
    def test_smoke_runs_from_clean_export(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture"
            shutil.copytree(
                self.source_root,
                fixture,
                ignore=shutil.ignore_patterns(
                    ".git", ".superpowers", ".memory", ".runs", "__pycache__", "*.pyc"
                ),
            )
            self.git(fixture, "init", "-b", "main")
            self.git(fixture, "config", "user.email", "fixture@example.com")
            self.git(fixture, "config", "user.name", "Fixture")
            self.git(fixture, "add", "-f", ".gitignore")
            self.git(fixture, "add", ".")
            self.git(fixture, "commit", "-m", "fixture")
            result = subprocess.run(
                ("bash", "scripts/release-smoke.sh"),
                cwd=fixture,
                text=True,
                capture_output=True,
                check=False,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in (
            "doctor",
            "unit-tests",
            "adapters",
            "docs",
            "memory",
            "skills",
            "licenses",
            "tracked-text",
        ):
            self.assertIn(f"PASS {name}", result.stdout)

    @staticmethod
    def git(root: Path, *arguments: str):
        subprocess.run(
            ("git", *arguments), cwd=root, check=True, capture_output=True, text=True
        )


if __name__ == "__main__":
    unittest.main()
