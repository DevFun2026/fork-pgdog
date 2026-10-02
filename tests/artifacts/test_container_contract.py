"""Validate external dependencies in the Docker build graph.

Runtime capabilities are exercised separately by container-smoke.sh against the
actual built image; these checks enforce the build's supply-chain boundary.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ContainerDependencyTests(unittest.TestCase):
    def test_build_graph_has_no_official_pgdog_dependency(self):
        variables = {}
        bases = []
        for line in (ROOT / "applications/pgdog/Dockerfile").read_text().splitlines():
            if line.startswith("ARG ") and "=" in line:
                key, value = line[4:].split("=", 1)
                variables[key] = value
            if line.startswith("FROM "):
                value = line.split()[1]
                for key, replacement in variables.items():
                    value = value.replace("${" + key + "}", replacement)
                bases.append(value)
        self.assertTrue(bases)
        for base in bases:
            self.assertNotIn("pgdogdev/", base, "clean build still consumes official PgDog artifacts")
            self.assertRegex(base, r"@sha256:[0-9a-f]{64}$", "base is not pinned to a manifest digest")

    def test_git_metadata_is_not_a_build_input(self):
        # Copying local Git state can leak credential-bearing remote configuration.
        instructions = (ROOT / "applications/pgdog/Dockerfile").read_text()
        copies = re.findall(r"^COPY\s+([^\n]+)", instructions, re.MULTILINE)
        self.assertFalse(any(re.search(r"(^|\s)\.git(/|\s|$)", copy) for copy in copies))
        rules = (ROOT / ".dockerignore").read_text().splitlines()
        self.assertTrue(any(rule in (".git", ".git/", "**/.git") for rule in rules),
                        "Git data remains exposed to the Docker context")


if __name__ == "__main__":
    unittest.main()
