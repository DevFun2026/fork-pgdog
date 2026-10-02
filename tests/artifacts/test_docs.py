from pathlib import Path
import tomllib
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]


class DocsTests(unittest.TestCase):
    def test_operator_and_release_contracts_have_owned_mapping_and_limits(self):
        paths = ("docs/operations/containers-and-helm.md", "docs/releases/fork-artifacts.md", "docs/operations/fork-artifact-rollback.md")
        self.assertTrue(all((ROOT / path).exists() for path in paths), "operator/release documentation missing")
        operator = (ROOT / "docs/operations/containers-and-helm.md").read_text()
        for required in ("ghcr.io/devfun2026/fork-pgdog", "charts/fork-pgdog", "existingSecret", "rollout restart", "2PC", "150", "arm64"):
            self.assertIn(required, operator)
        release = (ROOT / "docs/releases/fork-artifacts.md").read_text()
        self.assertIn("receipt", release)
        self.assertIn("not published", release)

    def test_shipped_config_examples_align_ports_and_finite_drain(self):
        for relative in ("charts/fork-pgdog/examples/values.yaml", "tests/artifacts/kubernetes/values.yaml"):
            with self.subTest(path=relative):
                values = yaml.safe_load((ROOT / relative).read_text())
                general = tomllib.loads(values["config"]["pgdogToml"])["general"]
                self.assertEqual(general["port"], 6432)
                self.assertEqual(general["healthcheck_port"], 9090)
                self.assertLess(general["shutdown_timeout"] + general["shutdown_termination_timeout"], 150000)


if __name__ == "__main__":
    unittest.main()
