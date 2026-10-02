from pathlib import Path
import unittest
import subprocess
import yaml

ROOT = Path(__file__).resolve().parents[2]
PATHS = ["applications/pgdog/docker-compose.yml"] + [f"applications/pgdog/examples/{name}/docker-compose.yml" for name in ("immich", "pgbouncer_benchmark", "grafana_prometheus")]


class DistributionTests(unittest.TestCase):
    def test_active_compose_builds_our_source(self):
        for relative in PATHS:
            with self.subTest(path=relative):
                path = ROOT / relative
                services = yaml.safe_load(path.read_text())["services"]
                service = services["database" if "immich" in relative else "pgdog"]
                self.assertEqual(service.get("image"), "fork-pgdog:local")
                build = service.get("build", {})
                self.assertEqual((path.parent / build.get("context", ".")).resolve(), ROOT)
                self.assertEqual(build.get("dockerfile"), "applications/pgdog/Dockerfile")
                self.assertEqual(service.get("pull_policy"), "build")
                original = yaml.safe_load(subprocess.run(["git", "show", "HEAD:" + relative], cwd=ROOT, text=True, capture_output=True, check=True).stdout)
                current = yaml.safe_load(path.read_text())
                key = "database" if "immich" in relative else "pgdog"
                old_service = original["services"].pop(key)
                new_service = current["services"].pop(key)
                self.assertEqual(current, original, "unrelated Compose service/model changed")
                old_service.pop("image")
                for field in ("image", "build", "pull_policy"):
                    new_service.pop(field)
                self.assertEqual(new_service, old_service, "PgDog ports/mounts/environment changed")

    def test_upstream_distribution_pipeline_is_retired(self):
        for relative in (".github/workflows/package-base.yml", "applications/pgdog/docker/Dockerfile.base-builder", "applications/pgdog/docker/Dockerfile.base-runtime"):
            self.assertFalse((ROOT / relative).exists(), relative)

    def test_installation_uses_local_and_owned_oci_chart(self):
        text = (ROOT / "README.md").read_text()
        self.assertIn("charts/fork-pgdog", text)
        self.assertIn("oci://ghcr.io/devfun2026/charts/fork-pgdog", text)
        self.assertNotIn("helm repo add pgdogdev", text)


if __name__ == "__main__":
    unittest.main()
