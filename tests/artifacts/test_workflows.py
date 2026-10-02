from pathlib import Path
import re
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]


class WorkflowTests(unittest.TestCase):
    def load(self, name):
        path = ROOT / f".github/workflows/{name}.yml"
        self.assertTrue(path.exists(), f"{name} workflow missing")
        return yaml.load(path.read_text(), Loader=yaml.BaseLoader)

    def check_pins(self, workflow):
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if "uses" in step and not step["uses"].startswith("./"):
                    self.assertRegex(step["uses"], r"@[a-f0-9]{40}$")

    def test_validation_is_read_only_native_and_bounded(self):
        workflow = self.load("artifact-quality")
        self.assertEqual(set(workflow["on"]), {"pull_request", "workflow_dispatch"})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.check_pins(workflow)
        matrix = workflow["jobs"]["build"]["strategy"]["matrix"]["include"]
        self.assertEqual({(row["runner"], row["arch"]) for row in matrix}, {("ubuntu-24.04", "amd64"), ("ubuntu-24.04-arm", "arm64")})
        text = str(workflow)
        self.assertNotIn("packages", text)
        self.assertNotIn("id-token", text)
        self.assertNotIn("login-action", text)
        self.assertIn("scripts/build-artifact", text)
        self.assertIn("bash scripts/helm-smoke.sh", (ROOT / "scripts/build-artifact").read_text())
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if "checkout@" in step.get("uses", ""):
                    self.assertEqual(step["with"]["persist-credentials"], "false")
                if "upload-artifact@" in step.get("uses", ""):
                    self.assertNotIn(".agent", step["with"]["path"])

    def test_publish_has_approved_receipt_source_and_protected_write_job(self):
        workflow = self.load("package")
        self.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
        self.assertIsInstance(workflow["on"]["workflow_dispatch"], dict, "publish workflow has no source/receipt inputs")
        self.assertEqual(set(workflow["on"]["workflow_dispatch"]["inputs"]), {"source_sha", "image_version", "chart_version", "receipt_json", "receipt_sha256"})
        self.check_pins(workflow)
        self.assertEqual(workflow["jobs"]["publish"]["environment"], "packages")
        self.assertEqual(workflow["jobs"]["publish"]["needs"], ["preflight", "build"])
        self.assertIn("publish-preflight", str(workflow["jobs"]["preflight"]))
        self.assertIn("scripts/publish-artifacts", str(workflow["jobs"]["publish"]))
        for name, job in workflow["jobs"].items():
            if name != "publish":
                self.assertNotIn("write", str(job.get("permissions", {})))
        self.assertEqual(workflow["concurrency"]["cancel-in-progress"], "false")
        self.assertIn("source-sha", str(workflow["jobs"]["publish"]))

    def test_authorization_is_rechecked_after_environment_approval_before_login(self):
        workflow = self.load("package")
        self.assertEqual(workflow["jobs"]["preflight"]["permissions"]["actions"], "read")
        steps = workflow["jobs"]["publish"]["steps"]
        recheck = next(i for i, step in enumerate(steps) if step.get("name") == "Revalidate receipt after owner approval")
        login = next(i for i, step in enumerate(steps) if "docker/login-action@" in step.get("uses", ""))
        self.assertLess(recheck, login)
        self.assertIn("publish-preflight", steps[recheck]["run"])
        self.assertIn("GH_TOKEN", steps[recheck]["env"])
        self.assertEqual(workflow["jobs"]["publish"]["permissions"]["actions"], "read")


if __name__ == "__main__":
    unittest.main()
