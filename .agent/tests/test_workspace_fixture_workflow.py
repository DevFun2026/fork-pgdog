from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/tests.yml"
PINNED_WORKFLOW = ROOT / ".github/workflows/fork-quality.yml"


class WorkspaceFixtureWorkflowTests(unittest.TestCase):
    def test_coverage_step_uses_owned_fixture_runner_fixed_coverage_mode(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("working-directory: applications/pgdog", workflow)
        self.assertIn("python3 ../../scripts/workspace_read_tests.py --coverage", workflow)
        self.assertIn("cargo llvm-cov clean --workspace", workflow)
        self.assertNotIn("cargo llvm-cov nextest", workflow)
        self.assertIn("files: applications/pgdog/lcov.info", workflow)

    def test_coverage_fixture_images_are_pulled_from_pinned_quality_sources(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        pinned_workflow = PINNED_WORKFLOW.read_text(encoding="utf-8")
        images = re.findall(
            r"(?m)^\s+run: docker pull (postgres:[^\s]+)\s*$", pinned_workflow
        )

        self.assertEqual(len(images), 2)
        self.assertEqual(
            {image.split("@", 1)[0].split(":", 1)[1].split(".", 1)[0] for image in images},
            {"12", "18"},
        )
        for image in images:
            self.assertRegex(image, r"^postgres:[^@]+@sha256:[0-9a-f]{64}$")
            self.assertIn(f"docker pull {image}", workflow)


if __name__ == "__main__":
    unittest.main()
