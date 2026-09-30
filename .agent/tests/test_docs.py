import tempfile
import unittest
from pathlib import Path

from agent_cli.docs import build_docs, check_docs, write_docs


GOLDEN = Path(__file__).parent / "golden"


class DocumentationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        model = self.root / ".agent/project-model"
        model.mkdir(parents=True)
        (self.root / "docs/architecture").mkdir(parents=True)
        (model / "components.toml").write_text(
            'title = "Minimal System"\n'
            'purpose = "Minimal purpose"\n'
            'data_categories = ["public"]\n'
            'sensitive_categories = []\n\n'
            '[[components]]\nid = "core"\nname = "Core"\nkind = "service"\n'
            'responsibility = "Does work."\ntrust_boundary = "local"\n',
            encoding="utf-8",
        )
        (model / "relationships.toml").write_text(
            '[[relationships]]\nid = "uses"\nsource = "core"\ntarget = "core"\n'
            'label = "uses"\n',
            encoding="utf-8",
        )
        (model / "data-flows.toml").write_text(
            '[[data_flows]]\nid = "flow"\nsource = "core"\ntarget = "core"\n'
            'data_categories = ["public"]\ntrust_boundary = "local"\n',
            encoding="utf-8",
        )
        (model / "environments.toml").write_text(
            '[[environments]]\nid = "local"\nname = "Local"\n'
            'description = "Local execution."\n',
            encoding="utf-8",
        )
        (self.root / "docs/architecture/system-context.md").write_text(
            "# Context\nLocal only.\n", encoding="utf-8"
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_build_is_byte_deterministic_and_matches_goldens(self):
        first = build_docs(
            self.root,
            generated_at="2026-09-21T00:00:00Z",
            commit="abc1234",
        )
        second = build_docs(
            self.root,
            generated_at="2026-09-21T00:00:00Z",
            commit="abc1234",
        )
        self.assertEqual(first, second)
        self.assertEqual(
            first.summary,
            (GOLDEN / "minimal-system-summary.md").read_text(encoding="utf-8"),
        )
        for section_id in (
            "overview",
            "components",
            "relationships",
            "data-flows",
            "environments",
            "architecture-docs",
            "contracts",
            "adr-index",
            "security",
            "operations",
            "traceability",
            "governance",
        ):
            self.assertIn(f'id="{section_id}"', first.html)

    def test_check_detects_stale_committed_html(self):
        write_docs(
            self.root,
            generated_at="2026-09-21T00:00:00Z",
            commit="abc1234",
        )
        (self.root / "docs/architecture/system.html").write_text(
            "stale", encoding="utf-8"
        )
        result = check_docs(
            self.root,
            generated_at="2026-09-21T00:00:00Z",
            commit="abc1234",
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.changed, ("docs/architecture/system.html",))

    def test_html_escapes_project_values(self):
        path = self.root / ".agent/project-model/components.toml"
        path.write_text(
            path.read_text(encoding="utf-8").replace("Core", "<script>alert(1)</script>"),
            encoding="utf-8",
        )
        output = build_docs(
            self.root,
            generated_at="2026-09-21T00:00:00Z",
            commit="abc1234",
        )
        self.assertNotIn("<script>alert(1)</script>", output.html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", output.html)


if __name__ == "__main__":
    unittest.main()
