import tempfile
import unittest
import re
from pathlib import Path
from html.parser import HTMLParser

from agent_cli.docs import build_docs, check_docs, write_docs
from agent_cli.docs_html import _graph
from agent_cli.project_model import Component


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

    def test_blueprint_page_renders_model_graph_and_readable_markdown(self):
        (self.root / "docs/architecture/system-context.md").write_text(
            "# Context\n\n**Current runtime** uses `Core`.\n\n"
            "| State | Scope |\n| --- | --- |\n| Planned | Agent |\n",
            encoding="utf-8",
        )
        page = build_docs(self.root, generated_at="fixed", commit="abc").html
        self.assertIn('class="shell"', page)
        self.assertIn('class="rail"', page)
        self.assertIn('<svg', page)
        self.assertIn('data-component="core"', page)
        self.assertIn('<strong>Current runtime</strong>', page)
        self.assertIn('<code>Core</code>', page)
        self.assertIn('<td>Planned</td>', page)
        self.assertNotIn('<pre># Context', page)

    def test_diagram_edge_does_not_cross_an_unrelated_component(self):
        nodes = tuple(Component(key, key, "service", "Work", "local")
                      for key in ("aa", "bb", "cc"))
        graph = _graph(nodes, [("aa", "bb"), ("aa", "cc")], "test", "Test")
        path = re.search(r'data-source="aa" data-target="cc" d="([^"]+)"', graph)[1]
        points = [(float(x), float(y)) for x, y in re.findall(r'[ML]([0-9.]+),([0-9.]+)', path)]
        self.assertGreaterEqual(len(points), 2)
        # The middle component occupies x=332..598, y=28..134.
        # No connecting segment may enter its interior and imply a false dependency.
        for (x1, y1), (x2, y2) in zip(points, points[1:]):
            if y1 == y2 and 28 < y1 < 134:
                self.assertFalse(max(min(x1, x2), 332) < min(max(x1, x2), 598))
            if x1 == x2 and 332 < x1 < 598:
                self.assertFalse(max(min(y1, y2), 28) < min(max(y1, y2), 134))

    def test_blueprint_has_valid_navigation_and_no_remote_assets(self):
        class Audit(HTMLParser):
            def __init__(self):
                super().__init__()
                self.ids = []
                self.targets = []
                self.assets = []
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if "id" in attrs:
                    self.ids.append(attrs["id"])
                if tag == "a" and attrs.get("href", "").startswith("#"):
                    self.targets.append(attrs["href"][1:])
                if tag in {"script", "link", "img", "iframe", "source"}:
                    self.assets.extend(attrs[key] for key in ("src", "href", "srcset") if key in attrs)
        page = build_docs(self.root, generated_at="fixed", commit="abc").html
        audit = Audit()
        audit.feed(page)
        self.assertEqual(len(audit.ids), len(set(audit.ids)))
        self.assertTrue(set(audit.targets).issubset(audit.ids))
        self.assertEqual(audit.assets, [])
        self.assertIn('aria-expanded="false"', page)
        self.assertIn('prefers-color-scheme: dark', page)

    def test_document_markdown_cannot_inject_active_html_or_unsafe_urls(self):
        (self.root / "docs/architecture/system-context.md").write_text(
            '# Context\n<img src=x onerror=alert(1)>\n\n'
            '[unsafe](javascript:alert) [protocol](//evil.invalid) '
            '[safe](https://docs.example.com/) [malformed](https://[broken)\n', encoding="utf-8",
        )
        page = build_docs(self.root, generated_at="fixed", commit="abc").html
        self.assertNotIn('<img src=x', page)
        self.assertNotIn('href="javascript:', page)
        self.assertNotIn('href="//evil.invalid', page)
        self.assertIn('href="https://docs.example.com/"', page)

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
