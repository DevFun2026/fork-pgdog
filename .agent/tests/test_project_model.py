import tempfile
import unittest
from pathlib import Path

from agent_cli.project_model import ModelError, load_project_model


class ProjectModelTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def write(self, name: str, content: str) -> None:
        (self.root / name).write_text(content, encoding="utf-8")

    def valid_files(self) -> None:
        self.write(
            "components.toml",
            'title = "Minimal System"\n'
            'purpose = "Minimal purpose"\n'
            'data_categories = ["public"]\n'
            'sensitive_categories = []\n\n'
            '[[components]]\nid = "core"\nname = "Core"\nkind = "service"\n'
            'responsibility = "Does work."\ntrust_boundary = "local"\n',
        )
        self.write(
            "relationships.toml",
            '[[relationships]]\nid = "uses"\nsource = "core"\ntarget = "core"\n'
            'label = "uses"\n',
        )
        self.write(
            "data-flows.toml",
            '[[data_flows]]\nid = "flow"\nsource = "core"\ntarget = "core"\n'
            'data_categories = ["public"]\ntrust_boundary = "local"\n',
        )
        self.write(
            "environments.toml",
            '[[environments]]\nid = "local"\nname = "Local"\n'
            'description = "Local execution."\n',
        )

    def test_relationship_rejects_unknown_component(self):
        self.valid_files()
        self.write(
            "relationships.toml",
            '[[relationships]]\nid = "bad"\nsource = "core"\ntarget = "missing"\n'
            'label = "calls"\n',
        )
        with self.assertRaisesRegex(ModelError, "unknown component: missing"):
            load_project_model(self.root)

    def test_duplicate_component_id_is_rejected(self):
        self.valid_files()
        with (self.root / "components.toml").open("a", encoding="utf-8") as stream:
            stream.write(
                '\n[[components]]\nid = "core"\nname = "Duplicate"\nkind = "service"\n'
                'responsibility = "Bad."\ntrust_boundary = "local"\n'
            )
        with self.assertRaisesRegex(ModelError, "duplicate component id"):
            load_project_model(self.root)

    def test_flow_rejects_undeclared_data_category(self):
        self.valid_files()
        self.write(
            "data-flows.toml",
            '[[data_flows]]\nid = "flow"\nsource = "core"\ntarget = "core"\n'
            'data_categories = ["secret"]\ntrust_boundary = "local"\n',
        )
        with self.assertRaisesRegex(ModelError, "undeclared data category: secret"):
            load_project_model(self.root)

    def test_model_is_sorted_by_id(self):
        self.valid_files()
        with (self.root / "components.toml").open("a", encoding="utf-8") as stream:
            stream.write(
                '\n[[components]]\nid = "adapter"\nname = "Adapter"\nkind = "adapter"\n'
                'responsibility = "Adapts."\ntrust_boundary = "local"\n'
            )
        model = load_project_model(self.root)
        self.assertEqual(tuple(item.id for item in model.components), ("adapter", "core"))


if __name__ == "__main__":
    unittest.main()
