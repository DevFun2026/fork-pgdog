import json
import shutil
import tempfile
import unittest
from pathlib import Path

from agent_cli.adapters import AdapterError, build_adapters, check_adapters


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        source = Path(__file__).resolve().parents[1]
        shutil.copytree(source / "skills", self.root / ".agent/skills")
        shutil.copytree(source / "templates/adapters", self.root / ".agent/templates/adapters")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_native_skill_bodies_equal_canonical_bodies(self):
        build_adapters(self.root)
        expected = self.tree(self.root / ".agent/skills")
        for native in (".agents/skills", ".claude/skills"):
            self.assertEqual(self.tree(self.root / native), expected)

    def test_check_detects_native_edit(self):
        build_adapters(self.root)
        path = self.root / ".claude/skills/code-review/SKILL.md"
        path.write_text(path.read_text(encoding="utf-8") + "\ndrift\n", encoding="utf-8")
        result = check_adapters(self.root)
        self.assertFalse(result.ok)
        self.assertIn(".claude/skills/code-review/SKILL.md", result.changed)

    def test_native_reference_and_license_drift_is_detected(self):
        build_adapters(self.root)
        for relative in (
            "ui-design-system/references/token-contract.md",
            "ui-design-system/references/UI-UX-PRO-MAX-LICENSE.txt",
        ):
            with self.subTest(relative=relative):
                path = self.root / ".agents/skills" / relative
                original = path.read_bytes()
                path.unlink()
                result = check_adapters(self.root)
                self.assertFalse(result.ok)
                self.assertIn(f".agents/skills/{relative}", result.changed)
                path.write_bytes(original)
        self.assertTrue(check_adapters(self.root).ok)

    def test_unowned_native_file_is_rejected(self):
        path = self.root / ".agents/skills/unowned.txt"
        path.parent.mkdir(parents=True)
        path.write_text("do not delete\n", encoding="utf-8")
        with self.assertRaisesRegex(AdapterError, "unowned"):
            build_adapters(self.root)

    def test_existing_unowned_instruction_file_is_not_overwritten(self):
        path = self.root / "CLAUDE.md"
        path.write_text("existing project instructions\n", encoding="utf-8")
        with self.assertRaisesRegex(AdapterError, "unowned"):
            build_adapters(self.root)
        self.assertEqual(path.read_text(encoding="utf-8"), "existing project instructions\n")

    def test_settings_use_safe_memory_reminders(self):
        build_adapters(self.root)
        for path in (".claude/settings.json", ".agents/hooks.json"):
            data = json.loads((self.root / path).read_text(encoding="utf-8"))
            commands = json.dumps(data, sort_keys=True)
            self.assertIn("./scripts/agent memory hook-start", commands)
            self.assertIn("./scripts/agent memory hook-reminder", commands)
            self.assertNotIn("memory checkpoint", commands)

    @staticmethod
    def tree(root: Path):
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }


if __name__ == "__main__":
    unittest.main()
