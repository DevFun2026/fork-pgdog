"""Offline contract tests for project-scoped Codex subagent configuration.

Run from the repository root with Python 3.11+:
    python3 -m unittest discover -s .codex/tests -v

These tests do not invoke Codex, make model/API calls, or validate account access.
"""
from pathlib import Path
import tomllib
import unittest

CODEX_DIR = Path(__file__).resolve().parents[1]
ROLES = {"pgdog_core", "pgdog_security", "pgdog_ci", "agent_runtime"}
MODEL = "gpt-6-luna"
EFFORT = "high"


class CodexConfigTests(unittest.TestCase):
    def load(self, path: Path) -> dict:
        self.assertTrue(path.is_file(), f"Missing configuration: {path.name}")
        self.assertFalse(path.is_symlink(), f"Symlinked configuration: {path.name}")
        with path.open("rb") as handle:
            return tomllib.load(handle)

    def role(self, name: str) -> dict:
        return self.load(CODEX_DIR / "agents" / f"{name}.toml")

    def test_project_config_cannot_override_main_session_settings(self):
        # Also excludes profiles, providers, permissions and developer instructions.
        self.assertEqual(set(self.load(CODEX_DIR / "config.toml")), {"agents"})

    def test_default_subagent_settings_are_explicit(self):
        self.assertEqual(self.load(CODEX_DIR / "config.toml")["agents"], {
            "enabled": True,
            "max_concurrent_threads_per_session": 2,
            "default_subagent_model": MODEL,
            "default_subagent_reasoning_effort": EFFORT,
        })

    def test_exactly_four_custom_roles_are_registered(self):
        paths = list((CODEX_DIR / "agents").glob("*.toml"))
        self.assertEqual({path.stem for path in paths}, ROLES)
        self.assertEqual(len(paths), len(ROLES))

    def test_each_role_has_required_fields_and_matching_name(self):
        for name in sorted(ROLES):
            with self.subTest(role=name):
                config = self.role(name)
                self.assertEqual(config["name"], name)
                for field in ("name", "description", "developer_instructions"):
                    self.assertIsInstance(config[field], str)
                    self.assertTrue(config[field].strip())

    def test_each_role_pins_the_small_model(self):
        for name in sorted(ROLES):
            with self.subTest(role=name):
                self.assertEqual(self.role(name)["model"], MODEL)

    def test_each_role_pins_reasoning_instead_of_inheriting_it(self):
        for name in sorted(ROLES):
            with self.subTest(role=name):
                self.assertEqual(self.role(name)["model_reasoning_effort"], EFFORT)

    def test_each_role_is_read_only_by_default(self):
        for name in sorted(ROLES):
            with self.subTest(role=name):
                self.assertEqual(self.role(name)["sandbox_mode"], "read-only")

    def test_each_role_disables_nested_multi_agent_tools(self):
        for name in sorted(ROLES):
            with self.subTest(role=name):
                self.assertEqual(self.role(name)["agents"], {"enabled": False})

    def test_no_role_adds_provider_network_or_credential_settings(self):
        allowed = {"name", "description", "developer_instructions", "model",
                   "model_reasoning_effort", "sandbox_mode", "agents"}
        for name in sorted(ROLES):
            with self.subTest(role=name):
                self.assertEqual(set(self.role(name)), allowed)

    def test_role_instructions_keep_evidence_budget_and_repository_authority(self):
        # Text checks are guardrails for the shipped prompt, not proof of model behavior.
        for name in sorted(ROLES):
            with self.subTest(role=name):
                instructions = self.role(name)["developer_instructions"]
                for marker in ("AGENTS.md", ".agent/", "NEEDS_MAIN_REVIEW", "300-500", "file:dòng"):
                    self.assertIn(marker, instructions)


if __name__ == "__main__":
    unittest.main()
