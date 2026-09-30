import tempfile
import unittest
from pathlib import Path

from agent_cli.config import ConfigError, config_text_from_answers, load_config


class ConfigTests(unittest.TestCase):
    def write_config(self, body: str) -> Path:
        directory = Path(tempfile.mkdtemp())
        path = directory / "config.toml"
        path.write_text(body, encoding="utf-8")
        self.addCleanup(lambda: __import__("shutil").rmtree(directory))
        return path

    def test_rejects_string_command(self):
        path = self.write_config('[commands]\ntest_full = "pytest"\n')
        with self.assertRaisesRegex(ConfigError, "must be an array"):
            load_config(path)

    def test_rejects_string_provider_or_scanner_command(self):
        provider = self.write_config(
            '[review.provider_commands]\nclaude = "claude"\n'
        )
        with self.assertRaisesRegex(ConfigError, "provider_commands.claude"):
            load_config(provider)
        scanner = self.write_config(
            '[security.scanner_commands]\ndependency = "scan"\n'
        )
        with self.assertRaisesRegex(ConfigError, "scanner_commands.dependency"):
            load_config(scanner)

    def test_loads_argument_array_without_shell(self):
        path = self.write_config(
            '[commands]\ntest_full = ["python3", "-m", "unittest"]\n'
        )
        self.assertEqual(
            load_config(path).commands["test_full"],
            ("python3", "-m", "unittest"),
        )

    def test_commands_mapping_is_immutable(self):
        config = load_config(self.write_config('[commands]\nlint = ["ruff"]\n'))
        with self.assertRaises(TypeError):
            config.commands["lint"] = ("other",)

    def test_rejects_duplicate_or_unknown_provider(self):
        duplicate = self.write_config(
            '[review]\nprovider_order = ["claude", "claude"]\n'
        )
        with self.assertRaisesRegex(ConfigError, "duplicate provider"):
            load_config(duplicate)
        unknown = self.write_config('[review]\nprovider_order = ["other"]\n')
        with self.assertRaisesRegex(ConfigError, "unsupported provider"):
            load_config(unknown)

    def test_independent_provider_requirement_cannot_be_disabled(self):
        path = self.write_config(
            "[review]\nrequire_independent_provider = false\n"
        )
        with self.assertRaisesRegex(ConfigError, "must be true"):
            load_config(path)

    def test_init_answers_render_a_valid_deterministic_config(self):
        answers = {
            "project": {"name": "fixture", "security_profile": "standard"},
            "commands": {
                "format_check": [],
                "lint": ["python3", "-m", "compileall", "src"],
                "test_changed": [],
                "test_full": ["python3", "-m", "unittest"],
                "build": [],
                "smoke": [],
            },
            "review": {
                "enabled": True,
                "require_independent_provider": True,
                "max_package_bytes": 500000,
                "provider_order": ["claude", "codex", "gemini"],
                "provider_commands": {
                    "claude": ["claude"],
                    "codex": ["codex"],
                    "gemini": ["agy"],
                },
            },
            "security": {
                "required_scanners": ["dependency", "license", "sast"],
                "scanner_commands": {
                    "container": [],
                    "dependency": ["dependency-scan", "--json"],
                    "iac": [],
                    "license": ["license-scan", "--json"],
                    "sast": ["sast-scan", "--json"],
                },
                "scanner_support_paths": {
                    "container": [],
                    "dependency": [],
                    "iac": [],
                    "license": [],
                    "sast": [],
                },
                "scanner_version_commands": {
                    "container": [],
                    "dependency": ["dependency-scan", "--version"],
                    "iac": [],
                    "license": ["license-scan", "--version"],
                    "sast": ["sast-scan", "--version"],
                },
            },
            "memory": {
                "enabled": True,
                "startup_char_budget": 12000,
                "local_retention_days": 90,
            },
        }
        first = config_text_from_answers(answers)
        second = config_text_from_answers(answers)
        self.assertEqual(first, second)
        config = load_config(self.write_config(first))
        self.assertEqual(config.name, "fixture")
        self.assertEqual(config.commands["lint"][0], "python3")


if __name__ == "__main__":
    unittest.main()
