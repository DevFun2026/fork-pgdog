import dataclasses
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from agent_cli.cli import main
from agent_cli.config import ConfigError, load_config
from agent_cli.context import estimate_tokens, report
from agent_cli.memory.service import MemoryService


class ContextTests(unittest.TestCase):
    def test_unicode_estimate_uses_utf8_not_character_count(self):
        text = "Kiến trúc 🚀"
        self.assertEqual(estimate_tokens(text), (len(text.encode()) + 2) // 3)
        self.assertFalse(report(text, 1)["within_budget"])

    def test_budget_config_defaults_and_invalid_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text("")
            config = load_config(path)
            self.assertEqual(config.memory.startup_estimated_token_budget, 1200)
            self.assertEqual(config.review.max_estimated_tokens, 64000)
            path.write_text("[review]\nmax_estimated_tokens = false\n")
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_cli_startup_uses_foundational_selection_and_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".agent").mkdir()
            (root / ".agent/config.toml").write_text("")
            output = StringIO()
            with mock.patch("agent_cli.cli.ROOT", root), mock.patch.object(
                MemoryService, "bootstrap", return_value=""
            ) as bootstrap, redirect_stdout(output):
                main(["memory", "hook-start", "--provider", "claude"])
            self.assertEqual(bootstrap.call_args.args, ("",))
            self.assertTrue(bootstrap.call_args.kwargs["startup"])
            self.assertEqual(bootstrap.call_args.kwargs["token_budget"], 1200)

    def test_cli_bootstrap_report_has_profile_and_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".agent").mkdir()
            (root / ".agent/config.toml").write_text("")
            output = StringIO()
            with mock.patch("agent_cli.cli.ROOT", root), redirect_stdout(output):
                code = main(["memory", "bootstrap", "--query", "architecture", "--profile", "light", "--report"])
            self.assertEqual(code, 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["estimated_token_budget"], 600)
            self.assertEqual(result["estimated_tokens"], 0)
