import json
import platform
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from hashlib import sha256
from io import StringIO
from pathlib import Path
from unittest import mock

from agent_cli.adapters import AdapterError, build_adapters
from agent_cli.cli import main
from agent_cli.config import load_config
from agent_cli.memory.service import MemoryService
from agent_cli.providers.base import ProviderPolicyError, ReviewRequest, _sandboxed_command
from agent_cli.providers.gemini import GeminiAdapter


class AntigravityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / ".agent").mkdir()
        (self.root / ".agent/config.toml").write_text("")
        self.schema = self.root / "schema.json"
        self.schema.write_text('{"type":"object"}')

    def test_default_command_is_agy_with_gemini_identity(self):
        config = load_config(self.root / ".agent/config.toml")
        self.assertEqual(config.review.provider_commands["gemini"], ("agy",))
        with mock.patch("shutil.which", return_value="/usr/bin/agy") as which:
            command = GeminiAdapter()._resolved_command()
        which.assert_called_once_with("agy")
        self.assertEqual(command[0], "/usr/bin/agy")
        self.assertEqual(GeminiAdapter.provider, "gemini")

    def test_agy_argv_pins_gemini_and_requests_schema(self):
        request = ReviewRequest("private prompt", self.root, self.root, self.schema, 30)
        argv = GeminiAdapter(executable="agy").build_argv(request)
        self.assertIn("--print", argv)
        self.assertEqual(argv[argv.index("--model") + 1], "gemini-3.1-pro-high")
        self.assertEqual(argv[argv.index("--mode") + 1], "plan")
        self.assertEqual(argv[argv.index("--json-schema") + 1], str(self.schema))
        self.assertNotIn("--approval-mode", argv)
        self.assertNotIn("--dangerously-skip-permissions", argv)
        self.assertNotIn("--continue", argv)
        self.assertNotIn(request.prompt, argv)

    def test_agy_rejects_non_gemini_or_ambiguous_model(self):
        request = ReviewRequest("", self.root, self.root, self.schema, 30)
        for arguments in (("--model", "claude-sonnet-4-6"),
                          ("--model=claude-sonnet-4-6",),
                          ("--model",),
                          ("--model", "gemini-3.1-pro-high", "--model", "claude")):
            with self.subTest(arguments=arguments), mock.patch("shutil.which", return_value="/usr/bin/agy"):
                adapter = GeminiAdapter(command=("agy", *arguments))
                with self.assertRaises(ProviderPolicyError):
                    adapter.build_argv(request)
                self.assertFalse(adapter.detect().available)

    def test_success_requires_terminal_status_and_valid_structured_output(self):
        result = {"verdict": "pass", "findings": []}
        adapter = GeminiAdapter()
        valid = {"status": "SUCCESS", "structured_output": result,
                 "response": json.dumps(result)}
        self.assertEqual(adapter.parse(json.dumps(valid)).verdict, "pass")
        for payload in (result, {"response": json.dumps(result)},
                        {**valid, "status": "ERROR"}, {**valid, "status": "TIMEOUT"},
                        {**valid, "error": "auth required"},
                        {"status": "SUCCESS", "response": json.dumps(result)},
                        {**valid, "structured_output": None},
                        {**valid, "structured_output": {"verdict": [], "findings": []}, "response": '{"verdict":[],"findings":[]}'},
                        {**valid, "response": '{"verdict":"fail","findings":[]}'},
                        {**valid, "structured_output": {"verdict": "pass", "findings": [{}]}}):
            with self.subTest(payload=payload):
                self.assertEqual(adapter.parse(json.dumps(payload)).status, "incomplete")

    def test_linux_agy_settings_are_exact_disposable_mount_not_host_profile(self):
        sandbox = _sandboxed_command(("/bin/echo",), self.root, self.root, "gemini")
        with mock.patch("platform.system", return_value="Linux"), mock.patch("shutil.which", return_value="/usr/bin/bwrap"):
            with sandbox as argv:
                target = "/tmp/.gemini/antigravity-cli/settings.json"
                source = Path(argv[argv.index(target) - 1])
                self.assertEqual(argv[argv.index(target) - 2], "--ro-bind")
                self.assertEqual(json.loads(source.read_text()), {"modelProvider": "gemini"})
                self.assertNotEqual(source.parent, Path.home())
            self.assertFalse(source.exists())

    @unittest.skipUnless(platform.system() == "Darwin", "macOS sandbox sentinel")
    def test_sandbox_allows_disposable_home_writes_but_not_package_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "sentinel.sh"
            script.write_text('mkdir "$HOME/cache" && ! touch forbidden.txt\n')
            sandbox = _sandboxed_command(("/bin/sh", str(script)), self.root, self.root, "gemini", support_paths=(str(script),))
            with sandbox as argv:
                result = subprocess.run(argv, cwd=self.root, env=sandbox.environment, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((Path(sandbox.environment["HOME"]) / "cache").is_dir())
                self.assertFalse((self.root / "forbidden.txt").exists())

    def test_agy_hook_injects_only_first_invocation_without_system_authority(self):
        for payload, expected_calls in (({"invocationNum": 0}, 1),
                                        ({"invocationNum": 1}, 0), ({}, 0),
                                        ({"invocationNum": False}, 0)):
            output = StringIO()
            with mock.patch("agent_cli.cli.ROOT", self.root), mock.patch(
                "sys.stdin", StringIO(json.dumps(payload))
            ), mock.patch.object(MemoryService, "bootstrap", return_value="bounded memory") as bootstrap, redirect_stdout(output):
                code = main(["memory", "hook-start", "--provider", "gemini"])
            self.assertEqual(code, 0)
            self.assertEqual(bootstrap.call_count, expected_calls)
            result = json.loads(output.getvalue())
            if expected_calls:
                self.assertEqual(result, {"injectSteps": [{"userMessage": "bounded memory"}]})
                self.assertEqual(bootstrap.call_args.kwargs["token_budget"], 1200)
            else:
                self.assertEqual(result, {})

    def test_agy_stop_hook_does_not_restart_or_persist_transcript(self):
        output, diagnostic = StringIO(), StringIO()
        with mock.patch("agent_cli.cli.ROOT", self.root), redirect_stdout(output), redirect_stderr(diagnostic):
            self.assertEqual(main(["memory", "hook-reminder", "--provider", "gemini"]), 0)
        self.assertEqual(json.loads(output.getvalue()), {"decision": "allow"})
        self.assertIn("checkpoint", diagnostic.getvalue())

    def prepare_adapters(self):
        source = Path(__file__).resolve().parents[1]
        shutil.copytree(source / "skills", self.root / ".agent/skills")
        shutil.copytree(source / "templates/adapters", self.root / ".agent/templates/adapters")

    def test_native_agy_hooks_and_shared_skills_replace_legacy_outputs(self):
        self.prepare_adapters()
        build_adapters(self.root)
        legacy = self.root / ".gemini/skills/code-review/SKILL.md"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("old generated copy\n")
        manifest_path = self.root / ".agent/adapters-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"][str(legacy.relative_to(self.root))] = sha256(legacy.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        unowned = self.root / ".gemini/custom.txt"
        unowned.write_text("preserve me")
        build_adapters(self.root)
        self.assertFalse(legacy.exists())
        self.assertFalse((self.root / ".gemini/settings.json").exists())
        self.assertEqual(unowned.read_text(), "preserve me")
        hooks = json.loads((self.root / ".agents/hooks.json").read_text())
        self.assertIn("PreInvocation", hooks["project-memory"])
        self.assertIn("Stop", hooks["project-memory"])

    def test_locally_edited_retired_output_blocks_pruning_before_any_write(self):
        self.prepare_adapters()
        build_adapters(self.root)
        legacy = self.root / ".gemini/settings.json"
        legacy.parent.mkdir(exist_ok=True)
        legacy.write_text("local customization")
        manifest_path = self.root / ".agent/adapters-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"][".gemini/settings.json"] = sha256(b"original").hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(AdapterError, "modified retired"):
            build_adapters(self.root)
        self.assertEqual(legacy.read_text(), "local customization")

    def test_unowned_legacy_symlink_does_not_delete_external_directories(self):
        self.prepare_adapters()
        build_adapters(self.root)
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory)
            (external / "keep-empty-directory").mkdir()
            (self.root / ".gemini").mkdir()
            (self.root / ".gemini/skills").symlink_to(external, target_is_directory=True)
            build_adapters(self.root)
            self.assertTrue((external / "keep-empty-directory").is_dir())

    def test_retired_manifest_cannot_delete_arbitrary_repository_file(self):
        self.prepare_adapters()
        build_adapters(self.root)
        victim = self.root / "notes.txt"
        victim.write_text("preserve")
        manifest_path = self.root / ".agent/adapters-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"]["notes.txt"] = sha256(victim.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(AdapterError, "unsafe retired"):
            build_adapters(self.root)
        self.assertEqual(victim.read_text(), "preserve")

    @unittest.skipUnless(platform.system() == "Darwin", "macOS sandbox paths")
    def test_disposable_home_uses_canonical_path_and_only_minimal_agy_settings(self):
        for credentials in (True, False):
            sandbox = _sandboxed_command(("/bin/echo",), self.root, self.root, "gemini", include_credentials=credentials)
            with sandbox:
                home = Path(sandbox.environment["HOME"])
                self.assertEqual(home, home.resolve())
                settings = home / ".gemini/antigravity-cli/settings.json"
                if credentials:
                    self.assertEqual(json.loads(settings.read_text()), {"modelProvider": "gemini"})
                else:
                    self.assertFalse(settings.exists())


if __name__ == "__main__":
    unittest.main()
