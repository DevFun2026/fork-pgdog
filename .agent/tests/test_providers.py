import json
import os
import platform
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_cli.providers.base import (
    Capability,
    ProviderPolicyError,
    ReviewRequest,
    _package_bundle,
    _sandboxed_command,
    invoke_provider,
    select_reviewer,
    validated_result,
)
from agent_cli.providers.claude import ClaudeAdapter
from agent_cli.providers.codex import CodexAdapter
from agent_cli.providers.gemini import GeminiAdapter


FIXTURES = Path(__file__).parent / "fixtures/providers"


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.package = Path(self.tempdir.name)
        self.schema = self.package / "schema.json"
        self.schema.write_text(
            json.dumps(
                {
                    "type": "object",
                    "required": ["verdict", "findings"],
                    "properties": {
                        "verdict": {"enum": ["pass", "fail"]},
                        "findings": {"type": "array"},
                    },
                }
            ),
            encoding="utf-8",
        )
        self.request = ReviewRequest(
            prompt="Review only the approved package.",
            repository_root=self.package,
            package_path=self.package,
            output_schema_path=self.schema,
            timeout=30,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_missing_cli_is_unavailable_without_install_attempt(self):
        with mock.patch("shutil.which", return_value=None):
            capability = ClaudeAdapter().detect()
        self.assertFalse(capability.available)
        self.assertEqual(capability.reason, "claude executable not found")

    def test_same_provider_selection_is_rejected(self):
        with self.assertRaises(ProviderPolicyError):
            select_reviewer(author="gemini", order=("gemini",))

    def test_selection_skips_unavailable_provider(self):
        capabilities = {
            "claude": Capability("claude", False, None, None, False, False, "missing"),
            "codex": Capability("codex", True, "/bin/codex", "1", True, True, None),
        }
        self.assertEqual(
            select_reviewer(
                author="gemini",
                order=("claude", "codex"),
                capabilities=capabilities,
            ),
            "codex",
        )

    def test_claude_json_fixture(self):
        result = ClaudeAdapter().parse(
            (FIXTURES / "claude-success.json").read_text(encoding="utf-8")
        )
        self.assertEqual(result.verdict, "pass")

    def test_gemini_json_fixture(self):
        result = GeminiAdapter().parse(
            (FIXTURES / "gemini-success.json").read_text(encoding="utf-8")
        )
        self.assertEqual(result.verdict, "pass")

    def test_codex_jsonl_fixture(self):
        result = CodexAdapter().parse(
            (FIXTURES / "codex-success.jsonl").read_text(encoding="utf-8")
        )
        self.assertEqual(result.verdict, "pass")

    def test_codex_ignores_progress_messages_before_terminal_json(self):
        raw = "\n".join(
            [
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {
                            "type": "agent_message",
                            "text": "I will inspect the approved package first.",
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {
                            "type": "agent_message",
                            "text": json.dumps({"verdict": "pass", "findings": []}),
                        },
                    }
                ),
            ]
        )

        result = CodexAdapter().parse(raw)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.verdict, "pass")

    def test_malformed_or_path_escape_never_passes(self):
        malformed = ClaudeAdapter().parse("not json")
        self.assertEqual(malformed.status, "incomplete")
        escaped = json.dumps(
            {
                "verdict": "fail",
                "findings": [
                    {
                        "id": "F-1",
                        "severity": "high",
                        "category": "security",
                        "file": "../outside",
                        "line": 1,
                        "evidence": "escape",
                        "reasoning": "unsafe",
                        "remediation": "remove",
                        "confidence": "high",
                    }
                ],
            }
        )
        self.assertEqual(ClaudeAdapter().parse(escaped).status, "incomplete")

    def test_invocations_are_read_only_and_nonpersistent(self):
        claude = ClaudeAdapter(executable="claude").build_argv(self.request)
        gemini = GeminiAdapter(executable="agy").build_argv(self.request)
        codex = CodexAdapter(executable="codex").build_argv(self.request)
        self.assertIn("--no-session-persistence", claude)
        self.assertIn("--restricted", claude)
        self.assertEqual(claude[claude.index("--tools") + 1], "Read")
        self.assertIn("plan", gemini)
        self.assertIn("read-only", codex)
        self.assertIn("--ephemeral", codex)
        self.assertIn("--skip-git-repo-check", codex)
        self.assertIn('shell_environment_policy.inherit="none"', codex)
        self.assertNotIn(self.request.prompt, (*claude, *gemini, *codex))

    @unittest.skipUnless(platform.system() == "Darwin", "macOS sandbox sentinel")
    def test_os_sandbox_denies_read_outside_review_package(self):
        outside = self.package.parent / "outside-sentinel.txt"
        outside.write_text("must-not-be-readable", encoding="utf-8")
        script = self.package.parent / "sandbox-sentinel.sh"
        script.write_text(
            '#!/bin/sh\nif cat "$1" >/dev/null 2>&1; then exit 9; '
            'elif ! cat "$2" >/dev/null 2>&1; then exit 8; '
            'else printf \'{"verdict":"pass","findings":[]}\'; fi\n',
            encoding="utf-8",
        )
        command = (
            "/bin/sh",
            str(script),
            str(outside),
            str(self.schema),
        )

        result = invoke_provider(
            provider="sentinel",
            argv=command,
            request=self.request,
            parser=lambda raw: validated_result("sentinel", json.loads(raw), raw),
            support_paths=(str(script),),
        )

        self.assertEqual(
            result.status,
            "completed",
            f"exit={result.exit_code} stderr={result.stderr_excerpt}",
        )
        self.assertEqual(result.verdict, "pass")

    @unittest.skipUnless(platform.system() == "Darwin", "macOS environment sentinel")
    def test_os_sandbox_drops_unrelated_host_secret(self):
        script = self.package.parent / "environment-sentinel.sh"
        script.write_text(
            '#!/bin/sh\nif env | grep -q UNRELATED_SECRET; then exit 9; '
            'else printf \'{"verdict":"pass","findings":[]}\'; fi\n',
            encoding="utf-8",
        )
        command = (
            "/bin/sh",
            str(script),
        )
        with mock.patch.dict(
            "os.environ", {"UNRELATED_SECRET": "must-not-enter-provider"}, clear=False
        ):
            result = invoke_provider(
                provider="sentinel",
                argv=command,
                request=self.request,
                parser=lambda raw: validated_result("sentinel", json.loads(raw), raw),
                support_paths=(str(script),),
            )
        self.assertEqual(
            result.status,
            "completed",
            f"exit={result.exit_code} stderr={result.stderr_excerpt}",
        )

    def test_linux_sandbox_mounts_only_exact_support_files(self):
        support = self.package.parent / "provider-support.sh"
        support.write_text("#!/bin/sh\n", encoding="utf-8")
        sandbox = _sandboxed_command(
            ("/bin/sh", str(support), "claude", str(self.schema)),
            self.package,
            self.package,
            "claude",
            (str(support),),
        )
        with mock.patch("platform.system", return_value="Linux"), mock.patch(
            "shutil.which", return_value="/usr/bin/bwrap"
        ):
            with sandbox as argv:
                destination = f"/agent-support/0-{support.name}"
                self.assertIn(("--ro-bind", str(support.resolve()), destination), tuple(
                    tuple(argv[index:index + 3])
                    for index in range(len(argv) - 2)
                ))
                self.assertIn(destination, argv)
                command_index = argv.index("--") + 1
                self.assertNotIn(str(support.resolve()), argv[command_index:])
                self.assertIn("/review-package/schema.json", argv[command_index:])
                self.assertNotIn(str(self.package.resolve()), argv[command_index:])

    def test_provider_environment_is_minimal_and_provider_specific(self):
        with mock.patch.dict(
            "os.environ",
            {
                "UNRELATED_SECRET": "must-not-enter-provider",
                "OPENAI_API_KEY": "openai-fixture-key",
                "ANTHROPIC_API_KEY": "anthropic-fixture-key",
                "HTTPS_PROXY": "https://proxy-user:proxy-pass@example.test",
                "PATH": "/usr/bin:/bin",
            },
            clear=True,
        ):
            sandbox = _sandboxed_command(
                ("/usr/bin/true",),
                self.package,
                self.package,
                "codex",
            )
        self.assertNotIn("UNRELATED_SECRET", sandbox.environment)
        self.assertNotIn("ANTHROPIC_API_KEY", sandbox.environment)
        self.assertEqual(sandbox.environment["OPENAI_API_KEY"], "openai-fixture-key")
        self.assertIn("openai-fixture-key", sandbox.secret_values)
        self.assertIn(
            "https://proxy-user:proxy-pass@example.test", sandbox.secret_values
        )

    def test_capability_sandbox_has_no_credentials_or_network_share(self):
        with mock.patch.dict(
            "os.environ",
            {
                "OPENAI_API_KEY": "must-not-enter-probe",
                "HTTPS_PROXY": "https://proxy-user:proxy-pass@example.test",
                "PATH": "/usr/bin:/bin",
            },
            clear=True,
        ):
            sandbox = _sandboxed_command(
                ("/usr/bin/true",),
                self.package,
                self.package,
                "codex",
                allow_network=False,
                include_credentials=False,
            )
        self.assertNotIn("OPENAI_API_KEY", sandbox.environment)
        self.assertNotIn("HTTPS_PROXY", sandbox.environment)
        with mock.patch("platform.system", return_value="Linux"), mock.patch(
            "shutil.which", return_value="/usr/bin/bwrap"
        ):
            with sandbox as argv:
                self.assertNotIn("--share-net", argv)

    def test_repository_contained_provider_executable_is_rejected(self):
        executable = self.package / "provider"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        with self.assertRaisesRegex(ProviderPolicyError, "outside the repository"):
            _sandboxed_command(
                (str(executable),),
                self.package,
                self.package,
                "claude",
            )

    def test_capability_probe_rejects_repository_script_before_execution(self):
        marker = self.package.parent / "capability-marker"
        script = self.package / "malicious.py"
        script.write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
            encoding="utf-8",
        )
        capability = ClaudeAdapter(
            command=("python3", str(script)), repository_root=self.package
        ).detect()
        self.assertFalse(capability.available)
        self.assertFalse(marker.exists())
        self.assertIn("outside the repository", capability.reason or "")

    def test_capability_probe_rejects_inline_interpreter_code(self):
        capability = ClaudeAdapter(
            command=("python3", "-c", "print('unsafe')"),
            repository_root=self.package,
        ).detect()
        self.assertFalse(capability.available)
        self.assertIn("inline or module", capability.reason or "")

    def test_provider_command_cannot_allowlist_host_directory(self):
        capability = ClaudeAdapter(
            command=("/bin/sh", str(self.package.parent)),
            repository_root=self.package,
        ).detect()
        self.assertFalse(capability.available)
        self.assertIn("argument directories", capability.reason or "")

    def test_provider_binary_argument_cannot_allowlist_host_file(self):
        host_file = self.package.parent / "host-credential.txt"
        host_file.write_text("secret", encoding="utf-8")
        capability = ClaudeAdapter(
            command=("/usr/bin/true", str(host_file)),
            repository_root=self.package,
        ).detect()
        self.assertFalse(capability.available)
        self.assertIn("host files", capability.reason or "")

    def test_provider_bundle_cannot_expand_to_home_directory(self):
        with tempfile.TemporaryDirectory(prefix="provider-home-") as directory:
            home = Path(directory)
            (home / "package.json").write_text('{"name":"too-broad"}\n', encoding="utf-8")
            script = home / "provider.js"
            script.write_text("#!/usr/bin/env node\n", encoding="utf-8")
            with mock.patch("pathlib.Path.home", return_value=home):
                capability = ClaudeAdapter(
                    command=(str(script),), repository_root=self.package
                ).detect()
        self.assertFalse(capability.available)
        self.assertIn("broad host directory", capability.reason or "")

    def test_provider_bundle_rejects_shared_temporary_and_system_roots(self):
        broad_roots = (
            Path("/private/tmp"),
            Path("/tmp"),
            Path("/var"),
        )
        package_manifests = {
            root / "package.json" for root in broad_roots
        }
        with mock.patch.object(
            Path,
            "is_file",
            autospec=True,
            side_effect=lambda path: path in package_manifests,
        ):
            for root in broad_roots:
                with self.subTest(root=root):
                    with self.assertRaisesRegex(
                        ProviderPolicyError, "broad host directory"
                    ):
                        _package_bundle(root / "provider.js")

    @unittest.skipIf(
        os.environ.get("CI"), "provider sandbox integration is excluded from hosted CI"
    )
    @unittest.skipUnless(
        shutil.which("node")
        and (platform.system() == "Darwin" or shutil.which("bwrap")),
        "Node and an OS provider sandbox are required",
    )
    def test_capability_probe_runs_dependency_bearing_script_in_sandbox(self):
        bundle = Path(tempfile.mkdtemp(prefix="provider-node-bundle-"))
        self.addCleanup(shutil.rmtree, bundle, True)
        (bundle / "package.json").write_text(
            '{"name":"provider-fixture","version":"1.0.0"}\n', encoding="utf-8"
        )
        (bundle / "markers.cjs").write_text(
            "module.exports = '--output-format --json-schema --restricted --no-session-persistence';\n",
            encoding="utf-8",
        )
        script = bundle / "provider.js"
        script.write_text(
            "#!/usr/bin/env node\n"
            "const markers = require('./markers.cjs');\n"
            "if (process.argv.includes('--version')) console.log('fixture 1.0');\n"
            "else if (process.argv.includes('--help')) console.log(markers);\n"
            "else process.exit(2);\n",
            encoding="utf-8",
        )

        capability = ClaudeAdapter(
            command=(str(script),), repository_root=self.package
        ).detect()

        self.assertTrue(capability.available, capability.reason)
        self.assertEqual(capability.version, "fixture 1.0")

    @unittest.skipIf(
        os.environ.get("CI"), "provider sandbox integration is excluded from hosted CI"
    )
    @unittest.skipUnless(
        Path("/usr/bin/yes").is_file()
        and (platform.system() == "Darwin" or shutil.which("bwrap")),
        "yes and an OS provider sandbox are required",
    )
    def test_provider_output_is_bounded_before_parsing(self):
        result = invoke_provider(
            provider="sentinel",
            argv=("/usr/bin/yes", "unbounded"),
            request=self.request,
            parser=lambda raw: self.fail("oversized output must not reach parser"),
        )
        self.assertEqual(result.status, "incomplete")
        self.assertIn("output exceeds limit", result.stderr_excerpt)


if __name__ == "__main__":
    unittest.main()
