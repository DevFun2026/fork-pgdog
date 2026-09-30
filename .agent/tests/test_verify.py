from hashlib import sha256
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import MappingProxyType

from agent_cli.config import MemoryConfig, ProjectConfig, ReviewConfig, SecurityConfig
from agent_cli.verify import _scanner_evidence, git_identity, run_gate, tool_identity


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def config(self, commands):
        return ProjectConfig(
            name="fixture",
            security_profile="standard",
            commands=MappingProxyType(commands),
            review=ReviewConfig(
                enabled=True,
                require_independent_provider=True,
                max_package_bytes=500000,
                provider_order=("claude", "codex", "gemini"),
                provider_commands=MappingProxyType(
                    {"claude": ("claude",), "codex": ("codex",), "gemini": ("agy",)}
                ),
            ),
            memory=MemoryConfig(
                enabled=True,
                startup_char_budget=12000,
                local_retention_days=90,
            ),
            security=SecurityConfig(
                required_scanners=("dependency", "license", "sast"),
                scanner_commands=MappingProxyType(
                    {
                        "container": (),
                        "dependency": (),
                        "iac": (),
                        "license": (),
                        "sast": (),
                    }
                ),
                scanner_version_commands=MappingProxyType(
                    {
                        "container": (),
                        "dependency": (),
                        "iac": (),
                        "license": (),
                        "sast": (),
                    }
                ),
                scanner_support_paths=MappingProxyType(
                    {
                        "container": (),
                        "dependency": (),
                        "iac": (),
                        "license": (),
                        "sast": (),
                    }
                ),
            ),
        )

    def test_merge_blocks_skipped_required_command(self):
        result = run_gate("merge", self.config({"test_full": ()}), self.root)
        self.assertEqual(result.status, "blocked")
        self.assertIn("test_full", result.reasons)

    def test_review_evidence_runs_merge_commands_without_review_artifacts(self):
        passing = ("python3", "-c", "raise SystemExit(0)")
        result = run_gate(
            "review",
            self.config({"lint": passing, "test_full": passing, "build": passing}),
            self.root,
        )
        self.assertEqual(result.status, "passed", result.reasons)
        self.assertEqual(result.executed, ("lint", "test_full", "build"))

    def test_unconfigured_quick_gate_is_incomplete(self):
        result = run_gate("quick", self.config({}), self.root)
        self.assertEqual(result.status, "incomplete")
        self.assertIn("quick commands", " ".join(result.reasons))

    def test_configured_quick_command_can_pass(self):
        result = run_gate(
            "quick",
            self.config({"test_changed": ("python3", "-c", "print('ok')")}),
            self.root,
        )
        self.assertEqual(result.status, "passed", result.reasons)
        self.assertEqual(result.executed, ("test_changed",))

    def test_failed_quick_command_blocks(self):
        result = run_gate(
            "quick",
            self.config({"lint": ("python3", "-c", "raise SystemExit(7)")}),
            self.root,
        )
        self.assertEqual(result.status, "blocked")
        self.assertIn("lint", result.reasons)

    def test_scanner_evidence_is_bound_to_head_diff_config_and_output(self):
        subprocess.run(("git", "init", "-b", "main"), cwd=self.root, check=True, capture_output=True)
        subprocess.run(("git", "config", "user.email", "fixture@example.com"), cwd=self.root, check=True)
        subprocess.run(("git", "config", "user.name", "Fixture"), cwd=self.root, check=True)
        output = self.root / "scanner.json"
        output.write_text(
            json.dumps(
                {
                    "scanner": "dependency",
                    "status": "passed",
                    "exit_code": 0,
                    "timed_out": False,
                    "started_at": "2026-09-22T00:00:00Z",
                    "duration_ms": 1,
                    "stdout": "no findings",
                    "stderr": "",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        subprocess.run(("git", "add", "."), cwd=self.root, check=True)
        subprocess.run(("git", "commit", "-m", "fixture"), cwd=self.root, check=True, capture_output=True)
        head, diff_hash = git_identity(self.root)
        required = ("dependency", "license", "sast")
        command = ("python3", "-c", "raise SystemExit(0)")
        scanner_commands = {
            "dependency": command,
            "license": (),
            "sast": (),
            "iac": (),
            "container": (),
        }
        scanner_version_commands = {
            "dependency": ("python3", "--version"),
            "license": (),
            "sast": (),
            "iac": (),
            "container": (),
        }
        scanner_support_paths = {
            scanner: () for scanner in scanner_commands
        }
        checks = {
            "head_sha": head,
            "working_tree_diff_sha256": diff_hash,
            "required": list(required),
            "results": {
                "dependency": {
                    "status": "passed",
                    "tool_version": tool_identity(
                        command,
                        self.root,
                        version_argv=scanner_version_commands["dependency"],
                    ),
                    "command_sha256": sha256(
                        json.dumps(list(command), separators=(",", ":")).encode(
                            "utf-8"
                        )
                    ).hexdigest(),
                    "output_path": "scanner.json",
                    "output_sha256": sha256(output.read_bytes()).hexdigest(),
                }
            },
        }
        self.assertEqual(
            _scanner_evidence(
                self.root,
                checks,
                current_head=head,
                current_worktree_diff=diff_hash,
                required_scanners=required,
                scanner_commands=scanner_commands,
                scanner_version_commands=scanner_version_commands,
                scanner_support_paths=scanner_support_paths,
            ),
            {"dependency": "passed"},
        )

        inconsistent_timeout = json.loads(output.read_text(encoding="utf-8"))
        inconsistent_timeout["status"] = "timeout"
        inconsistent_timeout["timed_out"] = True
        output.write_text(
            json.dumps(inconsistent_timeout, sort_keys=True) + "\n", encoding="utf-8"
        )
        checks["results"]["dependency"]["status"] = "timeout"
        checks["results"]["dependency"]["output_sha256"] = sha256(
            output.read_bytes()
        ).hexdigest()
        self.assertEqual(
            _scanner_evidence(
                self.root,
                checks,
                current_head=head,
                current_worktree_diff=diff_hash,
                required_scanners=required,
                scanner_commands=scanner_commands,
                scanner_version_commands=scanner_version_commands,
                scanner_support_paths=scanner_support_paths,
            ),
            {},
        )

        inconsistent_timeout["status"] = "passed"
        inconsistent_timeout["timed_out"] = False
        output.write_text(
            json.dumps(inconsistent_timeout, sort_keys=True) + "\n", encoding="utf-8"
        )
        checks["results"]["dependency"]["status"] = "passed"

        invalid_types = json.loads(output.read_text(encoding="utf-8"))
        invalid_types["exit_code"] = False
        invalid_types["timed_out"] = "false"
        output.write_text(json.dumps(invalid_types, sort_keys=True) + "\n", encoding="utf-8")
        checks["results"]["dependency"]["output_sha256"] = sha256(
            output.read_bytes()
        ).hexdigest()
        self.assertEqual(
            _scanner_evidence(
                self.root,
                checks,
                current_head=head,
                current_worktree_diff=diff_hash,
                required_scanners=required,
                scanner_commands=scanner_commands,
                scanner_version_commands=scanner_version_commands,
                scanner_support_paths=scanner_support_paths,
            ),
            {},
        )

        output.write_text('{"tampered": true}\n', encoding="utf-8")
        self.assertEqual(
            _scanner_evidence(
                self.root,
                checks,
                current_head=head,
                current_worktree_diff=diff_hash,
                required_scanners=required,
                scanner_commands=scanner_commands,
                scanner_version_commands=scanner_version_commands,
                scanner_support_paths=scanner_support_paths,
            ),
            {},
        )
        stale = {**checks, "head_sha": "0" * 40}
        self.assertEqual(
            _scanner_evidence(
                self.root,
                stale,
                current_head=head,
                current_worktree_diff=diff_hash,
                required_scanners=required,
                scanner_commands=scanner_commands,
                scanner_version_commands=scanner_version_commands,
                scanner_support_paths=scanner_support_paths,
            ),
            {},
        )

    def test_tool_identity_changes_when_support_script_changes(self):
        script = self.root / "scanner.py"
        script.write_text("print('scanner 1')\n", encoding="utf-8")
        command = ("python3", str(script))
        before = tool_identity(command, self.root)
        script.write_text("print('scanner 2')\n", encoding="utf-8")
        after = tool_identity(command, self.root)
        self.assertNotEqual(before, after)

    def test_tool_identity_binds_flag_value_and_directory_support(self):
        with tempfile.TemporaryDirectory(prefix="scanner-support-") as directory:
            policy = Path(directory)
            rules = policy / "rules.yml"
            rules.write_text("deny: one\n", encoding="utf-8")
            command = ("python3", f"--config={rules}", ".")
            before = tool_identity(command, self.root, support_paths=(str(policy),))
            (self.root / "ignored-runtime.txt").write_text(
                "must not affect scanner identity\n", encoding="utf-8"
            )
            after_target_change = tool_identity(
                command, self.root, support_paths=(str(policy),)
            )
            self.assertEqual(before, after_target_change)
            rules.write_text("deny: two\n", encoding="utf-8")
            after_support_change = tool_identity(
                command, self.root, support_paths=(str(policy),)
            )
            self.assertNotEqual(before, after_support_change)


if __name__ == "__main__":
    unittest.main()
