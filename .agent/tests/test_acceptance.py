from datetime import datetime, timezone
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "fixture"
        source = Path(__file__).resolve().parents[2]
        shutil.copytree(
            source,
            self.root,
            ignore=shutil.ignore_patterns(
                ".git", ".superpowers", ".memory", ".runs", "__pycache__", "*.pyc"
            ),
        )
        self.git("init", "-b", "main")
        self.git("config", "user.email", "fixture@example.com")
        self.git("config", "user.name", "Fixture")
        self.provider_script = Path(self.tempdir.name) / "provider-fixture.sh"
        self.provider_script.write_text(
            "#!/bin/sh\n"
            "provider=$1\n"
            "shift\n"
            "case \" $* \" in\n"
            "  *' --version '*) echo \"$provider acceptance-mock 1.0\" ;;\n"
            "  *' --help '*)\n"
            "    case \"$provider\" in\n"
            "      claude) echo '--output-format --json-schema --restricted --no-session-persistence' ;;\n"
            "      gemini) echo '--print --output-format json --json-schema --model --mode plan' >&2 ;;\n"
            "      codex) echo '--output-schema --json --sandbox read-only --ephemeral' ;;\n"
            "    esac ;;\n"
            "  *)\n"
            "    case \"$provider\" in\n"
            "      claude) echo '{\"structured_output\":{\"verdict\":\"pass\",\"findings\":[]}}' ;;\n"
            "      gemini) echo '{\"status\":\"SUCCESS\",\"structured_output\":{\"verdict\":\"pass\",\"findings\":[]}}' ;;\n"
            "      codex) echo '{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"{\\\"verdict\\\":\\\"pass\\\",\\\"findings\\\":[]}\"}}' ;;\n"
            "    esac ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        passing = '["python3", "-c", "raise SystemExit(0)"]'
        passing_command = json.loads(passing)
        self.answers = self.root / "init-answers.json"
        self.answers.write_text(
            json.dumps(
                {
                    "project": {
                        "name": "acceptance-fixture",
                        "security_profile": "standard",
                    },
                    "commands": {
                        "format_check": [],
                        "lint": passing_command,
                        "test_changed": [],
                        "test_full": passing_command,
                        "build": passing_command,
                        "smoke": [],
                    },
                    "review": {
                        "enabled": True,
                        "require_independent_provider": True,
                        "max_package_bytes": 500000,
                        "provider_order": ["claude", "codex", "gemini"],
                        "provider_commands": {
                            "claude": ["/bin/sh", str(self.provider_script), "claude"],
                            "codex": ["/bin/sh", str(self.provider_script), "codex"],
                            "gemini": ["/bin/sh", str(self.provider_script), "gemini"],
                        },
                    },
                    "security": {
                        "required_scanners": ["dependency", "license", "sast"],
                        "scanner_commands": {
                            "container": [],
                            "dependency": passing_command,
                            "iac": [],
                            "license": passing_command,
                            "sast": passing_command,
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
                            "dependency": ["python3", "--version"],
                            "iac": [],
                            "license": ["python3", "--version"],
                            "sast": ["python3", "--version"],
                        },
                    },
                    "memory": {
                        "enabled": True,
                        "startup_char_budget": 12000,
                        "local_retention_days": 90,
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        self.env = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        self.agent("init", "--answers", "init-answers.json")
        self.git("add", "-f", ".gitignore")
        self.git("add", ".")
        self.git("commit", "-m", "base template")
        base_sha = self.git_output("rev-parse", "HEAD").strip()
        self.git("update-ref", "refs/remotes/origin/main", base_sha)
        self.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
        self.git("switch", "-c", "feature/acceptance")

    def tearDown(self):
        self.tempdir.cleanup()

    @unittest.skipIf(
        os.environ.get("CI"), "mock provider sandbox integration is excluded from hosted CI"
    )
    def test_fresh_fixture_reaches_merge_ready_with_mock_reviewers(self):
        product_source = self.root / "product-source.txt"
        product_source.write_text("do not modify product source\n", encoding="utf-8")
        expected_product = product_source.read_bytes()
        self.agent("init", "--answers", "init-answers.json")
        self.assertEqual(product_source.read_bytes(), expected_product)
        for scanner in ("dependency", "license", "sast"):
            scanner_result = self.agent_result(
                "release", "run-scanner", "--scanner", scanner
            )
            self.assertEqual(
                json.loads(scanner_result.stdout)["results"][scanner]["status"],
                "passed",
            )
        base_sha = self.git_output("rev-parse", "HEAD").strip()
        candidate = {
            "id": "MEM-ACCEPTANCE-001",
            "type": "verification",
            "title": "Acceptance fixture memory",
            "summary": "The fixture validates progressive memory across a fresh repository.",
            "details": "Use this record only for deterministic acceptance coverage.",
            "components": ["runtime"],
            "paths": ["README.md"],
            "evidence": ["README.md"],
            "source_provider": "human",
            "source_session": "acceptance-fixture",
            "branch": "main",
            "observed_commit": base_sha,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "sensitivity": "internal",
            "reuse_guidance": "Use when checking the template acceptance fixture.",
        }
        checkpoint = self.root / "candidate.json"
        checkpoint.write_text(json.dumps(candidate), encoding="utf-8")
        self.agent("memory", "checkpoint", "--file", str(checkpoint))
        self.agent("memory", "promote", "MEM-ACCEPTANCE-001")
        checkpoint.unlink()
        (self.root / "product.txt").write_text("fixture product change\n", encoding="utf-8")
        self.agent("docs", "build")
        self.agent("adapters", "build")
        self.git("add", ".")
        self.git("commit", "-m", "fixture change")
        self.agent("docs", "check")
        review_evidence = self.agent_result("verify", "review", "--json")
        self.assertEqual(json.loads(review_evidence.stdout)["status"], "passed")
        pre_review = self.agent_result("verify", "merge", "--json", expected=3)
        self.assertIn(
            "independent-code-review", json.loads(pre_review.stdout)["reasons"]
        )

        for author in ("claude", "gemini", "codex"):
            for reviewer in ("claude", "gemini", "codex"):
                if author == reviewer:
                    continue
                preview = self.agent_result(
                    "review",
                    "--base",
                    "HEAD~1",
                    "--head",
                    "HEAD",
                    "--author-provider",
                    author,
                    "--reviewer-provider",
                    reviewer,
                    "--context",
                    "product.txt",
                    expected=4,
                )
                manifest = json.loads(preview.stdout)
                completed = self.agent_result(
                    "review",
                    "--base",
                    "HEAD~1",
                    "--head",
                    "HEAD",
                    "--author-provider",
                    author,
                    "--reviewer-provider",
                    reviewer,
                    "--context",
                    "product.txt",
                    "--package",
                    manifest["package_path"],
                    "--approve-manifest",
                    manifest["manifest_sha256"],
                )
                self.assertEqual(json.loads(completed.stdout)["status"], "completed")
        self.assertEqual(
            self.git_output("status", "--short", "--untracked-files=all"), ""
        )
        merge = self.agent_result("verify", "merge", "--json")
        self.assertEqual(json.loads(merge.stdout)["status"], "passed", merge.stdout)

        review_artifact = json.loads(
            (self.root / ".agent/.runs/code-review.json").read_text(encoding="utf-8")
        )
        findings_path = self.root / review_artifact["package_path"] / "findings.json"
        original_findings = findings_path.read_bytes()
        findings_path.write_text('{"verdict":"pass","findings":[]}\n', encoding="utf-8")
        tampered_merge = self.agent_result("verify", "merge", "--json", expected=3)
        self.assertIn(
            "independent-code-review", json.loads(tampered_merge.stdout)["reasons"]
        )
        findings_path.write_bytes(original_findings)

        adjudication_path = self.root / ".agent/.runs/adjudication.json"
        original_adjudication = adjudication_path.read_bytes()
        adjudication = json.loads(original_adjudication)
        adjudication["head_sha"] = "0" * 40
        adjudication_path.write_text(json.dumps(adjudication), encoding="utf-8")
        stale_adjudication = self.agent_result("verify", "merge", "--json", expected=3)
        self.assertIn(
            "independent-code-review", json.loads(stale_adjudication.stdout)["reasons"]
        )
        adjudication_path.write_bytes(original_adjudication)

        (self.root / "product.txt").write_text(
            "fixture product change\nunreviewed dirty change\n", encoding="utf-8"
        )
        dirty_merge = self.agent_result("verify", "merge", "--json", expected=3)
        dirty_payload = json.loads(dirty_merge.stdout)
        self.assertEqual(dirty_payload["status"], "blocked")
        self.assertIn("unreviewed-working-tree", dirty_payload["reasons"])

    def agent(self, *arguments: str):
        return self.agent_result(*arguments).stdout

    def agent_result(self, *arguments: str, expected: int = 0):
        result = subprocess.run(
            ("./scripts/agent", *arguments),
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            expected,
            f"agent {' '.join(arguments)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        return result

    def git(self, *arguments: str):
        subprocess.run(
            ("git", *arguments), cwd=self.root, check=True, capture_output=True, text=True
        )

    def git_output(self, *arguments: str):
        return subprocess.run(
            ("git", *arguments),
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout


if __name__ == "__main__":
    unittest.main()
