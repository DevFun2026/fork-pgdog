import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from agent_cli.providers.base import Capability, validated_result
from agent_cli.review.models import ReviewPackageRequest
from agent_cli.review.partition_orchestrator import PartitionOrchestrator


class Provider:
    def __init__(self):
        self.calls = 0
        self.probes = 0
        self.fail_at = None
        self.invalid_at = None
        self.identity_at = None

    def detect(self):
        self.probes += 1
        return Capability("claude", True, "claude", "fixture", True, True, None)

    def review(self, request):
        self.calls += 1
        raw = json.dumps({"verdict": "pass", "findings": []})
        if self.identity_at == self.calls:
            return replace(
                validated_result("claude", json.loads(raw), raw), provider="codex"
            )
        if self.invalid_at == self.calls:
            return replace(
                validated_result("claude", json.loads(raw), raw),
                findings_json="malformed",
            )
        if self.fail_at == self.calls:
            raw = json.dumps(
                {
                    "verdict": "fail",
                    "findings": [
                        {
                            "id": "F1",
                            "severity": "high",
                            "category": "correctness",
                            "file": "one.txt",
                            "line": 1,
                            "evidence": "fixture",
                            "reasoning": "fixture",
                            "remediation": "fix",
                            "confidence": "high",
                        }
                    ],
                }
            )
        return validated_result("claude", json.loads(raw), raw)


class PartitionOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.git("init", "-b", "main")
        self.git("config", "user.email", "fixture@example.com")
        self.git("config", "user.name", "Fixture")
        config = Path(".agent/config.toml").read_text()
        (self.root / ".agent").mkdir()
        (self.root / ".agent/config.toml").write_text(config)
        (self.root / "contract.md").write_text(
            "Protocol/catalog/deployment integration contract.\n"
        )
        (self.root / "one.txt").write_text("before\n")
        self.git("add", ".")
        self.git("commit", "-m", "base")
        (self.root / "one.txt").write_text("before\nafter\n")
        self.git("add", ".")
        self.git("commit", "-m", "feature")
        self.request = ReviewPackageRequest(
            self.root,
            "HEAD~1",
            "HEAD",
            "codex",
            "claude",
            (),
            "Review all cross-boundary contracts.",
            {"tests": "passed"},
            500000,
            96000,
        )
        self.provider = Provider()
        self.runtime = PartitionOrchestrator({"claude": self.provider})

    def git(self, *args):
        return subprocess.run(
            ("git", *args), cwd=self.root, capture_output=True, check=True
        ).stdout

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self):
        return self.runtime.prepare(
            self.request, integration_context_paths=("contract.md",)
        )

    def test_no_probe_before_root_approval(self):
        part = self.prepare()
        result = self.runtime.run_partition(part, self.request)
        self.assertEqual(result.status, "manifest_pending")
        self.assertEqual(self.provider.probes, 0)
        self.assertEqual(self.provider.calls, 0)

    def test_feature_local_enablement_cannot_authorize_egress(self):
        self.git("checkout", "-b", "old-trust", "HEAD~1")
        base_config = self.root / ".agent/config.toml"
        base_config.write_text(
            base_config.read_text().replace(
                "partition_enabled = true", "partition_enabled = false"
            )
        )
        self.git("add", ".")
        self.git("commit", "-m", "old trusted policy")
        base_config.write_text(
            base_config.read_text().replace(
                "partition_enabled = false", "partition_enabled = true"
            )
        )
        self.git("add", ".")
        self.git("commit", "-m", "feature only enablement")
        part = self.prepare()
        with self.assertRaisesRegex(ValueError, "trusted"):
            self.runtime.run_partition(
                part,
                self.request,
                approved_manifest_sha256=part.manifest_sha256,
                trusted_partition_enabled=True,
            )
        self.assertEqual(self.provider.probes, 0)

    def test_two_approval_stages_and_no_child_clearance(self):
        part = self.prepare()
        result = self.runtime.run_partition(
            part,
            self.request,
            approved_manifest_sha256=part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual(result.status, "integration_manifest_pending")
        self.assertFalse((self.root / ".agent/.runs/cross-review.json").exists())
        integration = self.runtime.integration_package(part, self.request)
        probes = self.provider.probes
        result = self.runtime.run_integration(
            part, self.request, integration, trusted_partition_enabled=True
        )
        self.assertEqual(result.status, "manifest_pending")
        self.assertEqual(self.provider.probes, probes)
        result = self.runtime.run_integration(
            part,
            self.request,
            integration,
            approved_manifest_sha256=integration.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual((result.status, result.verdict), ("completed", "pass"))
        self.assertTrue(self.runtime.clearance_valid(part))

    def test_invalid_child_output_cannot_reach_integration(self):
        part = self.prepare()
        self.provider.invalid_at = 1
        result = self.runtime.run_partition(
            part,
            self.request,
            approved_manifest_sha256=part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual(result.status, "review_pending")
        self.assertFalse((self.root / ".agent/.runs/cross-review.json").exists())
        with self.assertRaises(ValueError):
            self.runtime.integration_package(part, self.request)

    def test_failed_child_cannot_be_overridden(self):
        part = self.prepare()
        self.provider.fail_at = 1
        result = self.runtime.run_partition(
            part,
            self.request,
            approved_manifest_sha256=part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual(result.verdict, "fail")
        self.assertFalse(self.runtime.clearance_valid(part))

    def test_tampered_child_result_blocks_second_stage(self):
        part = self.prepare()
        self.runtime.run_partition(
            part,
            self.request,
            approved_manifest_sha256=part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        integration = self.runtime.integration_package(part, self.request)
        (part.children[0].path / "findings.json").write_text(
            '{"verdict":"pass","findings":[]}\n'
        )
        with self.assertRaises(ValueError):
            self.runtime.run_integration(
                part,
                self.request,
                integration,
                approved_manifest_sha256=integration.manifest_sha256,
                trusted_partition_enabled=True,
            )

    def test_current_budget_is_rechecked_before_probe(self):
        part = self.prepare()
        with self.assertRaises(ValueError):
            self.runtime.run_partition(
                part,
                replace(self.request, max_package_bytes=1),
                approved_manifest_sha256=part.manifest_sha256,
                trusted_partition_enabled=True,
            )
        self.assertEqual(self.provider.probes, 0)

    def test_invalid_integration_output_never_publishes(self):
        part = self.prepare()
        self.runtime.run_partition(
            part,
            self.request,
            approved_manifest_sha256=part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        integration = self.runtime.integration_package(part, self.request)
        self.provider.invalid_at = self.provider.calls + 1
        result = self.runtime.run_integration(
            part,
            self.request,
            integration,
            approved_manifest_sha256=integration.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual(result.status, "review_pending")
        self.assertFalse((self.root / ".agent/.runs/cross-review.json").exists())

    def test_extra_integration_payload_blocks_before_probe(self):
        part = self.prepare()
        self.runtime.run_partition(
            part,
            self.request,
            approved_manifest_sha256=part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        integration = self.runtime.integration_package(part, self.request)
        (integration.path / "extra.txt").write_text("unapproved")
        probes = self.provider.probes
        with self.assertRaises(ValueError):
            self.runtime.run_integration(
                part,
                self.request,
                integration,
                approved_manifest_sha256=integration.manifest_sha256,
                trusted_partition_enabled=True,
            )
        self.assertEqual(self.provider.probes, probes)

    def test_fresh_refs_are_required_before_probe(self):
        part = self.prepare()
        (self.root / "extra.txt").write_text("new source")
        self.git("add", ".")
        self.git("commit", "-m", "drift")
        with self.assertRaises(ValueError):
            self.runtime.run_partition(
                part,
                self.request,
                approved_manifest_sha256=part.manifest_sha256,
                trusted_partition_enabled=True,
            )
        self.assertEqual(self.provider.probes, 0)

    def test_merge_loader_validates_every_result(self):
        from agent_cli.verify import _review_artifact_valid

        part = self.prepare()
        self.runtime.run_partition(
            part,
            self.request,
            approved_manifest_sha256=part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        integration = self.runtime.integration_package(part, self.request)
        self.runtime.run_integration(
            part,
            self.request,
            integration,
            approved_manifest_sha256=integration.manifest_sha256,
            trusted_partition_enabled=True,
        )
        summary = json.loads((self.root / ".agent/.runs/cross-review.json").read_text())
        m = part.root_package.manifest
        self.assertTrue(
            _review_artifact_valid(
                self.root,
                summary,
                kind="cross-provider-review",
                current_head=m.head_sha,
                trusted_base=m.base_sha,
            )
        )
        (integration.path / "findings.json").write_text("invalid")
        self.assertFalse(
            _review_artifact_valid(
                self.root,
                summary,
                kind="cross-provider-review",
                current_head=m.head_sha,
                trusted_base=m.base_sha,
            )
        )

    def test_provider_identity_mismatch_is_pending(self):
        part = self.prepare()
        self.provider.identity_at = 1
        result = self.runtime.run_partition(
            part,
            self.request,
            approved_manifest_sha256=part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual(result.status, "review_pending")
        self.assertFalse(self.runtime.clearance_valid(part))

    def test_integration_context_maps_each_child_to_exact_ranges(self):
        part = self.prepare()
        self.runtime.run_partition(
            part,
            self.request,
            approved_manifest_sha256=part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        integration = self.runtime.integration_package(part, self.request)
        data = json.loads(
            (integration.path / "context/partition-review-results.json").read_text()
        )
        self.assertEqual(data["shards"], part.manifest["children"])

    def test_empty_unlisted_directory_is_rejected(self):
        part = self.prepare()
        self.runtime.run_partition(
            part,
            self.request,
            approved_manifest_sha256=part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        integration = self.runtime.integration_package(part, self.request)
        (integration.path / "context/unlisted").mkdir()
        with self.assertRaises(ValueError):
            self.runtime.integration_package(part, self.request)

    def test_clearance_respects_lower_trusted_invocation_caps(self):
        self.git("checkout", "-b", "lower-caps", "HEAD~1")
        config = self.root / ".agent/config.toml"
        config.write_text(
            config.read_text()
            .replace("max_package_bytes = 500000", "max_package_bytes = 100000")
            .replace("max_estimated_tokens = 96000", "max_estimated_tokens = 30000")
        )
        self.git("add", ".")
        self.git("commit", "-m", "lower trusted caps")
        (self.root / "one.txt").write_text("after")
        self.git("add", ".")
        self.git("commit", "-m", "feature")
        self.request = replace(
            self.request, max_package_bytes=100000, max_estimated_tokens=30000
        )
        part = self.prepare()
        self.runtime.run_partition(
            part,
            self.request,
            approved_manifest_sha256=part.manifest_sha256,
            trusted_partition_enabled=True,
        )
        integration = self.runtime.integration_package(part, self.request)
        result = self.runtime.run_integration(
            part,
            self.request,
            integration,
            approved_manifest_sha256=integration.manifest_sha256,
            trusted_partition_enabled=True,
        )
        self.assertEqual(result.verdict, "pass")
        self.assertTrue(self.runtime.clearance_valid(part))
