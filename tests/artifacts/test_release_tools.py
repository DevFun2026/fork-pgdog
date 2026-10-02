import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SHA = "1" * 40
DIGEST = "sha256:" + "2" * 64


class ReleaseToolsTests(unittest.TestCase):
    def module(self, name):
        self.assertTrue((ROOT / f"scripts/artifacts/{name}.py").is_file(), f"{name} missing")
        return importlib.import_module("artifacts." + name)

    def receipt(self):
        return {"schema_version": 1, "repository": "DevFun2026/fork-pgdog", "source_sha": SHA,
                "base_sha": "3" * 40, "worktree_diff_sha256": hashlib.sha256(b"").hexdigest(),
                "created_at": "2026-10-01T00:00:00Z", "gate": {"level": "release", "status": "passed", "reasons": [], "executed": ["lint", "test_full", "build", "smoke"]},
                "evidence_sha256": {key: "4" * 64 for key in ("code-review", "cross-review", "security-clearance", "security-checks", "documentation-impact", "threat-model-delta", "clean-checkout-smoke", "release-notes", "migration-rollback", "residual-risks")},
                "artifact_checks": {"status": "passed", "source_sha": SHA, "image_platforms": ["linux/amd64", "linux/arm64"], "chart": "passed", "container": "passed", "kubernetes": "passed", "container_scan": "passed", "iac_scan": "passed"}}

    def test_strict_receipt_accepts_metadata_and_rejects_tampering(self):
        mod = self.module("release_receipt")
        raw = mod.canonical(self.receipt())
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(mod.parse_receipt(raw, digest, SHA)["source_sha"], SHA)
        for payload, expected_hash in [(raw, "0" * 64), (raw.replace(b'"passed"', b'"failed"'), digest), (b"x" * 32769, digest), (b'{"schema_version":1,"schema_version":1}', digest)]:
            with self.subTest(payload=payload[:40]), self.assertRaises(ValueError):
                mod.parse_receipt(payload, expected_hash, SHA)
        for mutate in (lambda d: d.update({"private_prompt": "secret"}), lambda d: d["gate"].update({"status": "incomplete"}), lambda d: d["evidence_sha256"].pop("security-clearance"), lambda d: d["artifact_checks"].update({"image_platforms": ["linux/arm64"]})):
            payload = self.receipt(); mutate(payload); raw = mod.canonical(payload)
            with self.assertRaises(ValueError):
                mod.parse_receipt(raw, hashlib.sha256(raw).hexdigest(), SHA)

    def test_gate_failure_or_dirty_tree_cannot_export_a_receipt(self):
        mod = self.module("release_receipt")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            with patch.object(mod, "git", return_value="dirty"), self.assertRaises(ValueError):
                mod.create_receipt(ROOT, output)
            self.assertFalse(output.exists())
            with patch.object(mod, "git", side_effect=["", SHA]), patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, '{"status":"blocked"}', "")), self.assertRaises(ValueError):
                mod.create_receipt(ROOT, output)
            self.assertFalse(output.exists())

    def test_semver_and_digest_input_are_strict(self):
        mod = self.module("release_receipt")
        for value in ("latest", "1.2", "v1.2.3", "1.2.3;echo bad", "01.2.3", "1.2.3-01", "1.2.3+build"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mod.validate_version(value)
        self.assertEqual(mod.validate_version("0.1.0-rc.1"), "0.1.0-rc.1")
        with self.assertRaises(ValueError):
            mod.validate_digest("sha256:" + "a" * 63)
        self.assertEqual(mod.validate_digest(DIGEST), DIGEST)

    def test_registry_only_authenticated_manifest_absence_allows_publish(self):
        mod = self.module("registry")
        mod.assert_absent_response(404, {"errors": [{"code": "MANIFEST_UNKNOWN"}]}, authenticated=True)
        for status, body, authenticated in [(200, {}, True), (404, {}, True), (404, {"errors": [{"code": "NAME_UNKNOWN"}]}, True), (404, {"errors": [{"code": "MANIFEST_UNKNOWN"}]}, False), (401, {}, True), (403, {}, True), (429, {}, True), (500, {}, True)]:
            with self.subTest(status=status), self.assertRaises(ValueError):
                mod.assert_absent_response(status, body, authenticated=authenticated)

    def test_chart_manifest_digest_hashes_raw_registry_bytes(self):
        import io
        import os
        mod = self.module("registry")
        raw = b'{"schemaVersion":2,"config":{"mediaType":"application/vnd.cncf.helm.config.v1+json"},"layers":[]}'
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        def response(body, headers=None):
            obj = io.BytesIO(body); obj.headers = headers or {}; obj.status = 200
            return obj
        for advertised in (digest, "sha256:" + "f" * 64):
            with patch.dict(os.environ, {"GITHUB_ACTOR": "fixture", "GITHUB_TOKEN": "fixture"}), patch.object(mod.urllib.request, "urlopen", side_effect=[response(b'{"token":"fixture"}'), response(raw, {"Docker-Content-Digest": advertised})]):
                if advertised == digest:
                    self.assertEqual(mod.manifest_digest("devfun2026/charts/fork-pgdog", "0.1.0"), digest)
                else:
                    with self.assertRaises(ValueError):
                        mod.manifest_digest("devfun2026/charts/fork-pgdog", "0.1.0")

    def test_chart_package_pins_digest_without_mutating_source(self):
        mod = self.module("package_chart")
        before = (ROOT / "charts/fork-pgdog/values.yaml").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            package = mod.package_chart(ROOT / "charts/fork-pgdog", DIGEST, "0.1.60", "0.1.0", Path(directory))
            self.assertTrue(package.is_file())
            result = subprocess.run(["helm", "show", "values", str(package)], capture_output=True, text=True, check=True)
            self.assertEqual(yaml.safe_load(result.stdout)["image"]["digest"], DIGEST)
        self.assertEqual((ROOT / "charts/fork-pgdog/values.yaml").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
