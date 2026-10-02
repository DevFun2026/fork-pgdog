import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64


class PublishTests(unittest.TestCase):
    def test_exact_verified_archives_are_copied_and_failures_stop_publication(self):
        self.assertTrue((ROOT / "scripts/artifacts/publish.py").exists(), "publish orchestration missing")
        mod = importlib.import_module("artifacts.publish")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            metadata = {arch: {"source_sha": SHA, "platform": "linux/" + arch, "archive_sha256": "c" * 64, "manifest_digest": DIGEST, "publication_digest": DIGEST, "config_digest": "sha256:" + "d" * 64} for arch in ("amd64", "arm64")}
            for arch in metadata:
                (path / f"image-{arch}.tar").touch()
                (path / f"image-{arch}.json").write_text(json.dumps({**metadata[arch], "checks": {key: "passed" for key in ("chart", "container", "kubernetes", "iac", "container_scan")}}))
            calls = []
            def command(argv):
                calls.append(argv)
                if "inspect" in argv:
                    return json.dumps({"digest": DIGEST})
                return ""
            with patch.object(mod, "archive_metadata", side_effect=lambda p, arch, source: metadata[arch]), patch.object(mod, "assert_tag_absent") as absent, patch.object(mod, "command", side_effect=command), patch.object(mod, "verify_combined"):
                result = mod.publish_images(path, SHA, "0.1.60", "0.1.0")
                self.assertEqual(result["combined"], DIGEST)
                copies = [c for c in calls if c[:2] == ["skopeo", "copy"]]
                self.assertEqual(len(copies), 2)
                create = next(c for c in calls if "create" in c)
                self.assertEqual(create[-2:], [mod.IMAGE + "@" + DIGEST] * 2)
                for call in copies:
                    self.assertIn("--all", call); self.assertIn("--preserve-digests", call)
                    self.assertTrue(any(value.startswith("oci-archive:") for value in call))
                self.assertGreaterEqual(absent.call_count, 6)
                self.assertFalse(any("helm" in c for c in calls))
            with patch.object(mod, "archive_metadata", side_effect=lambda p, arch, source: metadata[arch]), patch.object(mod, "assert_tag_absent"), patch.object(mod, "command", return_value=json.dumps({"digest": "sha256:" + "e" * 64})) as writer, self.assertRaisesRegex(ValueError, "root differs"):
                mod.publish_images(path, SHA, "0.1.60", "0.1.0")
            self.assertFalse(any("create" in call.args[0] for call in writer.call_args_list))
            with patch.object(mod, "archive_metadata", side_effect=lambda p, arch, source: metadata[arch]), patch.object(mod, "assert_tag_absent"), patch.object(mod, "command", side_effect=ValueError("network failed")), self.assertRaises(ValueError):
                mod.publish_images(path, SHA, "0.1.60", "0.1.0")
            (path / "image-arm64.json").write_text(json.dumps({**metadata["arm64"], "checks": {"container": "failed"}}))
            with patch.object(mod, "archive_metadata", side_effect=lambda p, arch, source: metadata[arch]), patch.object(mod, "assert_tag_absent"), patch.object(mod, "command") as writer, self.assertRaises(ValueError):
                mod.publish_images(path, SHA, "0.1.60", "0.1.0")
            writer.assert_not_called()

    def test_combined_image_checks_exact_child_digests_and_duplicates(self):
        mod = importlib.import_module("artifacts.publish")
        manifests = [{"digest": DIGEST, "platform": {"os": "linux", "architecture": arch}} for arch in ("amd64", "arm64")]
        expected = {arch: DIGEST for arch in ("amd64", "arm64")}
        with patch.object(mod, "command", return_value=json.dumps({"manifests": manifests})):
            mod.verify_combined(DIGEST, expected)
        for changed in ([{**manifests[0], "digest": "sha256:" + "e" * 64}, manifests[1]], manifests + [manifests[0]]):
            with patch.object(mod, "command", return_value=json.dumps({"manifests": changed})), self.assertRaises(ValueError):
                mod.verify_combined(DIGEST, expected)

    def test_chart_publication_reports_package_and_oci_digests(self):
        import hashlib
        import shutil
        mod = importlib.import_module("artifacts.publish")
        state = {}
        def materialize(root, source_sha, target):
            shutil.copytree(ROOT / "charts/fork-pgdog", target)
        def command(argv):
            if argv[:2] == ["helm", "push"]:
                state["package"] = Path(argv[2])
            elif argv[:2] == ["helm", "pull"]:
                shutil.copy2(state["package"], Path(argv[-1]) / state["package"].name)
            return ""
        with patch.object(mod, "materialize_chart", side_effect=materialize), patch.object(mod, "command", side_effect=command), patch.object(mod, "verify_combined"), patch.object(mod, "assert_tag_absent"), patch.object(mod, "manifest_digest", return_value=DIGEST, create=True):
            result = mod.publish_chart(ROOT, SHA, DIGEST, "0.1.60", "0.1.0")
            self.assertEqual(result["oci_digest"], DIGEST)
            self.assertRegex(result["package_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
