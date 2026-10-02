import importlib
from pathlib import Path
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT / "scripts/artifacts/scan.py").is_file(), "scan binding missing")
        self.scan = importlib.import_module("artifacts.scan")

    def test_stale_or_wrong_image_binding_is_rejected(self):
        binding = {"source_sha": "a" * 40, "tree_sha256": "b" * 64, "image": "fixture:local", "image_config_digest": "sha256:" + "c" * 64, "inputs": {"Dockerfile": "d" * 64}}
        with patch.object(self.scan, "source_identity", return_value=("a" * 40, "b" * 64)), patch.object(self.scan, "image_identity", return_value="sha256:" + "c" * 64), patch.object(self.scan, "input_hashes", return_value={"Dockerfile": "d" * 64}):
            self.scan.validate_binding(ROOT, binding)
            for field in ("source_sha", "tree_sha256", "image_config_digest", "inputs"):
                invalid = dict(binding); invalid[field] = "invalid"
                with self.subTest(field=field), self.assertRaises(ValueError):
                    self.scan.validate_binding(ROOT, invalid)

    def test_missing_version_and_database_failure_block_scan(self):
        for result in ("Version: 0.73.0", "not trivy"):
            with patch.object(self.scan, "command", return_value=result), self.assertRaises(ValueError):
                self.scan.require_version()
        with patch.object(self.scan, "require_version"), patch.object(self.scan, "validate_binding"), patch.object(self.scan, "load_binding", return_value={"image": "fixture:local"}), patch.object(self.scan, "command", side_effect=ValueError("database update failed")), self.assertRaisesRegex(ValueError, "database"):
            self.scan.run_scan(ROOT, "container")

    def test_image_option_and_shell_injection_inputs_are_rejected(self):
        for image in ("-option", "fixture;touch /tmp/pwned", "$(echo bad)", "fixture\nother"):
            with self.subTest(image=image), self.assertRaises(ValueError):
                self.scan.valid_image(image)

    def test_git_symlinks_hash_the_link_without_reading_outside_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"; root.mkdir()
            external = Path(directory) / "external"; external.write_text("private")
            (root / "link").symlink_to(external)
            with patch.object(self.scan, "command", side_effect=["a" * 40, "link\0"]):
                first = self.scan.source_identity(root)
            external.write_text("changed private content")
            with patch.object(self.scan, "command", side_effect=["a" * 40, "link\0"]):
                self.assertEqual(self.scan.source_identity(root), first)

    def test_empty_scanner_report_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / ".agent/.runs/artifacts").mkdir(parents=True)
            with patch.object(self.scan, "require_version"), patch.object(self.scan, "validate_binding"), patch.object(self.scan, "load_binding", return_value={"image":"fixture:local"}), patch.object(self.scan, "command", return_value=""), patch.object(self.scan.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, '{"Results":[]}', '')), self.assertRaisesRegex(ValueError, "coverage"):
                self.scan.run_scan(root, "container")


if __name__ == "__main__":
    unittest.main()
