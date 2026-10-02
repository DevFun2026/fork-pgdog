import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import test_release_tools

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


class SourceGraphTests(unittest.TestCase):
    def test_older_approved_source_is_reachable_and_chart_uses_that_source(self):
        mod = importlib.import_module("artifacts.release_receipt")
        publish = importlib.import_module("artifacts.publish")
        self.assertTrue(hasattr(publish, "materialize_chart"), "chart source selection missing")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"; root.mkdir()
            def git(*args):
                return subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", *args], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
            git("init", "--initial-branch=main")
            chart = root / "charts/fork-pgdog"; chart.mkdir(parents=True)
            (chart / "Chart.yaml").write_text("name: first\n")
            git("add", "."); git("commit", "-m", "base fixture")
            base = git("rev-parse", "HEAD")
            (chart / "Chart.yaml").write_text("name: approved\n")
            git("add", "."); git("commit", "-m", "approved fixture")
            source = git("rev-parse", "HEAD")
            (chart / "Chart.yaml").write_text("name: dispatch\n")
            git("add", "."); git("commit", "-m", "dispatch fixture")
            git("update-ref", "refs/remotes/origin/main", "HEAD")
            receipt = test_release_tools.ReleaseToolsTests().receipt()
            receipt.update(source_sha=source, base_sha=base)
            receipt["artifact_checks"]["source_sha"] = source
            raw = mod.canonical(receipt); checksum = hashlib.sha256(raw).hexdigest()
            mod.publish_preflight(root, raw, checksum, source, "0.1.60", "0.1.0", "refs/heads/main", "DevFun2026/fork-pgdog")
            out = Path(directory) / "chart"
            publish.materialize_chart(root, source, out)
            self.assertEqual((out / "Chart.yaml").read_text(), "name: approved\n")
            with self.assertRaises(ValueError):
                mod.publish_preflight(root, raw, checksum, source, "0.1.60", "0.1.0", "refs/heads/feature", "DevFun2026/fork-pgdog")
            git("checkout", "--orphan", "unrelated")
            git("add", "."); git("commit", "-m", "unrelated fixture")
            unrelated = git("rev-parse", "HEAD")
            receipt["source_sha"] = unrelated; receipt["artifact_checks"]["source_sha"] = unrelated
            raw = mod.canonical(receipt)
            with self.assertRaises(subprocess.CalledProcessError):
                mod.publish_preflight(root, raw, hashlib.sha256(raw).hexdigest(), unrelated, "0.1.60", "0.1.0", "refs/heads/main", "DevFun2026/fork-pgdog")


if __name__ == "__main__":
    unittest.main()
