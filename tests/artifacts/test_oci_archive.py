import hashlib
import importlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SHA = "a" * 40


class ArchiveTests(unittest.TestCase):
    def test_archive_platform_source_and_blob_integrity_are_checked(self):
        self.assertTrue((ROOT / "scripts/artifacts/oci.py").exists(), "OCI metadata validation missing")
        mod = importlib.import_module("artifacts.oci")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.tar"
            blobs = {}
            def blob(value):
                raw = json.dumps(value).encode(); digest = hashlib.sha256(raw).hexdigest()
                blobs["blobs/sha256/" + digest] = raw
                return {"digest": "sha256:" + digest, "size": len(raw)}
            config = blob({"architecture": "arm64", "os": "linux", "config": {"Labels": {"org.opencontainers.image.revision": SHA}}})
            manifest = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config, "layers": []})
            blobs["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [manifest]}).encode()
            def write():
                with tarfile.open(path, "w") as archive:
                    for name, raw in blobs.items():
                        info = tarfile.TarInfo(name); info.size = len(raw); archive.addfile(info, io.BytesIO(raw))
            write()
            self.assertEqual(mod.archive_metadata(path, "arm64", SHA)["config_digest"], config["digest"])
            self.assertEqual(mod.archive_metadata(path, "arm64", SHA)["publication_digest"], manifest["digest"])
            for arch, source in (("amd64", SHA), ("arm64", "b" * 40)):
                with self.assertRaises(ValueError):
                    mod.archive_metadata(path, arch, source)
            blobs["blobs/sha256/" + config["digest"].split(":")[1]] = b"{}"; write()
            with self.assertRaisesRegex(ValueError, "digest"):
                mod.archive_metadata(path, "arm64", SHA)


if __name__ == "__main__":
    unittest.main()
