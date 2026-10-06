"""Prevent stale source excerpts in the bounded registry review context."""
import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONTEXT = ROOT / "docs/security/strict-read-registry-review-context.md"
PREFIX = "applications/pgdog/pgdog/src/backend/schema/read_policy/"


class RegistryReviewContextTests(unittest.TestCase):
    def test_source_hashes_and_excerpts_match_the_reviewed_code(self):
        text = CONTEXT.read_text()
        metadata = json.loads(re.search(r"```json\n(.*?)\n```", text, re.S).group(1))
        self.assertEqual({item["path"] for item in metadata}, {
            PREFIX + name for name in ("registry.rs", "resolve.rs", "rows.rs", "mod.rs")
        })
        excerpts = re.findall(r"```rust\n(.*?)\n```", text, re.S)
        expected = []
        for item in metadata:
            source = ROOT / item["path"]
            self.assertFalse(source.is_symlink())
            data = source.read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"], item["path"])
            lines = data.decode().splitlines()
            for span in item["ranges"]:
                start, end = span["start"], span["end"]
                self.assertGreaterEqual(start, 1)
                self.assertGreaterEqual(end, start)
                self.assertLessEqual(end, len(lines))
                expected.append("\n".join(lines[start - 1:end]))
        self.assertEqual(excerpts, expected)
