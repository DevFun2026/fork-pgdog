from hashlib import sha256
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from agent_cli.memory.models import MemoryCandidate
from agent_cli.memory.service import MemoryService
from agent_cli.memory.records import write_record


class MemoryPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / "docs/evidence").mkdir(parents=True)
        (self.root / "docs/evidence/check.json").write_text("{}", encoding="utf-8")
        self.service = MemoryService(self.root)

    def tearDown(self):
        self.tempdir.cleanup()

    def candidate(self, summary: str) -> MemoryCandidate:
        return MemoryCandidate(
            id="MEM-0001",
            type="discovery",
            title="Privacy behavior",
            summary=summary,
            details="No transcript capture.",
            components=("project-memory",),
            paths=("src/memory.py",),
            evidence=("docs/evidence/check.json",),
            source_provider="codex",
            source_session="session-private",
            branch="main",
            observed_commit="a" * 40,
            created_at="2026-09-21T00:00:00Z",
            sensitivity="internal",
            reuse_guidance="Use when reviewing persistence.",
        )

    def test_private_content_never_reaches_database_or_export(self):
        candidate = self.candidate(
            summary="keep <no-memory>SECRET=abc</no-memory> AKIAABCDEFGHIJKLMNOP"
        )
        self.service.checkpoint(candidate)
        dump = self.service.debug_plaintext_dump()
        exported = self.service.export_redacted().decode("utf-8")
        self.assertNotIn("SECRET=abc", dump)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", dump)
        self.assertNotIn("SECRET=abc", exported)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", exported)

    def test_export_redacts_canonical_records_again_at_boundary(self):
        record = self.service.promote(self.candidate("safe summary"))
        write_record(
            replace(record, details="late edit sk-aaaaaaaaaaaaaaaaaaaaaaaa"),
            self.root / ".agent/memory/records/MEM-0001.md",
        )

        exported = self.service.export_redacted().decode("utf-8")

        self.assertNotIn("sk-aaaaaaaaaaaaaaaaaaaaaaaa", exported)
        self.assertIn("[REDACTED_SECRET]", exported)

    def test_checksum_valid_malicious_import_is_redacted_before_sqlite(self):
        record = self.service.promote(self.candidate("safe summary"))
        payload = json.loads(self.service.export_redacted())
        payload["records"][0]["record"]["details"] = "sk-aaaaaaaaaaaaaaaaaaaaaaaa"
        canonical = json.dumps(payload["records"][0]["record"], sort_keys=True, separators=(",", ":"))
        digest = sha256(canonical.encode("utf-8")).hexdigest()
        payload["records"][0]["sha256"] = digest
        payload["manifest"][0]["sha256"] = digest
        path = self.root / "malicious-import.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        target_root = self.root / "target"

        target = MemoryService(target_root)
        imported = target.import_file(path)

        self.assertEqual(imported[0].trust, "untrusted-candidate")
        self.assertNotIn("sk-aaaaaaaaaaaaaaaaaaaaaaaa", target.debug_plaintext_dump())
        self.assertIn("[REDACTED_SECRET]", target.debug_plaintext_dump())


if __name__ == "__main__":
    unittest.main()
