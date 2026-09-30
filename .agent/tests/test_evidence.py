import json
import tempfile
import unittest
from pathlib import Path

from agent_cli.evidence import EvidenceRecord, EvidenceStore


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tempdir.name))
        self.record = EvidenceRecord(
            command_id="test.full",
            commit="a" * 40,
            diff_sha256="1" * 64,
            exit_code=0,
            status="passed",
            output_sha256="2" * 64,
            tool_version="Python 3.11",
            started_at="2026-09-21T00:00:00Z",
            duration_ms=1,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_record_is_stale_for_different_commit(self):
        self.assertFalse(
            self.record.is_fresh(commit="b" * 40, diff_sha256="1" * 64)
        )

    def test_record_is_stale_for_different_diff(self):
        self.assertFalse(
            self.record.is_fresh(commit="a" * 40, diff_sha256="3" * 64)
        )

    def test_atomic_evidence_write_has_checksum(self):
        path = self.store.write(self.record)
        loaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["output_sha256"], self.record.output_sha256)
        self.assertEqual(path.name, "test.full-aaaaaaaa-22222222.json")

    def test_invalid_hash_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "diff_sha256"):
            EvidenceRecord(
                command_id="test.full",
                commit="a" * 40,
                diff_sha256="bad",
                exit_code=0,
                status="passed",
                output_sha256="2" * 64,
                tool_version="Python 3.11",
                started_at="2026-09-21T00:00:00Z",
                duration_ms=1,
            )


if __name__ == "__main__":
    unittest.main()
