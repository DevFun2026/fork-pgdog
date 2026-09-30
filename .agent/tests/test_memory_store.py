import dataclasses
import os
import tempfile
import unittest
from pathlib import Path

from agent_cli.memory.models import MemoryCandidate
from agent_cli.memory.store import MemoryStore


class MemoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.memory_dir = Path(self.tempdir.name) / ".agent/.memory"
        self.db_path = self.memory_dir / "memory.db"
        self.store = MemoryStore(self.db_path)

    def tearDown(self):
        self.tempdir.cleanup()

    def candidate(self, title: str, identifier: str = "MEM-0001") -> MemoryCandidate:
        return MemoryCandidate(
            id=identifier,
            type="discovery",
            title=title,
            summary=f"Summary for {title}",
            details="Evidence-backed detail.",
            components=("runtime",),
            paths=("src/runtime.py",),
            evidence=("docs/evidence/check.json",),
            source_provider="codex",
            source_session="session-1",
            branch="main",
            observed_commit="a" * 40,
            created_at="2026-09-21T00:00:00Z",
            sensitivity="internal",
            reuse_guidance="Apply when changing the runtime component.",
        )

    def test_failed_checkpoint_rolls_back(self):
        invalid = dataclasses.replace(self.candidate("bad"), evidence=())
        with self.assertRaises(ValueError):
            self.store.checkpoint(invalid)
        self.assertEqual(self.store.count_candidates(), 0)

    def test_two_connections_can_read_after_serialized_writes(self):
        first = MemoryStore(self.db_path)
        second = MemoryStore(self.db_path)
        first.checkpoint(self.candidate("one", "MEM-0001"))
        second.checkpoint(self.candidate("two", "MEM-0002"))
        self.assertEqual([x.title for x in first.list_candidates()], ["one", "two"])

    def test_local_directory_and_database_are_owner_only(self):
        self.assertEqual(os.stat(self.memory_dir).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(self.db_path).st_mode & 0o777, 0o600)

    def test_search_mode_is_recorded(self):
        self.assertIn(self.store.search_mode, {"fts5", "fallback"})


if __name__ == "__main__":
    unittest.main()
