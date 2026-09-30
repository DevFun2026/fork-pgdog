import dataclasses
from contextlib import redirect_stdout
from io import StringIO
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_cli.cli import main
from agent_cli.memory.models import MemoryCandidate
from agent_cli.memory.service import MemoryService


class MemoryServiceTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / "docs/evidence").mkdir(parents=True)
        (self.root / "docs/evidence/check.json").write_text("{}", encoding="utf-8")
        self.service = MemoryService(self.root)
        (self.root / ".agent/config.toml").write_text("")

    def tearDown(self):
        self.tempdir.cleanup()

    def candidate(
        self,
        identifier: str,
        title: str,
        *,
        sensitivity: str = "internal",
    ) -> MemoryCandidate:
        return MemoryCandidate(
            id=identifier,
            type="decision",
            title=title,
            summary=f"{title} summary for payments.",
            details=f"{title} evidence-backed detail.",
            components=("payments",),
            paths=("src/payments/**",),
            evidence=("docs/evidence/check.json",),
            source_provider="codex",
            source_session="session-service",
            branch="main",
            observed_commit="a" * 40,
            created_at=f"2026-09-21T00:00:0{identifier[-1]}Z",
            sensitivity=sensitivity,
            reuse_guidance="Use when changing payments.",
        )

    def test_bootstrap_respects_character_budget_by_whole_record(self):
        self.service.promote(self.candidate("MEM-0001", "First"))
        self.service.promote(self.candidate("MEM-0002", "Second"))
        one_record_budget = 150
        context = self.service.bootstrap("payments", char_budget=one_record_budget)
        self.assertLessEqual(len(context), one_record_budget)
        self.assertNotIn("[TRUNCATED_RECORD]", context)
        self.assertEqual(context.count("MEM-"), 1)

    def test_cli_search_serializes_real_rows(self):
        self.service.promote(self.candidate("MEM-0001", "Payment lock"))
        output = StringIO()
        with mock.patch("agent_cli.cli.ROOT", self.root), redirect_stdout(output):
            exit_code = main(["memory", "search", "payment"])
        self.assertEqual(exit_code, 0)
        self.assertIn('"id": "MEM-0001"', output.getvalue())

    def test_search_timeline_and_show_are_progressive(self):
        self.service.checkpoint(self.candidate("MEM-0001", "Payment lock"))
        self.service.promote("MEM-0001")
        search = self.service.search("payment")
        self.assertEqual(search.ids, ("MEM-0001",))
        self.assertNotIn("evidence-backed detail", search.rows[0].summary)
        self.assertIn("checkpoint", " ".join(self.service.timeline("MEM-0001")))
        self.assertIn("evidence-backed detail", self.service.show(("MEM-0001",)))

    def test_private_record_is_not_auto_injected_or_indexed_for_startup(self):
        self.service.promote(
            self.candidate("MEM-0001", "Private payment", sensitivity="private")
        )
        self.assertEqual(self.service.bootstrap("payment", char_budget=1000), "")
        index = (self.root / ".agent/memory/INDEX.md").read_text(encoding="utf-8")
        self.assertNotIn("Private payment", index.split("## Status inventory", 1)[0])

    def test_promotion_requires_existing_evidence(self):
        missing = dataclasses.replace(
            self.candidate("MEM-0001", "Missing evidence"),
            evidence=("docs/evidence/missing.json",),
        )
        with self.assertRaisesRegex(ValueError, "evidence file does not exist"):
            self.service.promote(missing)

    def test_partial_query_matches_rank_relevant_title_first(self):
        self.service.promote(self.candidate("MEM-0001", "Accounting notes"))
        self.service.promote(self.candidate("MEM-0002", "Payment lock"))
        result = self.service.search("payment lock unknown", limit=1)
        self.assertEqual(result.ids, ("MEM-0002",))

    def test_startup_selects_foundational_records_without_magic_query(self):
        self.service.promote(self.candidate("MEM-0001", "Database choice"))
        self.service.promote(dataclasses.replace(
            self.candidate("MEM-0002", "Recent run"), type="verification"))
        self.service.promote(self.candidate("MEM-0003", "Private choice", sensitivity="private"))
        result = self.service.bootstrap("", char_budget=1000, startup=True)
        self.assertIn("MEM-0001", result)
        self.assertNotIn("MEM-0002", result)
        self.assertNotIn("MEM-0003", result)

    def test_search_is_bounded_and_excludes_private_records(self):
        self.service.promote(self.candidate("MEM-0001", "Payment lock", sensitivity="private"))
        self.service.promote(self.candidate("MEM-0002", "Payment retry"))
        self.assertEqual(self.service.search("payment").ids, ("MEM-0002",))
        self.assertEqual(self.service.search("payment", char_budget=2).ids, ())

    def test_bootstrap_checks_each_distinct_commit_once(self):
        self.service.promote(self.candidate("MEM-0001", "First"))
        self.service.promote(self.candidate("MEM-0002", "Second"))
        with mock.patch.object(self.service, "_git_changed_paths_since", return_value=()) as changed:
            self.service.bootstrap("payments", char_budget=1000, limit=1)
        self.assertEqual(changed.call_count, 1)

    def test_full_record_budget_blocks_instead_of_truncating(self):
        self.service.promote(self.candidate("MEM-0001", "Payment"))
        with self.assertRaisesRegex(ValueError, "budget"):
            self.service.show(("MEM-0001",), token_budget=1)

    def test_unicode_bootstrap_obeys_estimated_token_budget(self):
        from agent_cli.context import estimate_tokens
        self.service.promote(self.candidate("MEM-0001", "Kiến trúc thanh toán"))
        content = self.service.bootstrap("thanh toán unrelated", char_budget=4000, token_budget=100)
        self.assertIn("MEM-0001", content)
        self.assertLessEqual(estimate_tokens(content), 100)


if __name__ == "__main__":
    unittest.main()
