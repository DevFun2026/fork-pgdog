import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from agent_cli.memory.models import MemoryCandidate
from agent_cli.memory.service import MemoryService


class MemoryFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / "docs/evidence").mkdir(parents=True)
        (self.root / "docs/evidence/check.json").write_text("{}", encoding="utf-8")
        self.service = MemoryService(self.root)
        self.canonical_dir = self.root / ".agent/memory/records"

    def tearDown(self):
        self.tempdir.cleanup()

    def candidate_for(self, path: str, identifier: str = "MEM-0001") -> MemoryCandidate:
        return MemoryCandidate(
            id=identifier,
            type="discovery",
            title="Auth memory",
            summary="Auth uses a transactional lock.",
            details="Verified by the current integration evidence.",
            components=("auth",),
            paths=(path,),
            evidence=("docs/evidence/check.json",),
            source_provider="codex",
            source_session="session-freshness",
            branch="main",
            observed_commit="a" * 40,
            created_at="2026-09-21T00:00:00Z",
            sensitivity="internal",
            reuse_guidance="Use when modifying authentication.",
        )

    def test_changed_path_excludes_record_from_bootstrap(self):
        self.service.promote(self.candidate_for("src/auth/**"))
        result = self.service.bootstrap(
            "auth", changed_paths=("src/auth/login.py",), char_budget=1000
        )
        self.assertNotIn("MEM-0001", result)
        self.assertIn("MEM-0001", self.service.search("auth", include_stale=True).ids)
        self.assertNotIn("MEM-0001", self.service.search("auth").ids)

    def test_import_is_always_untrusted_candidate(self):
        source_temp = tempfile.TemporaryDirectory()
        self.addCleanup(source_temp.cleanup)
        source_root = Path(source_temp.name)
        (source_root / "docs/evidence").mkdir(parents=True)
        (source_root / "docs/evidence/check.json").write_text("{}", encoding="utf-8")
        source = MemoryService(source_root)
        source.promote(self.candidate_for("src/auth/**", "MEM-9000"))
        export_path = self.root / "export.json"
        export_path.write_bytes(source.export_redacted())

        imported = self.service.import_file(export_path)
        self.assertEqual(imported[0].trust, "untrusted-candidate")
        self.assertFalse((self.canonical_dir / "MEM-9000.md").exists())

    def test_import_rejects_checksum_tampering(self):
        self.service.promote(self.candidate_for("src/auth/**"))
        payload = json.loads(self.service.export_redacted())
        payload["records"][0]["record"]["title"] = "tampered"
        path = self.root / "tampered.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        target_temp = tempfile.TemporaryDirectory()
        self.addCleanup(target_temp.cleanup)
        with self.assertRaisesRegex(ValueError, "checksum"):
            MemoryService(Path(target_temp.name)).import_file(path)

    def test_bootstrap_derives_staleness_from_git_history(self):
        subprocess.run(("git", "init", "-b", "main"), cwd=self.root, check=True, capture_output=True)
        subprocess.run(("git", "config", "user.email", "fixture@example.com"), cwd=self.root, check=True)
        subprocess.run(("git", "config", "user.name", "Fixture"), cwd=self.root, check=True)
        target = self.root / "src/auth/login.py"
        target.parent.mkdir(parents=True)
        target.write_text("version one\n", encoding="utf-8")
        subprocess.run(("git", "add", "."), cwd=self.root, check=True)
        subprocess.run(("git", "commit", "-m", "base"), cwd=self.root, check=True, capture_output=True)
        observed = subprocess.run(
            ("git", "rev-parse", "HEAD"), cwd=self.root, check=True, text=True, capture_output=True
        ).stdout.strip()
        self.service.promote(
            self.candidate_for("src/auth/**", "MEM-GIT-STALE-001").__class__(
                **{
                    **self.candidate_for("src/auth/**", "MEM-GIT-STALE-001").__dict__,
                    "observed_commit": observed,
                }
            )
        )
        target.write_text("version two\n", encoding="utf-8")
        subprocess.run(("git", "add", "."), cwd=self.root, check=True)
        subprocess.run(("git", "commit", "-m", "change auth"), cwd=self.root, check=True, capture_output=True)

        result = self.service.bootstrap("auth", char_budget=1000)

        self.assertNotIn("MEM-GIT-STALE-001", result)
        self.assertIn(
            "MEM-GIT-STALE-001", self.service.search("auth", include_stale=True).ids
        )

    def test_bootstrap_detects_staged_unstaged_and_evidence_changes(self):
        subprocess.run(("git", "init", "-b", "main"), cwd=self.root, check=True, capture_output=True)
        subprocess.run(("git", "config", "user.email", "fixture@example.com"), cwd=self.root, check=True)
        subprocess.run(("git", "config", "user.name", "Fixture"), cwd=self.root, check=True)
        target = self.root / "src/auth/login.py"
        target.parent.mkdir(parents=True)
        target.write_text("one\n", encoding="utf-8")
        subprocess.run(("git", "add", "."), cwd=self.root, check=True)
        subprocess.run(("git", "commit", "-m", "base"), cwd=self.root, check=True, capture_output=True)
        observed = subprocess.run(("git", "rev-parse", "HEAD"), cwd=self.root, check=True, text=True, capture_output=True).stdout.strip()

        for identifier, changed_path, stage in (
            ("MEM-DIRTY-001", target, False),
            ("MEM-STAGED-001", target, True),
            ("MEM-EVIDENCE-001", self.root / "docs/evidence/check.json", False),
        ):
            candidate = self.candidate_for("src/auth/**", identifier)
            self.service.promote(candidate.__class__(**{**candidate.__dict__, "observed_commit": observed}))
            changed_path.write_text(f"changed {identifier}\n", encoding="utf-8")
            if stage:
                subprocess.run(("git", "add", changed_path.relative_to(self.root)), cwd=self.root, check=True)
            self.assertNotIn(identifier, self.service.bootstrap("auth", char_budget=2000))
            subprocess.run(("git", "reset", "--hard", "HEAD"), cwd=self.root, check=True, capture_output=True)

    def test_import_is_transactional_and_rejects_id_mismatch(self):
        source_temp = tempfile.TemporaryDirectory()
        self.addCleanup(source_temp.cleanup)
        source_root = Path(source_temp.name)
        (source_root / "docs/evidence").mkdir(parents=True)
        (source_root / "docs/evidence/check.json").write_text("{}", encoding="utf-8")
        source = MemoryService(source_root)
        source.promote(self.candidate_for("src/auth/**", "MEM-IMPORT-001"))
        source.promote(self.candidate_for("src/auth/**", "MEM-IMPORT-002"))
        payload = json.loads(source.export_redacted())
        payload["records"][1]["record"]["title"] = "tampered"
        path = self.root / "partial.json"
        path.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "checksum"):
            self.service.import_file(path)
        self.assertEqual(self.service.store.count_candidates(), 0)

        mismatch = json.loads(source.export_redacted())
        mismatch["records"][0]["id"] = "MEM-DIFFERENT"
        mismatch_path = self.root / "mismatch.json"
        mismatch_path.write_text(json.dumps(mismatch), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "ID mismatch"):
            self.service.import_file(mismatch_path)


if __name__ == "__main__":
    unittest.main()
