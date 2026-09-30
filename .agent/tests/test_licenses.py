import tempfile
import unittest
from pathlib import Path

from agent_cli.licenses import audit_sources


class LicenseTests(unittest.TestCase):
    @property
    def root(self):
        return Path(__file__).resolve().parents[2]

    def test_every_source_has_revision_license_and_boundary(self):
        report = audit_sources(
            self.root / ".agent/sources/SOURCES.md",
            notice_path=self.root / "THIRD_PARTY_NOTICES.md",
        )
        self.assertTrue(report.ok, report.errors)
        self.assertGreaterEqual(report.source_count, 8)

    def test_branch_name_is_not_a_pinned_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "SOURCES.md"
            notice = root / "THIRD_PARTY_NOTICES.md"
            notice.write_text("notice\n", encoding="utf-8")
            source.write_text(
                "| Source | Reviewed revision/version | License | Concepts used | Clean-room boundary |\n"
                "|---|---|---|---|---|\n"
                "| [Source](https://example.com/repo) | `main` | MIT | concept | original implementation |\n",
                encoding="utf-8",
            )
            report = audit_sources(source, notice_path=notice)
        self.assertFalse(report.ok)
        self.assertIn("unpinned revision", " ".join(report.errors))

    def test_document_adaptation_can_declare_no_executable_vendoring(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            notice = root / "THIRD_PARTY_NOTICES.md"
            notice.write_text("Adapted text: upstream MIT notice retained.\n", encoding="utf-8")
            source = root / "SOURCES.md"
            source.write_text(
                "This project does not vendor executable code; selected documents are adapted.\n\n"
                "| Source | Reviewed revision/version | License | Concepts used | Reuse boundary |\n"
                "|---|---|---|---|---|\n"
                "| [Source](https://example.com/repo) | 1.0 | MIT | Token layers | Adapted documentation; local notice retained |\n",
                encoding="utf-8",
            )
            self.assertTrue(audit_sources(source, notice_path=notice).ok)


if __name__ == "__main__":
    unittest.main()
