import tempfile
import unittest
from pathlib import Path

from agent_cli.review.adjudication import ReproductionEvidence, adjudicate, adjudicate_findings
from agent_cli.review.models import ReviewFinding


class AdjudicationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / "src").mkdir()
        (self.root / "src/app.py").write_text("one\ntwo\nthree\n", encoding="utf-8")
        self.high_finding = ReviewFinding(
            id="F-1",
            severity="high",
            category="security",
            file="src/app.py",
            line=2,
            evidence="Untrusted input reaches a sink.",
            reasoning="The path is reproducible.",
            remediation="Validate before use.",
            confidence="high",
        )
        self.medium_finding = ReviewFinding(
            id="F-2",
            severity="medium",
            category="correctness",
            file="src/app.py",
            line=3,
            evidence="Potential edge case.",
            reasoning="Needs reproduction.",
            remediation="Add a regression test.",
            confidence="medium",
        )
        self.reproduced_evidence = ReproductionEvidence(
            reference="docs/evidence/F-1.json",
            reproduced=True,
            notes="Regression test failed before the fix.",
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_confirmed_high_blocks_merge(self):
        result = adjudicate(
            self.high_finding,
            evidence=self.reproduced_evidence,
            root=self.root,
        )
        self.assertEqual(result.disposition, "confirmed")
        self.assertTrue(result.blocks_merge)

    def test_unreproduced_finding_needs_evidence_not_rejected(self):
        result = adjudicate(self.medium_finding, evidence=None, root=self.root)
        self.assertEqual(result.disposition, "needs-evidence")

    def test_unreproduced_high_finding_blocks_merge(self):
        result = adjudicate(self.high_finding, evidence=None, root=self.root)
        self.assertEqual(result.disposition, "needs-evidence")
        self.assertTrue(result.blocks_merge)

    def test_every_finding_requires_exactly_one_decision(self):
        with self.assertRaisesRegex(ValueError, "every finding"):
            adjudicate_findings([self.high_finding.__dict__], [], root=self.root)

    def test_rejection_requires_explicit_reason(self):
        with self.assertRaisesRegex(ValueError, "rejection reason"):
            adjudicate(self.medium_finding, evidence=None, reject=True, root=self.root)

    def test_nonexistent_line_needs_evidence(self):
        finding = ReviewFinding(**{**self.medium_finding.__dict__, "line": 99})
        result = adjudicate(finding, evidence=self.reproduced_evidence, root=self.root)
        self.assertEqual(result.disposition, "needs-evidence")


if __name__ == "__main__":
    unittest.main()
