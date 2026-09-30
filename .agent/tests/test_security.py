import json
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from hashlib import sha256

from agent_cli.security import (
    ChangeImpact,
    SecurityPolicyError,
    assess_change,
    assess_repository,
    render_security_report,
    validate_signed_approval,
)


class SecurityTests(unittest.TestCase):
    def test_agent_cannot_downgrade_approved_profile(self):
        with self.assertRaises(SecurityPolicyError):
            assess_change(
                approved_profile="high",
                requested_profile="baseline",
                change=ChangeImpact(changed_paths=("src/app.py",)),
            )

    def test_trust_boundary_change_requires_threat_model_delta(self):
        result = assess_change(
            approved_profile="standard",
            requested_profile="standard",
            change=ChangeImpact(
                changed_paths=("src/integration.py",),
                trust_boundary_changed=True,
                external_integration=True,
            ),
        )
        self.assertIn("threat_model_delta", result.required_artifacts)
        self.assertIn("input-and-injection", result.review_lenses)
        self.assertIn("data-and-secrets", result.review_lenses)

    def test_supply_chain_and_infrastructure_changes_select_lenses(self):
        result = assess_change(
            approved_profile="standard",
            requested_profile="high",
            change=ChangeImpact(
                changed_paths=("Dockerfile", "requirements.lock"),
                dependency_changed=True,
                infrastructure_changed=True,
            ),
        )
        self.assertIn("supply-chain", result.review_lenses)
        self.assertIn("infrastructure", result.review_lenses)

    def test_security_report_is_scope_bounded(self):
        assessment = assess_change(
            approved_profile="standard",
            requested_profile="standard",
            change=ChangeImpact(changed_paths=("src/app.py",)),
        )
        report = render_security_report(assessment)
        self.assertNotIn("system is secure", report.lower())
        self.assertIn("reviewed scope", report.lower())
        self.assertIn("residual risk", report.lower())
        self.assertIn("unverified", report.lower())

    def test_repository_assessment_includes_untracked_security_relevant_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(("git", "init", "-b", "main"), cwd=root, check=True, capture_output=True)
            subprocess.run(("git", "config", "user.email", "fixture@example.com"), cwd=root, check=True)
            subprocess.run(("git", "config", "user.name", "Fixture"), cwd=root, check=True)
            (root / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(("git", "add", "README.md"), cwd=root, check=True)
            subprocess.run(("git", "commit", "-m", "fixture"), cwd=root, check=True, capture_output=True)
            target = root / ".agent/project-model/data-flows.toml"
            target.parent.mkdir(parents=True)
            target.write_text("[[data_flows]]\n", encoding="utf-8")
            result = assess_repository(root, approved_profile="standard")
        self.assertIn(".agent/project-model/data-flows.toml", result.reviewed_scope)
        self.assertIn("threat_model_delta", result.required_artifacts)

    def test_repository_assessment_uses_committed_base_head_diff(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(("git", "init", "-b", "main"), cwd=root, check=True, capture_output=True)
            subprocess.run(("git", "config", "user.email", "fixture@example.com"), cwd=root, check=True)
            subprocess.run(("git", "config", "user.name", "Fixture"), cwd=root, check=True)
            (root / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(("git", "add", "README.md"), cwd=root, check=True)
            subprocess.run(("git", "commit", "-m", "base"), cwd=root, check=True, capture_output=True)
            target = root / ".agent/project-model/data-flows.toml"
            target.parent.mkdir(parents=True)
            target.write_text("[[data_flows]]\n", encoding="utf-8")
            subprocess.run(("git", "add", "."), cwd=root, check=True)
            subprocess.run(("git", "commit", "-m", "change"), cwd=root, check=True, capture_output=True)

            result = assess_repository(
                root,
                approved_profile="standard",
                base="HEAD~1",
                head="HEAD",
            )

        self.assertIn(".agent/project-model/data-flows.toml", result.reviewed_scope)
        self.assertIn("threat_model_delta", result.required_artifacts)
        self.assertEqual(len(result.base_sha), 40)
        self.assertEqual(len(result.head_sha), 40)
        self.assertEqual(len(result.diff_sha256), 64)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is required")
    def test_signed_approval_is_schema_scope_and_base_trust_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(("git", "init", "-b", "main"), cwd=root, check=True, capture_output=True)
            subprocess.run(("git", "config", "user.email", "fixture@example.com"), cwd=root, check=True)
            subprocess.run(("git", "config", "user.name", "Fixture"), cwd=root, check=True)
            key = root / "reviewer-key"
            subprocess.run(
                ("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)),
                cwd=root,
                check=True,
            )
            public_key = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
            signer_file = root / ".agent/security/allowed_signers"
            signer_file.parent.mkdir(parents=True)
            signer_file.write_text(
                f'reviewer@example.com namespaces="agent-security-approval" {public_key}\n',
                encoding="utf-8",
            )
            (root / "README.md").write_text("base\n", encoding="utf-8")
            subprocess.run(("git", "add", "."), cwd=root, check=True)
            subprocess.run(("git", "commit", "-m", "base"), cwd=root, check=True, capture_output=True)
            (root / "README.md").write_text("changed\n", encoding="utf-8")
            subprocess.run(("git", "add", "README.md"), cwd=root, check=True)
            subprocess.run(("git", "commit", "-m", "change"), cwd=root, check=True, capture_output=True)
            assessment = assess_repository(
                root,
                approved_profile="standard",
                base="HEAD~1",
                head="HEAD",
            )
            evidence = root / "security-approval.json"
            assessment_payload = json.loads(
                json.dumps(assessment.to_dict(), sort_keys=True)
            )
            assessment_sha = sha256(
                json.dumps(
                    assessment_payload, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            evidence.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "decision": "approve",
                        "reviewer_identity": "reviewer@example.com",
                        "reviewer_provider": "claude",
                        "author_provider": "codex",
                        "assessment": assessment_payload,
                        "assessment_sha256": assessment_sha,
                        "reviewed_at": "2026-09-22T00:00:00Z",
                        "provenance": "ssh-signature-from-base-trusted-signer",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            subprocess.run(
                (
                    "ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    str(key),
                    "-n",
                    "agent-security-approval",
                    str(evidence),
                ),
                cwd=root,
                check=True,
                capture_output=True,
            )

            approved = validate_signed_approval(
                root,
                assessment,
                evidence,
                evidence.with_suffix(".json.sig"),
            )
            self.assertEqual(approved["reviewer_identity"], "reviewer@example.com")

            with self.assertRaisesRegex(SecurityPolicyError, "stale or has the wrong scope"):
                validate_signed_approval(
                    root,
                    replace(assessment, required_artifacts=()),
                    evidence,
                    evidence.with_suffix(".json.sig"),
                )

            arbitrary = root / "arbitrary.txt"
            arbitrary.write_text('{"approved": true}\n', encoding="utf-8")
            with self.assertRaisesRegex(SecurityPolicyError, "strict schema"):
                validate_signed_approval(
                    root,
                    assessment,
                    arbitrary,
                    evidence.with_suffix(".json.sig"),
                )


if __name__ == "__main__":
    unittest.main()
