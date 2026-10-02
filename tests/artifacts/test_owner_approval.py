import copy
import hashlib
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SOURCE = "09026eec63e0cb2da60389ef623e56ff1e4ba74b"
WORKFLOW = "a" * 40
BODY = "> Tôi duyệt dùng GitHub owner approval và environment packages thay chữ ký SSH cho lần phát hành đầu: image 0.1.0, Helm chart 0.1.0. Giữ nguyên review, CI, scanner và kiểm tra artifact."


def receipt():
    def review(head, base, manifest):
        return {"status": "passed", "verdict": "pass", "author_provider": "codex", "reviewer_provider": "gemini", "head_sha": head, "base_sha": base, "diff_sha256": "b" * 64, "manifest_sha256": manifest, "findings_sha256": "c" * 64}
    def run(role, source, path, number):
        return {"role": role, "id": number, "attempt": 1, "head_sha": source, "path": path}
    return {"schema_version": 2, "repository": "DevFun2026/fork-pgdog", "source_sha": SOURCE, "workflow_sha": WORKFLOW,
            "image_version": "0.1.0", "chart_version": "0.1.0", "created_at": "2000-01-01T00:00:00Z",
            "authorization": {"method": "github-owner-first-release-exception", "comment_id": 5948092075, "actor_id": 107181711, "actor_login": "simonle251289", "comment_body_sha256": hashlib.sha256(BODY.encode()).hexdigest(), "security_profile": "standard", "ssh_clearance": "waived-by-owner", "canonical_release_gate": "not-claimed"},
            "reviews": {"source": review(SOURCE, "135b4f471761d006a52ce689fa4ed0aee60b73ae", "3f2f2acd47069382f05e62ac5feb67728cb5fe9ba7346cf89da05f192a55660f"), "workflow": review(WORKFLOW, SOURCE, "d" * 64)},
            "ci_runs": [run("source-quality", SOURCE, ".github/workflows/fork-quality.yml", 36960858752), run("source-artifacts", SOURCE, ".github/workflows/artifact-quality.yml", 36961300035), run("workflow-quality", WORKFLOW, ".github/workflows/fork-quality.yml", 10), run("workflow-artifacts", WORKFLOW, ".github/workflows/artifact-quality.yml", 11)],
            "evidence_sha256": {key: "e" * 64 for key in ("source-review-audit", "workflow-review-audit", "security-assessment", "threat-model", "release-notes", "migration-rollback", "residual-risks")}}


class OwnerApprovalTests(unittest.TestCase):
    def parse(self, payload):
        mod = importlib.import_module("artifacts.release_receipt")
        raw = mod.canonical(payload)
        return mod.parse_receipt(raw, hashlib.sha256(raw).hexdigest(), SOURCE)

    def test_explicit_first_release_receipt_does_not_claim_ssh_clearance(self):
        parsed = self.parse(receipt())
        self.assertEqual(parsed["authorization"]["ssh_clearance"], "waived-by-owner")
        self.assertEqual(parsed["authorization"]["canonical_release_gate"], "not-claimed")
        self.assertNotIn("gate", parsed)

    def test_exception_cannot_widen_scope_or_claim_passed_signature(self):
        changes = [("source_sha", "f" * 40), ("workflow_sha", SOURCE), ("image_version", "0.1.60"), ("chart_version", "0.1.1"), ("repository", "other/repo"), ("schema_version", True)]
        for key, value in changes:
            payload = receipt(); payload[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.parse(payload)
        for key, value in [("actor_id", 1), ("comment_id", 2), ("security_profile", "baseline"), ("ssh_clearance", "passed"), ("canonical_release_gate", "passed"), ("comment_body_sha256", "0" * 64)]:
            payload = receipt(); payload["authorization"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.parse(payload)
        for change in (lambda p: p["reviews"]["workflow"].update({"reviewer_provider": "codex"}), lambda p: p["reviews"]["source"].update({"manifest_sha256": "0" * 64}), lambda p: p["ci_runs"].pop(), lambda p: p["ci_runs"][2].update({"head_sha": SOURCE}), lambda p: p["evidence_sha256"].pop("security-assessment")):
            payload = receipt(); change(payload)
            with self.assertRaises(ValueError): self.parse(payload)

    def github(self, endpoint):
        if endpoint.endswith("issues/comments/5948092075"):
            return {"id": 5948092075, "user": {"id": 107181711, "login": "simonle251289"}, "body": BODY}
        if endpoint.endswith("collaborators/simonle251289/permission"):
            return {"permission": "admin", "user": {"id": 107181711, "login": "simonle251289"}}
        if endpoint.endswith("environments/packages"):
            return {"protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "User", "reviewer": {"id": 107181711}}]}], "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
        if endpoint.endswith("deployment-branch-policies"):
            return {"branch_policies": [{"name": "main", "type": "branch"}], "total_count": 1}
        for item in receipt()["ci_runs"]:
            if endpoint.endswith(f"actions/runs/{item['id']}"):
                return {"id": item["id"], "head_sha": item["head_sha"], "path": item["path"], "run_attempt": 1, "status": "completed", "conclusion": "success"}
            if f"actions/runs/{item['id']}/attempts/1/jobs" in endpoint:
                names = ["verification", "scanners (dependency)", "scanners (license)", "scanners (sast)"] if item["role"].endswith("quality") else ["build (ubuntu-24.04, amd64)", "build (ubuntu-24.04-arm, arm64)"]
                return {"total_count": len(names), "jobs": [{"name": name, "status": "completed", "conclusion": "success"} for name in names]}
        raise AssertionError(endpoint)

    def test_live_owner_and_all_required_jobs_are_validated(self):
        mod = importlib.import_module("artifacts.owner_approval")
        mod.validate_live(receipt(), actor_id="107181711", workflow_sha=WORKFLOW, api=self.github)
        for target, change in [
            ("issues/comments/5948092075", lambda d: d.update({"body": "withdrawn"})),
            ("issues/comments/5948092075", lambda d: d["user"].update({"id": 1})),
            ("collaborators/simonle251289/permission", lambda d: d.update({"permission": "read"})),
            ("environments/packages", lambda d: d.update({"protection_rules": []})),
            ("deployment-branch-policies", lambda d: d["branch_policies"][0].update({"name": "*"})),
            ("actions/runs/10", lambda d: d.update({"head_sha": SOURCE})),
            ("actions/runs/10", lambda d: d.update({"run_attempt": 2})),
            ("actions/runs/10/attempts/1/jobs", lambda d: d["jobs"][0].update({"conclusion": "skipped"})),
            ("actions/runs/11/attempts/1/jobs", lambda d: d["jobs"].pop()),
        ]:
            def api(endpoint):
                data = self.github(endpoint)
                if target in endpoint: change(data)
                return data
            with self.subTest(target=target), self.assertRaises(ValueError):
                mod.validate_live(receipt(), actor_id="107181711", workflow_sha=WORKFLOW, api=api)
        with self.assertRaises(ValueError): mod.validate_live(receipt(), actor_id="1", workflow_sha=WORKFLOW, api=self.github)
        with self.assertRaises(ValueError): mod.validate_live(receipt(), actor_id="107181711", workflow_sha="f" * 40, api=self.github)

    def test_preflight_rechecks_owner_before_any_publication(self):
        mod = importlib.import_module("artifacts.release_receipt")
        payload = receipt(); raw = mod.canonical(payload); digest = hashlib.sha256(raw).hexdigest()
        with patch.dict("os.environ", {"GITHUB_ACTOR_ID": "107181711", "GITHUB_SHA": WORKFLOW}), patch("artifacts.owner_approval.validate_live", side_effect=ValueError("owner approval withdrawn")), patch.object(mod.subprocess, "run") as commands:
            with self.assertRaisesRegex(ValueError, "withdrawn"):
                mod.publish_preflight(ROOT, raw, digest, SOURCE, "0.1.0", "0.1.0", "refs/heads/main", "DevFun2026/fork-pgdog")
            commands.assert_not_called()

    def test_dirty_candidate_or_failed_ci_cannot_export_exception_receipt(self):
        mod = importlib.import_module("artifacts.owner_approval")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / "receipt.json"
            with patch.object(mod, "_git", return_value="dirty"), self.assertRaises(ValueError):
                mod.create_initial_receipt(root, output, root / "source", root / "workflow", 10, 11)
            self.assertFalse(output.exists())
            assessment_path = root / ".agent/.runs/artifacts/fork-image-helm-handoff/security-assessment-09026eec.json"
            assessment_path.parent.mkdir(parents=True)
            assessment = {"head_sha": SOURCE, "base_sha": mod.SOURCE_BASE, "approved_profile": "standard", "assessed_profile": "standard", "diff_sha256": "b" * 64, "reviewed_scope": []}
            assessment_path.write_text(json.dumps({"assessment": assessment}))
            for path in ("docs/security/threat-model.md", "docs/releases/fork-artifacts.md", "docs/operations/fork-artifact-rollback.md", "docs/security/residual-risks.md"):
                target = root / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_text("reviewed doc")
            def git(path, *args):
                return WORKFLOW if args[0] == "rev-parse" else ""
            def api(endpoint):
                if endpoint == "user": return {"id": 107181711}
                data = self.github(endpoint)
                if endpoint.endswith("actions/runs/10"): data["conclusion"] = "failure"
                return data
            def review(path, package, head, base):
                return copy.deepcopy(receipt()["reviews"]["source" if head == SOURCE else "workflow"]), "e" * 64
            for field, value in (("assessed_profile", "baseline"), ("diff_sha256", "f" * 64), ("reviewed_scope", ["unreviewed.py"])):
                altered = dict(assessment); altered[field] = value
                assessment_path.write_text(json.dumps({"assessment": altered}))
                with self.subTest(field=field), patch.object(mod, "_git", side_effect=git), patch.object(mod, "review_metadata", side_effect=review), patch.object(mod, "github_api", side_effect=api), self.assertRaisesRegex(ValueError, "security assessment"):
                    mod.create_initial_receipt(root, output, root / "source", root / "workflow", 10, 11)
                self.assertFalse(output.exists())
            assessment_path.write_text(json.dumps({"assessment": assessment}))
            with patch.object(mod, "_git", side_effect=git), patch.object(mod, "review_metadata", side_effect=review), patch.object(mod, "github_api", side_effect=api), self.assertRaisesRegex(ValueError, "CI witness"):
                mod.create_initial_receipt(root, output, root / "source", root / "workflow", 10, 11)
            self.assertFalse(output.exists())

    def test_historical_source_review_uses_real_diff_and_rejects_modified_package(self):
        mod = importlib.import_module("artifacts.owner_approval")
        receipt_mod = importlib.import_module("artifacts.release_receipt")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); package = root / ".agent/.runs/review-source"
            package.mkdir(parents=True)
            diff = "reviewed change\n"; digest = hashlib.sha256(diff.encode()).hexdigest()
            manifest = {"head_sha": SOURCE, "base_sha": mod.SOURCE_BASE, "author_provider": "codex", "reviewer_provider": "gemini", "diff_sha256": digest, "scope": ["example.py"], "files": []}
            for name, field in (("requirements.md", "requirements_sha256"), ("verification.json", "verification_sha256"), ("policy.md", "policy_sha256"), ("review-schema.json", "schema_sha256")):
                (package / name).write_text("checked metadata")
                manifest[field] = hashlib.sha256((package / name).read_bytes()).hexdigest()
            manifest_hash = hashlib.sha256(receipt_mod.canonical(manifest)).hexdigest()
            (package / "manifest.json").write_bytes(receipt_mod.canonical(manifest))
            (package / "diff.patch").write_text(diff)
            (package / "findings.json").write_text('{"verdict":"pass","findings":[]}')
            (package / "audit.jsonl").write_text(json.dumps({"manifest_sha256": manifest_hash, "status": "completed", "provider": "gemini", "verdict": "pass", "exit_code": 0, "stdout_sha256": "f" * 64}))
            def git(path, *args): return "example.py\n" if "--name-only" in args else diff
            with patch.object(mod, "_git", side_effect=git):
                metadata, _ = mod.review_metadata(root, package, SOURCE, mod.SOURCE_BASE)
                self.assertEqual(metadata["head_sha"], SOURCE)
                (package / "diff.patch").write_text("tampered")
                with self.assertRaises(ValueError): mod.review_metadata(root, package, SOURCE, mod.SOURCE_BASE)


if __name__ == "__main__":
    unittest.main()
