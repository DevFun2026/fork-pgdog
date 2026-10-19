import hashlib
import importlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / ".agent/runtime"))


def git(root, *args, input=None):
    result = subprocess.run(["git", *args], cwd=root, input=input, text=True,
                            capture_output=True, check=True)
    return result.stdout.strip()


def graph(root, *, security_profile="standard"):
    git(root, "init", "-q")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture@example.invalid")
    docs = {
        "docs/security/threat-model.md": "threat model\n",
        "docs/releases/fork-artifacts.md": "release notes\n",
        "docs/operations/fork-artifact-rollback.md": "rollback\n",
        "docs/security/residual-risks.md": "residual risks\n",
    }
    for name, value in docs.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
    if security_profile is not None:
        config = root / ".agent/config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        configured = (ROOT / ".agent/config.toml").read_text()
        if security_profile == "malformed":
            config.write_text("[project\nsecurity_profile = 'standard'\n")
        else:
            config.write_text(configured.replace(
                'security_profile = "standard"',
                f'security_profile = "{security_profile}"',
                1,
            ))
    base = git(root, "add", "-A") or git(root, "write-tree")
    base_tree = git(root, "write-tree")
    base = git(root, "commit-tree", base_tree, input="base\n")

    def commit_file(name, content, parent):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        git(root, "add", name)
        tree = git(root, "write-tree")
        return git(root, "commit-tree", tree, "-p", parent, input=f"{name}\n")

    source_head = commit_file("source.txt", "source\n", base)
    source_tree = git(root, "rev-parse", f"{source_head}^{{tree}}")
    source_merge = git(root, "commit-tree", source_tree, "-p", base, "-p", source_head,
                       input="source merge\n")
    workflow_head = commit_file("workflow.txt", "workflow\n", source_merge)
    workflow_tree = git(root, "rev-parse", f"{workflow_head}^{{tree}}")
    workflow_merge = git(root, "commit-tree", workflow_tree, "-p", source_merge, "-p", workflow_head,
                          input="workflow merge\n")
    git(root, "symbolic-ref", "HEAD", "refs/heads/main")
    git(root, "reset", "--hard", workflow_merge)
    exclude = root / ".git/info/exclude"
    exclude.write_text(exclude.read_text() + "\n.agent/.runs/\n")
    return {"base": base, "source_head": source_head, "source_merge": source_merge,
            "workflow_head": workflow_head, "workflow_merge": workflow_merge}


def review_package(root, name, head, base, *, author="codex"):
    from artifacts.release_receipt import canonical

    package = root / ".agent/.runs" / name
    package.mkdir(parents=True)
    diff = subprocess.run(["git", "diff", "--binary", base, head], cwd=root,
                          capture_output=True, check=True).stdout
    scope = git(root, "diff", "--name-only", base, head).splitlines()
    manifest = {
        "head_sha": head, "base_sha": base, "author_provider": author,
        "reviewer_provider": "gemini", "diff_sha256": hashlib.sha256(diff).hexdigest(),
        "full_diff_sha256": hashlib.sha256(diff).hexdigest(), "scope": scope,
        "files": [],
    }
    for filename, field in (("requirements.md", "requirements_sha256"),
                            ("verification.json", "verification_sha256"),
                            ("policy.md", "policy_sha256"),
                            ("review-schema.json", "schema_sha256")):
        contents = b"reviewed metadata"
        (package / filename).write_bytes(contents)
        manifest[field] = hashlib.sha256(contents).hexdigest()
    manifest_bytes = canonical(manifest)
    (package / "manifest.json").write_bytes(manifest_bytes)
    (package / "diff.patch").write_bytes(diff)
    findings = b'{"verdict":"pass","findings":[]}'
    (package / "findings.json").write_bytes(findings)
    audit = {
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "status": "completed", "provider": "gemini", "verdict": "pass",
        "exit_code": 0, "stdout_sha256": "f" * 64,
    }
    (package / "audit.jsonl").write_text(json.dumps(audit))
    return package


def export_inputs(root, *, security_profile="standard"):
    history = graph(root, security_profile=security_profile)
    source_review = review_package(root, "review-source", history["source_head"], history["base"])
    workflow_review = review_package(root, "review-workflow", history["workflow_head"], history["source_merge"])
    runs = root / ".agent/.runs"
    assessments = []
    lenses = [
        "authentication-and-authorization", "input-and-injection", "data-and-secrets",
        "session-and-cryptography", "business-logic-and-races", "supply-chain",
        "infrastructure", "recovery-and-auditing",
    ]
    for head, base, review in ((history["source_head"], history["base"], source_review),
                               (history["workflow_head"], history["source_merge"], workflow_review)):
        manifest = json.loads((review / "manifest.json").read_text())
        assessment = {
            "head_sha": head, "base_sha": base,
            "diff_sha256": manifest["full_diff_sha256"],
            "reviewed_scope": manifest["scope"],
            "approved_profile": "standard", "assessed_profile": "standard",
            "review_lenses": lenses,
        }
        path = runs / f"security-{len(assessments)}.json"
        path.write_text(json.dumps({"assessment": assessment}))
        assessments.append(path)
    ids = {"source-quality": 101, "source-artifacts": 102,
           "workflow-quality": 201, "workflow-artifacts": 202}
    run_heads = {"source-quality": history["source_head"],
                 "source-artifacts": history["source_head"],
                 "workflow-quality": history["workflow_head"],
                 "workflow-artifacts": history["workflow_head"]}
    run_paths = {"source-quality": ".github/workflows/fork-quality.yml",
                 "source-artifacts": ".github/workflows/artifact-quality.yml",
                 "workflow-quality": ".github/workflows/fork-quality.yml",
                 "workflow-artifacts": ".github/workflows/artifact-quality.yml"}

    def api(endpoint):
        run_id = int(endpoint.rsplit("/", 1)[-1])
        role = next(role for role, value in ids.items() if value == run_id)
        return {"id": run_id, "head_sha": run_heads[role], "path": run_paths[role],
                "run_attempt": 1, "status": "completed", "conclusion": "success"}

    return history, source_review, workflow_review, assessments, ids, api


def complete_partition(root, history):
    import json as json_module

    from agent_cli.providers.base import Capability, validated_result
    from agent_cli.review.models import ReviewPackageRequest
    from agent_cli.review.partition import build_partition
    from agent_cli.review.partition_orchestrator import PartitionOrchestrator

    class GeminiFixture:
        def detect(self):
            return Capability("gemini", True, "gemini", "fixture", True, True, None)

        def review(self, request):
            raw = json_module.dumps({"verdict": "pass", "findings": []})
            return validated_result("gemini", json_module.loads(raw), raw)

    request = ReviewPackageRequest(
        root=root,
        base=history["source_merge"],
        head=history["workflow_head"],
        author_provider="codex",
        reviewer_provider="gemini",
        context_paths=(),
        requirements="Verify the reviewed workflow change.",
        verification={"checks": "fixture"},
        max_package_bytes=500_000,
        max_estimated_tokens=96_000,
    )
    partition = build_partition(
        request,
        max_aggregate_bytes=1_000_000,
        max_aggregate_tokens=300_000,
        target_bytes=100_000,
        integration_context_paths=("docs/security/threat-model.md",),
    )
    runtime = PartitionOrchestrator({"gemini": GeminiFixture()})
    result = runtime.run_partition(
        partition,
        request,
        approved_manifest_sha256=partition.manifest_sha256,
        trusted_partition_enabled=True,
    )
    if result.status != "integration_manifest_pending":
        raise AssertionError(f"partition child stage did not complete: {result.status}")
    integration = runtime.integration_package(partition, request)
    result = runtime.run_integration(
        partition,
        request,
        integration,
        approved_manifest_sha256=integration.manifest_sha256,
        trusted_partition_enabled=True,
    )
    if (result.status, result.verdict) != ("completed", "pass") or not runtime.clearance_valid(partition):
        raise AssertionError("partition integration did not produce runtime-validated clearance")
    return partition


class OwnerReleaseExportTests(unittest.TestCase):
    def test_exporter_api_exists_and_refuses_output_overwrite(self):
        exporter = importlib.import_module("artifacts.owner_release_export")
        self.assertTrue(callable(exporter.create_draft_receipt))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            output.write_text("keep")
            with self.assertRaisesRegex(ValueError, "preserv|exist|overwrite"):
                exporter.create_draft_receipt(
                    root=Path(directory), output=output, source_merge_sha="a" * 40,
                    workflow_merge_sha="b" * 40, source_pr=9, workflow_pr=10,
                    source_review=Path(directory) / "source-review",
                    workflow_review=Path(directory) / "workflow-review",
                    source_assessment=Path(directory) / "source-assessment.json",
                    workflow_assessment=Path(directory) / "workflow-assessment.json",
                    ci_run_ids={"source-quality": 1, "source-artifacts": 2,
                                "workflow-quality": 3, "workflow-artifacts": 4},
                    image_version="0.2.0", chart_version="0.2.0",
                )
            self.assertEqual(output.read_text(), "keep")

    def test_review_accepts_claude_or_codex_author_with_independent_gemini(self):
        exporter = importlib.import_module("artifacts.owner_release_export")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history = graph(root)
            head, base = history["source_head"], history["base"]
            for author in ("claude", "codex"):
                package = review_package(root, f"review-{author}", head, base, author=author)
                self.assertEqual(exporter._review(root, package, head, base)["author_provider"], author)
            for author in ("gemini", "openai"):
                package = review_package(root, f"review-{author}", head, base, author=author)
                with self.subTest(author=author), self.assertRaises(ValueError):
                    exporter._review(root, package, head, base)

    def test_exports_review_bound_draft_and_captures_ci_attempts(self):
        exporter = importlib.import_module("artifacts.owner_release_export")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history = graph(root)
            source_review = review_package(root, "review-source", history["source_head"], history["base"])
            workflow_review = review_package(root, "review-workflow", history["workflow_head"], history["source_merge"])
            runs = root / ".agent/.runs"
            assessments = []
            for head, base, review in ((history["source_head"], history["base"], source_review),
                                       (history["workflow_head"], history["source_merge"], workflow_review)):
                manifest = json.loads((review / "manifest.json").read_text())
                assessment = {
                    "head_sha": head, "base_sha": base,
                    "diff_sha256": manifest["full_diff_sha256"],
                    "reviewed_scope": manifest["scope"],
                    "approved_profile": "standard", "assessed_profile": "standard",
                    "review_lenses": [
                        "authentication-and-authorization", "input-and-injection",
                        "data-and-secrets", "session-and-cryptography",
                        "business-logic-and-races", "supply-chain", "infrastructure",
                        "recovery-and-auditing",
                    ],
                }
                path = runs / f"security-{len(assessments)}.json"
                path.write_text(json.dumps({"assessment": assessment}))
                assessments.append(path)
            roles = {"source-quality": 101, "source-artifacts": 102,
                     "workflow-quality": 201, "workflow-artifacts": 202}
            run_heads = {"source-quality": history["source_head"],
                         "source-artifacts": history["source_head"],
                         "workflow-quality": history["workflow_head"],
                         "workflow-artifacts": history["workflow_head"]}
            run_paths = {"source-quality": ".github/workflows/fork-quality.yml",
                         "source-artifacts": ".github/workflows/artifact-quality.yml",
                         "workflow-quality": ".github/workflows/fork-quality.yml",
                         "workflow-artifacts": ".github/workflows/artifact-quality.yml"}
            calls = []

            def api(endpoint):
                calls.append(endpoint)
                run_id = int(endpoint.rsplit("/", 1)[-1])
                role = next(role for role, value in roles.items() if value == run_id)
                return {"id": run_id, "head_sha": run_heads[role], "path": run_paths[role],
                        "run_attempt": 2, "status": "in_progress", "conclusion": None}

            output = runs / "draft-receipt.json"
            draft = exporter.create_draft_receipt(
                root, output, history["source_merge"], history["workflow_merge"], 9, 10,
                source_review, workflow_review, assessments[0], assessments[1], roles,
                image_version="0.2.0", chart_version="0.2.0", api=api,
            )
            self.assertEqual(draft.payload["source_sha"], history["source_merge"])
            self.assertEqual(draft.payload["workflow_sha"], history["workflow_merge"])
            self.assertEqual(draft.payload["reviews"]["source"]["head_sha"], history["source_head"])
            self.assertEqual(draft.payload["reviews"]["workflow"]["head_sha"], history["workflow_head"])
            self.assertTrue(all(row["attempt"] == 2 for row in draft.payload["ci_runs"]))
            self.assertEqual(len(calls), 4)
            self.assertEqual(json.loads(output.read_text()), draft.payload)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

            def wrong_ci(endpoint):
                value = api(endpoint)
                if endpoint.endswith("/202"):  # workflow artifact run must bind the workflow head/path
                    value["head_sha"] = history["source_head"]
                return value

            rejected = runs / "rejected-draft.json"
            with self.assertRaisesRegex(ValueError, "CI run metadata"):
                exporter.create_draft_receipt(
                    root, rejected, history["source_merge"], history["workflow_merge"], 9, 10,
                    source_review, workflow_review, assessments[0], assessments[1], roles,
                    image_version="0.2.0", chart_version="0.2.0", api=wrong_ci,
                )
            self.assertFalse(rejected.exists())

    def test_rejects_non_matching_ci_run_and_assessment_lens_drift(self):
        # Full behavior is exercised by the export test; these mutations must
        # fail before a draft can be written.
        exporter = importlib.import_module("artifacts.owner_release_export")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history = graph(root)
            source_review = review_package(root, "review-source", history["source_head"], history["base"])
            workflow_review = review_package(root, "review-workflow", history["workflow_head"], history["source_merge"])
            runs = root / ".agent/.runs"
            assessments = []
            for head, base, review in ((history["source_head"], history["base"], source_review),
                                       (history["workflow_head"], history["source_merge"], workflow_review)):
                manifest = json.loads((review / "manifest.json").read_text())
                path = runs / f"security-{len(assessments)}.json"
                assessment = {"head_sha": head, "base_sha": base,
                              "diff_sha256": manifest["full_diff_sha256"],
                              "reviewed_scope": manifest["scope"], "approved_profile": "standard",
                              "assessed_profile": "standard", "review_lenses": ["input-and-injection"]}
                path.write_text(json.dumps({"assessment": assessment}))
                assessments.append(path)
            ids = {"source-quality": 1, "source-artifacts": 2,
                   "workflow-quality": 3, "workflow-artifacts": 4}
            output = root / "draft.json"
            with self.assertRaisesRegex(ValueError, "assessment"):
                exporter.create_draft_receipt(
                    root, output, history["source_merge"], history["workflow_merge"], 9, 10,
                    source_review, workflow_review, assessments[0], assessments[1], ids,
                    image_version="0.2.0", chart_version="0.2.0",
                    api=lambda endpoint: {"id": int(endpoint.rsplit("/", 1)[-1]),
                                          "head_sha": history["source_head"],
                                          "path": ".github/workflows/fork-quality.yml", "run_attempt": 1},
                )
            self.assertFalse(output.exists())

    def test_rejects_dirty_or_wrong_head_and_review_package_hash_drift(self):
        exporter = importlib.import_module("artifacts.owner_release_export")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history = graph(root)
            output = root / "draft.json"
            ids = {"source-quality": 1, "source-artifacts": 2,
                   "workflow-quality": 3, "workflow-artifacts": 4}
            git(root, "reset", "--hard", history["source_merge"])
            with self.assertRaisesRegex(ValueError, "Workflow checkout HEAD"):
                exporter.create_draft_receipt(
                    root, output, history["source_merge"], history["workflow_merge"], 9, 10,
                    root / "source-review", root / "workflow-review", root / "source-assessment.json",
                    root / "workflow-assessment.json", ids, image_version="0.2.0",
                    chart_version="0.2.0", api=lambda endpoint: {},
                )
            self.assertFalse(output.exists())

    def test_export_rejects_high_missing_and_malformed_committed_policy(self):
        exporter = importlib.import_module("artifacts.owner_release_export")
        for profile in ("high", None, "malformed"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                history, source_review, workflow_review, assessments, ids, api = export_inputs(
                    root, security_profile=profile,
                )
                output = root / ".agent/.runs/draft.json"
                with self.assertRaisesRegex(ValueError, "Standard security|config"):
                    exporter.create_draft_receipt(
                        root, output, history["source_merge"], history["workflow_merge"], 9, 10,
                        source_review, workflow_review, assessments[0], assessments[1], ids,
                        image_version="0.2.0", chart_version="0.2.0", api=api,
                    )
                self.assertFalse(output.exists())

    def test_exports_runtime_validated_partition_audit(self):
        exporter = importlib.import_module("artifacts.owner_release_export")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history, source_review, _, assessments, ids, api = export_inputs(root)
            partition = complete_partition(root, history)
            audit_bytes = (partition.root_package.path / "partition-results.json").read_bytes()
            output = root / ".agent/.runs/partition-draft.json"
            draft = exporter.create_draft_receipt(
                root, output, history["source_merge"], history["workflow_merge"], 9, 10,
                source_review, partition.root_package.path, assessments[0], assessments[1], ids,
                image_version="0.2.0", chart_version="0.2.0", api=api,
            )
            workflow = draft.payload["reviews"]["workflow"]
            self.assertIs(workflow["partitioned"], True)
            self.assertEqual(workflow["audit_sha256"], hashlib.sha256(audit_bytes).hexdigest())
            self.assertEqual(workflow["head_sha"], history["workflow_head"])
            self.assertEqual(workflow["base_sha"], history["source_merge"])
            self.assertTrue(output.is_file())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history = graph(root)
            source_review = review_package(root, "review-source", history["source_head"], history["base"])
            workflow_review = review_package(root, "review-workflow", history["workflow_head"], history["source_merge"])
            (source_review / "findings.json").write_text('{"verdict":"pass","findings":["added"]}')
            output = root / "draft.json"
            with self.assertRaisesRegex(ValueError, "Independent review"):
                exporter.create_draft_receipt(
                    root, output, history["source_merge"], history["workflow_merge"], 9, 10,
                    source_review, workflow_review, root / ".agent/.runs/absent-source.json",
                    root / ".agent/.runs/absent-workflow.json",
                    {"source-quality": 1, "source-artifacts": 2,
                     "workflow-quality": 3, "workflow-artifacts": 4},
                    image_version="0.2.0", chart_version="0.2.0", api=lambda endpoint: {},
                )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
