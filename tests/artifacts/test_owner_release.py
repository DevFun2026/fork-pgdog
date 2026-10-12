import copy
import hashlib
import importlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

REPOSITORY = "DevFun2026/fork-pgdog"
OWNER_ID = 107181711
OWNER = "simonle251289"
QUALITY = ".github/workflows/fork-quality.yml"
ARTIFACTS = ".github/workflows/artifact-quality.yml"


def make_receipt(source_merge, workflow_merge, source_head, source_base, workflow_head):
    def review(head, base, seed, *, partitioned=False):
        return {
            "status": "passed", "verdict": "pass", "author_provider": "codex",
            "reviewer_provider": "gemini", "head_sha": head, "base_sha": base,
            "diff_sha256": seed * 64, "manifest_sha256": seed * 64,
            "findings_sha256": seed * 64, "partitioned": partitioned,
            "audit_sha256": seed * 64,
        }

    return {
        "schema_version": 3, "repository": REPOSITORY,
        "source_sha": source_merge, "workflow_sha": workflow_merge,
        "image_version": "0.2.0", "chart_version": "0.2.0",
        "created_at": "2026-10-12T00:00:00Z",
        "authorization": {
            "method": "github-owner-reviewed-release", "actor_id": OWNER_ID,
            "actor_login": OWNER, "comment_id": 42,
            "comment_body_sha256": "0" * 64, "security_profile": "standard",
            "ssh_clearance": "waived-by-owner", "canonical_release_gate": "not-claimed",
        },
        "provenance": {"source_pr": 9, "workflow_pr": 10},
        "reviews": {
            "source": review(source_head, source_base, "a"),
            "workflow": review(workflow_head, source_merge, "b", partitioned=True),
        },
        "ci_runs": [
            {"role": "source-quality", "id": 100, "attempt": 1, "head_sha": source_head, "path": QUALITY},
            {"role": "source-artifacts", "id": 101, "attempt": 1, "head_sha": source_head, "path": ARTIFACTS},
            {"role": "workflow-quality", "id": 102, "attempt": 1, "head_sha": workflow_head, "path": QUALITY},
            {"role": "workflow-artifacts", "id": 103, "attempt": 1, "head_sha": workflow_head, "path": ARTIFACTS},
        ],
        "evidence_sha256": {
            "source-review-audit": "a" * 64, "workflow-review-audit": "b" * 64,
            **{key: "c" * 64 for key in (
                "source-security-assessment", "workflow-security-assessment", "threat-model",
                "release-notes", "migration-rollback", "residual-risks",
            )},
        },
    }


def git(root, *args, input=None):
    result = subprocess.run(["git", *args], cwd=root, input=input, text=True,
                            capture_output=True, check=True)
    return result.stdout.strip()


def git_fixture(root, security_config='[project]\nname = "fork-pgdog"\nsecurity_profile = "standard"\n', *, symlink_config=False):
    git(root, "init", "-q")
    git(root, "symbolic-ref", "HEAD", "refs/heads/main")
    git(root, "config", "user.name", "Test")
    git(root, "config", "user.email", "test@example.invalid")

    def commit_file(name, value, parent=None, merge_parent=None):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        git(root, "add", name)
        tree = git(root, "write-tree")
        args = ["commit-tree", tree]
        if parent:
            args += ["-p", parent]
        if merge_parent:
            args += ["-p", merge_parent]
        sha = git(root, *args, input="fixture\n")
        git(root, "update-ref", "refs/heads/main", sha)
        return sha, tree

    policy = root / ".agent/config.toml"
    policy.parent.mkdir(parents=True)
    if symlink_config:
        (root / "config-standard.toml").write_text(security_config)
        policy.symlink_to("../config-standard.toml")
    else:
        policy.write_text(security_config)
    git(root, "add", ".agent/config.toml")
    base, _ = commit_file("base.txt", "base\n")
    source_head, source_tree = commit_file("source.txt", "source\n", base)
    source_merge = git(root, "commit-tree", source_tree, "-p", base, "-p", source_head, input="source merge\n")
    git(root, "update-ref", "refs/heads/main", source_merge)
    workflow_head, workflow_tree = commit_file("workflow.txt", "workflow\n", source_merge)
    workflow_merge = git(root, "commit-tree", workflow_tree, "-p", source_merge, "-p", workflow_head, input="workflow merge\n")
    git(root, "update-ref", "refs/heads/main", workflow_merge)
    return {"base": base, "source_head": source_head, "source_tree": source_tree,
            "source_merge": source_merge, "workflow_head": workflow_head,
            "workflow_tree": workflow_tree, "workflow_merge": workflow_merge}


class OwnerReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = importlib.import_module("artifacts.owner_release")

    def valid_receipt(self, graph):
        payload = make_receipt(graph["source_merge"], graph["workflow_merge"],
                               graph["source_head"], graph["base"], graph["workflow_head"])
        payload["authorization"]["comment_body_sha256"] = hashlib.sha256(
            self.mod.approval_body(payload).encode()).hexdigest()
        return payload

    def test_parse_requires_complete_schema3_and_strict_types_while_allowing_drafts(self):
        with tempfile.TemporaryDirectory() as directory:
            graph = git_fixture(Path(directory))
            payload = self.valid_receipt(graph)
            draft = copy.deepcopy(payload)
            draft["authorization"]["comment_id"] = 0
            self.assertEqual(self.mod.parse_owner_receipt(draft, graph["source_merge"], allow_unapproved=True), draft)
            with self.assertRaisesRegex(ValueError, "comment|approval|draft"):
                self.mod.parse_owner_receipt(draft, graph["source_merge"])
            self.assertEqual(self.mod.parse_owner_receipt(payload, graph["source_merge"]), payload)

            mutations = [
                lambda p: p.update(extra=True),
                lambda p: p.update(schema_version=True),
                lambda p: p["authorization"].update(actor_id="107181711"),
                lambda p: p["authorization"].update(comment_id=True),
                lambda p: p["authorization"].update(security_profile="baseline"),
                lambda p: p["authorization"].update(ssh_clearance="passed"),
                lambda p: p["provenance"].update(workflow_pr=p["provenance"]["source_pr"]),
                lambda p: p["reviews"]["source"].update(partitioned=1),
                lambda p: p["reviews"]["workflow"].update(findings_sha256="z" * 64),
                lambda p: p["ci_runs"][0].update(attempt=False),
                lambda p: p["evidence_sha256"].pop("threat-model"),
                lambda p: p["evidence_sha256"].update({"source-review-audit": "d" * 64}),
                lambda p: p.update(created_at="2999-01-01T00:00:00Z"),
                lambda p: p.update(created_at="2026-10-11T12:00:00+07:00"),
            ]
            for mutate in mutations:
                changed = copy.deepcopy(payload)
                mutate(changed)
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    self.mod.parse_owner_receipt(changed, graph["source_merge"])

            legacy = copy.deepcopy(payload)
            legacy["schema_version"] = 2
            with self.assertRaises(ValueError):
                self.mod.parse_owner_receipt(legacy, graph["source_merge"])

    def test_approval_body_binds_entire_payload_without_comment_cycle(self):
        with tempfile.TemporaryDirectory() as directory:
            graph = git_fixture(Path(directory))
            payload = self.valid_receipt(graph)
            body = self.mod.approval_body(payload)
            self.assertEqual(body, self.mod.approval_body(payload))
            for line in (
                "Image: 0.2.0", "Helm chart: 0.2.0",
                "Source commit: " + graph["source_merge"],
                "Workflow commit: " + graph["workflow_merge"],
                "Security profile: standard", "SSH clearance: waived by owner",
                "Canonical release gate: not claimed",
            ):
                self.assertIn(line, body)
            self.assertEqual(payload["authorization"]["comment_body_sha256"], hashlib.sha256(body.encode()).hexdigest())
            authorization_only = copy.deepcopy(payload)
            authorization_only["authorization"]["comment_id"] += 100
            authorization_only["authorization"]["comment_body_sha256"] = "d" * 64
            self.assertEqual(body, self.mod.approval_body(authorization_only))
            changed = copy.deepcopy(payload)
            changed["evidence_sha256"]["threat-model"] = "d" * 64
            self.assertNotEqual(body, self.mod.approval_body(changed))

    def test_standard_security_profile_is_read_from_all_committed_review_and_merge_blobs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph = git_fixture(root)
            payload = self.valid_receipt(graph)
            self.assertIsNone(self.mod.validate_standard_policy(root, payload))
            (root / ".agent/config.toml").write_text('[project]\nsecurity_profile = "high"\n')
            self.assertIsNone(self.mod.validate_standard_policy(root, payload), "policy must come from Git blobs, not the working tree")

        for config in (
            '[project]\nname = "fork-pgdog"\nsecurity_profile = "high"\n',
            '[project]\nname = "fork-pgdog"\n',
            '[project\nsecurity_profile = "standard"\n',
        ):
            with self.subTest(config=config), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                graph = git_fixture(root, security_config=config)
                payload = self.valid_receipt(graph)
                with self.assertRaises(ValueError):
                    self.mod.validate_standard_policy(root, payload)
                api_calls = []
                with self.assertRaises(ValueError):
                    self.mod.validate_live(
                        payload, actor_id=str(OWNER_ID), workflow_sha=graph["workflow_merge"],
                        root=root, api=lambda endpoint, calls=api_calls: calls.append(endpoint),
                    )
                self.assertEqual(api_calls, [], "invalid committed profile must fail before live trust reads")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph = git_fixture(root, symlink_config=True)
            payload = self.valid_receipt(graph)
            with self.assertRaises(ValueError):
                self.mod.validate_standard_policy(root, payload)

    def test_live_validation_checks_pr_merge_tree_main_and_owner_environment_ci(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph = git_fixture(root)
            payload = self.valid_receipt(graph)
            live = self.fake_github(root, graph, payload)
            self.mod.validate_live(payload, actor_id=str(OWNER_ID), workflow_sha=graph["workflow_merge"], root=root, api=live)

            failures = [
                ("pulls/9", lambda d: d.update(number=8)),
                ("pulls/9", lambda d: d.update(merged=False)),
                ("pulls/9", lambda d: d["base"].update(ref="release")),
                ("pulls/10", lambda d: d["head"].update(sha=graph["source_head"])),
                ("pulls/10", lambda d: d["base"].update(sha=graph["base"])),
                ("commits/" + graph["source_merge"], lambda d: d["parents"].reverse()),
                ("commits/" + graph["source_merge"], lambda d: d["commit"]["tree"].update(sha="f" * 40)),
                ("commits/" + graph["workflow_merge"], lambda d: d["parents"].reverse()),
                ("git/ref/heads/main", lambda d: d["object"].update(sha=graph["source_merge"])),
                ("issues/comments/42", lambda d: d.update(issue_url="https://api.github.com/repos/DevFun2026/fork-pgdog/issues/9")),
                ("issues/comments/42", lambda d: d.update(body="changed approval")),
                ("collaborators/simonle251289/permission", lambda d: d.update(permission="write")),
                ("collaborators/simonle251289/permission", lambda d: d["user"].update(id=1)),
                ("environments/packages", lambda d: d.update(protection_rules=[])),
                ("environments/packages", lambda d: d.update(deployment_branch_policy={"protected_branches": True, "custom_branch_policies": False})),
                ("deployment-branch-policies", lambda d: d["branch_policies"][0].update(name="*")),
                ("actions/runs/100", lambda d: d.update(conclusion="failure")),
                ("actions/runs/102", lambda d: d.update(run_attempt=2)),
                ("actions/runs/103", lambda d: d.update(status="queued")),
                ("attempts/1/jobs", lambda d: d["jobs"][0].update(conclusion="skipped")),
                ("attempts/1/jobs", lambda d: d["jobs"].pop()),
            ]
            for endpoint_fragment, mutate in failures:
                def api(endpoint, fragment=endpoint_fragment, action=mutate):
                    value = self.fake_github(root, graph, payload)(endpoint)
                    if fragment in endpoint:
                        action(value)
                    return value
                with self.subTest(endpoint=endpoint_fragment), self.assertRaises(ValueError):
                    self.mod.validate_live(payload, actor_id=str(OWNER_ID), workflow_sha=graph["workflow_merge"], root=root, api=api)

            with self.assertRaises(ValueError):
                self.mod.validate_live(payload, actor_id="1", workflow_sha=graph["workflow_merge"], root=root, api=live)
            with self.assertRaises(ValueError):
                self.mod.validate_live(payload, actor_id=str(OWNER_ID), workflow_sha=graph["source_merge"], root=root, api=live)

    def fake_github(self, root, graph, payload):
        def pr(number, merge_sha, head, base, base_sha):
            return {"number": number, "state": "closed", "merged": True, "merged_at": "2026-10-11T00:00:00Z",
                    "merge_commit_sha": merge_sha,
                    "base": {"ref": "main", "sha": base_sha, "repo": {"full_name": REPOSITORY}},
                    "head": {"sha": head, "repo": {"full_name": REPOSITORY}}}

        def commit(sha, tree, parents):
            return {"sha": sha, "commit": {"tree": {"sha": tree}}, "parents": [{"sha": parent} for parent in parents]}

        def api(endpoint):
            if endpoint == "repos/" + REPOSITORY + "/pulls/9":
                return pr(9, graph["source_merge"], graph["source_head"], "main", graph["base"])
            if endpoint == "repos/" + REPOSITORY + "/pulls/10":
                return pr(10, graph["workflow_merge"], graph["workflow_head"], "main", graph["source_merge"])
            if endpoint.endswith("/commits/" + graph["source_merge"]):
                return commit(graph["source_merge"], graph["source_tree"], [graph["base"], graph["source_head"]])
            if endpoint.endswith("/commits/" + graph["workflow_merge"]):
                return commit(graph["workflow_merge"], graph["workflow_tree"], [graph["source_merge"], graph["workflow_head"]])
            if endpoint.endswith("/commits/" + graph["source_head"]):
                return commit(graph["source_head"], graph["source_tree"], [graph["base"]])
            if endpoint.endswith("/commits/" + graph["workflow_head"]):
                return commit(graph["workflow_head"], graph["workflow_tree"], [graph["source_merge"]])
            if endpoint.endswith("/git/ref/heads/main"):
                return {"object": {"sha": graph["workflow_merge"]}}
            if endpoint.endswith("/issues/comments/42"):
                return {"id": 42, "user": {"id": OWNER_ID, "login": OWNER},
                        "body": self.mod.approval_body(payload),
                        "issue_url": "https://api.github.com/repos/DevFun2026/fork-pgdog/issues/10"}
            if endpoint.endswith("/collaborators/simonle251289/permission"):
                return {"permission": "admin", "user": {"id": OWNER_ID, "login": OWNER}}
            if endpoint.endswith("/environments/packages"):
                return {"protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "User", "reviewer": {"id": OWNER_ID}}]}],
                        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
            if endpoint.endswith("/deployment-branch-policies"):
                return {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}
            for witness in payload["ci_runs"]:
                if endpoint.endswith(f"/actions/runs/{witness['id']}"):
                    return {"id": witness["id"], "head_sha": witness["head_sha"], "path": witness["path"],
                            "run_attempt": witness["attempt"], "status": "completed", "conclusion": "success"}
                if f"/actions/runs/{witness['id']}/attempts/{witness['attempt']}/jobs" in endpoint:
                    names = ["verification", "scanners (dependency)", "scanners (license)", "scanners (sast)"] if witness["path"] == QUALITY else ["build (ubuntu-24.04, amd64)", "build (ubuntu-24.04-arm, arm64)"]
                    jobs = [{"name": name, "status": "completed", "conclusion": "success"} for name in names]
                    return {"total_count": len(jobs), "jobs": jobs}
            raise AssertionError(endpoint)
        return api


if __name__ == "__main__":
    unittest.main()
