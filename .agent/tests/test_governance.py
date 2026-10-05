import subprocess
import tempfile
import unittest
from pathlib import Path

from agent_cli.governance import GovernanceBaseError, resolve_trusted_base


class GovernanceBaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.git("init", "-b", "main")
        self.git("config", "user.email", "fixture@example.com")
        self.git("config", "user.name", "Fixture")
        (self.root / "tracked.txt").write_text("base\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "base")
        self.base = self.output("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.base)
        self.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
        self.git("switch", "-c", "feature")
        (self.root / "tracked.txt").write_text("feature\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "feature")

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *arguments: str) -> None:
        subprocess.run(("git", *arguments), cwd=self.root, check=True, capture_output=True)

    def output(self, *arguments: str) -> str:
        return subprocess.run(
            ("git", *arguments),
            cwd=self.root,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()

    def test_resolves_remote_default_branch_as_immutable_base(self):
        base, head = resolve_trusted_base(self.root, requested_base="origin/main")
        self.assertEqual(base, self.base)
        self.assertEqual(head, self.output("rev-parse", "HEAD"))

    def test_rejects_head_as_caller_selected_base(self):
        with self.assertRaisesRegex(GovernanceBaseError, "requested base"):
            resolve_trusted_base(self.root, requested_base="HEAD")

    def test_rejects_intermediate_feature_commit_as_base(self):
        (self.root / "second.txt").write_text("second\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "second")
        with self.assertRaisesRegex(GovernanceBaseError, "requested base"):
            resolve_trusted_base(self.root, requested_base="HEAD~1")

    def test_rejects_empty_diff_when_head_is_trusted_base(self):
        self.git("switch", "main")
        with self.assertRaisesRegex(GovernanceBaseError, "proper ancestor"):
            resolve_trusted_base(self.root)

    def test_shallow_checkout_needs_then_accepts_materialized_anchor(self):
        (self.root / "second.txt").write_text("feature tip\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "feature tip")
        # Advertise main as the remote default while cloning only the shallow
        # feature branch. Otherwise Git may set origin/HEAD to feature itself.
        self.git("switch", "main")
        clone_parent = tempfile.TemporaryDirectory(prefix="governance-shallow-")
        self.addCleanup(clone_parent.cleanup)
        clone = Path(clone_parent.name) / "clone"
        subprocess.run(
            (
                "git",
                "clone",
                "--quiet",
                "--depth",
                "1",
                "--branch",
                "feature",
                f"file://{self.root}",
                str(clone),
            ),
            check=True,
        )
        with self.assertRaisesRegex(GovernanceBaseError, "no trusted"):
            resolve_trusted_base(clone)
        subprocess.run(
            ("git", "fetch", "--quiet", "--unshallow", "origin"),
            cwd=clone,
            check=True,
        )
        subprocess.run(
            (
                "git",
                "fetch",
                "--quiet",
                "origin",
                f"main:refs/remotes/origin/main",
            ),
            cwd=clone,
            check=True,
        )
        subprocess.run(
            (
                "git",
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/main",
            ),
            cwd=clone,
            check=True,
        )
        base, _ = resolve_trusted_base(clone)
        self.assertEqual(base, self.base)


if __name__ == "__main__":
    unittest.main()
