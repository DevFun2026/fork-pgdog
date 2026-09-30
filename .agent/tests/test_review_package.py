from hashlib import sha256
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_cli.providers.base import Capability, ProviderResult
from agent_cli.review.models import ReviewPackageRequest
from agent_cli.review.orchestrator import ReviewOrchestrator
from agent_cli.review.package import (
    ReviewPackageBlocked,
    build_package,
    load_package,
    read_review_requirements,
)


class ReviewPackageTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.git("init", "-b", "main")
        self.git("config", "user.email", "fixture@example.com")
        self.git("config", "user.name", "Fixture")
        self.write("README.md", "initial\n")
        self.git("add", "README.md")
        self.git("commit", "-m", "initial")
        self.write("README.md", "initial\nsecond\n")
        self.git("add", "README.md")
        self.git("commit", "-m", "second")

    def tearDown(self):
        self.tempdir.cleanup()

    def git(self, *args):
        subprocess.run(("git", *args), cwd=self.root, check=True, capture_output=True)

    def write(self, path: str, content: str):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def request(self, **changes):
        values = dict(
            root=self.root,
            base="HEAD~1",
            head="HEAD",
            author_provider="gemini",
            reviewer_provider="claude",
            context_paths=("README.md",),
            requirements="Review correctness and security.",
            verification={"tests": "passed"},
            max_package_bytes=500000,
        )
        values.update(changes)
        return ReviewPackageRequest(**values)

    def test_secret_blocks_package_before_provider_call(self):
        self.write("src/config.py", 'TOKEN="ghp_abcdefghijklmnopqrstuvwxyz123456"\n')
        self.git("add", "src/config.py")
        self.git("commit", "-m", "secret")
        provider = mock.Mock()
        provider.provider = "claude"
        provider.detect.return_value = Capability(
            "claude", True, "claude", "1", True, True, None
        )
        provider.review.return_value = ProviderResult.timeout("claude")
        orchestrator = ReviewOrchestrator({"claude": provider})
        with self.assertRaises(ReviewPackageBlocked):
            orchestrator.prepare(
                self.request(base="HEAD~1", context_paths=("src/config.py",))
            )
        provider.review.assert_not_called()

    def test_manifest_binds_diff_and_each_file(self):
        package = build_package(self.request())
        self.assertEqual(package.manifest.diff_sha256, sha256(package.diff_bytes).hexdigest())
        self.assertEqual(
            package.manifest.files[0].sha256,
            sha256(package.context_file_bytes(0)).hexdigest(),
        )

    def skill_change(self, *, drift=False):
        paths = (".agent/skills/demo/SKILL.md", ".claude/skills/demo/SKILL.md",
                 ".agents/skills/demo/SKILL.md", ".gemini/skills/demo/SKILL.md")
        for path in paths:
            self.write(path, "old content\n" * 40)
        self.git("add", ".")
        self.git("commit", "-m", "old skills")
        for path in paths:
            self.write(path, "new content\n" * 40)
        if drift:
            self.write(paths[1], "unreviewed instruction\n")
        self.git("add", ".")
        self.git("commit", "-m", "new skills")
        return paths

    def test_identical_generated_diffs_are_omitted_but_full_change_is_bound(self):
        paths = self.skill_change()
        package = build_package(self.request())
        self.assertEqual(len(package.manifest.omitted_generated), 3)
        self.assertIn(paths[0].encode(), package.diff_bytes)
        self.assertNotIn(paths[1].encode(), package.diff_bytes)
        self.assertEqual(set(package.manifest.scope), set(paths))
        full = subprocess.check_output(("git", "diff", "--binary", "HEAD~1", "HEAD"), cwd=self.root)
        self.assertEqual(package.manifest.full_diff_sha256, sha256(full).hexdigest())
        self.assertLess(len(package.diff_bytes), len(full) // 2)
        self.assertEqual(load_package(package.path, root=self.root).manifest, package.manifest)

    def test_generated_drift_remains_visible(self):
        paths = self.skill_change(drift=True)
        package = build_package(self.request())
        self.assertIn(paths[1].encode(), package.diff_bytes)
        self.assertEqual(len(package.manifest.omitted_generated), 2)

    def test_forged_omission_proof_is_rejected_on_reload(self):
        self.skill_change()
        package = build_package(self.request())
        path = package.path / "manifest.json"
        payload = json.loads(path.read_text())
        payload["omitted_generated"] = []
        path.write_text(json.dumps(payload))
        with self.assertRaisesRegex(ReviewPackageBlocked, "projection"):
            load_package(package.path, root=self.root)

    def test_legacy_manifest_rejects_unhashed_projection_fields(self):
        package = build_package(self.request())
        path = package.path / "manifest.json"
        payload = json.loads(path.read_text())
        for field in ("full_diff_sha256", "omitted_generated", "estimated_tokens"):
            payload.pop(field)
        path.write_text(json.dumps(payload))
        legacy = load_package(package.path, root=self.root)
        self.assertIsNone(legacy.manifest.full_diff_sha256)
        payload.update(full_diff_sha256=None,
                       omitted_generated=[["README.md", "ignored-source.md"]],
                       estimated_tokens=1)
        path.write_text(json.dumps(payload))
        with self.assertRaisesRegex(ReviewPackageBlocked, "manifest"):
            load_package(package.path, root=self.root)

    def test_equivalent_requested_context_is_read_once(self):
        paths = self.skill_change()
        package = build_package(self.request(context_paths=paths))
        self.assertEqual(tuple(item.path for item in package.manifest.files), (paths[0],))

    def test_old_generated_drift_is_not_hidden_by_fixing_the_copy(self):
        paths = self.skill_change(drift=True)
        for path in paths:
            self.write(path, "fixed content\n")
        self.git("add", ".")
        self.git("commit", "-m", "fix drift")
        package = build_package(self.request())
        self.assertIn(paths[1].encode(), package.diff_bytes)


    def test_generated_mode_change_is_not_hidden(self):
        paths = self.skill_change()
        self.git("update-index", "--chmod=+x", paths[1])
        self.git("commit", "-m", "mode")
        package = build_package(self.request(base="HEAD~2"))
        self.assertIn(paths[1].encode(), package.diff_bytes)

    def move_fixture(self, name="src/demo.txt", *, content_change=False, mode_change=False, symlink=False):
        self.write(name, "original fixture\n" * 50)
        if symlink:
            (self.root / name).unlink()
            (self.root / name).symlink_to("README.md")
        self.git("add", ".")
        self.git("commit", "-m", "fixture")
        destination = "applications/pgdog/" + name
        (self.root / destination).parent.mkdir(parents=True, exist_ok=True)
        self.git("mv", name, destination)
        if content_change:
            self.write(destination, "modified fixture\n" * 50)
        self.git("add", ".")
        if mode_change:
            self.git("update-index", "--chmod=+x", destination)
        self.git("commit", "-m", "move")
        return destination

    def test_verified_rename_is_bound_and_compacted(self):
        destination = self.move_fixture()
        package = build_package(self.request())
        self.assertEqual(package.diff_bytes, b"")
        proof = package.manifest.verified_renames
        self.assertEqual(proof["count"], 1)
        self.assertEqual(proof["groups"], [{"from": "", "to": "applications/pgdog/", "paths": ["src/demo.txt"]}])
        self.assertEqual(package.manifest.scope, (destination,))
        self.assertEqual(json.loads((package.path / "manifest.json").read_text())["scope"],
                         {"applications/pgdog/": ["src/demo.txt"]})
        self.assertEqual(load_package(package.path, root=self.root).manifest, package.manifest)

    def test_sensitive_rename_only_sends_metadata_and_explicit_context_stays_denied(self):
        destination = self.move_fixture("fixtures/server.pem")
        package = build_package(self.request())
        self.assertEqual(package.diff_bytes, b"")
        self.assertEqual(load_package(package.path, root=self.root).manifest, package.manifest)
        with self.assertRaisesRegex(ReviewPackageBlocked, "denied"):
            build_package(self.request(context_paths=(destination,)))

    def test_changed_sensitive_rename_is_denied(self):
        for change in ("content_change", "mode_change"):
            with self.subTest(change=change):
                self.move_fixture("fixtures/" + change + ".pem", **{change: True})
                with self.assertRaisesRegex(ReviewPackageBlocked, "denied"):
                    build_package(self.request())

    def test_changed_regular_rename_and_symlink_remain_visible(self):
        for change in ("content_change", "mode_change", "symlink"):
            with self.subTest(change=change):
                destination = self.move_fixture("src/" + change, **{change: True})
                package = build_package(self.request())
                self.assertIn(destination.encode(), package.diff_bytes)
                self.assertIsNone(package.manifest.verified_renames)

    def test_forged_rename_proof_and_legacy_downgrade_are_rejected(self):
        self.move_fixture()
        package = build_package(self.request())
        manifest_path = package.path / "manifest.json"
        original = json.loads(manifest_path.read_text())
        for field, value in (("count", 0), ("entries_sha256", "0" * 64), ("groups", [])):
            payload = json.loads(json.dumps(original))
            payload["verified_renames"][field] = value
            manifest_path.write_text(json.dumps(payload))
            with self.assertRaises(ReviewPackageBlocked):
                load_package(package.path, root=self.root)
        for field in ("full_diff_sha256", "omitted_generated", "estimated_tokens"):
            original.pop(field)
        manifest_path.write_text(json.dumps(original))
        with self.assertRaisesRegex(ReviewPackageBlocked, "manifest"):
            load_package(package.path, root=self.root)

    def test_sensitive_source_cannot_be_laundered_by_new_filename(self):
        self.move_fixture("fixtures/secret.pem")
        self.git("mv", "applications/pgdog/fixtures/secret.pem", "ordinary.txt")
        self.write("ordinary.txt", "different content\n")
        self.git("add", ".")
        self.git("commit", "-m", "rename and modify")
        with self.assertRaisesRegex(ReviewPackageBlocked, "denied"):
            build_package(self.request())

    def test_rename_paths_are_literal_and_arbitrary_basename_is_preserved(self):
        destination = self.move_fixture('src/a space "quote".txt')
        package = build_package(self.request())
        self.assertEqual(package.manifest.verified_renames["groups"][0]["paths"], ['src/a space "quote".txt'])
        self.assertEqual(load_package(package.path, root=self.root).manifest, package.manifest)
        self.git("mv", destination, "new-name.txt")
        self.git("commit", "-m", "rename basename")
        package = build_package(self.request())
        self.assertEqual(package.manifest.verified_renames["groups"],
                         [{"from": destination, "to": "new-name.txt", "paths": [""]}])

    def test_unsafe_directory_and_control_character_moves_stay_blocked(self):
        for name in (".memory/fixture.txt", "src/new\nline.txt"):
            with self.subTest(name=name):
                self.move_fixture(name)
                with self.assertRaises(ReviewPackageBlocked):
                    build_package(self.request())

    def test_legacy_uncompacted_rename_package_still_loads(self):
        self.move_fixture()
        from agent_cli.review.package import project_diff
        def old_projection(root, base, head, **kwargs):
            return project_diff(root, base, head, compact_renames=False)
        with mock.patch("agent_cli.review.package.project_diff", side_effect=old_projection):
            package = build_package(self.request())
        self.assertIsNone(package.manifest.verified_renames)
        self.assertIn(b"rename from src/demo.txt", package.diff_bytes)
        self.assertEqual(load_package(package.path, root=self.root).manifest, package.manifest)

    def test_large_move_table_preserves_every_path_in_directory_tree(self):
        for index in range(12):
            self.write(f"src/nested/{index}.txt", f"unique fixture {index}\n")
        self.git("add", ".")
        self.git("commit", "-m", "large fixture")
        (self.root / "applications").mkdir()
        self.git("mv", "src", "applications/src")
        self.git("commit", "-m", "large move")
        package = build_package(self.request())
        self.assertEqual(package.diff_bytes, b"")
        proof = package.manifest.verified_renames
        self.assertEqual(proof["count"], 12)
        self.assertEqual(proof["groups"], [{"from": "", "to": "applications/",
                         "tree": {"src": {"nested": {f"{i}.txt": None for i in range(12)}}}}])
        self.assertEqual(load_package(package.path, root=self.root).manifest, package.manifest)

    def test_token_budget_blocks_without_truncating_review(self):
        with self.assertRaisesRegex(ReviewPackageBlocked, "estimated.token"):
            build_package(self.request(max_estimated_tokens=1))

    def test_report_counts_manifest_and_context_in_budget(self):
        package = build_package(self.request())
        self.assertGreater(package.manifest.estimated_tokens, 0)
        actual_bytes = sum(p.stat().st_size for p in package.path.rglob("*") if p.is_file())
        self.assertGreaterEqual(package.manifest.total_bytes, actual_bytes)

    def test_symlink_escape_is_rejected(self):
        outside = self.root.parent / "outside-review.txt"
        outside.write_text("outside", encoding="utf-8")
        self.addCleanup(outside.unlink)
        (self.root / "escape").symlink_to(outside)
        with self.assertRaisesRegex(ReviewPackageBlocked, "symlink"):
            build_package(self.request(context_paths=("escape",)))

    def test_load_package_rejects_tampered_diff(self):
        package = build_package(self.request())
        (package.path / "diff.patch").write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(ReviewPackageBlocked, "checksum"):
            load_package(package.path, root=self.root)

    def test_requirements_file_must_be_safe_and_inside_repository(self):
        outside = self.root.parent / "outside-requirements.md"
        outside.write_text("host private requirements", encoding="utf-8")
        self.addCleanup(outside.unlink)
        with self.assertRaisesRegex(ReviewPackageBlocked, "escapes repository"):
            read_review_requirements(self.root, outside, max_bytes=500000)

        self.write("requirements.md", "Review the public behavior.\n")
        self.assertEqual(
            read_review_requirements(
                self.root, "requirements.md", max_bytes=500000
            ),
            "Review the public behavior.\n",
        )


if __name__ == "__main__":
    unittest.main()
