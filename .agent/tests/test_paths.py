import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_cli.paths import PathPolicyError, atomic_write, resolve_inside


class PathTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        base = Path(self.tempdir.name)
        self.root = base / "repo"
        self.outside = base / "outside"
        self.root.mkdir()
        self.outside.mkdir()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_rejects_parent_escape(self):
        with self.assertRaises(PathPolicyError):
            resolve_inside(self.root, self.root / ".." / "outside.txt")

    def test_rejects_symlink_escape(self):
        (self.root / "link").symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(PathPolicyError):
            resolve_inside(self.root, self.root / "link" / "secret.txt")

    def test_accepts_missing_descendant(self):
        expected = self.root / "new" / "record.json"
        self.assertEqual(resolve_inside(self.root, expected), expected.resolve())

    def test_atomic_write_leaves_old_file_when_replace_fails(self):
        target = self.root / "record.json"
        target.write_text("old", encoding="utf-8")
        with mock.patch("os.replace", side_effect=OSError("interrupted")):
            with self.assertRaises(OSError):
                atomic_write(target, b"new")
        self.assertEqual(target.read_text(encoding="utf-8"), "old")

    def test_atomic_write_uses_owner_only_mode(self):
        target = self.root / "record.json"
        atomic_write(target, "new")
        self.assertEqual(target.read_text(encoding="utf-8"), "new")
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
