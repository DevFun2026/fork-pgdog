"""Compile the production revision resolver and exercise its public contract."""
from pathlib import Path
import os
import json
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BuildMetadataTests(unittest.TestCase):
    def test_revision_selection_and_validation(self):
        source = ROOT / "applications/pgdog/pgdog/build_metadata.rs"
        self.assertTrue(source.is_file(), "revision resolver has not been implemented")
        harness = '''
#[path = SOURCE] mod metadata;
use metadata::resolve_revision;
#[test] fn explicit_source_wins() {
    assert_eq!(resolve_revision(Some("0123456789abcdef0123456789abcdef01234567"),
        Some("ffffffffffffffffffffffffffffffffffffffff"), "0.1.60").unwrap(), "0123456");
}
#[test] fn git_source_fallback() {
    assert_eq!(resolve_revision(None, Some("abcdef0123456789abcdef0123456789abcdef01"), "0.1.60").unwrap(), "abcdef0");
}
#[test] fn package_fallback() {
    assert_eq!(resolve_revision(None, None, "0.1.60").unwrap(), "0.1.60");
    assert_eq!(resolve_revision(None, Some(""), "0.1.60").unwrap(), "0.1.60");
    assert_eq!(resolve_revision(None, Some("not-a-repository"), "0.1.60").unwrap(), "0.1.60");
}
#[test] fn bad_explicit_revision_is_rejected() {
    for value in ["", "abcdef0", "0123456789abcdef0123456789abcdef0123456g",
                  " 0123456789abcdef0123456789abcdef01234567", "$(echo bad)"] {
        assert!(resolve_revision(Some(value), None, "0.1.60").is_err(), "{value}");
    }
}
#[test] fn uppercase_is_normalized() {
    assert_eq!(resolve_revision(Some("ABCDEF0123456789ABCDEF0123456789ABCDEF01"), None, "0.1.60").unwrap(), "abcdef0");
}
'''.replace("SOURCE", json.dumps(str(source)))
        with tempfile.TemporaryDirectory(prefix="pgdog-revision-tests-") as directory:
            path = Path(directory)
            (path / "test.rs").write_text(harness)
            compile_result = subprocess.run(
                ["rustc", "+" + os.environ.get("PGDOG_TEST_TOOLCHAIN", "1.96"), "--edition=2024", "--test", str(path / "test.rs"),
                 "-o", str(path / "tests")], capture_output=True, text=True)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            result = subprocess.run([str(path / "tests")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("5 passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
