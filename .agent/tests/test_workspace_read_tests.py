import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/workspace_read_tests.py"
SPEC = importlib.util.spec_from_file_location("workspace_read_tests", RUNNER)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class WorkspaceReadTestsLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = []

    def write_required_fixtures(self, profile_dir):
        profile_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        variants = profile_dir / "variants"
        variants.mkdir(mode=0o700)
        names = [f"reference-extended-pg{major}.json" for major in runner.SUPPORTED_MAJORS]
        names += [f"index-attribute-matrix-pg{major}.json" for major in runner.SUPPORTED_MAJORS]
        names += [
            f"read-dependency-profile-pg{major}-{suffix}.json"
            for major in runner.SUPPORTED_MAJORS
            for suffix in runner.VARIANT_NAMES
        ]
        for name in names:
            path = (variants if name.startswith("read-dependency-profile-") else profile_dir) / name
            path.write_text("{}\n", encoding="utf-8")
            path.chmod(0o600)
            self.paths.append(path)
        return profile_dir

    def prepare(self, temp_path, env):
        return self.write_required_fixtures(temp_path / "profile-fixtures")

    def test_child_sees_owned_fixtures_and_ambient_path_is_overridden(self):
        observed = {}

        def child(command, *, cwd, env, check):
            observed.update(command=command, cwd=cwd, env=env, check=check)
            owned = Path(env["PGDOG_PROFILE_TEST_FIXTURE_DIR"])
            self.assertTrue(owned.is_dir())
            self.assertTrue(all(path.is_file() for path in self.paths))
            self.assertNotEqual(env["PGDOG_PROFILE_TEST_FIXTURE_DIR"], "/private/ambient")
            self.assertEqual(env["DATABASE_URL"], "postgres://legacy-workspace-test")
            return mock.Mock(returncode=0)

        status = runner.run_workspace_tests(
            {
                "PATH": "/usr/bin",
                "DATABASE_URL": "postgres://legacy-workspace-test",
                "PGDOG_PROFILE_TEST_FIXTURE_DIR": "/private/ambient",
            },
            prepare=self.prepare,
            run=child,
            temp_parent=Path(self.temp.name),
        )

        self.assertEqual(status, 0)
        self.assertEqual(observed["command"], runner.NEXTEST_COMMAND)
        self.assertEqual(observed["cwd"], runner.APPLICATION)
        self.assertFalse(Path(observed["env"]["PGDOG_PROFILE_TEST_FIXTURE_DIR"]).exists())

    def test_owned_fixtures_are_cleaned_after_child_failure_and_status_is_preserved(self):
        observed = {}

        def child(_command, *, env, **_kwargs):
            observed["fixture_dir"] = env["PGDOG_PROFILE_TEST_FIXTURE_DIR"]
            self.assertTrue(Path(observed["fixture_dir"]).is_dir())
            return mock.Mock(returncode=17)

        status = runner.run_workspace_tests(
            {}, prepare=self.prepare, run=child, temp_parent=Path(self.temp.name)
        )

        self.assertEqual(status, 17)
        self.assertFalse(Path(observed["fixture_dir"]).exists())

    def test_fixture_preparation_failure_prevents_child_start(self):
        child = mock.Mock()

        def fail_prepare(_temp, _env):
            raise RuntimeError("capture failed")

        with self.assertRaisesRegex(RuntimeError, "capture failed"):
            runner.run_workspace_tests({}, prepare=fail_prepare, run=child,
                                      temp_parent=Path(self.temp.name))

        child.assert_not_called()

    def test_fixture_directory_is_cleaned_when_child_raises(self):
        observed = {}

        def child(_command, *, env, **_kwargs):
            observed["fixture_dir"] = env["PGDOG_PROFILE_TEST_FIXTURE_DIR"]
            raise OSError("could not start cargo")

        with self.assertRaisesRegex(OSError, "could not start cargo"):
            runner.run_workspace_tests({}, prepare=self.prepare, run=child,
                                      temp_parent=Path(self.temp.name))

        self.assertFalse(Path(observed["fixture_dir"]).exists())

    def test_fixture_directory_is_cleaned_when_child_is_interrupted(self):
        observed = {}

        def child(_command, *, env, **_kwargs):
            observed["fixture_dir"] = env["PGDOG_PROFILE_TEST_FIXTURE_DIR"]
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            runner.run_workspace_tests({}, prepare=self.prepare, run=child,
                                      temp_parent=Path(self.temp.name))

        self.assertFalse(Path(observed["fixture_dir"]).exists())

    def test_missing_index_matrix_prevents_child_start(self):
        child = mock.Mock()

        def omit_matrix(temp_path, env):
            profile_dir = self.write_required_fixtures(temp_path / "profile-fixtures")
            (profile_dir / "index-attribute-matrix-pg12.json").unlink()
            return profile_dir

        with self.assertRaisesRegex(RuntimeError, "matrix"):
            runner.run_workspace_tests({}, prepare=omit_matrix, run=child,
                                      temp_parent=Path(self.temp.name))

        child.assert_not_called()

    def test_non_regular_fixture_prevents_child_start(self):
        child = mock.Mock()

        def replace_with_symlink(temp_path, env):
            profile_dir = self.write_required_fixtures(temp_path / "profile-fixtures")
            target = profile_dir / "reference-extended-pg12.json"
            target.unlink()
            target.symlink_to("/etc/passwd")
            return profile_dir

        with self.assertRaisesRegex(RuntimeError, "regular private file"):
            runner.run_workspace_tests({}, prepare=replace_with_symlink, run=child,
                                      temp_parent=Path(self.temp.name))

        child.assert_not_called()


if __name__ == "__main__":
    unittest.main()
