"""Run workspace nextest with fresh, owned PostgreSQL profile fixtures."""
from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APPLICATION = ROOT / "applications/pgdog"
FIXTURE_MODULE_PATH = ROOT / "scripts/strict_read_fixture.py"
FIXTURE_SPEC = importlib.util.spec_from_file_location("strict_read_fixture", FIXTURE_MODULE_PATH)
if FIXTURE_SPEC is None or FIXTURE_SPEC.loader is None:
    raise RuntimeError("could not load strict-read fixture helpers")
FIXTURE_MODULE = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(FIXTURE_MODULE)

SUPPORTED_MAJORS = FIXTURE_MODULE.SUPPORTED_MAJORS
VARIANT_NAMES = ("core", "pg-trgm", "btree-gist", "both")
NEXTEST_COMMAND = (
    "cargo", "nextest", "run", "--locked", "--workspace", "--no-fail-fast",
    "--test-threads=1",
)


def required_fixture_paths(profile_dir: Path) -> tuple[Path, ...]:
    references = tuple(profile_dir / f"reference-extended-pg{major}.json"
                       for major in SUPPORTED_MAJORS)
    matrices = tuple(profile_dir / f"index-attribute-matrix-pg{major}.json"
                     for major in SUPPORTED_MAJORS)
    variants_dir = profile_dir / "variants"
    variants = tuple(
        variants_dir / f"read-dependency-profile-pg{major}-{name}.json"
        for major in SUPPORTED_MAJORS
        for name in VARIANT_NAMES
    )
    return references + matrices + variants


def validate_owned_fixture_set(profile_dir: Path, temporary_root: Path) -> None:
    expected_dir = (temporary_root / "profile-fixtures").resolve()
    if profile_dir.resolve() != expected_dir:
        raise RuntimeError("owned profile fixture directory escaped its temporary workspace")
    for directory in (profile_dir, profile_dir / "variants"):
        try:
            mode = directory.lstat().st_mode
        except FileNotFoundError as error:
            raise RuntimeError("owned profile fixture matrix or variants directory is missing") from error
        if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) & 0o077:
            raise RuntimeError("owned profile fixture directories must be private directories")

    missing_matrices = [path.name for path in required_fixture_paths(profile_dir)
                        if not path.exists()]
    if missing_matrices:
        raise RuntimeError("owned profile fixture matrix is incomplete: " + ", ".join(missing_matrices))

    for path in required_fixture_paths(profile_dir):
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError as error:
            raise RuntimeError(f"owned fixture is missing: {path.name}") from error
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode) & 0o077:
            raise RuntimeError(f"owned fixture must be a regular private file: {path.name}")


def run_workspace_tests(parent_env: dict[str, str] | None = None, *,
                        prepare=None, run=None, temp_parent: Path | None = None) -> int:
    """Generate private fixtures, run the fixed nextest command, and clean up."""
    env = dict(os.environ if parent_env is None else parent_env)
    prepare_fixtures = prepare or FIXTURE_MODULE.prepare_profile_fixtures
    run_child = run or subprocess.run
    with tempfile.TemporaryDirectory(prefix="pgdog-workspace-tests-", dir=temp_parent) as temp:
        temporary_root = Path(temp)
        temporary_root.chmod(0o700)
        profile_dir = prepare_fixtures(temporary_root, env)
        validate_owned_fixture_set(profile_dir, temporary_root)
        test_env = FIXTURE_MODULE.core_test_environment(env, profile_dir)
        result = run_child(NEXTEST_COMMAND, cwd=APPLICATION, env=test_env, check=False)
        return int(result.returncode)


def main() -> int:
    try:
        return run_workspace_tests()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL: workspace profile fixture setup or nextest execution: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
