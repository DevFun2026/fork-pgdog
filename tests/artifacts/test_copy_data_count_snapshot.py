import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_SYNC = ROOT / "applications/pgdog/integration/copy_data/data_sync"
HELPER = DATA_SYNC / "count_snapshot.sh"
RUN = DATA_SYNC / "run.sh"


class CopyDataCountSnapshotTests(unittest.TestCase):
    def _fake_psql(self, directory: Path) -> Path:
        psql = directory / "psql"
        psql.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "args = sys.argv[1:]\n"
            "db = args[args.index('-d') + 1]\n"
            "if os.environ.get('PSQL_FAIL_DB') == db:\n"
            "    print(10)\n"
            "    print('intentional query failure', file=sys.stderr)\n"
            "    raise SystemExit(2)\n"
            "counts = {'pgdog': 17, 'pgdog1': 7, 'pgdog2': 10}\n"
            "print(counts[db])\n",
            encoding="utf-8",
        )
        psql.chmod(0o755)
        return psql

    def _env(self, directory: Path, **extra: str) -> dict[str, str]:
        env = os.environ.copy()
        env["PATH"] = f"{directory}:{env['PATH']}"
        env.update(extra)
        return env

    def test_snapshot_reports_only_quiescent_hop_counts(self) -> None:
        self.assertTrue(HELPER.is_file(), "strict count snapshot helper is missing")
        with tempfile.TemporaryDirectory() as temp:
            bin_dir = Path(temp)
            self._fake_psql(bin_dir)
            result = subprocess.run(
                ["bash", str(HELPER), "pgdog", "pgdog1", "pgdog2", "copy_data.log_actions"],
                capture_output=True,
                text=True,
                env=self._env(bin_dir),
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "DIAG hop=0->2 table=copy_data.log_actions source=17 shard0=7 shard1=10 total=17",
        )
        self.assertNotIn("id", result.stdout.lower())

    def test_query_failure_is_not_substituted_with_zero(self) -> None:
        self.assertTrue(HELPER.is_file(), "strict count snapshot helper is missing")
        with tempfile.TemporaryDirectory() as temp:
            bin_dir = Path(temp)
            self._fake_psql(bin_dir)
            result = subprocess.run(
                ["bash", str(HELPER), "pgdog", "pgdog1", "pgdog2", "copy_data.log_actions"],
                capture_output=True,
                text=True,
                env=self._env(bin_dir, PSQL_FAIL_DB="pgdog2"),
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("intentional query failure", result.stderr)
        self.assertNotIn("shard1=0", result.stdout)
        self.assertNotIn("DIAG ", result.stdout)

    def test_run_places_snapshot_between_cutover_hops(self) -> None:
        script = RUN.read_text(encoding="utf-8")
        first_cutover_command = (
            "schema-sync --from-database source --to-database destination "
            "--publication pgdog --cutover"
        )
        first_cutover = script.index(first_cutover_command)
        snapshot = script.index("count_snapshot.sh")
        second_hop = script.index("# 2 --> 2")
        final_assertion = script.index('if [ "${SRC}" -ne "${DST}" ]; then')
        self.assertLess(first_cutover, snapshot)
        self.assertLess(snapshot, second_hop)
        self.assertGreater(final_assertion, second_hop)


if __name__ == "__main__":
    unittest.main()
