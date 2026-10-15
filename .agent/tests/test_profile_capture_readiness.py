import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "profile_capture_readiness", ROOT / "scripts/capture_read_dependency_reference.py"
)
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


class ProfileCaptureReadinessTests(unittest.TestCase):
    def exercise_capture(self, *, final_server_starts):
        state = {"final_ready": False, "probes": 0, "cleanup": 0, "ddl": 0}

        def command(argv, **kwargs):
            if argv[:3] == ["docker", "image", "inspect"]:
                return json.dumps([{"Os": "linux", "Architecture": "arm64"}])
            if argv[:2] == ["docker", "run"]:
                self.assertIn("none", argv)
                return "owned-container\n"
            self.fail(f"unexpected command: {argv}")

        def process(argv, **kwargs):
            if "pg_isready" in argv:
                state["probes"] += 1
                # The entrypoint's temporary server accepts socket connections
                # but cannot satisfy a TCP loopback readiness check.
                uses_tcp = "-h" in argv and argv[argv.index("-h") + 1] == "127.0.0.1"
                return mock.Mock(returncode=0 if state["final_ready"] or not uses_tcp else 1)
            self.assertEqual(argv, ["docker", "rm", "--force", "owned-container"])
            state["cleanup"] += 1
            return mock.Mock(returncode=0)

        def pause(_seconds):
            state["final_ready"] = final_server_starts

        def ddl(container, statement):
            self.assertTrue(state["final_ready"], "DDL reached temporary init server")
            self.assertEqual(container, "owned-container")
            self.assertEqual(statement, capture.DDL)
            state["ddl"] += 1
            return ""

        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(capture, "pinned_image", return_value="postgres:12@sha256:" + "a" * 64), \
                mock.patch.object(capture, "run", side_effect=command), \
                mock.patch.object(capture.subprocess, "run", side_effect=process), \
                mock.patch.object(capture.time, "sleep", side_effect=pause), \
                mock.patch.object(capture, "sql", side_effect=ddl), \
                mock.patch.object(capture, "capture_index_attribute_matrix", return_value={}) as matrix:
            if final_server_starts:
                capture.capture_major(12, Path(temp), matrix_only=True)
                self.assertEqual(state["probes"], 2)
                self.assertEqual(state["ddl"], 1)
                matrix.assert_called_once()
            else:
                with self.assertRaisesRegex(RuntimeError, "did not become ready"):
                    capture.capture_major(12, Path(temp), matrix_only=True)
                self.assertEqual(state["probes"], 120)
                self.assertEqual(state["ddl"], 0)
                matrix.assert_not_called()
        self.assertEqual(state["cleanup"], 1)

    def test_temporary_socket_server_does_not_allow_catalog_capture(self):
        self.exercise_capture(final_server_starts=True)

    def test_timeout_prevents_catalog_capture_and_cleans_container(self):
        self.exercise_capture(final_server_starts=False)


if __name__ == "__main__":
    unittest.main()
