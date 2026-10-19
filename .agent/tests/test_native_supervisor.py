from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from agent_cli.providers import native_supervisor
from agent_cli.providers.native_supervisor import InvocationOutcome, run_native


class NativeSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.stdout = self.root / "stdout.txt"
        self.stderr = self.root / "stderr.txt"

    def tearDown(self):
        self.tempdir.cleanup()

    def run_python(self, source: str, *, timeout: float = 5.0):
        return run_native(
            (sys.executable, "-c", source),
            cwd=self.root,
            stdout_path=self.stdout,
            stderr_path=self.stderr,
            timeout=timeout,
        )

    def assert_group_gone(self, pgid: int):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.02)
        self.fail(f"owned process group {pgid} still exists")

    def test_normal_exit_returns_terminal_identity_and_private_outputs(self):
        outcome = self.run_python(
            "import sys; print('done'); print('warning', file=sys.stderr)"
        )

        self.assertIsInstance(outcome, InvocationOutcome)
        self.assertEqual(outcome.exit_code, 0)
        self.assertGreater(outcome.pid, 0)
        self.assertEqual(outcome.pgid, outcome.pid)
        self.assertIn(str(outcome.pid), outcome.process_start_identity)
        self.assertTrue(outcome.process_start_identity)
        self.assertTrue(outcome.owned_process_group_ended)
        self.assertFalse(outcome.timed_out)
        self.assertLessEqual(outcome.started_at, outcome.finished_at)
        self.assertEqual(self.stdout.read_text(), "done\n")
        self.assertEqual(self.stderr.read_text(), "warning\n")
        self.assertEqual(self.stdout.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.stderr.stat().st_mode & 0o777, 0o600)
        self.assert_group_gone(outcome.pgid)

    def test_timeout_terminates_owned_group_including_descendant(self):
        child_pid_file = self.root / "child.pid"
        source = (
            "import pathlib, subprocess, sys, time; "
            "child = subprocess.Popen([sys.executable, '-c', "
            "'import time; time.sleep(60)']); "
            f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
            "time.sleep(60)"
        )

        outcome = self.run_python(source, timeout=0.2)

        self.assertTrue(outcome.timed_out)
        self.assertEqual(outcome.exit_code, 124)
        self.assertTrue(outcome.owned_process_group_ended)
        self.assertTrue(child_pid_file.exists())
        self.assert_group_gone(outcome.pgid)

    def test_direct_exit_cleans_descendant_before_reporting_terminal(self):
        child_pid_file = self.root / "child.pid"
        source = (
            "import pathlib, subprocess, sys; "
            "child = subprocess.Popen([sys.executable, '-c', "
            "'import time; time.sleep(60)']); "
            f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
            "print(child.pid)"
        )

        outcome = self.run_python(source)

        self.assertEqual(outcome.exit_code, 0)
        self.assertTrue(outcome.owned_process_group_ended)
        self.assert_group_gone(outcome.pgid)

    def test_file_size_limit_bounds_provider_output(self):
        outcome = run_native(
            (sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"),
            cwd=self.root,
            stdout_path=self.stdout,
            stderr_path=self.stderr,
            timeout=5,
            max_output_bytes=128,
        )

        self.assertNotEqual(outcome.exit_code, 0)
        self.assertTrue(outcome.owned_process_group_ended)
        # One byte of headroom makes overflow observable to callers that
        # compare against the maximum; the write is still bounded.
        self.assertEqual(self.stdout.stat().st_size, 129)

    def test_output_exactly_at_limit_is_not_reported_as_overflow(self):
        outcome = run_native(
            (sys.executable, "-c", "import sys; sys.stdout.write('x' * 128)"),
            cwd=self.root,
            stdout_path=self.stdout,
            stderr_path=self.stderr,
            timeout=5,
            max_output_bytes=128,
        )

        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(self.stdout.stat().st_size, 128)

    def test_threaded_launch_is_rejected_before_output_creation(self):
        errors = []

        def invoke():
            try:
                self.run_python("print('should not launch')")
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=invoke)
        worker.start()
        worker.join(timeout=5)

        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], RuntimeError)
        self.assertIn("main thread", str(errors[0]))
        self.assertFalse(self.stdout.exists())
        self.assertFalse(self.stderr.exists())

    def test_output_size_limit_requires_integer_before_output_creation(self):
        with self.assertRaises(TypeError):
            run_native(
                (sys.executable, "-c", "print('should not launch')"),
                cwd=self.root,
                stdout_path=self.stdout,
                stderr_path=self.stderr,
                timeout=5,
                max_output_bytes=128.5,
            )
        self.assertFalse(self.stdout.exists())
        self.assertFalse(self.stderr.exists())

    def test_keyboard_interrupt_cleans_owned_group_then_reraises(self):
        real_popen = native_supervisor.subprocess.Popen
        processes = []

        def tracked_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        with (
            mock.patch.object(
                native_supervisor.subprocess, "Popen", side_effect=tracked_popen
            ),
            mock.patch.object(
                native_supervisor, "_wait_for_exit", side_effect=KeyboardInterrupt
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            self.run_python("import time; time.sleep(60)")

        self.assertEqual(len(processes), 1)
        self.assert_group_gone(processes[0].pid)

    def test_existing_or_symlink_output_is_rejected_before_launch(self):
        marker = self.root / "launched"
        script = (
            "from pathlib import Path; "
            f"Path({str(marker)!r}).write_text('launched')"
        )
        self.stdout.write_text("preserve")
        with self.assertRaises(FileExistsError):
            self.run_python(script)
        self.assertFalse(marker.exists())
        self.assertEqual(self.stdout.read_text(), "preserve")

        self.stdout.unlink()
        target = self.root / "target.txt"
        target.write_text("preserve")
        self.stdout.symlink_to(target)
        with self.assertRaises((FileExistsError, OSError)):
            self.run_python(script)
        self.assertFalse(marker.exists())
        self.assertEqual(target.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
