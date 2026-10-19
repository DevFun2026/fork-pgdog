"""Run one native provider process in a supervised, private process group.

The returned identity binds the launch nonce to the initial PID and process
group. It does not prove that a hostile child could not escape the group.
"""

from __future__ import annotations

import os
import resource
import secrets
import signal
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_EXIT_TIMEOUT = 124
# Shell convention for a process terminated by SIGXFSZ.
_EXIT_OUTPUT_LIMIT = 128 + int(signal.SIGXFSZ)
_TERM_GRACE_SECONDS = 0.5
_KILL_GRACE_SECONDS = 0.5
_REAP_GRACE_SECONDS = 0.5


@dataclass(frozen=True)
class InvocationOutcome:
    exit_code: int
    pid: int
    pgid: int
    process_start_identity: str
    owned_process_group_ended: bool
    timed_out: bool
    started_at: str
    finished_at: str


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _set_file_size_limit(max_output_bytes: int) -> None:
    # One byte of headroom makes an overflow observable as a file larger than
    # the allowed maximum; children that ignore SIGXFSZ (CPython does) would
    # otherwise exit 0 with output silently truncated at exactly the limit.
    limit = max_output_bytes + 1
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def _open_private_output(path: Path) -> tuple[int, tuple[int, int]]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    identity = None
    try:
        info = os.fstat(descriptor)
        identity = (info.st_dev, info.st_ino)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"provider output is not a regular file: {path}")
        os.fchmod(descriptor, 0o600)
        assert identity is not None
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        if identity is not None:
            _unlink_our_output(path, identity)
        raise


def _unlink_our_output(path: Path, identity: tuple[int, int]) -> None:
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (info.st_dev, info.st_ino) == identity:
        os.unlink(path)


def _group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_group(pgid: int, signum: int) -> bool:
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return True


def _wait_group_ended(pgid: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _group_exists(pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def _terminate_owned_group(process: subprocess.Popen[bytes]) -> bool:
    """Terminate only the dedicated group and confirm that it disappeared."""
    pgid = process.pid
    if not _group_exists(pgid):
        try:
            process.wait(timeout=_REAP_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        return not _group_exists(pgid)

    if not _signal_group(pgid, signal.SIGTERM):
        return False
    # Reap the direct child before probing the group. Otherwise its zombie can
    # keep the group visible after TERM and make a later group signal fail.
    try:
        process.wait(timeout=_REAP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    ended = _wait_group_ended(pgid, _TERM_GRACE_SECONDS)
    if not ended and _signal_group(pgid, signal.SIGKILL):
        ended = _wait_group_ended(pgid, _KILL_GRACE_SECONDS)
    try:
        process.wait(timeout=_REAP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    return ended and not _group_exists(pgid)


def _wait_for_exit(process: subprocess.Popen[bytes], timeout: float) -> int:
    return process.wait(timeout=timeout)


def run_native(
    argv: tuple[str, ...],
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout: float,
    max_output_bytes: int = 1_000_000,
    env: dict | None = None,
) -> InvocationOutcome:
    """Run a command and report whether its dedicated process group ended.

    Timeout is represented as exit code 124, regardless of the process's
    signal exit status. Existing output paths are never followed or replaced.
    """
    if os.name != "posix":
        raise OSError("native process-group supervision requires POSIX")
    if not argv or any(not isinstance(arg, str) for arg in argv):
        raise ValueError("argv must contain one or more strings")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool):
        raise TypeError("max_output_bytes must be an integer")
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be a positive integer")
    if (
        threading.current_thread() is not threading.main_thread()
        or threading.active_count() > 1
    ):
        raise RuntimeError(
            "native supervision requires the otherwise-idle main thread because "
            "preexec_fn is not thread-safe"
        )

    stdout_path = Path(stdout_path)
    stderr_path = Path(stderr_path)
    opened: list[tuple[Path, int, tuple[int, int]]] = []
    process = None
    launched = False
    try:
        out_fd, out_identity = _open_private_output(stdout_path)
        opened.append((stdout_path, out_fd, out_identity))
        err_fd, err_identity = _open_private_output(stderr_path)
        opened.append((stderr_path, err_fd, err_identity))

        started_at = _timestamp()
        with os.fdopen(out_fd, "wb", buffering=0) as stdout_file:
            opened[0] = (stdout_path, -1, out_identity)
            with os.fdopen(err_fd, "wb", buffering=0) as stderr_file:
                opened[1] = (stderr_path, -1, err_identity)
                process = subprocess.Popen(
                    argv,
                    cwd=cwd,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    shell=False,
                    start_new_session=True,
                    env=env,
                    # RLIMIT_FSIZE must be set before exec; the guard above
                    # enforces this sole-thread use of preexec_fn.
                    preexec_fn=lambda: _set_file_size_limit(max_output_bytes),  # noqa: PLW1509
                )
                launched = True
                pgid = process.pid
                identity = f"{secrets.token_hex(16)}:{process.pid}"
                try:
                    exit_code = _wait_for_exit(process, timeout)
                    timed_out = False
                except subprocess.TimeoutExpired:
                    exit_code = _EXIT_TIMEOUT
                    timed_out = True
                except KeyboardInterrupt:
                    _terminate_owned_group(process)
                    raise
                group_ended = _terminate_owned_group(process)
        if (
            exit_code == 0
            and os.stat(stdout_path, follow_symlinks=False).st_size > max_output_bytes
        ):
            exit_code = _EXIT_OUTPUT_LIMIT
        return InvocationOutcome(
            exit_code=exit_code,
            pid=process.pid,
            pgid=pgid,
            process_start_identity=identity,
            owned_process_group_ended=group_ended,
            timed_out=timed_out,
            started_at=started_at,
            finished_at=_timestamp(),
        )
    except BaseException:
        if process is not None and launched and process.poll() is None:
            _terminate_owned_group(process)
        raise
    finally:
        for path, descriptor, identity in opened:
            if descriptor >= 0:
                os.close(descriptor)
                if not launched:
                    _unlink_our_output(path, identity)
