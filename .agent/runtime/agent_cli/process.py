from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
import subprocess
import time


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def run_command(
    argv: Sequence[str],
    cwd: str | Path,
    timeout: float,
) -> CommandResult:
    if isinstance(argv, (str, bytes)) or not argv:
        raise ValueError("argv must be a non-empty argument sequence")
    arguments = tuple(argv)
    if any(not isinstance(item, str) or not item for item in arguments):
        raise ValueError("argv must contain non-empty strings")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    started = time.monotonic()
    try:
        completed = subprocess.run(
            arguments,
            shell=False,
            text=True,
            capture_output=True,
            timeout=timeout,
            cwd=Path(cwd),
            check=False,
        )
        return CommandResult(
            argv=arguments,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_ms=max(0, round((time.monotonic() - started) * 1000)),
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=arguments,
            exit_code=None,
            stdout=_text(exc.stdout),
            stderr=_text(exc.stderr),
            duration_ms=max(0, round((time.monotonic() - started) * 1000)),
            timed_out=True,
        )
