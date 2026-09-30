from __future__ import annotations

import os
from pathlib import Path
import tempfile


class PathPolicyError(ValueError):
    """Raised when a path leaves the approved repository boundary."""


def resolve_inside(root: str | Path, candidate: str | Path) -> Path:
    root_path = Path(root).resolve()
    candidate_path = Path(candidate)
    if not candidate_path.is_absolute():
        candidate_path = root_path / candidate_path
    resolved = candidate_path.resolve(strict=False)
    try:
        resolved.relative_to(root_path)
    except ValueError as exc:
        raise PathPolicyError(f"path escapes repository: {candidate}") from exc
    return resolved


def atomic_write(path: str | Path, data: str | bytes) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = data.encode("utf-8") if isinstance(data, str) else data
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
