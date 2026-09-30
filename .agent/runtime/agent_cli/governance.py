from __future__ import annotations

from pathlib import Path
import subprocess


class GovernanceBaseError(ValueError):
    """Raised when governance evidence is not anchored to a trusted base."""


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *arguments),
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )


def _resolve_commit(root: Path, revision: str) -> str | None:
    result = _git(root, "rev-parse", "--verify", f"{revision}^{{commit}}")
    value = result.stdout.strip()
    return value if result.returncode == 0 and len(value) == 40 else None


def resolve_trusted_base(
    root: str | Path,
    *,
    head: str = "HEAD",
    requested_base: str | None = None,
) -> tuple[str, str]:
    """Return an immutable trusted base and head SHA for governance evidence.

    The trust anchor must come from a remote default/protected branch reference,
    not from a caller-selected commit or repository configuration on the feature
    branch. A requested base is accepted only when it resolves to that anchor.
    """

    repository = Path(root).resolve()
    head_sha = _resolve_commit(repository, head)
    if head_sha is None:
        raise GovernanceBaseError(f"cannot resolve governance head: {head}")

    candidates: list[str] = []
    symbolic = _git(repository, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD")
    if symbolic.returncode == 0 and symbolic.stdout.strip():
        candidates.append(symbolic.stdout.strip())
    candidates.extend(("refs/remotes/origin/main", "refs/remotes/origin/master"))

    trusted_sha = None
    trusted_ref = None
    for candidate in dict.fromkeys(candidates):
        candidate_sha = _resolve_commit(repository, candidate)
        if candidate_sha is None:
            continue
        ancestor = _git(
            repository, "merge-base", "--is-ancestor", candidate_sha, head_sha
        )
        if ancestor.returncode == 0:
            trusted_sha = candidate_sha
            trusted_ref = candidate
            break
    if trusted_sha is None:
        raise GovernanceBaseError(
            "no trusted origin default/base branch is available; fetch origin and "
            "set refs/remotes/origin/HEAD before review"
        )
    if trusted_sha == head_sha:
        raise GovernanceBaseError(
            "trusted governance base must be a proper ancestor distinct from HEAD"
        )
    if requested_base is not None:
        requested_sha = _resolve_commit(repository, requested_base)
        if requested_sha != trusted_sha:
            raise GovernanceBaseError(
                f"requested base must resolve to trusted base {trusted_ref} ({trusted_sha})"
            )
    return trusted_sha, head_sha
