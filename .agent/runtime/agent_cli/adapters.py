from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import tempfile

from agent_cli.paths import atomic_write
from agent_cli.skills import load_skills


SKILL_DESTINATIONS = (".agents/skills", ".claude/skills")
RETIRED_SKILL_DESTINATIONS = (".gemini/skills",)
FIXED_OUTPUTS = {
    "CLAUDE.md": ".agent/templates/adapters/CLAUDE.md",
    "GEMINI.md": ".agent/templates/adapters/GEMINI.md",
    ".claude/settings.json": ".agent/templates/adapters/claude-settings.json",
    ".agents/hooks.json": ".agent/templates/adapters/agy-hooks.json",
}
MANIFEST_PATH = ".agent/adapters-manifest.json"


class AdapterError(ValueError):
    """Raised when generated adapter trees cannot be updated safely."""


@dataclass(frozen=True)
class AdapterCheck:
    ok: bool
    changed: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RenderedFile:
    data: bytes
    mode: int


def _normalized(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise AdapterError(f"unsafe adapter source: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise AdapterError(f"adapter source must be UTF-8 text: {path}") from exc
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _expected(root: Path) -> dict[str, RenderedFile]:
    canonical = root / ".agent/skills"
    load_skills(canonical)
    files: dict[str, RenderedFile] = {}
    for source in sorted(canonical.rglob("*")):
        if source.is_dir():
            continue
        relative = source.relative_to(canonical).as_posix()
        mode = stat.S_IMODE(source.stat().st_mode)
        payload = _normalized(source)
        for destination in SKILL_DESTINATIONS:
            files[f"{destination}/{relative}"] = RenderedFile(payload, mode)
    for destination, source in FIXED_OUTPUTS.items():
        source_path = root / source
        files[destination] = RenderedFile(_normalized(source_path), 0o644)
    return files


def _manifest(root: Path) -> dict[str, str]:
    path = root / MANIFEST_PATH
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        files = data["files"]
    except (OSError, KeyError, json.JSONDecodeError, TypeError):
        raise AdapterError("invalid adapter ownership manifest")
    if not isinstance(files, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in files.items()
    ):
        raise AdapterError("invalid adapter ownership manifest")
    return dict(files)


def _current_native_files(root: Path) -> set[str]:
    paths: set[str] = set()
    for destination in SKILL_DESTINATIONS:
        tree = root / destination
        if tree.is_symlink():
            raise AdapterError(f"native adapter tree is a symlink: {destination}")
        if tree.is_dir():
            for path in tree.rglob("*"):
                if path.is_symlink():
                    raise AdapterError(
                        f"native adapter path is a symlink: {path.relative_to(root)}"
                    )
                if path.is_file():
                    paths.add(path.relative_to(root).as_posix())
    for destination in FIXED_OUTPUTS:
        path = root / destination
        if path.is_symlink():
            raise AdapterError(f"generated adapter path is a symlink: {destination}")
        if path.is_file():
            paths.add(destination)
    return paths


def _render_and_validate(root: Path, expected: dict[str, RenderedFile]) -> None:
    temp_parent = root / ".agent"
    temp_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".adapters-", dir=temp_parent) as directory:
        rendered = Path(directory)
        for relative, item in expected.items():
            target = rendered / relative
            atomic_write(target, item.data)
            os.chmod(target, item.mode)
        for destination in SKILL_DESTINATIONS:
            load_skills(rendered / destination)
        for destination in (".claude/settings.json", ".agents/hooks.json"):
            json.loads((rendered / destination).read_text(encoding="utf-8"))


def build_adapters(root: Path) -> AdapterCheck:
    repository = root.resolve()
    expected = _expected(repository)
    previous = _manifest(repository)
    current = _current_native_files(repository)
    expected_paths = set(expected)
    unowned = sorted(current - expected_paths - set(previous))
    for relative in sorted((current & expected_paths) - set(previous)):
        if (repository / relative).read_bytes() != expected[relative].data:
            unowned.append(relative)
    if unowned:
        raise AdapterError(f"unowned native adapter file: {unowned[0]}")
    retired = []
    for relative in sorted(set(previous) - expected_paths):
        path = Path(relative)
        allowed = (relative in {".gemini/settings.json", *FIXED_OUTPUTS}
                   or any(relative.startswith(prefix + "/")
                          for prefix in (*SKILL_DESTINATIONS, *RETIRED_SKILL_DESTINATIONS)))
        if path.is_absolute() or ".." in path.parts or not allowed:
            raise AdapterError(f"unsafe retired adapter path: {relative}")
        target = repository / path
        if any(parent.is_symlink() for parent in (target, *target.parents) if parent != repository):
            raise AdapterError(f"unsafe retired adapter symlink: {relative}")
        if target.exists():
            if not target.is_file() or sha256(target.read_bytes()).hexdigest() != previous[relative]:
                raise AdapterError(f"modified retired adapter file: {relative}")
            retired.append(target)
    _render_and_validate(repository, expected)
    for relative, item in expected.items():
        target = repository / relative
        atomic_write(target, item.data)
        os.chmod(target, item.mode)
    for target in retired:
        target.unlink()
    # Retired trees may contain unowned paths/symlinks. Only their validated,
    # manifest-owned files above are removed; never traverse those trees.
    for destination in SKILL_DESTINATIONS:
        tree = repository / destination
        if tree.is_dir():
            for directory in sorted(
                (path for path in tree.rglob("*") if path.is_dir()),
                key=lambda path: len(path.parts),
                reverse=True,
            ):
                try:
                    directory.rmdir()
                except OSError:
                    pass
    hashes = {
        relative: sha256(item.data).hexdigest()
        for relative, item in sorted(expected.items())
    }
    atomic_write(
        repository / MANIFEST_PATH,
        json.dumps({"version": 1, "files": hashes}, sort_keys=True, indent=2) + "\n",
    )
    os.chmod(repository / MANIFEST_PATH, 0o644)
    return AdapterCheck(True, ())


def check_adapters(root: Path) -> AdapterCheck:
    repository = root.resolve()
    expected = _expected(repository)
    current = _current_native_files(repository)
    changed: set[str] = set(current - set(expected))
    for relative, item in expected.items():
        target = repository / relative
        if not target.is_file() or target.is_symlink() or target.read_bytes() != item.data:
            changed.add(relative)
    manifest = _manifest(repository)
    expected_hashes = {
        relative: sha256(item.data).hexdigest() for relative, item in expected.items()
    }
    if manifest != expected_hashes:
        changed.add(MANIFEST_PATH)
    return AdapterCheck(not changed, tuple(sorted(changed)))
