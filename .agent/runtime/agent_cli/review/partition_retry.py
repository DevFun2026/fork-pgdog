"""Immutable package and terminal-receipt validation for partition retries."""

from __future__ import annotations

import json
import re
import shutil
import stat
import uuid
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType

from agent_cli.paths import atomic_write
from agent_cli.providers.base import validated_result
from agent_cli.review.package import (
    REVIEW_INSTRUCTIONS,
    ReviewPackage,
    ReviewPackageBlocked,
    load_package,
    package_usage,
)

_HEX = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_KEYS = frozenset(
    {
        "version", "root_manifest_sha256", "child_manifest_sha256",
        "invocation_id", "pid", "pgid", "process_start_identity", "exit_code",
        "owned_process_group_ended", "status", "prompt_sha256",
        "input_inventory_sha256", "stdout_sha256", "stderr_sha256",
        "audit_sha256", "native_paths", "legacy_audit_sha256",
    }
)


@dataclass(frozen=True)
class RetryPackage:
    """A retry clone plus its separately approved retry manifest."""

    package: ReviewPackage
    child_path: str
    attempt: int
    max_attempts: int
    manifest: object
    manifest_sha256: str
    manifest_path: Path
    receipt_path: Path
    receipt_sha256: str
    transport_identity: object


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def _read_regular(path: Path, *, root: Path | None = None) -> bytes:
    try:
        if root is not None:
            resolved_root = root.resolve(strict=True)
            resolved = path.resolve(strict=True)
            if resolved != resolved_root and resolved_root not in resolved.parents:
                raise ReviewPackageBlocked("terminal evidence escapes repository root")
            current = path
            while current != root and current != current.parent:
                if current.is_symlink():
                    raise ReviewPackageBlocked("terminal evidence path contains a symlink")
                current = current.parent
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ReviewPackageBlocked("terminal evidence must be a regular file")
        return path.read_bytes()
    except OSError as exc:
        raise ReviewPackageBlocked("terminal evidence is missing or unsafe") from exc


def input_inventory(package: ReviewPackage) -> tuple[dict[str, str], str]:
    """Hash the complete input payload, including generated review instructions."""
    files: dict[str, str] = {}
    for path in sorted(package.path.rglob("*")):
        relative = path.relative_to(package.path).as_posix()
        if path.is_symlink():
            raise ReviewPackageBlocked("retry source contains a symlink")
        if path.is_dir():
            continue
        if relative in {"audit.jsonl", "findings.json"}:
            continue
        if not path.is_file():
            raise ReviewPackageBlocked("retry source contains a special file")
        files[relative] = digest(path.read_bytes())
    files["instructions.md"] = digest(REVIEW_INSTRUCTIONS.encode("utf-8"))
    return files, digest(canonical_json(files))


def _safe_native_path(root: Path, reference: object) -> tuple[Path, bytes]:
    if not isinstance(reference, str) or not reference or Path(reference).is_absolute():
        raise ReviewPackageBlocked("terminal receipt has an invalid evidence path")
    relative = Path(reference)
    if ".." in relative.parts or relative.as_posix() != reference:
        raise ReviewPackageBlocked("terminal receipt evidence path is not canonical")
    path = root / relative
    return path, _read_regular(path, root=root)


def validate_terminal_receipt(
    *, part, child, request, receipt_path: Path
) -> tuple[dict[str, object], dict[str, str], dict[str, str]]:
    """Validate supervisor receipt and all native/legacy bytes it names."""
    receipt_path = Path(receipt_path)
    root = Path(request.root)
    raw_receipt = _read_regular(receipt_path, root=root)
    try:
        receipt = json.loads(raw_receipt)
    except (ValueError, UnicodeError) as exc:
        raise ReviewPackageBlocked("terminal receipt is malformed") from exc
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_KEYS:
        raise ReviewPackageBlocked("terminal receipt fields are incomplete or unknown")
    if (
        type(receipt["version"]) is not int
        or receipt["version"] != 1
        or receipt["root_manifest_sha256"] != part.manifest_sha256
        or receipt["child_manifest_sha256"] != child.manifest_sha256
        or receipt["exit_code"] != 0
        or type(receipt["exit_code"]) is not int
        or receipt["owned_process_group_ended"] is not True
        or receipt["status"] != "terminal_incomplete"
        or type(receipt["pid"]) is not int
        or receipt["pid"] <= 0
        or type(receipt["pgid"]) is not int
        or receipt["pgid"] <= 0
        or receipt["pid"] != receipt["pgid"]
        or not isinstance(receipt["invocation_id"], str)
        or not receipt["invocation_id"]
        or not isinstance(receipt["process_start_identity"], str)
        or re.fullmatch(
            rf"[0-9a-f]{{32}}:{receipt['pid']}",
            receipt["process_start_identity"],
        ) is None
    ):
        raise ReviewPackageBlocked("terminal receipt does not prove an ended incomplete invocation")
    for name in (
        "root_manifest_sha256", "child_manifest_sha256", "prompt_sha256",
        "input_inventory_sha256", "stdout_sha256", "stderr_sha256",
        "audit_sha256", "legacy_audit_sha256",
    ):
        if not isinstance(receipt[name], str) or not _HEX.fullmatch(receipt[name]):
            raise ReviewPackageBlocked("terminal receipt contains an invalid digest")

    canonical_audit_path = child.path / "audit.jsonl"
    canonical_audit_raw = _read_regular(canonical_audit_path)
    canonical_audit_sha = digest(canonical_audit_raw)
    if canonical_audit_sha != receipt["legacy_audit_sha256"]:
        raise ReviewPackageBlocked("original child audit changed after terminal receipt")
    try:
        canonical_audit = json.loads(canonical_audit_raw)
    except (ValueError, UnicodeError) as exc:
        raise ReviewPackageBlocked("original child audit is malformed") from exc
    if (
        not isinstance(canonical_audit, dict)
        or canonical_audit.get("status") not in {"incomplete", "review_pending"}
        or canonical_audit.get("manifest_sha256") != child.manifest_sha256
        or canonical_audit.get("provider") != child.manifest.reviewer_provider
        or canonical_audit.get("exit_code") != 0
        or canonical_audit.get("verdict") is not None
        or canonical_audit.get("stdout_sha256") != receipt["stdout_sha256"]
    ):
        raise ReviewPackageBlocked("original child audit is not terminal incomplete")
    findings_path = child.path / "findings.json"
    if findings_path.exists() or findings_path.is_symlink():
        findings = _read_regular(findings_path)
        try:
            payload = json.loads(findings)
        except (ValueError, UnicodeError):
            payload = None
        if payload is not None:
            try:
                valid = validated_result(
                    child.manifest.reviewer_provider, payload, findings.decode("utf-8")
                )
            except (ValueError, TypeError, UnicodeError):
                valid = None
            if valid is not None and valid.status == "completed" and valid.verdict in {"pass", "fail"}:
                raise ReviewPackageBlocked("a valid child verdict cannot be retried")
    else:
        findings = b""

    files, inventory_sha = input_inventory(child)
    if receipt["input_inventory_sha256"] != inventory_sha:
        raise ReviewPackageBlocked("terminal receipt input inventory differs")
    if not isinstance(receipt["native_paths"], dict) or set(receipt["native_paths"]) != {
        "audit", "stdout", "stderr"
    }:
        raise ReviewPackageBlocked("terminal receipt native evidence paths are incomplete")
    native_bytes: dict[str, bytes] = {}
    for name in ("audit", "stdout", "stderr"):
        _path, native_bytes[name] = _safe_native_path(root, receipt["native_paths"][name])
    if (
        digest(native_bytes["audit"]) != receipt["audit_sha256"]
        or digest(native_bytes["stdout"]) != receipt["stdout_sha256"]
        or digest(native_bytes["stderr"]) != receipt["stderr_sha256"]
    ):
        raise ReviewPackageBlocked("terminal receipt evidence checksum differs")
    try:
        native_audit = json.loads(native_bytes["audit"])
    except (ValueError, UnicodeError) as exc:
        raise ReviewPackageBlocked("supervisor audit is malformed") from exc
    if (
        not isinstance(native_audit, dict)
        or native_audit.get("status") != "review_pending"
        or native_audit.get("payload_unchanged") is not True
        or native_audit.get("manifest_identity_unchanged") is not True
        or native_audit.get("root_manifest_sha256") != part.manifest_sha256
        or native_audit.get("package_manifest_sha256") != child.manifest_sha256
        or native_audit.get("stdout_sha256") != receipt["stdout_sha256"]
        or native_audit.get("prompt_sha256") != receipt["prompt_sha256"]
        or native_audit.get("exit_code") != 0
        or native_audit.get("invocation_id") != receipt["invocation_id"]
        or native_audit.get("pid") != receipt["pid"]
        or native_audit.get("pgid") != receipt["pgid"]
        or type(native_audit.get("pid")) is not int
        or type(native_audit.get("pgid")) is not int
        or native_audit.get("process_start_identity") != receipt["process_start_identity"]
        or native_audit.get("owned_process_group_ended") is not True
        or native_audit.get("timed_out") is not False
    ):
        raise ReviewPackageBlocked("supervisor audit does not corroborate terminal receipt")
    receipt_sha = digest(raw_receipt)
    prior = {
        "audit_sha256": canonical_audit_sha,
        "findings_sha256": digest(findings) if findings else None,
        "receipt_sha256": receipt_sha,
        "native_audit_sha256": receipt["audit_sha256"],
        "stdout_sha256": receipt["stdout_sha256"],
        "stderr_sha256": receipt["stderr_sha256"],
    }
    return receipt, files, prior


def preview_retry(
    *, part, request, child_path, terminal_receipt_path, transport_identity,
    attempt: int, max_attempts: int = 2, aggregate_remaining_bytes: int,
    aggregate_remaining_tokens: int, used_receipt_hashes=(), source_package=None,
    logical_child_path=None,
) -> RetryPackage:
    if type(max_attempts) is not int or not 1 <= max_attempts <= 2:
        raise ReviewPackageBlocked("retry limit must be between one and two")
    if type(attempt) is not int or attempt < 1 or attempt > max_attempts:
        raise ReviewPackageBlocked("partition retry limit is exhausted")
    source = source_package or next(
        (item for item in part.children if item.path == Path(child_path)), None
    )
    logical_path = logical_child_path or (source.path.name if source is not None else None)
    child = next((item for item in part.children if item.path.name == logical_path), None)
    if (
        source is None or child is None
        or source.manifest_sha256 != child.manifest_sha256
        or source.manifest.reviewer_provider != child.manifest.reviewer_provider
    ):
        raise ReviewPackageBlocked("retry child is outside the prepared partition")
    if not isinstance(transport_identity, dict):
        raise ReviewPackageBlocked("retry transport identity must be an object")
    identity = dict(transport_identity)
    if set(identity) != {"model", "executable_sha256", "prompt_sha256", "argv_sha256"}:
        raise ReviewPackageBlocked("retry transport identity fields are incomplete or unknown")
    prompt_sha = identity.get("prompt_sha256")
    if not isinstance(prompt_sha, str) or not _HEX.fullmatch(prompt_sha):
        raise ReviewPackageBlocked("retry transport prompt digest is missing")
    if not isinstance(identity.get("model"), str) or not identity["model"]:
        raise ReviewPackageBlocked("retry model identity is missing")
    executable_sha = identity.get("executable_sha256")
    if not isinstance(executable_sha, str) or not _HEX.fullmatch(executable_sha):
        raise ReviewPackageBlocked("retry executable digest is missing")
    argv_sha = identity.get("argv_sha256")
    if not isinstance(argv_sha, str) or not _HEX.fullmatch(argv_sha):
        raise ReviewPackageBlocked("retry argv digest is missing")
    receipt, input_files, prior = validate_terminal_receipt(
        part=part, child=source, request=request,
        receipt_path=Path(terminal_receipt_path),
    )
    if prior["receipt_sha256"] in set(used_receipt_hashes):
        raise ReviewPackageBlocked("terminal receipt has already authorized a retry")
    inventory_sha = digest(canonical_json(input_files))
    if receipt["input_inventory_sha256"] != inventory_sha:
        raise ReviewPackageBlocked("retry source inputs changed")
    usage = package_usage(source)
    size = usage["bytes"]
    tokens = usage["estimated_tokens"]
    if size > request.max_package_bytes or tokens > request.max_estimated_tokens:
        raise ReviewPackageBlocked("retry package exceeds per-invocation budget")
    if size > aggregate_remaining_bytes or tokens > aggregate_remaining_tokens:
        raise ReviewPackageBlocked("retry exceeds remaining aggregate review budget")
    run_root = Path(request.root) / ".agent/.runs"
    clone_path = run_root / f"review-{uuid.uuid4()}"
    clone_path.mkdir(mode=0o700)
    for path in sorted(source.path.rglob("*")):
        relative = path.relative_to(source.path)
        if path.is_symlink():
            shutil.rmtree(clone_path)
            raise ReviewPackageBlocked("retry source contains a symlink")
        if path.is_dir():
            (clone_path / relative).mkdir(parents=True, exist_ok=True, mode=0o700)
        elif relative.as_posix() not in {"audit.jsonl", "findings.json"}:
            target = clone_path / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_write(target, path.read_bytes())
    package = load_package(clone_path, root=request.root)
    if package.manifest_sha256 != child.manifest_sha256:
        shutil.rmtree(clone_path)
        raise ReviewPackageBlocked("retry clone changed the approved child manifest")
    manifest = {
        "version": 1,
        "root_manifest_sha256": part.manifest_sha256,
        "base_sha": part.root_package.manifest.base_sha,
        "head_sha": part.root_package.manifest.head_sha,
        "child_path": child.path.name,
        "child_manifest_sha256": child.manifest_sha256,
        "source_package_path": source.path.name,
        "retry_package_path": clone_path.name,
        "attempt": attempt,
        "max_attempts": max_attempts,
        "input_inventory_sha256": inventory_sha,
        "prior_artifacts": prior,
        "terminal_receipt_path": Path(terminal_receipt_path).resolve().relative_to(
            Path(request.root).resolve()
        ).as_posix(),
        "transport_identity": identity,
    }
    manifest_sha = digest(canonical_json(manifest))
    manifest_path = run_root / f"{clone_path.name}.retry.json"
    atomic_write(manifest_path, canonical_json(manifest) + b"\n")
    frozen_manifest = MappingProxyType(json.loads(canonical_json(manifest)))
    frozen_identity = MappingProxyType(identity)
    return RetryPackage(
        package, child.path.name, attempt, max_attempts, frozen_manifest,
        manifest_sha, manifest_path, Path(terminal_receipt_path),
        prior["receipt_sha256"], frozen_identity,
    )


def retry_manifest_digest(retry: RetryPackage) -> str:
    return digest(canonical_json(dict(retry.manifest)))


def load_retry(*, part, request, manifest_path: Path) -> RetryPackage:
    """Rehydrate a previewed retry package without changing its bytes."""
    run_root = Path(request.root).resolve() / ".agent/.runs"
    manifest_path = Path(manifest_path)
    if (
        manifest_path.is_symlink()
        or manifest_path.resolve().parent != run_root.resolve()
        or not manifest_path.name.endswith(".retry.json")
    ):
        raise ReviewPackageBlocked("retry manifest path is outside the run directory")
    raw = _read_regular(manifest_path, root=Path(request.root))
    try:
        manifest = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ReviewPackageBlocked("retry manifest is malformed") from exc
    if not isinstance(manifest, dict) or digest(canonical_json(manifest)) != digest(raw.rstrip(b"\n")):
        raise ReviewPackageBlocked("retry manifest is not canonical")
    expected_keys = {
        "version", "root_manifest_sha256", "base_sha", "head_sha",
        "child_path", "child_manifest_sha256", "source_package_path",
        "retry_package_path", "attempt", "max_attempts",
        "input_inventory_sha256", "prior_artifacts", "terminal_receipt_path",
        "transport_identity",
    }
    if set(manifest) != expected_keys:
        raise ReviewPackageBlocked("retry manifest fields are incomplete or unknown")
    manifest_sha = digest(canonical_json(manifest))
    clone_name = manifest.get("retry_package_path")
    child_name = manifest.get("child_path")
    child = next((item for item in part.children if item.path.name == child_name), None)
    if (
        manifest.get("version") != 1
        or manifest.get("root_manifest_sha256") != part.manifest_sha256
        or manifest.get("base_sha") != part.root_package.manifest.base_sha
        or manifest.get("head_sha") != part.root_package.manifest.head_sha
        or child is None
        or manifest.get("child_manifest_sha256") != child.manifest_sha256
        or not isinstance(clone_name, str)
        or Path(clone_name).name != clone_name
        or manifest_path.name != f"{clone_name}.retry.json"
    ):
        raise ReviewPackageBlocked("retry manifest does not match partition identity")
    package = load_package(run_root / clone_name, root=Path(request.root))
    if package.manifest_sha256 != child.manifest_sha256:
        raise ReviewPackageBlocked("retry clone differs from approved child inputs")
    source_name = manifest.get("source_package_path")
    if not isinstance(source_name, str) or Path(source_name).name != source_name:
        raise ReviewPackageBlocked("retry source package path is invalid")
    source = (
        child if source_name == child.path.name
        else load_package(run_root / source_name, root=Path(request.root))
    )
    if source.manifest_sha256 != child.manifest_sha256:
        raise ReviewPackageBlocked("retry source package differs from partition child")
    receipt_relative = manifest.get("terminal_receipt_path")
    receipt_path, _receipt_bytes = _safe_native_path(Path(request.root), receipt_relative)
    receipt, input_files, prior = validate_terminal_receipt(
        part=part, child=source, request=request, receipt_path=receipt_path
    )
    if (
        prior != manifest.get("prior_artifacts")
        or receipt.get("input_inventory_sha256") != manifest.get("input_inventory_sha256")
        or digest(canonical_json(input_files)) != manifest.get("input_inventory_sha256")
    ):
        raise ReviewPackageBlocked("retry prior evidence changed after preview")
    identity = manifest.get("transport_identity")
    if (
        not isinstance(identity, dict)
        or set(identity) != {
            "model", "executable_sha256", "prompt_sha256", "argv_sha256"
        }
        or not isinstance(identity.get("model"), str)
        or not identity["model"]
        or any(
            not isinstance(identity.get(key), str)
            or not _HEX.fullmatch(identity[key])
            for key in ("executable_sha256", "prompt_sha256", "argv_sha256")
        )
    ):
        raise ReviewPackageBlocked("retry transport identity is malformed")
    if (
        type(manifest["attempt"]) is not int
        or type(manifest["max_attempts"]) is not int
        or not 1 <= manifest["max_attempts"] <= 2
        or not 1 <= manifest["attempt"] <= manifest["max_attempts"]
    ):
        raise ReviewPackageBlocked("retry attempt limit is invalid")
    return RetryPackage(
        package=package,
        child_path=child_name,
        attempt=manifest.get("attempt"),
        max_attempts=manifest.get("max_attempts"),
        manifest=MappingProxyType(manifest),
        manifest_sha256=manifest_sha,
        manifest_path=manifest_path,
        receipt_path=receipt_path,
        receipt_sha256=prior["receipt_sha256"],
        transport_identity=MappingProxyType(identity),
    )
