from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path

from agent_cli.paths import atomic_write
from agent_cli.review.models import ManifestFile, ReviewManifest, ReviewPackageRequest
from agent_cli.review.package import (
    REVIEW_INSTRUCTIONS,
    ReviewPackage,
    ReviewPackageBlocked,
    _manifest_hash,
    build_package,
    load_package,
    package_usage,
)

REGISTRY_PATH = (
    "applications/pgdog/pgdog/src/backend/schema/read_policy/registry-pg18.json"
)
_ALLOWED_OUTPUTS = frozenset({"audit.jsonl", "findings.json"})
_ROOT_ALLOWED_OUTPUTS = _ALLOWED_OUTPUTS | frozenset({"partition-results.json"})


@dataclass(frozen=True)
class PartitionedReview:
    root_package: ReviewPackage
    manifest: dict[str, object]
    manifest_sha256: str
    children: tuple[ReviewPackage, ...]


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _positive_limits(*values: int) -> bool:
    return all(type(value) is int and value > 0 for value in values)


def _diff_sections(diff: bytes) -> list[tuple[int, int, bytes]]:
    starts = [match.start() for match in re.finditer(rb"(?m)^diff --git ", diff)]
    if not starts or starts[0] != 0:
        raise ReviewPackageBlocked("projected diff has an unsupported patch boundary")
    return [
        (
            start,
            starts[index + 1] if index + 1 < len(starts) else len(diff),
            diff[start : starts[index + 1] if index + 1 < len(starts) else len(diff)],
        )
        for index, start in enumerate(starts)
    ]


def _skip_ws(text: str, position: int) -> int:
    while position < len(text) and text[position] in " \t\r\n":
        position += 1
    return position


def _object_members(text: str, start: int, decoder: json.JSONDecoder):
    position = _skip_ws(text, start)
    if position >= len(text) or text[position] != "{":
        raise ReviewPackageBlocked(
            "pinned PG18 registry has an unsupported JSON structure"
        )
    position += 1
    members = []
    while True:
        position = _skip_ws(text, position)
        if position < len(text) and text[position] == "}":
            return members
        try:
            key, key_end = decoder.raw_decode(text, position)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ReviewPackageBlocked("pinned PG18 registry has invalid JSON") from exc
        if not isinstance(key, str):
            raise ReviewPackageBlocked("pinned PG18 registry object key is invalid")
        position = _skip_ws(text, key_end)
        if position >= len(text) or text[position] != ":":
            raise ReviewPackageBlocked("pinned PG18 registry has invalid JSON")
        value_start = _skip_ws(text, position + 1)
        try:
            value, value_end = decoder.raw_decode(text, value_start)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ReviewPackageBlocked("pinned PG18 registry has invalid JSON") from exc
        members.append((key, value_start, value_end, value))
        position = _skip_ws(text, value_end)
        if position < len(text) and text[position] == ",":
            position += 1
            continue
        if position < len(text) and text[position] == "}":
            return members
        raise ReviewPackageBlocked("pinned PG18 registry has invalid JSON")


def _array_items(text: str, start: int, decoder: json.JSONDecoder):
    position = _skip_ws(text, start)
    if position >= len(text) or text[position] != "[":
        raise ReviewPackageBlocked("pinned PG18 registry tables must be arrays")
    position += 1
    items = []
    while True:
        position = _skip_ws(text, position)
        if position < len(text) and text[position] == "]":
            return items
        try:
            value, end = decoder.raw_decode(text, position)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ReviewPackageBlocked("pinned PG18 registry has invalid JSON") from exc
        if not isinstance(value, dict):
            raise ReviewPackageBlocked(
                "pinned PG18 registry records must be JSON objects"
            )
        items.append((position, end))
        position = _skip_ws(text, end)
        if position < len(text) and text[position] == ",":
            position += 1
            continue
        if position < len(text) and text[position] == "]":
            return items
        raise ReviewPackageBlocked("pinned PG18 registry has invalid JSON")


def _registry_records(section: bytes, section_start: int) -> list[dict[str, object]]:
    if (
        b"new file mode " not in section
        or b"\n--- /dev/null\n" not in section
        or f"\n+++ b/{REGISTRY_PATH}\n".encode() not in section
    ):
        raise ReviewPackageBlocked(
            "only a newly added pinned PG18 registry can be record-split"
        )
    lines = section.splitlines(keepends=True)
    offset = section_start
    json_line = None
    for line in lines:
        if line.startswith(b"+") and not line.startswith(b"+++"):
            if json_line is not None:
                raise ReviewPackageBlocked(
                    "pinned PG18 registry format is unsupported for record splitting"
                )
            json_line = (offset + 1, line[1:].rstrip(b"\r\n"))
        offset += len(line)
    if json_line is None:
        raise ReviewPackageBlocked("pinned PG18 registry addition is missing")
    json_start, raw_json = json_line
    try:
        text = raw_json.decode("utf-8", errors="strict")
        decoder = json.JSONDecoder()
        value, end = decoder.raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReviewPackageBlocked(
            "pinned PG18 registry format is unsupported"
        ) from exc
    if end != len(text) or not isinstance(value, dict):
        raise ReviewPackageBlocked("pinned PG18 registry format is unsupported")
    top_members = _object_members(text, 0, decoder)
    tables_member = next(
        (member for member in top_members if member[0] == "tables"), None
    )
    if tables_member is None or not isinstance(tables_member[3], dict):
        raise ReviewPackageBlocked("pinned PG18 registry has no tables object")

    # Build a linear character-to-byte map so offsets remain exact for UTF-8 data.
    byte_offsets = [0]
    for character in text:
        byte_offsets.append(byte_offsets[-1] + len(character.encode("utf-8")))
    records: list[dict[str, object]] = []
    for table, table_start, _, table_value in _object_members(
        text, tables_member[1], decoder
    ):
        if not isinstance(table_value, list):
            raise ReviewPackageBlocked("pinned PG18 registry tables must be arrays")
        for row, (record_start, record_end) in enumerate(
            _array_items(text, table_start, decoder)
        ):
            records.append(
                {
                    "start": json_start + byte_offsets[record_start],
                    "end": json_start + byte_offsets[record_end],
                    "table": table,
                    "row": row,
                }
            )
    if not records:
        raise ReviewPackageBlocked("pinned PG18 registry contains no complete records")
    records.sort(key=lambda record: (record["start"], record["end"]))
    return records


def _compact_record_spans(records: list[dict[str, object]]) -> list[dict[str, object]]:
    spans: list[dict[str, object]] = []
    for record in records:
        table = str(record["table"])
        row = int(record["row"])
        start = int(record["start"])
        end = int(record["end"])
        if spans and spans[-1]["table"] == table and spans[-1]["last_row"] + 1 == row:
            spans[-1]["last_row"] = row
            spans[-1]["count"] += 1
            spans[-1]["end"] = end
        else:
            spans.append(
                {
                    "table": table,
                    "first_row": row,
                    "last_row": row,
                    "count": 1,
                    "start": start,
                    "end": end,
                }
            )
    return spans


def _registry_fragments(
    section: bytes, start: int, end: int, target_bytes: int
) -> list[dict[str, object]]:
    records = _registry_records(section, start)
    groups: list[list[dict[str, object]]] = []
    current: list[dict[str, object]] = []
    cursor = start
    for record in records:
        candidate_end = int(record["end"])
        candidate_size = candidate_end - cursor
        if candidate_size > target_bytes:
            if not current:
                raise ReviewPackageBlocked(
                    f"an indivisible registry record exceeds the shard target ({candidate_size} > {target_bytes})"
                )
            groups.append(current)
            cursor = int(current[-1]["end"])
            current = []
            candidate_size = candidate_end - cursor
            if candidate_size > target_bytes:
                raise ReviewPackageBlocked(
                    "an indivisible registry record exceeds the shard target"
                )
        current.append(record)
    if current:
        groups.append(current)
    while groups:
        last_start = start if len(groups) == 1 else int(groups[-2][-1]["end"])
        if end - last_start <= target_bytes:
            break
        if len(groups[-1]) == 1:
            raise ReviewPackageBlocked(
                "pinned registry framing exceeds the shard target"
            )
        moved = groups[-1].pop()
        groups.append([moved])
    fragments = []
    cursor = start
    for index, group in enumerate(groups):
        fragment_end = end if index == len(groups) - 1 else int(group[-1]["end"])
        if fragment_end - cursor > target_bytes:
            raise ReviewPackageBlocked(
                f"pinned registry framing exceeds the shard target ({fragment_end - cursor} > {target_bytes})"
            )
        fragments.append(
            {
                "start": cursor,
                "end": fragment_end,
                "kind": "registry-records",
                "path": REGISTRY_PATH,
                "records": _compact_record_spans(group),
                "record_start": int(group[0]["start"]),
                "record_end": int(group[-1]["end"]),
            }
        )
        cursor = fragment_end
    if fragments:
        last_record_end = int(records[-1]["end"])
        # Closing JSON and patch framing belongs to the last range and is byte-bound.
        if end - last_record_end > target_bytes:
            raise ReviewPackageBlocked(
                f"pinned registry trailing framing exceeds the shard target ({end - last_record_end} > {target_bytes})"
            )
        if cursor != end:
            raise ReviewPackageBlocked(
                "pinned registry ranges do not cover the source patch"
            )
    return fragments


def _atoms(diff: bytes, target_bytes: int) -> list[dict[str, object]]:
    atoms = []
    for start, end, section in _diff_sections(diff):
        if end - start <= target_bytes:
            atoms.append({"start": start, "end": end, "kind": "patch"})
        elif f"a/{REGISTRY_PATH} b/{REGISTRY_PATH}".encode() in section:
            atoms.extend(_registry_fragments(section, start, end, target_bytes))
        else:
            raise ReviewPackageBlocked(
                "ordinary changed-file patch is indivisible and exceeds the shard target"
            )
    if not atoms or int(atoms[0]["start"]) != 0 or int(atoms[-1]["end"]) != len(diff):
        raise ReviewPackageBlocked(
            "deterministic shards do not cover the projected diff bytes"
        )
    return atoms


def _group_atoms(
    atoms: list[dict[str, object]], target_bytes: int
) -> list[list[dict[str, object]]]:
    groups: list[list[dict[str, object]]] = []
    current: list[dict[str, object]] = []
    current_start = current_end = 0
    for atom in atoms:
        start, end = int(atom["start"]), int(atom["end"])
        if end <= start or (current and start != current_end):
            raise ReviewPackageBlocked("partition byte ranges have a gap or overlap")
        if current and end - current_start > target_bytes:
            groups.append(current)
            current = []
        if not current:
            current_start = start
        current.append(atom)
        current_end = end
        if current_end - current_start > target_bytes:
            raise ReviewPackageBlocked(
                "indivisible patch fragment exceeds the shard target"
            )
    if current:
        groups.append(current)
    if not groups:
        raise ReviewPackageBlocked(
            "partition review requires a non-empty projected diff"
        )
    return groups


def _manifest_usage(
    manifest: ReviewManifest, diff_bytes: bytes, package_path: Path
) -> ReviewManifest:
    payload_bytes = (
        len(diff_bytes)
        + sum(item.size for item in manifest.files)
        + (package_path / "requirements.md").stat().st_size
        + (package_path / "verification.json").stat().st_size
        + (package_path / "policy.md").stat().st_size
        + (package_path / "review-schema.json").stat().st_size
    )
    updated = replace(manifest, total_bytes=payload_bytes, estimated_tokens=0)
    for _ in range(10):
        size = (
            payload_bytes
            + len(_manifest_hash(updated)[1])
            + 1
            + len(REVIEW_INSTRUCTIONS.encode("utf-8"))
        )
        next_value = replace(
            updated, total_bytes=size, estimated_tokens=(size + 2) // 3
        )
        if next_value == updated:
            return updated
        updated = next_value
    raise ReviewPackageBlocked("child manifest budget did not stabilize")


def _build_child(
    root_package: ReviewPackage,
    request: ReviewPackageRequest,
    context_paths: tuple[str, ...],
    diff_bytes: bytes,
    ranges: list[dict[str, object]],
) -> tuple[ReviewPackage, dict[str, object]]:
    root = request.root.resolve()
    run_root = root / ".agent/.runs"
    child_path = run_root / f"review-{uuid.uuid4()}"
    child_path.mkdir(mode=0o700)
    (child_path / "context").mkdir(mode=0o700)
    for name in (
        "requirements.md",
        "verification.json",
        "policy.md",
        "review-schema.json",
    ):
        atomic_write(child_path / name, (root_package.path / name).read_bytes())
    root_files = {item.path: item for item in root_package.manifest.files}
    selected_files = []
    for path in context_paths:
        item = root_files.get(path)
        if item is None:
            raise ReviewPackageBlocked("child context is not bound by the root package")
        content = (root_package.path / "context" / item.path).read_bytes()
        target = child_path / "context" / item.path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(target, content)
        selected_files.append(item)
    atomic_write(child_path / "diff.patch", diff_bytes)
    if any(item.path == "partition-scope.json" for item in root_package.manifest.files):
        raise ReviewPackageBlocked(
            "partition-scope.json is reserved for shard inventory binding"
        )
    scope_payload = {
        "version": 1,
        "root_manifest_sha256": root_package.manifest_sha256,
        "base_sha": root_package.manifest.base_sha,
        "head_sha": root_package.manifest.head_sha,
        "author_provider": root_package.manifest.author_provider,
        "reviewer_provider": root_package.manifest.reviewer_provider,
        "scope": list(root_package.manifest.scope),
        "child_context_paths": list(context_paths),
        "full_diff_sha256": root_package.manifest.full_diff_sha256,
        "projected_diff_sha256": root_package.manifest.diff_sha256,
        "omitted_generated": [
            list(pair) for pair in root_package.manifest.omitted_generated
        ],
        "verified_renames": root_package.manifest.verified_renames,
        "ranges": ranges,
        "review_guidance": (
            "This is one complete byte range from a larger independent review. "
            "The parent manifest binds every range to the full projected diff and full Git diff. "
            "Use the complete scope inventory for cross-file reasoning; report local findings "
            "with paths and evidence, and do not infer clearance from this shard alone."
        ),
    }
    scope_bytes = _canonical_json(scope_payload) + b"\n"
    scope_file = child_path / "context" / "partition-scope.json"
    atomic_write(scope_file, scope_bytes)
    child_files = tuple(selected_files) + (
        ManifestFile(
            "partition-scope.json", sha256(scope_bytes).hexdigest(), len(scope_bytes)
        ),
    )
    manifest = replace(
        root_package.manifest,
        diff_sha256=sha256(diff_bytes).hexdigest(),
        files=child_files,
        total_bytes=0,
        full_diff_sha256=None,
        omitted_generated=(),
        estimated_tokens=0,
        verified_renames=None,
    )
    manifest = _manifest_usage(manifest, diff_bytes, child_path)
    manifest_sha256, manifest_payload = _manifest_hash(manifest)
    atomic_write(child_path / "manifest.json", manifest_payload + b"\n")
    child = load_package(child_path, root=root)
    entry = {
        "path": child_path.name,
        "manifest_sha256": manifest_sha256,
        "diff_sha256": manifest.diff_sha256,
        "ranges": ranges,
        "payload_bytes": len(diff_bytes),
    }
    return child, entry


def _expected_inventory(
    package_path: Path, manifest: ReviewManifest, *, root: bool
) -> None:
    expected_files = {
        "diff.patch",
        "manifest.json",
        "requirements.md",
        "verification.json",
        "policy.md",
        "review-schema.json",
        *(f"context/{item.path}" for item in manifest.files),
    }
    if root:
        expected_files.add("partition.json")
        allowed_outputs = _ROOT_ALLOWED_OUTPUTS
    else:
        allowed_outputs = _ALLOWED_OUTPUTS
    expected_dirs = {"context"}
    for item in manifest.files:
        parts = Path("context") / item.path
        for parent in parts.parents:
            if parent == Path("."):
                break
            expected_dirs.add(parent.as_posix())
    actual_files: set[str] = set()
    actual_dirs: set[str] = set()
    for current, dirs, files in os.walk(package_path, followlinks=False):
        current_path = Path(current)
        for name in list(dirs):
            candidate = current_path / name
            relative = candidate.relative_to(package_path).as_posix()
            if candidate.is_symlink():
                raise ReviewPackageBlocked("partition package contains a symlink")
            actual_dirs.add(relative)
        for name in files:
            candidate = current_path / name
            relative = candidate.relative_to(package_path).as_posix()
            if candidate.is_symlink() or not candidate.is_file():
                raise ReviewPackageBlocked("partition package contains an unsafe file")
            actual_files.add(relative)
    extras = actual_files - expected_files - allowed_outputs
    missing = expected_files - actual_files
    if extras:
        raise ReviewPackageBlocked(
            f"partition package contains unlisted file: {min(extras)}"
        )
    if missing:
        raise ReviewPackageBlocked(
            f"partition package is missing required file: {min(missing)}"
        )
    if actual_dirs != expected_dirs:
        raise ReviewPackageBlocked(
            "partition package contains unlisted directory content"
        )


def partition_usage(partition: PartitionedReview) -> dict[str, int]:
    root_manifest_path = partition.root_package.path / "manifest.json"
    root_bytes = root_manifest_path.stat().st_size
    children_bytes = sum(
        int(package_usage(child)["bytes"]) for child in partition.children
    )
    manifest_path = partition.root_package.path / "partition.json"
    manifest_bytes = (
        manifest_path.stat().st_size
        if manifest_path.is_file()
        else len(_canonical_json(partition.manifest)) + 1
    )
    limits = partition.manifest.get("limits", {})
    reserved = int(limits.get("target_bytes", 0)) if isinstance(limits, dict) else 0
    total_bytes = root_bytes + children_bytes + manifest_bytes + reserved
    child_tokens = sum(
        int(package_usage(child)["estimated_tokens"]) for child in partition.children
    )
    estimated_tokens = (
        child_tokens
        + (root_bytes + 2) // 3
        + (manifest_bytes + 2) // 3
        + (reserved + 2) // 3
    )
    return {
        "bytes": total_bytes,
        "estimated_tokens": estimated_tokens,
        "root_bytes": root_bytes,
        "children_bytes": children_bytes,
        "partition_manifest_bytes": manifest_bytes,
        "integration_reserved_bytes": reserved,
        "child_count": len(partition.children),
    }


def build_partition(
    request: ReviewPackageRequest,
    *,
    max_aggregate_bytes: int = 2_500_000,
    max_aggregate_tokens: int = 800_000,
    target_bytes: int = 250_000,
    integration_context_paths: tuple[str, ...] = (),
) -> PartitionedReview:
    if not _positive_limits(max_aggregate_bytes, max_aggregate_tokens, target_bytes):
        raise ReviewPackageBlocked(
            "partition byte and token limits must be positive integers"
        )
    integration_paths = tuple(sorted(set(integration_context_paths)))
    if not integration_paths:
        raise ReviewPackageBlocked(
            "partition review requires explicit integration context"
        )
    invocation_byte_limit = min(
        target_bytes,
        request.max_package_bytes,
        request.max_estimated_tokens * 3,
    )
    if invocation_byte_limit <= 0:
        raise ReviewPackageBlocked("per-invocation review budget must be positive")
    root_request = replace(
        request,
        context_paths=tuple(
            sorted(set(request.context_paths) | set(integration_paths))
        ),
        max_package_bytes=max_aggregate_bytes,
        max_estimated_tokens=max_aggregate_tokens,
    )
    root_package = build_package(root_request)
    generated_sources = dict(root_package.manifest.omitted_generated)
    child_context_paths = tuple(
        sorted({generated_sources.get(path, path) for path in request.context_paths})
    )
    if not set(child_context_paths) <= {
        item.path for item in root_package.manifest.files
    }:
        raise ReviewPackageBlocked(
            "shared child context is not present in the root package"
        )
    atom_budget = invocation_byte_limit
    children: list[ReviewPackage] = []
    entries: list[dict[str, object]] = []
    for _attempt in range(20):
        groups = _group_atoms(_atoms(root_package.diff_bytes, atom_budget), atom_budget)
        children = []
        entries = []
        for group in groups:
            start, end = int(group[0]["start"]), int(group[-1]["end"])
            ranges = [dict(atom) for atom in group]
            child, entry = _build_child(
                root_package,
                root_request,
                child_context_paths,
                root_package.diff_bytes[start:end],
                ranges,
            )
            children.append(child)
            entries.append(entry)
        overages = []
        for child in children:
            usage = package_usage(child)
            overages.append(
                max(
                    int(usage["bytes"]) - invocation_byte_limit,
                    (int(usage["estimated_tokens"]) - request.max_estimated_tokens) * 3,
                    0,
                )
            )
        excess = max(overages, default=0)
        if excess == 0:
            break
        for child in children:
            shutil.rmtree(child.path)
        children = []
        entries = []
        atom_budget -= max(excess, 1)
        if atom_budget <= 0:
            raise ReviewPackageBlocked(
                "package metadata and context exceed the per-invocation review budget"
            )
    else:
        raise ReviewPackageBlocked(
            "partition sizing did not converge within its bounded retries"
        )

    manifest: dict[str, object] = {
        "version": 1,
        "root_package_path": root_package.path.name,
        "root_manifest_sha256": root_package.manifest_sha256,
        "base_sha": root_package.manifest.base_sha,
        "head_sha": root_package.manifest.head_sha,
        "author_provider": root_package.manifest.author_provider,
        "reviewer_provider": root_package.manifest.reviewer_provider,
        "scope": list(root_package.manifest.scope),
        "projected_diff_sha256": root_package.manifest.diff_sha256,
        "full_diff_sha256": root_package.manifest.full_diff_sha256,
        "integration_context_paths": list(integration_paths),
        "child_context_paths": list(child_context_paths),
        "limits": {
            "max_aggregate_bytes": max_aggregate_bytes,
            "max_aggregate_tokens": max_aggregate_tokens,
            "target_bytes": target_bytes,
            "atom_budget": atom_budget,
            "per_invocation_max_bytes": request.max_package_bytes,
            "per_invocation_max_tokens": request.max_estimated_tokens,
        },
        "children": entries,
        "aggregate_usage": {"bytes": 0, "estimated_tokens": 0},
    }
    for _ in range(10):
        payload_size = len(_canonical_json(manifest)) + 1
        root_bytes = (root_package.path / "manifest.json").stat().st_size
        children_bytes = sum(int(package_usage(child)["bytes"]) for child in children)
        aggregate_bytes = root_bytes + children_bytes + payload_size + target_bytes
        aggregate_tokens = (
            sum(int(package_usage(child)["estimated_tokens"]) for child in children)
            + (root_bytes + 2) // 3
            + (payload_size + 2) // 3
            + (target_bytes + 2) // 3
        )
        updated = dict(manifest)
        updated["aggregate_usage"] = {
            "bytes": aggregate_bytes,
            "estimated_tokens": aggregate_tokens,
        }
        if updated == manifest:
            break
        manifest = updated
    else:
        raise ReviewPackageBlocked("partition aggregate budget did not stabilize")
    manifest_sha256 = sha256(_canonical_json(manifest)).hexdigest()
    atomic_write(
        root_package.path / "partition.json", _canonical_json(manifest) + b"\n"
    )
    result = PartitionedReview(root_package, manifest, manifest_sha256, tuple(children))
    usage = partition_usage(result)
    if (
        usage["bytes"] > max_aggregate_bytes
        or usage["estimated_tokens"] > max_aggregate_tokens
    ):
        raise ReviewPackageBlocked(
            "partition review exceeds the aggregate byte or token budget"
        )
    # Persist the exact measured aggregate counts after metadata has been written.
    if manifest["aggregate_usage"] != {
        "bytes": usage["bytes"],
        "estimated_tokens": usage["estimated_tokens"],
    }:
        manifest = dict(manifest)
        manifest["aggregate_usage"] = {
            "bytes": usage["bytes"],
            "estimated_tokens": usage["estimated_tokens"],
        }
        manifest_sha256 = sha256(_canonical_json(manifest)).hexdigest()
        atomic_write(
            root_package.path / "partition.json", _canonical_json(manifest) + b"\n"
        )
        result = PartitionedReview(
            root_package, manifest, manifest_sha256, tuple(children)
        )
    return load_partition(root_package.path, root=request.root)


def load_partition(path: Path, *, root: Path) -> PartitionedReview:
    root = root.resolve()
    if Path(path).is_symlink():
        raise ReviewPackageBlocked("partition package path may not be a symlink")
    root_package = load_package(path, root=root)
    _expected_inventory(root_package.path, root_package.manifest, root=True)
    manifest_path = root_package.path / "partition.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ReviewPackageBlocked("partition manifest is missing or unsafe")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or manifest.get("version") != 1:
            raise ValueError("unsupported partition manifest")
        children_raw = manifest["children"]
        limits = manifest["limits"]
        integration_paths = manifest["integration_context_paths"]
        child_context_paths = manifest["child_context_paths"]
        if not isinstance(children_raw, list) or not children_raw:
            raise ValueError("partition children are missing")
        if not isinstance(limits, dict) or not _positive_limits(
            limits.get("max_aggregate_bytes"),
            limits.get("max_aggregate_tokens"),
            limits.get("target_bytes"),
            limits.get("atom_budget"),
            limits.get("per_invocation_max_bytes"),
            limits.get("per_invocation_max_tokens"),
        ):
            raise ValueError("partition limits are invalid")
        if (
            not isinstance(integration_paths, list)
            or not integration_paths
            or not all(isinstance(item, str) for item in integration_paths)
        ):
            raise ValueError("integration context paths are missing")
        if not isinstance(child_context_paths, list) or not all(
            isinstance(item, str) for item in child_context_paths
        ):
            raise ValueError("shared child context paths are invalid")
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise ReviewPackageBlocked("invalid partition manifest") from exc
    canonical_sha = sha256(_canonical_json(manifest)).hexdigest()
    if (
        manifest.get("root_package_path") != root_package.path.name
        or manifest.get("root_manifest_sha256") != root_package.manifest_sha256
        or manifest.get("base_sha") != root_package.manifest.base_sha
        or manifest.get("head_sha") != root_package.manifest.head_sha
        or manifest.get("author_provider") != root_package.manifest.author_provider
        or manifest.get("reviewer_provider") != root_package.manifest.reviewer_provider
        or manifest.get("scope") != list(root_package.manifest.scope)
        or manifest.get("projected_diff_sha256") != root_package.manifest.diff_sha256
        or manifest.get("full_diff_sha256") != root_package.manifest.full_diff_sha256
        or root_package.manifest.full_diff_sha256 is None
    ):
        raise ReviewPackageBlocked("partition root binding does not match its package")
    root_context = {item.path for item in root_package.manifest.files}
    if not set(integration_paths) <= root_context:
        raise ReviewPackageBlocked(
            "integration context is not bound by the root package"
        )
    if not set(child_context_paths) <= root_context:
        raise ReviewPackageBlocked(
            "shared child context is not bound by the root package"
        )

    target_bytes = limits["target_bytes"]
    atom_budget = limits["atom_budget"]
    invocation_byte_limit = min(
        target_bytes,
        limits["per_invocation_max_bytes"],
        limits["per_invocation_max_tokens"] * 3,
    )
    if atom_budget > invocation_byte_limit:
        raise ReviewPackageBlocked(
            "partition atom budget exceeds its approved invocation limit"
        )
    expected_groups = _group_atoms(
        _atoms(root_package.diff_bytes, atom_budget), atom_budget
    )
    if len(expected_groups) != len(children_raw):
        raise ReviewPackageBlocked(
            "partition child count does not match deterministic ranges"
        )
    run_root = (root / ".agent/.runs").resolve()
    children = []
    expected_offset = 0
    seen_paths: set[str] = set()
    for index, (entry, group) in enumerate(zip(children_raw, expected_groups)):
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ReviewPackageBlocked("partition child entry is invalid")
        name = entry["path"]
        if (
            name in seen_paths
            or Path(name).name != name
            or not name.startswith("review-")
        ):
            raise ReviewPackageBlocked("partition child path is invalid")
        seen_paths.add(name)
        child_path = run_root / name
        if child_path.is_symlink() or child_path.parent != run_root:
            raise ReviewPackageBlocked("partition child path is unsafe")
        child = load_package(child_path, root=root)
        _expected_inventory(child.path, child.manifest, root=False)
        start, end = int(group[0]["start"]), int(group[-1]["end"])
        expected_ranges = [dict(atom) for atom in group]
        if start != expected_offset or end <= start:
            raise ReviewPackageBlocked("partition ranges contain a gap or overlap")
        expected_offset = end
        if (
            entry.get("ranges") != expected_ranges
            or entry.get("payload_bytes") != end - start
            or entry.get("manifest_sha256") != child.manifest_sha256
            or entry.get("diff_sha256")
            != sha256(root_package.diff_bytes[start:end]).hexdigest()
            or child.diff_bytes != root_package.diff_bytes[start:end]
        ):
            raise ReviewPackageBlocked(
                "partition child bytes or range metadata do not match root diff"
            )
        root_manifest = root_package.manifest
        child_manifest = child.manifest
        common_fields = (
            "base_sha",
            "head_sha",
            "requirements_sha256",
            "verification_sha256",
            "policy_sha256",
            "schema_sha256",
            "author_provider",
            "reviewer_provider",
            "scope",
        )
        if any(
            getattr(child_manifest, field) != getattr(root_manifest, field)
            for field in common_fields
        ):
            raise ReviewPackageBlocked(
                "partition child inventory differs from the root package"
            )
        if (
            child_manifest.full_diff_sha256 is not None
            or child_manifest.verified_renames is not None
            or tuple(
                item
                for item in child_manifest.files
                if item.path != "partition-scope.json"
            )
            != tuple(
                item for item in root_manifest.files if item.path in child_context_paths
            )
            or child.manifest.diff_sha256 != entry.get("diff_sha256")
        ):
            raise ReviewPackageBlocked(
                "partition child manifest is not bound to the root inventory"
            )
        scope_path = child.path / "context" / "partition-scope.json"
        expected_scope = {
            "version": 1,
            "root_manifest_sha256": root_package.manifest_sha256,
            "base_sha": root_manifest.base_sha,
            "head_sha": root_manifest.head_sha,
            "author_provider": root_manifest.author_provider,
            "reviewer_provider": root_manifest.reviewer_provider,
            "scope": list(root_manifest.scope),
            "child_context_paths": list(child_context_paths),
            "full_diff_sha256": root_manifest.full_diff_sha256,
            "projected_diff_sha256": root_manifest.diff_sha256,
            "omitted_generated": [
                list(pair) for pair in root_manifest.omitted_generated
            ],
            "verified_renames": root_manifest.verified_renames,
            "ranges": expected_ranges,
            "review_guidance": (
                "This is one complete byte range from a larger independent review. "
                "The parent manifest binds every range to the full projected diff and full Git diff. "
                "Use the complete scope inventory for cross-file reasoning; report local findings "
                "with paths and evidence, and do not infer clearance from this shard alone."
            ),
        }
        if scope_path.read_bytes() != _canonical_json(expected_scope) + b"\n":
            raise ReviewPackageBlocked(
                "partition child scope context does not match root ranges"
            )
        usage = package_usage(child)
        if (
            usage["bytes"] > invocation_byte_limit
            or usage["estimated_tokens"] > limits["per_invocation_max_tokens"]
        ):
            raise ReviewPackageBlocked(
                "partition child exceeds its approved invocation budget"
            )
        children.append(child)
    if expected_offset != len(root_package.diff_bytes):
        raise ReviewPackageBlocked(
            "partition ranges do not cover the full projected diff"
        )
    result = PartitionedReview(root_package, manifest, canonical_sha, tuple(children))
    usage = partition_usage(result)
    if (
        usage["bytes"] > limits["max_aggregate_bytes"]
        or usage["estimated_tokens"] > limits["max_aggregate_tokens"]
        or manifest.get("aggregate_usage")
        != {
            "bytes": usage["bytes"],
            "estimated_tokens": usage["estimated_tokens"],
        }
    ):
        raise ReviewPackageBlocked("partition aggregate budget metadata is invalid")
    return result
