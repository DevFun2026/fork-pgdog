from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from dataclasses import dataclass, replace
from hashlib import sha256
from itertools import pairwise
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

PARTITION_REVIEW_GUIDANCE = (
    "Manifest file paths are relative to package/context; read only listed files. "
    "The child manifest diff_sha256 covers only this shard's diff.patch. This context "
    "binds the root_manifest_sha256, full_diff_sha256, complete scope, and this shard's "
    "ranges to the exact base_sha..head_sha commits; do not substitute the current "
    "worktree or infer whole-review clearance from one shard."
)

REGISTRY_PATH = (
    "applications/pgdog/pgdog/src/backend/schema/read_policy/registry-pg18.json"
)
REGISTRY_PATHS = frozenset({REGISTRY_PATH, REGISTRY_PATH.replace("pg18", "pg12")})
PROFILE_DIRECTORY = (
    "applications/pgdog/pgdog/src/backend/schema/read_policy/profiles"
)
PROFILE_CATALOGS = frozenset(
    {
        "pg_aggregate", "pg_am", "pg_amop", "pg_amproc", "pg_cast",
        "pg_collation", "pg_enum", "pg_extension", "pg_namespace", "pg_opclass",
        "pg_operator", "pg_opfamily", "pg_proc", "pg_range", "pg_ts_config",
        "pg_ts_config_map", "pg_ts_dict", "pg_ts_parser", "pg_ts_template", "pg_type",
    }
)
PROFILE_FORMAT = "pgdog-read-dependency-profile/v2"
PROFILE_IMAGES = {
    12: "postgres:12.22-bookworm@sha256:2f2a8c2a7d10862e7fba2602e304523554f9df8244c632dafe2628ccb398fb5c",
    18: "postgres:18@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722",
}
PROFILE_SELECTORS = {
    "core": [],
    "pg-trgm": ["pg_trgm"],
    "btree-gist": ["btree_gist"],
    "both": ["btree_gist", "pg_trgm"],
}
PROFILE_PATHS = frozenset(
    f"{PROFILE_DIRECTORY}/dependency-pg{major}-{selector}.json"
    for major in (12, 18)
    for selector in PROFILE_SELECTORS
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


def _object_members(
    text: str,
    start: int,
    decoder: json.JSONDecoder,
    *,
    reject_duplicates: bool = False,
):
    position = _skip_ws(text, start)
    if position >= len(text) or text[position] != "{":
        raise ReviewPackageBlocked(
            "pinned PG18 registry has an unsupported JSON structure"
        )
    position += 1
    members = []
    seen_keys: set[str] = set()
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
        if reject_duplicates and key in seen_keys:
            raise ReviewPackageBlocked("profile or registry JSON has a duplicate object key")
        seen_keys.add(key)
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


def _registry_records(section: bytes, section_start: int,
                      registry_path: str = REGISTRY_PATH) -> list[dict[str, object]]:
    if (
        registry_path not in REGISTRY_PATHS
        or b"new file mode " not in section
        or b"\n--- /dev/null\n" not in section
        or f"\n+++ b/{registry_path}\n".encode() not in section
    ):
        raise ReviewPackageBlocked(
            "only a newly added pinned PG12 or PG18 registry can be record-split"
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


def _profile_selector(path: str) -> tuple[int, list[str]] | None:
    if not path.startswith(PROFILE_DIRECTORY + "/"):
        return None
    basename = path[len(PROFILE_DIRECTORY) + 1 :]
    match = re.fullmatch(r"dependency-pg(12|18)-(core|pg-trgm|btree-gist|both)\.json", basename)
    if match is None:
        return None
    return int(match.group(1)), PROFILE_SELECTORS[match.group(2)]


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str):
    raise ValueError(f"non-standard JSON constant: {value}")


def _profile_records(section: bytes, section_start: int, profile_path: str) -> list[dict[str, object]]:
    selector = _profile_selector(profile_path)
    if (
        selector is None
        or b"new file mode " not in section
        or b"\n--- /dev/null\n" not in section
        or f"\n+++ b/{profile_path}\n".encode() not in section
    ):
        raise ReviewPackageBlocked("only one of the eight new dependency profiles can be record-split")
    lines = section.splitlines(keepends=True)
    offset = section_start
    json_line = None
    for line in lines:
        if line.startswith(b"+") and not line.startswith(b"+++"):
            if json_line is not None:
                raise ReviewPackageBlocked("dependency profile must be one complete JSON line")
            json_line = (offset + 1, line[1:].rstrip(b"\r\n"))
        offset += len(line)
    if json_line is None:
        raise ReviewPackageBlocked("dependency profile addition is missing")
    json_start, raw_json = json_line
    try:
        text = raw_json.decode("utf-8", errors="strict")
        decoder = json.JSONDecoder(
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        document, end = decoder.raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReviewPackageBlocked("dependency profile JSON is invalid") from exc
    if end != len(text) or not isinstance(document, dict):
        raise ReviewPackageBlocked("dependency profile has an unsupported JSON envelope")

    top = _object_members(text, 0, decoder, reject_duplicates=True)
    top_map = {key: value for key, _, _, value in top}
    required_keys = {
        "format", "provenance", "roots", "catalog", "extensions",
        "module_sha256", "client_functions", "projection_types",
        "enabled_extensions", "namespace_authority",
    }
    if set(top_map) != required_keys or top_map.get("format") != PROFILE_FORMAT:
        raise ReviewPackageBlocked("dependency profile v2 envelope is invalid")

    major, expected_extensions = selector
    provenance = top_map.get("provenance")
    provenance_keys = {
        "postgres_major", "source_image", "server_version",
        "server_version_num", "platform", "capture_id",
    }
    if (
        not isinstance(provenance, dict)
        or set(provenance) != provenance_keys
        or type(provenance.get("postgres_major")) is not int
        or provenance["postgres_major"] != major
        or type(provenance.get("server_version_num")) is not int
        or provenance["server_version_num"] // 10_000 != major
        or not isinstance(provenance.get("server_version"), str)
        or not (
            provenance["server_version"].startswith(f"{major}.")
            or provenance["server_version"] == str(major)
        )
        or provenance.get("source_image") != PROFILE_IMAGES[major]
        or not isinstance(provenance.get("platform"), str)
        or provenance["platform"] not in {"linux/amd64", "linux/arm64"}
        or not isinstance(provenance.get("capture_id"), str)
        or not provenance["capture_id"].strip()
        or len(provenance["capture_id"]) > 256
    ):
        raise ReviewPackageBlocked("dependency profile provenance is invalid")
    if top_map.get("enabled_extensions") != expected_extensions:
        raise ReviewPackageBlocked("dependency profile selector does not match its exact filename")
    if (
        top_map.get("namespace_authority") != "actor-namespace-authority/v1"
        or top_map.get("client_functions") != []
        or not isinstance(top_map.get("roots"), list)
        or not isinstance(top_map.get("extensions"), list)
        or not all(isinstance(item, dict) for item in top_map["extensions"])
        or not isinstance(top_map.get("module_sha256"), dict)
        or not isinstance(top_map.get("projection_types"), list)
    ):
        raise ReviewPackageBlocked("dependency profile v2 metadata schema is invalid")
    hashes = top_map["module_sha256"]
    if (
        set(hashes) != set(expected_extensions)
        or any(
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in hashes.values()
        )
        or len(top_map["extensions"]) != len(expected_extensions)
        or [item.get("name") for item in top_map["extensions"]]
        != expected_extensions
        or any(
            set(item)
            != {"name", "version", "namespace", "members", "derived_members", "fields"}
            or not all(isinstance(item.get(key), list) for key in ("members", "derived_members"))
            or not isinstance(item.get("fields"), dict)
            or not isinstance(item.get("namespace"), str)
            or not item["namespace"].strip()
            or item.get("version")
            != {
                (12, "pg_trgm"): "1.4",
                (12, "btree_gist"): "1.5",
                (18, "pg_trgm"): "1.6",
                (18, "btree_gist"): "1.8",
            }[(major, item.get("name"))]
            for item in top_map["extensions"]
        )
    ):
        raise ReviewPackageBlocked("dependency profile extension metadata is invalid")
    previous_root: tuple[str, str] | None = None
    for root in top_map["roots"]:
        identity = root.get("identity") if isinstance(root, dict) else None
        identity_text = str(identity) if type(identity) in {int, str} else None
        if (
            not isinstance(root, dict)
            or set(root) != {"catalog", "identity"}
            or not isinstance(root.get("catalog"), str)
            or root.get("catalog") not in PROFILE_CATALOGS - {"pg_enum"}
            or identity_text is None
            or (type(identity) is int and not (0 < identity <= 2**32 - 1))
            or (type(identity) is str and (not identity or len(identity) > 4096))
            or (previous_root is not None and previous_root >= (root["catalog"], identity_text))
        ):
            raise ReviewPackageBlocked("dependency profile root schema is invalid")
        previous_root = (root["catalog"], identity_text)
    projection_types = top_map["projection_types"]
    if (
        len(projection_types) > 20_000
        or any(type(oid) is not int or not (0 < oid <= 2**32 - 1) for oid in projection_types)
        or any(left >= right for left, right in pairwise(projection_types))
    ):
        raise ReviewPackageBlocked("dependency profile projection type schema is invalid")

    catalog_member = next((member for member in top if member[0] == "catalog"), None)
    if catalog_member is None or not isinstance(catalog_member[3], dict):
        raise ReviewPackageBlocked("dependency profile catalog is missing")
    catalog_members = _object_members(text, catalog_member[1], decoder, reject_duplicates=True)
    if {key for key, _, _, _ in catalog_members} != PROFILE_CATALOGS:
        raise ReviewPackageBlocked("dependency profile catalog table set is invalid")
    byte_offsets = [0]
    for character in text:
        byte_offsets.append(byte_offsets[-1] + len(character.encode("utf-8")))
    records: list[dict[str, object]] = []
    total_rows = 0
    for table, table_start, _, table_value in catalog_members:
        if not isinstance(table_value, list):
            raise ReviewPackageBlocked("dependency profile catalog tables must be arrays")
        items = _array_items(text, table_start, decoder)
        total_rows += len(items)
        if total_rows > 20_000:
            raise ReviewPackageBlocked("dependency profile catalog row budget exceeded")
        previous_identity: str | None = None
        seen_identities: set[str] = set()
        for row, (record_start, record_end) in enumerate(items):
            _record, decoded_end = decoder.raw_decode(text, record_start)
            row_members = _object_members(text, record_start, decoder, reject_duplicates=True)
            row_map = {key: value for key, _, _, value in row_members}
            identity = row_map.get("identity")
            identity_text = str(identity) if type(identity) in {int, str} else None
            if (
                decoded_end != record_end
                or set(row_map) != {"identity", "fields"}
                or identity_text is None
                or (type(identity) is int and not (0 < identity <= 2**32 - 1))
                or (type(identity) is str and (not identity or len(identity) > 4096))
                or not isinstance(row_map.get("fields"), dict)
                or identity_text in seen_identities
                or (previous_identity is not None and previous_identity >= identity_text)
            ):
                raise ReviewPackageBlocked("dependency profile catalog record schema is invalid")
            seen_identities.add(identity_text)
            previous_identity = identity_text
            records.append(
                {
                    "start": json_start + byte_offsets[record_start],
                    "end": json_start + byte_offsets[record_end],
                    "table": table,
                    "row": row,
                }
            )
    if top_map["catalog"].get("pg_enum"):
        raise ReviewPackageBlocked("dependency profile pg_enum must remain empty")
    if not records:
        raise ReviewPackageBlocked("dependency profile contains no catalog records")
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
    section: bytes, start: int, end: int, target_bytes: int,
    registry_path: str = REGISTRY_PATH,
) -> list[dict[str, object]]:
    records = _registry_records(section, start, registry_path)
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
                "path": registry_path,
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


def _profile_fragments(
    section: bytes, start: int, end: int, target_bytes: int, profile_path: str
) -> list[dict[str, object]]:
    records = _profile_records(section, start, profile_path)
    groups: list[list[dict[str, object]]] = []
    current: list[dict[str, object]] = []
    cursor = start
    for record in records:
        candidate_end = int(record["end"])
        candidate_size = candidate_end - cursor
        if candidate_size > target_bytes:
            if not current:
                raise ReviewPackageBlocked(
                    f"an indivisible dependency profile record exceeds the shard target ({candidate_size} > {target_bytes})"
                )
            groups.append(current)
            cursor = int(current[-1]["end"])
            current = []
            candidate_size = candidate_end - cursor
            if candidate_size > target_bytes:
                raise ReviewPackageBlocked("an indivisible dependency profile record exceeds the shard target")
        current.append(record)
    if current:
        groups.append(current)
    while groups:
        last_start = start if len(groups) == 1 else int(groups[-2][-1]["end"])
        if end - last_start <= target_bytes:
            break
        if len(groups[-1]) == 1:
            raise ReviewPackageBlocked("dependency profile framing exceeds the shard target")
        moved = groups[-1].pop()
        groups.append([moved])
    fragments = []
    cursor = start
    for index, group in enumerate(groups):
        fragment_end = end if index == len(groups) - 1 else int(group[-1]["end"])
        if fragment_end - cursor > target_bytes:
            raise ReviewPackageBlocked("dependency profile framing exceeds the shard target")
        fragments.append(
            {
                "start": cursor,
                "end": fragment_end,
                "kind": "profile-catalog-records",
                "path": profile_path,
                "records": _compact_record_spans(group),
                "record_start": int(group[0]["start"]),
                "record_end": int(group[-1]["end"]),
            }
        )
        cursor = fragment_end
    if fragments:
        last_record_end = int(records[-1]["end"])
        if end - last_record_end > target_bytes:
            raise ReviewPackageBlocked("dependency profile trailing framing exceeds the shard target")
        if cursor != end:
            raise ReviewPackageBlocked("dependency profile ranges do not cover the source patch")
    return fragments


def _atoms(diff: bytes, target_bytes: int) -> list[dict[str, object]]:
    atoms = []
    for start, end, section in _diff_sections(diff):
        registry_path = next((path for path in sorted(REGISTRY_PATHS)
                              if section.startswith(f"diff --git a/{path} b/{path}\n".encode())), None)
        profile_path = next(
            (
                path
                for path in sorted(PROFILE_PATHS)
                if section.startswith(f"diff --git a/{path} b/{path}\n".encode())
            ),
            None,
        )
        if end - start <= target_bytes:
            if profile_path is not None:
                _profile_records(section, start, profile_path)
            atoms.append({"start": start, "end": end, "kind": "patch"})
        elif registry_path is not None:
            atoms.extend(_registry_fragments(section, start, end, target_bytes, registry_path))
        elif profile_path is not None:
            atoms.extend(_profile_fragments(section, start, end, target_bytes, profile_path))
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
        "review_guidance": PARTITION_REVIEW_GUIDANCE,
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


def _next_atom_budget(
    *,
    atom_budget: int,
    invocation_byte_limit: int,
    over_budget_children: tuple[tuple[int, int], ...],
) -> int:
    """Reduce diff payload allowance by each oversized child's measured overhead."""
    payload_limits = [
        invocation_byte_limit - (package_bytes - diff_bytes)
        for diff_bytes, package_bytes in over_budget_children
    ]
    if not payload_limits:
        return atom_budget
    return min(atom_budget - 1, min(payload_limits))


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
        over_budget_children = []
        for child in children:
            usage = package_usage(child)
            package_bytes = int(usage["bytes"])
            if (
                package_bytes > invocation_byte_limit
                or int(usage["estimated_tokens"]) > request.max_estimated_tokens
            ):
                over_budget_children.append(
                    (len(child.diff_bytes), package_bytes)
                )
        if not over_budget_children:
            break
        for child in children:
            shutil.rmtree(child.path)
        children = []
        entries = []
        atom_budget = _next_atom_budget(
            atom_budget=atom_budget,
            invocation_byte_limit=invocation_byte_limit,
            over_budget_children=tuple(over_budget_children),
        )
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
            "review_guidance": PARTITION_REVIEW_GUIDANCE,
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
