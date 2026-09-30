from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from fnmatch import fnmatch
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import unicodedata
from typing import Any, Iterable

from agent_cli.memory.models import (
    CanonicalMemory,
    MemoryCandidate,
    validate_candidate,
)
from agent_cli.memory.records import parse_record, render_record, validate_record, write_record
from agent_cli.memory.store import MemoryStore
from agent_cli.paths import atomic_write, resolve_inside
from agent_cli.redaction import redact
from agent_cli.context import estimate_tokens


@dataclass(frozen=True)
class SearchRow:
    id: str
    title: str
    type: str
    components: tuple[str, ...]
    summary: str
    status: str


@dataclass(frozen=True)
class SearchResult:
    ids: tuple[str, ...]
    rows: tuple[SearchRow, ...]


@dataclass(frozen=True)
class ImportedCandidate(MemoryCandidate):
    @property
    def trust(self) -> str:
        return "untrusted-candidate"


def _redacted_text(value: str) -> str:
    return redact(value).text


def candidate_from_dict(data: dict[str, Any]) -> MemoryCandidate:
    values = dict(data)
    for field in ("components", "paths", "evidence"):
        if field in values:
            values[field] = tuple(values[field])
    return MemoryCandidate(**values)


class MemoryService:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.local_dir = self.root / ".agent/.memory"
        self.canonical_dir = self.root / ".agent/memory/records"
        self.index_path = self.root / ".agent/memory/INDEX.md"
        self.local_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.local_dir, 0o700)
        self.canonical_dir.mkdir(parents=True, exist_ok=True)
        self.store = MemoryStore(self.local_dir / "memory.db")

    def init(self) -> dict[str, object]:
        self.rebuild_index()
        return self.doctor()

    def _redact_candidate(self, candidate: MemoryCandidate) -> MemoryCandidate:
        redacted = replace(
            candidate,
            title=_redacted_text(candidate.title),
            summary=_redacted_text(candidate.summary),
            details=_redacted_text(candidate.details),
            components=tuple(_redacted_text(item) for item in candidate.components),
            paths=tuple(_redacted_text(item) for item in candidate.paths),
            evidence=tuple(_redacted_text(item) for item in candidate.evidence),
            source_session=_redacted_text(candidate.source_session),
            branch=_redacted_text(candidate.branch),
            reuse_guidance=_redacted_text(candidate.reuse_guidance),
        )
        validate_candidate(redacted)
        return redacted

    def checkpoint(self, candidate: MemoryCandidate) -> MemoryCandidate:
        redacted = self._redact_candidate(candidate)
        self.store.checkpoint(redacted)
        return redacted

    def _records(self) -> tuple[CanonicalMemory, ...]:
        return tuple(
            parse_record(path)
            for path in sorted(self.canonical_dir.glob("MEM-*.md"))
        )

    def _candidate_for_promotion(
        self, candidate_or_id: MemoryCandidate | str
    ) -> MemoryCandidate:
        if isinstance(candidate_or_id, str):
            candidate = self.store.get_candidate(candidate_or_id)
            if candidate is None:
                raise KeyError(f"unknown memory candidate: {candidate_or_id}")
            return candidate
        return candidate_or_id

    def promote(self, candidate_or_id: MemoryCandidate | str) -> CanonicalMemory:
        candidate = self._redact_candidate(self._candidate_for_promotion(candidate_or_id))
        git_repository = subprocess.run(
            ("git", "rev-parse", "--is-inside-work-tree"),
            cwd=self.root,
            text=True,
            capture_output=True,
            check=False,
        ).returncode == 0
        if git_repository:
            observed = subprocess.run(
                ("git", "cat-file", "-e", f"{candidate.observed_commit}^{{commit}}"),
                cwd=self.root,
                capture_output=True,
                check=False,
            )
            if observed.returncode != 0:
                raise ValueError("observed_commit is not a valid repository commit")
        for evidence in candidate.evidence:
            path = resolve_inside(self.root, evidence)
            if not path.is_file():
                raise ValueError(f"evidence file does not exist: {evidence}")
            if git_repository:
                committed = subprocess.run(
                    ("git", "cat-file", "-e", f"{candidate.observed_commit}:{evidence}"),
                    cwd=self.root,
                    capture_output=True,
                    check=False,
                )
                if committed.returncode != 0:
                    raise ValueError(
                        f"evidence is not present at observed_commit: {evidence}"
                    )
        record = CanonicalMemory(
            **asdict(candidate),
            status="active",
            last_verified_commit=candidate.observed_commit,
            supersedes=(),
        )
        validate_record(record)
        target = self.canonical_dir / f"{record.id}.md"
        if target.exists():
            raise ValueError(f"canonical memory already exists: {record.id}")
        write_record(record, target)
        try:
            self.rebuild_index()
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        if self.store.get_candidate(record.id) is not None:
            self.store.add_timeline(record.id, "promoted", record.created_at)
        return record

    @staticmethod
    def _score(record: CanonicalMemory, query: str) -> int:
        normalize = lambda text: unicodedata.normalize("NFC", text).casefold()
        terms = set(re.findall(r"\w+", normalize(query)))
        if not terms:
            return 1 if not query.strip() else 0
        fields = (
            (record.id, 8), (record.title, 4),
            (" ".join((*record.components, *record.paths)), 3),
            (record.summary, 2), (record.type, 1),
        )
        return sum(weight for text, weight in fields for term in terms
                   if term in normalize(text))

    @classmethod
    def _matches(cls, record: CanonicalMemory, query: str) -> bool:
        return cls._score(record, query) > 0

    def _fresh_records(self, changed_paths: tuple[str, ...] = ()) -> tuple[CanonicalMemory, ...]:
        records = []
        changes_by_commit: dict[str, tuple[str, ...]] = {}
        changed = False
        for record in self._records():
            if record.last_verified_commit not in changes_by_commit:
                changes_by_commit[record.last_verified_commit] = self._git_changed_paths_since(
                    record.last_verified_commit)
            paths = tuple(sorted(set((*changed_paths, *changes_by_commit[record.last_verified_commit]))))
            if record.status == "active" and self._record_is_stale(record, paths):
                record = self._mark_stale(record)
                changed = True
            records.append(record)
        if changed:
            self.rebuild_index()
        return tuple(records)

    def search(self, query: str, *, include_stale: bool = False,
               limit: int = 5, char_budget: int = 4000, token_budget: int = 1200) -> SearchResult:
        if limit <= 0 or char_budget < 2 or token_budget <= 0:
            raise ValueError("search limit must be positive and char_budget at least 2")
        records = [
            record
            for record in self._fresh_records()
            if self._matches(record, query)
            and record.sensitivity != "private"
            and record.status not in {"superseded", "revoked"}
            and (include_stale or record.status != "possibly-stale")
        ]
        records.sort(key=lambda item: (-self._score(item, query), item.type, item.title, item.id))
        selected: list[SearchRow] = []
        for record in records:
            row = SearchRow(
                id=record.id,
                title=record.title,
                type=record.type,
                components=record.components,
                summary=record.summary,
                status=record.status,
            )
            payload = json.dumps([asdict(item) for item in (*selected, row)],
                                 ensure_ascii=False, sort_keys=True)
            if len(payload) > char_budget or estimate_tokens(payload) > token_budget:
                continue
            selected.append(row)
            if len(selected) >= limit:
                break
        rows = tuple(selected)
        return SearchResult(ids=tuple(row.id for row in rows), rows=rows)

    def timeline(self, identifier: str, *, limit: int = 11) -> tuple[str, ...]:
        known = {record.id for record in self._records()}
        if identifier not in known and self.store.get_candidate(identifier) is None:
            raise KeyError(f"unknown memory ID: {identifier}")
        return self.store.timeline_events(identifier, limit=limit)

    def show(self, identifiers: Iterable[str], *, char_budget: int = 16000,
             token_budget: int = 4800) -> str:
        if char_budget <= 0 or token_budget <= 0:
            raise ValueError("show budgets must be positive")
        blocks: list[str] = []
        canonical = {record.id: record for record in self._records()}
        for identifier in dict.fromkeys(identifiers):
            if identifier in canonical:
                blocks.append(render_record(canonical[identifier]).rstrip())
                continue
            candidate = self.store.get_candidate(identifier)
            if candidate is None:
                raise KeyError(f"unknown memory ID: {identifier}")
            blocks.append(json.dumps(asdict(candidate), sort_keys=True, indent=2))
        result = "\n\n".join(blocks) + ("\n" if blocks else "")
        if len(result) > char_budget or estimate_tokens(result) > token_budget:
            raise ValueError("full memory exceeds context budget; select fewer IDs or explicitly increase the show budget")
        return result

    def _record_is_stale(
        self, record: CanonicalMemory, changed_paths: tuple[str, ...]
    ) -> bool:
        if "**" in changed_paths:
            return True
        if any(
            fnmatch(changed_path, pattern)
            for pattern in record.paths
            for changed_path in changed_paths
        ):
            return True
        if any(evidence in changed_paths for evidence in record.evidence):
            return True
        return any(
            not resolve_inside(self.root, evidence).is_file()
            for evidence in record.evidence
        )

    def _git_changed_paths_since(self, commit: str) -> tuple[str, ...]:
        inside = subprocess.run(
            ("git", "rev-parse", "--is-inside-work-tree"),
            cwd=self.root,
            text=True,
            capture_output=True,
            check=False,
        )
        if inside.returncode != 0:
            return ()
        valid = subprocess.run(
            ("git", "cat-file", "-e", f"{commit}^{{commit}}"),
            cwd=self.root,
            capture_output=True,
            check=False,
        )
        if valid.returncode != 0:
            return ("**",)
        diff_commands = (
            ("git", "diff", "--name-only", commit, "HEAD"),
            ("git", "diff", "--name-only", "--cached"),
            ("git", "diff", "--name-only"),
        )
        changed_results = tuple(
            subprocess.run(
                command,
                cwd=self.root,
                text=True,
                capture_output=True,
                check=False,
            )
            for command in diff_commands
        )
        untracked = subprocess.run(
            ("git", "ls-files", "--others", "--exclude-standard"),
            cwd=self.root,
            text=True,
            capture_output=True,
            check=False,
        )
        if any(result.returncode != 0 for result in changed_results) or untracked.returncode != 0:
            return ("**",)
        return tuple(
            sorted(
                {
                    path
                    for path in (
                        *(path for result in changed_results for path in result.stdout.splitlines()),
                        *untracked.stdout.splitlines(),
                    )
                    if path
                }
            )
        )

    def _mark_stale(self, record: CanonicalMemory) -> CanonicalMemory:
        if record.status == "possibly-stale":
            return record
        stale = replace(record, status="possibly-stale")
        write_record(stale, self.canonical_dir / f"{record.id}.md")
        return stale

    def bootstrap(
        self,
        query: str,
        *,
        char_budget: int,
        changed_paths: tuple[str, ...] = (),
        limit: int = 5,
        startup: bool = False,
        token_budget: int = 1200,
    ) -> str:
        if char_budget <= 0 or limit <= 0 or token_budget <= 0:
            raise ValueError("char_budget, token_budget and limit must be positive")
        records: list[CanonicalMemory] = []
        for record in self._fresh_records(changed_paths):
            if (
                record.status == "active"
                and record.sensitivity != "private"
                and self._matches(record, query)
                and (not startup or record.type in {"architecture", "constraint", "decision", "workflow"})
            ):
                records.append(record)
        blocks = [
            f"## {record.id} — {record.title}\n"
            f"Type: {record.type}; Components: {', '.join(record.components) or 'none'}\n"
            f"Summary: {record.summary}\n"
            for record in sorted(records, key=lambda item: (-self._score(item, query), item.type, item.title, item.id))
        ]
        output = ""
        count = 0
        for block in blocks:
            separator = "\n" if output else ""
            if (len(output) + len(separator) + len(block) > char_budget
                    or estimate_tokens(output + separator + block) > token_budget):
                continue
            output += separator + block
            count += 1
            if count >= limit:
                break
        return output

    def rebuild_index(self) -> str:
        records = sorted(self._records(), key=lambda item: (item.type, item.title, item.id))
        startup = [
            record
            for record in records
            if record.status == "active" and record.sensitivity != "private"
        ]
        lines = ["# Project Memory Index", "", "## Startup context", ""]
        if startup:
            lines.extend(
                f"- **{record.id}** [{record.type}] {record.title} — {record.summary}"
                for record in startup
            )
        else:
            lines.append("No active, non-private canonical records.")
        lines.extend(["", "## Status inventory", ""])
        if records:
            lines.extend(
                f"- `{record.id}` — {record.status}; sensitivity: {record.sensitivity}"
                for record in records
            )
        else:
            lines.append("No canonical records.")
        content = "\n".join(lines) + "\n"
        atomic_write(self.index_path, content)
        return content

    def supersede(self, old_id: str, new_id: str) -> None:
        records = {record.id: record for record in self._records()}
        if old_id not in records or new_id not in records:
            raise KeyError("both canonical records must exist")
        old = replace(records[old_id], status="superseded")
        new = replace(
            records[new_id],
            supersedes=tuple(sorted(set((*records[new_id].supersedes, old_id)))),
        )
        write_record(old, self.canonical_dir / f"{old.id}.md")
        write_record(new, self.canonical_dir / f"{new.id}.md")
        self.rebuild_index()

    def forget(
        self,
        identifier: str,
        *,
        canonical: bool = False,
        reason: str | None = None,
    ) -> None:
        if not canonical:
            if not self.store.delete_candidate(identifier):
                raise KeyError(f"unknown candidate: {identifier}")
            return
        if not reason or not reason.strip():
            raise ValueError("canonical forget requires a reason")
        target = self.canonical_dir / f"{identifier}.md"
        if not target.is_file():
            raise KeyError(f"unknown canonical memory: {identifier}")
        target.unlink()
        tombstone = self.root / ".agent/memory/TOMBSTONES.jsonl"
        previous = tombstone.read_text(encoding="utf-8") if tombstone.exists() else ""
        entry = json.dumps({"id": identifier, "reason": _redacted_text(reason)}, sort_keys=True)
        atomic_write(tombstone, previous + entry + "\n")
        self.rebuild_index()

    @staticmethod
    def _record_payload(record: CanonicalMemory) -> dict[str, Any]:
        def redact_value(value):
            if isinstance(value, str):
                return _redacted_text(value)
            if isinstance(value, dict):
                return {key: redact_value(item) for key, item in value.items()}
            if isinstance(value, (list, tuple)):
                return [redact_value(item) for item in value]
            return value

        return redact_value(asdict(record))

    def export_redacted(self) -> bytes:
        items = []
        for record in self._records():
            payload = self._record_payload(record)
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            items.append(
                {
                    "id": record.id,
                    "sha256": sha256(canonical.encode("utf-8")).hexdigest(),
                    "record": payload,
                }
            )
        manifest = [{"id": item["id"], "sha256": item["sha256"]} for item in items]
        body = {"version": 1, "manifest": manifest, "records": items}
        return (json.dumps(body, sort_keys=True, indent=2) + "\n").encode("utf-8")

    def import_file(self, path: str | Path) -> tuple[ImportedCandidate, ...]:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid memory export: {exc}") from exc
        if (
            not isinstance(data, dict)
            or set(data) != {"version", "manifest", "records"}
            or data["version"] != 1
            or not isinstance(data["manifest"], list)
            or not isinstance(data["records"], list)
        ):
            raise ValueError("invalid memory export structure")
        expected: dict[str, str] = {}
        for item in data["manifest"]:
            if (
                not isinstance(item, dict)
                or set(item) != {"id", "sha256"}
                or not isinstance(item["id"], str)
                or not re.fullmatch(r"MEM-[A-Z0-9-]+", item["id"])
                or not isinstance(item["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or item["id"] in expected
            ):
                raise ValueError("invalid memory export manifest")
            expected[item["id"]] = item["sha256"]
        imported: list[ImportedCandidate] = []
        seen: set[str] = set()
        for item in data["records"]:
            if not isinstance(item, dict) or set(item) != {"id", "sha256", "record"}:
                raise ValueError("invalid memory export record")
            if (
                not isinstance(item["id"], str)
                or item["id"] in seen
                or not isinstance(item["record"], dict)
                or item["id"] != item["record"].get("id")
            ):
                raise ValueError("memory export ID mismatch")
            seen.add(item["id"])
            canonical = json.dumps(item["record"], sort_keys=True, separators=(",", ":"))
            actual = sha256(canonical.encode("utf-8")).hexdigest()
            if actual != item["sha256"] or expected.get(item["id"]) != actual:
                raise ValueError(f"checksum mismatch for {item['id']}")
            values = dict(item["record"])
            for field in ("components", "paths", "evidence", "supersedes"):
                values[field] = tuple(values[field])
            record = CanonicalMemory(**values)
            validate_record(record)
            candidate_values = {
                key: value
                for key, value in asdict(record).items()
                if key not in {"status", "last_verified_commit", "supersedes"}
            }
            for field in ("components", "paths", "evidence"):
                candidate_values[field] = tuple(candidate_values[field])
            candidate_values["source_provider"] = "import"
            imported_candidate = ImportedCandidate(**candidate_values)
            redacted = self._redact_candidate(imported_candidate)
            imported_candidate = ImportedCandidate(**asdict(redacted))
            imported.append(imported_candidate)
        if seen != set(expected):
            raise ValueError("memory export manifest and records do not match")
        self.store.checkpoint_many(tuple(imported))
        return tuple(imported)

    def debug_plaintext_dump(self) -> str:
        return self.store.plaintext_payloads()

    def doctor(self) -> dict[str, object]:
        records = self._records()
        return {
            "search_mode": self.store.search_mode,
            "local_directory_mode": oct(os.stat(self.local_dir).st_mode & 0o777),
            "database_mode": oct(os.stat(self.store.path).st_mode & 0o777),
            "candidate_count": self.store.count_candidates(),
            "canonical_count": len(records),
            "stale_count": sum(record.status == "possibly-stale" for record in records),
        }
