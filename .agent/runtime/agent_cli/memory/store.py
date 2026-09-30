from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import sqlite3

from agent_cli.memory.models import MemoryCandidate, validate_candidate


class MemoryStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        self._initialize()
        os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    observed_commit TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS candidates (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS candidate_paths (
                    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
                    path TEXT NOT NULL,
                    PRIMARY KEY (candidate_id, path)
                );
                CREATE TABLE IF NOT EXISTS timeline (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
                    event TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            mode = "fts5"
            try:
                connection.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS candidate_fts "
                    "USING fts5(id UNINDEXED, title, summary, details)"
                )
            except sqlite3.OperationalError:
                mode = "fallback"
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES('search_mode', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (mode,),
            )
            connection.commit()
        finally:
            connection.close()

    @property
    def search_mode(self) -> str:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='search_mode'"
            ).fetchone()
            return str(row["value"])
        finally:
            connection.close()

    def checkpoint(self, candidate: MemoryCandidate) -> None:
        self.checkpoint_many((candidate,))

    @staticmethod
    def _insert_candidate(
        connection: sqlite3.Connection, candidate: MemoryCandidate, search_mode: str
    ) -> None:
        payload = json.dumps(asdict(candidate), sort_keys=True, separators=(",", ":"))
        connection.execute(
            "INSERT INTO candidates(id, title, created_at, payload) VALUES(?, ?, ?, ?)",
            (candidate.id, candidate.title, candidate.created_at, payload),
        )
        connection.executemany(
            "INSERT INTO candidate_paths(candidate_id, path) VALUES(?, ?)",
            ((candidate.id, path) for path in candidate.paths),
        )
        connection.execute(
            "INSERT INTO timeline(candidate_id, event, created_at) VALUES(?, ?, ?)",
            (candidate.id, "checkpoint", candidate.created_at),
        )
        if search_mode == "fts5":
            connection.execute(
                "INSERT INTO candidate_fts(id, title, summary, details) VALUES(?, ?, ?, ?)",
                (candidate.id, candidate.title, candidate.summary, candidate.details),
            )

    def checkpoint_many(self, candidates: tuple[MemoryCandidate, ...]) -> None:
        for candidate in candidates:
            validate_candidate(candidate)
        identifiers = tuple(candidate.id for candidate in candidates)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("duplicate candidate ID in batch")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='search_mode'"
            ).fetchone()
            search_mode = str(row["value"])
            for candidate in candidates:
                self._insert_candidate(connection, candidate, search_mode)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def count_candidates(self) -> int:
        connection = self._connect()
        try:
            return int(connection.execute("SELECT COUNT(*) FROM candidates").fetchone()[0])
        finally:
            connection.close()

    def list_candidates(self) -> tuple[MemoryCandidate, ...]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT payload FROM candidates ORDER BY title, id"
            ).fetchall()
        finally:
            connection.close()
        return tuple(self._deserialize(row["payload"]) for row in rows)

    @staticmethod
    def _deserialize(payload_text: str) -> MemoryCandidate:
        payload = json.loads(payload_text)
        for field in ("components", "paths", "evidence"):
            payload[field] = tuple(payload[field])
        return MemoryCandidate(**payload)

    def get_candidate(self, identifier: str) -> MemoryCandidate | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT payload FROM candidates WHERE id=?", (identifier,)
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else self._deserialize(row["payload"])

    def delete_candidate(self, identifier: str) -> bool:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            deleted = connection.execute(
                "DELETE FROM candidates WHERE id=?", (identifier,)
            ).rowcount
            if self.search_mode == "fts5":
                connection.execute("DELETE FROM candidate_fts WHERE id=?", (identifier,))
            connection.commit()
            return bool(deleted)
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def add_timeline(self, identifier: str, event: str, created_at: str) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO timeline(candidate_id, event, created_at) VALUES(?, ?, ?)",
                (identifier, event, created_at),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def timeline_events(self, identifier: str, limit: int = 11) -> tuple[str, ...]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT created_at, event FROM timeline WHERE candidate_id=? "
                "ORDER BY sequence DESC LIMIT ?",
                (identifier, limit),
            ).fetchall()
        finally:
            connection.close()
        return tuple(
            f"{row['created_at']} {row['event']}" for row in reversed(rows)
        )

    def plaintext_payloads(self) -> str:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT payload FROM candidates ORDER BY id"
            ).fetchall()
        finally:
            connection.close()
        return "\n".join(str(row["payload"]) for row in rows)
