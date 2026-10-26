"""Disposable local scheduling state.

Nothing here is authoritative. GitHub Issues, leases, and pull requests are the
source of truth; this SQLite file only remembers attempt counts and quarantine
paths so a restart does not repeat expensive work. Deleting it is always safe:
`Coordinator.reconcile_once()` rebuilds every row from GitHub.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS candidates (
    candidate_key TEXT PRIMARY KEY,
    task_id       TEXT NOT NULL,
    issue_number  INTEGER NOT NULL,
    pr_number     INTEGER NOT NULL,
    head_sha      TEXT NOT NULL,
    author_id     INTEGER NOT NULL,
    status        TEXT NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    quarantine    TEXT
);
CREATE INDEX IF NOT EXISTS candidates_issue ON candidates (issue_number);
-- Refusals already announced on a pull request, so a silent reason is published
-- once per (pull request, head, reason) instead of on every 60-second pass.
CREATE TABLE IF NOT EXISTS notices (
    pr_number  INTEGER NOT NULL,
    head_sha   TEXT NOT NULL,
    reason     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (pr_number, head_sha, reason)
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


@dataclass(frozen=True)
class CandidateRow:
    candidate_key: str
    task_id: str
    issue_number: int
    pr_number: int
    head_sha: str
    author_id: int
    status: str
    attempts: int
    created_at: int
    updated_at: int
    quarantine: str | None


class CoordinatorState:
    """SQLite WAL queue cache; safe to delete, never authoritative."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(_SCHEMA)
        self._db.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )

    def __enter__(self) -> "CoordinatorState":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self._db.close()

    def rows(self) -> list[CandidateRow]:
        cursor = self._db.execute("SELECT * FROM candidates ORDER BY created_at, candidate_key")
        return [CandidateRow(**dict(row)) for row in cursor.fetchall()]

    def get(self, candidate_key: str) -> CandidateRow | None:
        row = self._db.execute(
            "SELECT * FROM candidates WHERE candidate_key = ?", (candidate_key,)
        ).fetchone()
        return CandidateRow(**dict(row)) if row is not None else None

    def upsert(
        self,
        *,
        candidate_key: str,
        task_id: str,
        issue_number: int,
        pr_number: int,
        head_sha: str,
        author_id: int,
        status: str,
        now: int,
    ) -> CandidateRow:
        self._db.execute(
            """
            INSERT INTO candidates (candidate_key, task_id, issue_number, pr_number, head_sha,
                                    author_id, status, attempts, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
            ON CONFLICT(candidate_key) DO UPDATE SET
                status = excluded.status,
                pr_number = excluded.pr_number,
                updated_at = excluded.updated_at
            """,
            (candidate_key, task_id, issue_number, pr_number, head_sha, author_id, status,
             now, now),
        )
        return self.get(candidate_key)

    def set_status(self, candidate_key: str, status: str, now: int,
                   *, quarantine: str | None = None) -> None:
        self._db.execute(
            "UPDATE candidates SET status = ?, updated_at = ?, "
            "quarantine = COALESCE(?, quarantine) WHERE candidate_key = ?",
            (status, now, quarantine, candidate_key),
        )

    def record_attempt(self, candidate_key: str, now: int) -> int:
        self._db.execute(
            "UPDATE candidates SET attempts = attempts + 1, updated_at = ? WHERE candidate_key = ?",
            (now, candidate_key),
        )
        row = self.get(candidate_key)
        return row.attempts if row is not None else 0

    def delete(self, candidate_key: str) -> None:
        self._db.execute("DELETE FROM candidates WHERE candidate_key = ?", (candidate_key,))

    def prune_except(self, live_keys: Iterable[str]) -> list[CandidateRow]:
        """Delete every cached row GitHub no longer vouches for."""

        live = set(live_keys)
        removed = [row for row in self.rows() if row.candidate_key not in live]
        for row in removed:
            self.delete(row.candidate_key)
        return removed

    def active_counts(self) -> tuple[int, dict[int, int]]:
        rows = [row for row in self.rows() if row.status in ("queued", "verifying")]
        per_author: dict[int, int] = {}
        for row in rows:
            per_author[row.author_id] = per_author.get(row.author_id, 0) + 1
        return len(rows), per_author

    def counts_by_status(self) -> dict[str, int]:
        """Candidate counts per status; `verified` here means verified-unmerged."""

        cursor = self._db.execute("SELECT status, COUNT(*) FROM candidates GROUP BY status")
        return {status: count for status, count in cursor.fetchall()}

    def claim_notice(self, *, pr_number: int, head_sha: str, reason: str, now: int) -> bool:
        """True the first time a (pull request, head, reason) refusal is announced."""

        cursor = self._db.execute(
            "INSERT OR IGNORE INTO notices (pr_number, head_sha, reason, created_at) "
            "VALUES (?, ?, ?, ?)",
            (int(pr_number), str(head_sha), str(reason), int(now)),
        )
        return cursor.rowcount > 0

    def verified_unmerged(self) -> list[CandidateRow]:
        """Rows whose verdict passed but whose merge has not happened yet."""

        return [row for row in self.rows() if row.status == "verified"]
