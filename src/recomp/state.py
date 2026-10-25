"""Persistent coordination state: keys, leases with fencing tokens, submissions, events.

SQLite is authoritative for P0 (solo/invited tiers); the design keeps every
mutation behind fencing checks so a swap to Postgres later is mechanical.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

CLAIM_TTL_SECONDS = 30 * 60
ENROLL_TTL_SECONDS = 24 * 3600
DEFAULT_BASE_SEATS = 1
DEFAULT_SEAT_TTL_SECONDS = 10 * 60
SCHEMA = """
CREATE TABLE IF NOT EXISTS keys(
  id INTEGER PRIMARY KEY, role TEXT NOT NULL, name TEXT UNIQUE,
  key_hash TEXT UNIQUE NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
  trusted INTEGER NOT NULL DEFAULT 0, last_seen REAL);
CREATE TABLE IF NOT EXISTS enroll(
  token_hash TEXT PRIMARY KEY, expires REAL NOT NULL, used_by TEXT);
CREATE TABLE IF NOT EXISTS workers(
  id INTEGER PRIMARY KEY, key_id INTEGER UNIQUE NOT NULL, name TEXT,
  heartbeat REAL, seat_expires REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS work(
  work_id TEXT PRIMARY KEY, kind TEXT, args TEXT,
  status TEXT NOT NULL DEFAULT 'open', gen INTEGER NOT NULL DEFAULT 0, policy_version INTEGER);
CREATE TABLE IF NOT EXISTS leases(
  work_id TEXT PRIMARY KEY, worker_id INTEGER NOT NULL,
  generation INTEGER NOT NULL, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS submissions(
  id INTEGER PRIMARY KEY, work_id TEXT, worker_id INTEGER, generation INTEGER,
  policy_version INTEGER, status TEXT, attestation TEXT, created REAL);
CREATE TABLE IF NOT EXISTS reverify(
  submission_id INTEGER PRIMARY KEY, work_id TEXT NOT NULL,
  worker_id INTEGER NOT NULL, args TEXT NOT NULL, files TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)
        self._db.commit()
        self._lock = threading.Lock()
        self.base_seats = DEFAULT_BASE_SEATS
        self.seat_ttl = DEFAULT_SEAT_TTL_SECONDS
        self.seat_ceiling = 0  # 0 = no hard ceiling
        self.owner_key: str | None = None
        self._migrate_schema()

    def _migrate_schema(self) -> None:
        """Add lease/trust fields to databases created by earlier recomp builds."""
        key_columns = {
            row["name"] for row in self._db.execute("PRAGMA table_info(keys)")}
        if "trusted" not in key_columns:
            self._db.execute(
                "ALTER TABLE keys ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0")
        worker_columns = {
            row["name"] for row in self._db.execute("PRAGMA table_info(workers)")}
        if "seat_expires" not in worker_columns:
            self._db.execute(
                "ALTER TABLE workers ADD COLUMN seat_expires REAL NOT NULL DEFAULT 0")
            self._db.execute(
                "UPDATE workers SET seat_expires=COALESCE(heartbeat, 0) + ?",
                (self.seat_ttl,))
        self._db.commit()

    def _tx(self):
        return _Tx(self._db, self._lock)

    # ------------------------------------------------------------- keys

    def _mint_key(self, role: str, name: str | None, prefix: str) -> str:
        key = prefix + secrets.token_urlsafe(24)
        with self._tx() as db:
            db.execute("INSERT INTO keys(role,name,key_hash) VALUES(?,?,?)",
                       (role, name, _hash(key)))
        return key

    def create_owner_key(self) -> str:
        if self.owner_key:
            return self.owner_key
        row = self._db.execute("SELECT key_hash FROM keys WHERE role='owner' AND revoked=0").fetchone()
        if row:
            raise RuntimeError("owner key already exists; read it from server/keys/owner.key")
        self.owner_key = self._mint_key("owner", "owner", "ro_")
        return self.owner_key

    def grant_worker_key(self, name: str) -> str:
        key = self._mint_key("worker", name, "rw_")
        self._ensure_worker(name)
        return key

    def _ensure_worker(self, name: str) -> int:
        with self._tx() as db:
            row = db.execute("SELECT k.id FROM keys k JOIN workers w ON w.key_id=k.id WHERE k.name=?",
                             (name,)).fetchone()
            if row:
                return row["id"]
            key_row = db.execute("SELECT id FROM keys WHERE name=? AND role='worker'", (name,)).fetchone()
            if key_row is None:
                raise KeyError(f"no worker key named {name!r}")
            cur = db.execute("INSERT INTO workers(key_id,name,heartbeat) VALUES(?,?,?)",
                             (key_row["id"], name, time.time()))
            return cur.lastrowid

    def revoke_key(self, name: str) -> None:
        with self._tx() as db:
            db.execute("UPDATE keys SET revoked=1 WHERE name=?", (name,))
            db.execute("DELETE FROM leases WHERE worker_id IN "
                       "(SELECT w.id FROM workers w JOIN keys k ON k.id=w.key_id WHERE k.name=?)", (name,))

    def key_role(self, key: str) -> str | None:
        with self._tx() as db:
            row = db.execute("SELECT id,role,revoked FROM keys WHERE key_hash=?", (_hash(key),)).fetchone()
            if row is None or row["revoked"]:
                return None
            db.execute("UPDATE keys SET last_seen=? WHERE id=?", (time.time(), row["id"]))
            return row["role"]

    def mint_enroll_token(self, ttl: float = ENROLL_TTL_SECONDS) -> str:
        token = "et_" + secrets.token_urlsafe(18)
        with self._tx() as db:
            db.execute("INSERT INTO enroll(token_hash,expires) VALUES(?,?)",
                       (_hash(token), time.time() + ttl))
        return token

    def redeem_enroll_token(self, token: str, name: str,
                            base_seats: int | None = None,
                            seat_ttl: float | None = None) -> str:
        base_seats = self.base_seats if base_seats is None else base_seats
        seat_ttl = self.seat_ttl if seat_ttl is None else seat_ttl
        with self._tx() as db:
            row = db.execute("SELECT expires,used_by FROM enroll WHERE token_hash=?",
                             (_hash(token),)).fetchone()
            if row is None:
                raise PermissionError("unknown token")
            if row["used_by"] is not None:
                raise PermissionError("token already used")
            if row["expires"] < time.time():
                raise PermissionError("token expired")
            if self._active_seats(db) >= self._effective_seats(db, base_seats):
                raise PermissionError(
                    "no seats free: seats grow with available work, so retry when work "
                    "opens up or a seat expires (agent ran out of tokens); the owner can "
                    "raise collab.base_seats")
            db.execute("UPDATE enroll SET used_by=? WHERE token_hash=?", (name, _hash(token)))
            key = "rw_" + secrets.token_urlsafe(24)
            db.execute("INSERT INTO keys(role,name,key_hash) VALUES('worker',?,?)", (name, _hash(key)))
            key_row = db.execute("SELECT id FROM keys WHERE key_hash=?", (_hash(key),)).fetchone()
            db.execute("INSERT INTO workers(key_id,name,heartbeat,seat_expires) VALUES(?,?,?,?)",
                       (key_row["id"], name, time.time(), time.time() + seat_ttl))
        return key

    @staticmethod
    def _active_seats(db) -> int:
        return db.execute(
            "SELECT COUNT(*) n FROM workers w JOIN keys k ON k.id=w.key_id "
            "WHERE k.role='worker' AND k.revoked=0 AND w.seat_expires >= ?",
            (time.time(),)).fetchone()["n"]

    def _effective_seats(self, db, base_seats: int) -> int:
        available_work = db.execute(
            "SELECT COUNT(*) n FROM work w WHERE w.status='open' "
            "AND NOT EXISTS (SELECT 1 FROM leases l WHERE l.work_id=w.work_id "
            "AND l.expires_at >= ?)",
            (time.time(),)).fetchone()["n"]
        limit = max(int(base_seats), int(available_work))
        if self.seat_ceiling > 0:
            limit = min(limit, self.seat_ceiling)
        return limit

    def touch_seat(self, worker_id: int, seat_ttl: float | None = None,
                   base_seats: int | None = None) -> bool:
        """Hold or re-claim this worker's seat. A live seat renews; an expired
        seat re-activates only if a vacancy exists under the dynamic limit."""
        seat_ttl = self.seat_ttl if seat_ttl is None else seat_ttl
        base_seats = self.base_seats if base_seats is None else base_seats
        with self._tx() as db:
            row = db.execute("SELECT seat_expires FROM workers WHERE id=?", (worker_id,)).fetchone()
            if row is None:
                raise KeyError("no such worker")
            now = time.time()
            if row["seat_expires"] < now:
                if self._active_seats(db) >= self._effective_seats(db, base_seats):
                    raise PermissionError(
                        "no seats free: your seat expired while you were away and the "
                        "project is at its work-sized seat limit; retry when work opens up")
            db.execute("UPDATE workers SET seat_expires=?, heartbeat=? WHERE id=?",
                       (now + seat_ttl, now, worker_id))
            return True

    def worker_name(self, worker_id: int) -> str:
        row = self._db.execute("SELECT name FROM workers WHERE id=?", (worker_id,)).fetchone()
        return row["name"] if row else "?"

    def promote(self, worker_id: int) -> None:
        with self._tx() as db:
            db.execute("UPDATE keys SET trusted=1 WHERE id="
                       "(SELECT key_id FROM workers WHERE id=?)", (worker_id,))

    def demote(self, worker_id: int) -> None:
        with self._tx() as db:
            db.execute("UPDATE keys SET trusted=0 WHERE id="
                       "(SELECT key_id FROM workers WHERE id=?)", (worker_id,))

    def is_trusted(self, key: str) -> bool:
        row = self._db.execute("SELECT trusted, revoked FROM keys WHERE key_hash=?",
                               (_hash(key),)).fetchone()
        return bool(row and not row["revoked"] and row["trusted"])

    def worker_id(self, key: str) -> int:
        with self._tx() as db:
            row = db.execute(
                "SELECT w.id FROM workers w JOIN keys k ON k.id=w.key_id WHERE k.key_hash=?",
                (_hash(key),)).fetchone()
            if row is None:
                raise KeyError("not a worker key")
            return row["id"]

    # ------------------------------------------------------------- work

    def sync_work(self, tasks: list[dict], policy_version: int) -> None:
        with self._tx() as db:
            for task in tasks:
                db.execute(
                    "INSERT OR IGNORE INTO work(work_id,kind,args,status,gen,policy_version) "
                    "VALUES(?,?,?,'open',0,?)",
                    (task["id"], task.get("kind", ""), json.dumps(task.get("args", {})), policy_version))

    def expire_leases(self, now: float | None = None) -> None:
        with self._tx() as db:
            db.execute("DELETE FROM leases WHERE expires_at < ?", (now or time.time(),))

    def claim(self, worker_id: int, ttl: float = CLAIM_TTL_SECONDS) -> dict | None:
        with self._tx() as db:
            db.execute("DELETE FROM leases WHERE expires_at < ?", (time.time(),))
            row = db.execute(
                "SELECT w.work_id, w.kind, w.args FROM work w "
                "WHERE w.status='open' AND w.work_id NOT IN (SELECT work_id FROM leases) "
                "ORDER BY w.work_id LIMIT 1").fetchone()
            if row is None:
                return None
            db.execute("UPDATE work SET gen = gen + 1 WHERE work_id=?", (row["work_id"],))
            gen = db.execute("SELECT gen FROM work WHERE work_id=?", (row["work_id"],)).fetchone()["gen"]
            db.execute("INSERT OR REPLACE INTO leases(work_id,worker_id,generation,expires_at) VALUES(?,?,?,?)",
                       (row["work_id"], worker_id, gen, time.time() + ttl))
            return {"work_id": row["work_id"], "generation": gen, "kind": row["kind"],
                    "args": json.loads(row["args"]), "expires_at": time.time() + ttl}

    def renew(self, worker_id: int, work_id: str, ttl: float = CLAIM_TTL_SECONDS) -> bool:
        with self._tx() as db:
            cur = db.execute("UPDATE leases SET expires_at=? WHERE work_id=? AND worker_id=?",
                             (time.time() + ttl, work_id, worker_id))
            return cur.rowcount > 0

    def release(self, worker_id: int, work_id: str) -> None:
        with self._tx() as db:
            db.execute("DELETE FROM leases WHERE work_id=? AND worker_id=?", (work_id, worker_id))

    def validate_lease(self, work_id: str, worker_id: int, generation: int) -> bool:
        with self._tx() as db:
            row = db.execute(
                "SELECT generation, expires_at FROM leases WHERE work_id=? AND worker_id=?",
                (work_id, worker_id)).fetchone()
            return bool(row and row["generation"] == generation and row["expires_at"] >= time.time())

    def complete(self, work_id: str, status: str) -> None:
        with self._tx() as db:
            db.execute("UPDATE work SET status=? WHERE work_id=?", (status, work_id))
            db.execute("DELETE FROM leases WHERE work_id=?", (work_id,))

    def reopen(self, work_id: str) -> None:
        with self._tx() as db:
            db.execute("UPDATE work SET status='open' WHERE work_id=?", (work_id,))
            db.execute("DELETE FROM leases WHERE work_id=?", (work_id,))

    def heartbeat(self, worker_id: int) -> None:
        with self._tx() as db:
            db.execute("UPDATE workers SET heartbeat=? WHERE id=?", (time.time(), worker_id))

    # -------------------------------------------------------- submissions

    def record_submission(self, work_id: str, worker_id: int, generation: int,
                          policy_version: int) -> int:
        with self._tx() as db:
            cur = db.execute(
                "INSERT INTO submissions(work_id,worker_id,generation,policy_version,status,created) "
                "VALUES(?,?,?,?, 'pending', ?)",
                (work_id, worker_id, generation, policy_version, time.time()))
            return cur.lastrowid

    def set_submission_status(self, submission_id: int, status: str, attestation: dict) -> None:
        with self._tx() as db:
            db.execute("UPDATE submissions SET status=?, attestation=? WHERE id=?",
                       (status, json.dumps(attestation), submission_id))

    def queue_reverify(self, submission_id: int, work_id: str, worker_id: int,
                       args: dict, files: dict) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT OR REPLACE INTO reverify"
                "(submission_id,work_id,worker_id,args,files) VALUES(?,?,?,?,?)",
                (submission_id, work_id, worker_id, json.dumps(args),
                 json.dumps(files)))

    def pending_reverify(self) -> list[dict]:
        rows = self._db.execute(
            "SELECT submission_id,work_id,worker_id,args,files "
            "FROM reverify ORDER BY submission_id").fetchall()
        return [
            {"submission_id": row["submission_id"], "work_id": row["work_id"],
             "worker_id": row["worker_id"], "args": json.loads(row["args"]),
             "files": json.loads(row["files"])}
            for row in rows
        ]

    def finish_reverify(self, submission_id: int) -> None:
        with self._tx() as db:
            db.execute(
                "DELETE FROM reverify WHERE submission_id=?", (submission_id,))

    def progress(self) -> dict:
        with self._tx() as db:
            self._db.execute("DELETE FROM leases WHERE expires_at < ?", (time.time(),))
            open_ = self._db.execute(
                "SELECT COUNT(*) n FROM work w WHERE w.status='open' "
                "AND w.work_id NOT IN (SELECT work_id FROM leases)").fetchone()["n"]
            leased = self._db.execute(
                "SELECT COUNT(*) n FROM work w JOIN leases l ON l.work_id=w.work_id "
                "WHERE w.status='open'").fetchone()["n"]
            merged = self._db.execute("SELECT COUNT(*) n FROM work WHERE status='merged'").fetchone()["n"]
            rejected = self._db.execute(
                "SELECT COUNT(*) n FROM submissions WHERE status='rejected'").fetchone()["n"]
        policy = self.get_policy()
        return {"open": open_, "leased": leased, "merged": merged, "rejected": rejected,
                "policy_version": policy["policy_version"]}

    # -------------------------------------------------------- events/policy

    def add_event(self, kind: str, detail: str) -> None:
        with self._tx() as db:
            db.execute("INSERT INTO events(ts,kind,detail) VALUES(?,?,?)", (time.time(), kind, detail))

    def events(self, since: int = 0, limit: int = 100) -> list[dict]:
        rows = self._db.execute(
            "SELECT id, ts, kind, detail FROM events WHERE id>? ORDER BY id LIMIT ?",
            (since, limit)).fetchall()
        return [dict(r) for r in rows]

    def set_policy(self, version: int, hash_: str) -> None:
        with self._tx() as db:
            db.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('policy',?)",
                       (json.dumps({"policy_version": version, "policy_hash": hash_}),))

    def get_policy(self) -> dict:
        row = self._db.execute("SELECT v FROM meta WHERE k='policy'").fetchone()
        if row is None:
            return {"policy_version": 0, "policy_hash": ""}
        return json.loads(row["v"])


class _Tx:
    def __init__(self, db: sqlite3.Connection, lock: threading.Lock):
        self._db, self._lock = db, lock

    def __enter__(self) -> sqlite3.Connection:
        self._lock.acquire()
        return self._db

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._db.commit()
            else:
                self._db.rollback()
        finally:
            self._lock.release()
