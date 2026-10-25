import sqlite3

import pytest

from recomp.state import Store


def test_existing_state_schema_gains_seat_and_trust_columns(tmp_path):
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE keys(
          id INTEGER PRIMARY KEY, role TEXT NOT NULL, name TEXT UNIQUE,
          key_hash TEXT UNIQUE NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
          last_seen REAL);
        CREATE TABLE workers(
          id INTEGER PRIMARY KEY, key_id INTEGER UNIQUE NOT NULL, name TEXT,
          heartbeat REAL);
    """)
    db.close()
    migrated = Store(path)
    key_columns = {row["name"] for row in migrated._db.execute("PRAGMA table_info(keys)")}
    worker_columns = {
        row["name"] for row in migrated._db.execute("PRAGMA table_info(workers)")}
    assert "trusted" in key_columns
    assert "seat_expires" in worker_columns

@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "state.db")
    s.create_owner_key()
    return s


def enroll(store, name, base_seats=1, seat_ttl=600):
    token = store.mint_enroll_token()
    return store.redeem_enroll_token(
        token, name, base_seats=base_seats, seat_ttl=seat_ttl)


def expire_seat(store, key):
    worker_id = store.worker_id(key)
    with store._tx() as db:
        db.execute("UPDATE workers SET seat_expires=0 WHERE id=?", (worker_id,))


def test_base_seat_blocks_second_agent_when_no_work_exists(store):
    enroll(store, "alice", base_seats=1)
    with pytest.raises(PermissionError, match="seats"):
        enroll(store, "bob", base_seats=1)


def test_open_unleased_work_expands_available_seats(store):
    store.sync_work([
        {"id": "one"}, {"id": "two"}, {"id": "three"},
    ], policy_version=1)
    enroll(store, "alice", base_seats=1)
    enroll(store, "bob", base_seats=1)
    enroll(store, "carol", base_seats=1)
    with pytest.raises(PermissionError, match="seats"):
        enroll(store, "dave", base_seats=1)

def test_seat_frees_on_expiry_and_new_agent_takes_it(store):
    k = enroll(store, "alice", base_seats=1, seat_ttl=60)
    expire_seat(store, k)
    kb = enroll(store, "bob", base_seats=1, seat_ttl=60)
    assert store.key_role(kb) == "worker"


def test_returning_agent_reactivates_seat_when_vacant(store):
    k = enroll(store, "alice", base_seats=1, seat_ttl=60)
    wid = store.worker_id(k)
    expire_seat(store, k)
    store.touch_seat(wid, seat_ttl=60, base_seats=1)
    with pytest.raises(PermissionError, match="seats"):
        enroll(store, "bob", base_seats=1)


def test_reactivation_refused_when_seats_full(store):
    ka = enroll(store, "alice", base_seats=1, seat_ttl=60)
    wa = store.worker_id(ka)
    expire_seat(store, ka)
    enroll(store, "bob", base_seats=1)
    with pytest.raises(PermissionError, match="seats"):
        store.touch_seat(wa, seat_ttl=60, base_seats=1)


def test_trust_survives_seat_expiry(store):
    k = enroll(store, "alice", base_seats=1, seat_ttl=60)
    store.promote(store.worker_id(k))
    assert store.is_trusted(k)
    expire_seat(store, k)
    assert store.is_trusted(k), "earned collaborator trust must survive seat expiry"


def test_promote_and_demote(store):
    k = enroll(store, "alice")
    wid = store.worker_id(k)
    assert not store.is_trusted(k)
    store.promote(wid)
    assert store.is_trusted(k)
    store.demote(wid)
    assert not store.is_trusted(k)


def test_worker_name_lookup(store):
    k = enroll(store, "alice")
    assert store.worker_name(store.worker_id(k)) == "alice"
