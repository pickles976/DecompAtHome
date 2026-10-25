import pytest

from recomp.state import Store


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "state.db")
    s.create_owner_key()
    return s


TASKS = [
    {"id": "t1", "kind": "t1-strings", "args": {"offset": 0, "length": 16}},
    {"id": "t2", "kind": "t1-strings", "args": {"offset": 16, "length": 16}},
]


def test_owner_key_authenticates(store):
    key = store.owner_key
    assert store.key_role(key) == "owner"
    assert store.key_role("ro_forged") is None


def test_enroll_token_is_single_use(store):
    token = store.mint_enroll_token()
    k1 = store.redeem_enroll_token(token, "alice")
    assert store.key_role(k1) == "worker"
    with pytest.raises(Exception, match="token"):
        store.redeem_enroll_token(token, "alice2")


def test_claim_lease_and_fencing(store):
    store.sync_work(TASKS, policy_version=1)
    ka = store.redeem_enroll_token(store.mint_enroll_token(), "alice")
    kb = store.redeem_enroll_token(store.mint_enroll_token(), "bob")
    la = store.claim(worker_id=store.worker_id(ka))
    lb = store.claim(worker_id=store.worker_id(kb))
    assert la["work_id"] != lb["work_id"], "two workers must not get the same item"
    assert la["generation"] == 1


def test_expired_lease_frees_item_and_bumps_generation(store):
    store.sync_work(TASKS, policy_version=1)
    k = store.redeem_enroll_token(store.mint_enroll_token(), "alice")
    wid = store.worker_id(k)
    l1 = store.claim(worker_id=wid)
    store.expire_leases(now=l1["expires_at"] + 1)
    l2 = store.claim(worker_id=wid)
    assert l2["work_id"] == l1["work_id"]
    assert l2["generation"] == l1["generation"] + 1, "reclaim must bump the fencing token"
    # stale submission from generation 1 must fail validation
    assert not store.validate_lease(l1["work_id"], wid, l1["generation"])


def test_submit_with_stale_generation_rejected(store):
    store.sync_work(TASKS, policy_version=1)
    k = store.redeem_enroll_token(store.mint_enroll_token(), "alice")
    wid = store.worker_id(k)
    l1 = store.claim(worker_id=wid)
    store.release(worker_id=wid, work_id=l1["work_id"])
    l2 = store.claim(worker_id=wid)
    assert not store.validate_lease(l1["work_id"], wid, l1["generation"])
    assert store.validate_lease(l2["work_id"], wid, l2["generation"])


def test_progress_counts(store):
    store.sync_work(TASKS, policy_version=1)
    k = store.redeem_enroll_token(store.mint_enroll_token(), "alice")
    wid = store.worker_id(k)
    lease = store.claim(worker_id=wid)
    p = store.progress()
    assert p["open"] == 1 and p["leased"] == 1 and p["merged"] == 0
    store.complete(lease["work_id"], "merged")
    p = store.progress()
    assert p["merged"] == 1 and p["leased"] == 0


def test_policy_persisted(store):
    store.set_policy(3, "deadbeef")
    assert store.get_policy() == {"policy_version": 3, "policy_hash": "deadbeef"}
