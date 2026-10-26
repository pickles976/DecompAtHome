from __future__ import annotations

from dataclasses import replace

import pytest

from recomp.claims import (
    CLAIM_TTL_SECONDS,
    MAX_CLOCK_SKEW_SECONDS,
    ClaimCommand,
    ClaimError,
    LeaseTransition,
    begin_verification,
    complete_verification,
    parse_command,
    reconcile_claims,
)
from recomp.contracts import CandidateKey, Sha256
from recomp.task_records import TaskRecord


def task_record():
    return TaskRecord.from_mapping({
        "schema": 1,
        "task_id": "strings-0000",
        "kind": "t1-strings",
        "args": {"offset": 0, "length": 64},
        "outputs": [{"path": "recovery/strings/strings-0000.json",
                     "media_type": "application/json", "max_bytes": 65536}],
        "policy_version": 2,
        "policy_hash": "1" * 64,
        "toolchain_digest": "2" * 64,
        "target_sha256": "3" * 64,
        "weight": 64,
        "generation": 1,
    })


def command(comment_id, login, user_id, body, *, at):
    return ClaimCommand(comment_id, user_id, login, body, at)


def trusted_lease(login, *, user_id, generation, expires_at, last_command_id=1):
    return LeaseTransition(
        task_id="strings-0000",
        phase="claimed",
        claimant_id=user_id,
        claimant_login=login,
        generation=generation,
        issued_at=expires_at - CLAIM_TTL_SECONDS,
        expires_at=expires_at,
        last_command_id=last_command_id,
    )


def candidate(generation=1, head="3" * 40):
    return CandidateKey(
        task_id="strings-0000",
        lease_generation=generation,
        policy_hash=Sha256("1" * 64),
        base_sha="2" * 40,
        head_sha=head,
        tree_sha="4" * 40,
        toolchain_digest=Sha256("5" * 64),
    )


def test_exact_command_parser():
    assert parse_command(" /claim\n") == "/claim"
    assert parse_command("/heartbeat") == "/heartbeat"
    for body in ("/claim please", "prefix /claim", "/Claim", "/heartbeat now", ""):
        assert parse_command(body) is None


def test_claim_and_heartbeat_each_set_two_hour_expiry():
    task = task_record()
    state = reconcile_claims(task, [], [command(10, "alice", 101, "/claim", at=1000)], now=1000)
    assert CLAIM_TTL_SECONDS == 7200
    assert state.lease.generation == 1
    assert state.lease.expires_at == 8200
    renewed = reconcile_claims(
        task, [state.transition],
        [command(11, "alice-renamed", 101, "/heartbeat", at=2000)],
        now=2000,
    )
    assert renewed.lease.expires_at == 9200
    assert renewed.lease.claimant_login == "alice-renamed"


def test_expired_claim_can_be_reclaimed_with_new_generation():
    prior = trusted_lease("alice", user_id=101, generation=7, expires_at=500)
    state = reconcile_claims(
        task_record(), [prior],
        [command(12, "bob", 202, "/claim", at=501)], now=501,
    )
    assert (state.lease.claimant_id, state.lease.generation) == (202, 8)


def test_author_id_not_mutable_login_controls_heartbeat():
    lease = trusted_lease("alice", user_id=101, generation=1, expires_at=9000)
    state = reconcile_claims(
        task_record(), [lease],
        [command(2, "alice", 202, "/heartbeat", at=2000)], now=2000,
    )
    assert state.lease.expires_at == 9000
    assert state.transition.last_command_id == 2
    assert state.transition.claimant_id == 101
    state = reconcile_claims(
        task_record(), [lease],
        [command(3, "renamed", 101, "/heartbeat", at=2000)], now=2000,
    )
    assert state.lease.claimant_login == "renamed"
    assert state.lease.expires_at == 9200


def test_replayed_and_duplicate_comments_are_consumed_once():
    lease = trusted_lease("alice", user_id=101, generation=2, expires_at=9000, last_command_id=10)
    state = reconcile_claims(
        task_record(), [lease],
        [
            command(10, "alice", 101, "/heartbeat", at=2000),
            command(11, "alice", 101, "/heartbeat", at=2000),
            command(11, "alice", 101, "/heartbeat", at=2000),
        ],
        now=2000,
    )
    assert state.lease.expires_at == 9200
    assert state.transition.last_command_id == 11
    replay = reconcile_claims(task_record(), [state.transition], [command(11, "alice", 101, "/heartbeat", at=3000)], now=3000)
    assert replay.transition is None
    assert replay.lease == state.lease


def test_commands_in_same_second_are_ordered_by_immutable_comment_id():
    state = reconcile_claims(
        task_record(), [],
        [
            command(20, "bob", 202, "/claim", at=1000),
            command(19, "alice", 101, "/claim", at=1000),
        ],
        now=1000,
    )
    assert state.lease.claimant_id == 101
    assert state.transition.last_command_id == 20


def test_dropped_event_reconciliation_uses_comment_time_not_poll_time():
    state = reconcile_claims(
        task_record(), [],
        [command(1, "alice", 101, "/claim", at=1000)], now=9000,
    )
    assert state.lease is None
    assert state.transition.expires_at == 8200
    assert state.transition.last_command_id == 1


def test_done_and_blocked_tasks_refuse_new_claims_and_ignore_labels():
    for status in ("done", "blocked"):
        state = reconcile_claims(
            task_record(), [],
            [command(1, "alice", 101, "/claim", at=1000)],
            now=1000,
            task_status=status,
            presentation_labels=["open", "claimed"],
        )
        assert state.lease is None
        assert state.transition is None
        assert state.task_status == status


def test_future_comment_beyond_clock_skew_is_not_consumed():
    with pytest.raises(ClaimError, match="clock skew"):
        reconcile_claims(
            task_record(), [],
            [command(1, "alice", 101, "/claim", at=1000 + MAX_CLOCK_SKEW_SECONDS + 1)],
            now=1000,
        )


def test_begin_and_complete_verification_bind_candidate_and_generation():
    lease = trusted_lease("alice", user_id=101, generation=3, expires_at=9000)
    key = candidate(generation=3)
    verifying = begin_verification(lease, key, now=2000, ttl_seconds=300)
    assert verifying.phase == "verifying"
    assert verifying.candidate_key == key
    assert verifying.expires_at == 2300
    accepted = complete_verification(verifying, "accepted", now=2100)
    assert accepted.phase == "done"
    assert accepted.expires_at is None


def test_rejection_and_inconclusive_restore_same_claimant_two_hour_lease():
    verifying = begin_verification(
        trusted_lease("alice", user_id=101, generation=3, expires_at=9000),
        candidate(generation=3),
        now=2000,
        ttl_seconds=300,
    )
    for verdict in ("rejected", "inconclusive"):
        resumed = complete_verification(verifying, verdict, now=2200)
        assert resumed.phase == "claimed"
        assert resumed.claimant_id == 101
        assert resumed.generation == 3
        assert resumed.expires_at == 2200 + 7200
        assert resumed.verdict == verdict


def test_new_head_replaces_only_verification_candidate():
    lease = trusted_lease("alice", user_id=101, generation=3, expires_at=9000)
    first = begin_verification(lease, candidate(generation=3), now=2000, ttl_seconds=300)
    replacement = begin_verification(
        first, candidate(generation=3, head="6" * 40), now=2050, ttl_seconds=300)
    assert replacement.candidate_key.head_sha == "6" * 40
    assert replacement.generation == first.generation
    assert replacement.claimant_id == first.claimant_id
    with pytest.raises(ClaimError, match="generation"):
        begin_verification(lease, candidate(generation=4), now=2000, ttl_seconds=300)


def test_invalid_verdict_is_rejected():
    verifying = begin_verification(
        trusted_lease("alice", user_id=101, generation=1, expires_at=9000),
        candidate(), now=1000, ttl_seconds=60,
    )
    with pytest.raises(ClaimError, match="verdict"):
        complete_verification(verifying, "maybe", now=1001)


def test_release_expires_the_lease_so_the_task_returns_to_the_pool():
    record = task_record()
    claim = command(1, "alice", 11, "/claim", at=1000)
    first = reconcile_claims(record, (), [claim], now=1000)
    assert first.lease is not None and first.lease.phase == "claimed"

    release = command(2, "alice", 11, "/release", at=1500)
    after = reconcile_claims(record, (first.transition,), [claim, release], now=1500)
    assert after.lease is None, "a released lease must not stay live"
    assert after.transition is not None and after.transition.expires_at == 1500
    assert after.task_status == "open"


def test_release_from_another_account_is_ignored():
    record = task_record()
    claim = command(1, "alice", 11, "/claim", at=1000)
    first = reconcile_claims(record, (), [claim], now=1000)
    intruder = command(2, "mallory", 99, "/release", at=1200)
    after = reconcile_claims(record, (first.transition,), [claim, intruder], now=1200)
    assert after.lease is not None, "only the claimant may release a lease"
    assert after.lease.claimant_id == 11
    assert after.lease.expires_at == 1000 + CLAIM_TTL_SECONDS


def test_release_then_claim_grants_a_fresh_generation_to_a_new_claimant():
    record = task_record()
    claim = command(1, "alice", 11, "/claim", at=1000)
    first = reconcile_claims(record, (), [claim], now=1000)
    release = command(2, "alice", 11, "/release", at=1100)
    released = reconcile_claims(record, (first.transition,), [claim, release], now=1100)
    reclaim = command(3, "bob", 22, "/claim", at=1200)
    after = reconcile_claims(record, (released.transition,),
                             [claim, release, reclaim], now=1200)
    assert after.lease is not None and after.lease.claimant_id == 22
    assert after.lease.generation == released.transition.generation + 1


def test_release_is_only_recognised_as_an_exact_command():
    assert parse_command("/release") == "/release"
    assert parse_command("  /release  ") == "/release"
    assert parse_command("/release now") is None
