from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from recomp.candidate import CandidateTree
from recomp.claims import (
    LeaseTransition,
    parse_lease_transition_body,
    parse_trusted_lease_transitions,
    render_lease_transition,
)
from recomp.contracts import CandidateKey, Sha256
from recomp.coordinator import HEALTH_SCHEMA, Coordinator, CoordinatorConfig
from recomp.coordinator_state import CoordinatorState
from recomp.github_api import GitHubError
from recomp.task_records import TaskRecord, render_task_record
from recomp.verification import VerificationAttestation, VerificationPlan

POLICY = Sha256("1" * 64)
TOOLCHAIN = Sha256("2" * 64)
TARGET = Sha256("3" * 64)
BOT = 99


def task_record(task_id="strings-0000", generation=3):
    return TaskRecord.from_mapping({
        "schema": 1,
        "task_id": task_id,
        "kind": "t1-strings",
        "args": {"offset": 0, "length": 64},
        "outputs": [{"path": "recovery/out.json", "media_type": "application/json",
                     "max_bytes": 4096}],
        "policy_version": 2,
        "policy_hash": POLICY.hex,
        "toolchain_digest": TOOLCHAIN.hex,
        "target_sha256": TARGET.hex,
        "weight": 64,
        "generation": generation,
    })


def pr_body(issue=12, lease=4, generation=3, policy=POLICY, toolchain=TOOLCHAIN):
    return (
        f"Closes #{issue}\n"
        f"Recomp-Policy: sha256:{policy.hex}\n"
        f"Recomp-Toolchain: sha256:{toolchain.hex}\n"
        f"Recomp-Lease: {lease}\n"
        f"Recomp-Task-Generation: {generation}\n"
    )


class FakeGitHub:
    def __init__(self):
        self.pulls = {}
        self.comments = {}
        self.issues = {}
        self.label_updates = []
        self.blobs = {}
        self.trees = {}
        self.files = {}
        self.check_runs = []
        self.check_updates = []
        self.rate_limited = False

    def add_task_issue(self, issue=12, record=None):
        record = record or task_record()
        self.comments.setdefault(issue, []).append({
            "id": 1, "user": {"id": BOT, "login": "app"},
            "body": render_task_record(record), "created_at": "1970-01-01T00:00:01Z",
        })
        return record

    def set_lease(self, issue=12, claimant_id=7, generation=4, expires_at=9999, phase="claimed",
                  task_id="strings-0000"):
        transition = LeaseTransition(
            task_id=task_id, phase=phase, claimant_id=claimant_id,
            claimant_login="alice", generation=generation, issued_at=100,
            expires_at=expires_at, last_command_id=10, issue_number=issue,
        )
        self.comments.setdefault(issue, []).append({
            "id": 100 + generation, "user": {"id": BOT, "login": "app"},
            "body": render_lease_transition(transition), "created_at": "1970-01-01T00:02:00Z",
        })
        return transition

    def add_pr(self, number=5, author_id=7, issue=12, head="a" * 40, base="b" * 40,
               body=None, content=b'{"ok":true}', path="recovery/out.json"):
        blob_sha = f"{number:040x}"
        self.blobs[blob_sha] = {
            "encoding": "base64", "content": base64.b64encode(content).decode(),
            "size": len(content),
        }
        self.trees[head] = {"truncated": False, "tree": [{
            "path": path, "mode": "100644", "type": "blob", "sha": blob_sha,
            "size": len(content),
        }]}
        self.files[number] = [{"filename": path, "status": "modified", "sha": blob_sha}]
        self.pulls[number] = {
            "number": number, "state": "open", "draft": False,
            "user": {"id": author_id},
            "body": body if body is not None else pr_body(issue=issue),
            "head": {"sha": head},
            "base": {"sha": base, "repo": {"full_name": "acme/game"}},
        }
        return self.pulls[number]

    # client surface
    def list_pulls(self):
        if self.rate_limited:
            raise GitHubError(403, "rate limited", rate_limit_reset=1200)
        return iter(list(self.pulls.values()))

    def get_pull(self, number):
        return self.pulls[number]

    def list_comments(self, issue_number):
        return iter(list(self.comments.get(issue_number, [])))

    def create_comment(self, issue_number, text):
        comment = {"id": 500 + len(self.comments.get(issue_number, [])),
                   "user": {"id": BOT, "login": "app"}, "body": text,
                   "created_at": "1970-01-01T00:30:00Z"}
        self.comments.setdefault(issue_number, []).append(comment)
        return comment

    def list_issues(self):
        return iter(list(self.issues.values()))

    def set_issue_labels(self, issue_number, labels):
        self.label_updates.append((issue_number, list(labels)))
        issue = self.issues.get(issue_number)
        if issue is not None:
            issue["labels"] = [{"name": name} for name in labels]
        return {"labels": labels}

    def get_tree(self, sha, recursive=False):
        return self.trees.get(sha, {"truncated": False, "tree": []})

    def list_pull_files(self, number):
        return iter(list(self.files.get(number, [])))

    def get_blob(self, sha):
        return self.blobs[sha]

    def create_check_run(self, body):
        run = {"id": 900 + len(self.check_runs), **dict(body)}
        self.check_runs.append(run)
        return run

    def update_check_run(self, check_run_id, body):
        self.check_updates.append((check_run_id, dict(body)))
        return {"id": check_run_id, **dict(body)}


class FakeVerifier:
    def __init__(self, passed=True, codes=()):
        self.passed = passed
        self.codes = codes
        self.keys = []

    def __call__(self, candidate, target, key, *, now, task_args=None, output_rules=()):
        self.keys.append(key)
        return VerificationAttestation(
            candidate_key=key, verifier_policy_hash=POLICY, mode="static",
            passed=self.passed, evidence={"outputs": 1},
            reason_codes=() if self.passed else tuple(self.codes),
            started_at=now, completed_at=now,
        )


class FakeBuilder:
    def __init__(self, tmp_path, error=None):
        self.tmp_path = tmp_path
        self.error = error
        self.calls = []

    def __call__(self, base_sha, head_sha, *, task_id, lease_generation, policy_hash,
                 toolchain_digest, preflight_report):
        self.calls.append((base_sha, head_sha, task_id, lease_generation))
        if self.error is not None:
            raise self.error
        path = self.tmp_path / f"candidate-{head_sha[:8]}"
        path.mkdir(exist_ok=True)
        key = CandidateKey(
            task_id=task_id, lease_generation=lease_generation, policy_hash=policy_hash,
            base_sha=base_sha, head_sha=head_sha, tree_sha="c" * 40,
            toolchain_digest=toolchain_digest,
        )
        return CandidateTree(key, path)


@pytest.fixture
def github():
    client = FakeGitHub()
    client.add_task_issue()
    client.set_lease()
    return client


@pytest.fixture
def config(tmp_path):
    return CoordinatorConfig(
        repository_url="https://github.com/acme/game.git",
        repository_full_name="acme/game",
        trusted_actor_id=BOT,
        quarantine_root=tmp_path / "quarantine",
        state_path=tmp_path / "state.db",
        health_path=tmp_path / "health.json",
        max_concurrent=2,
        max_per_author=1,
        max_attempts=2,
    )


@pytest.fixture
def plan():
    return VerificationPlan(
        mode="static", public=True, timeout_seconds=30, max_artifact_bytes=4096,
        cases=(), command_id="generic.static", verifier_policy_hash=POLICY,
    )


def make_coordinator(config, github, plan, tmp_path, *, verifier=None, builder=None,
                     state_path=None, merge=None, publish_progress=None):
    """Admission/verification harness; merge and progress have their own e2e suite."""

    return Coordinator(
        config=config if state_path is None else config.with_state_path(state_path),
        github=github,
        plan=plan,
        build_candidate=builder or FakeBuilder(tmp_path),
        verify=verifier or FakeVerifier(),
        merge=merge,
        publish_progress=publish_progress,
    )


def test_coordinator_grants_claim_commands_with_a_trusted_lease(config, plan, tmp_path):
    client = FakeGitHub()
    client.add_task_issue(issue=12)
    client.issues[12] = {"number": 12, "state": "open", "user": {"id": BOT}, "body": "",
                         "labels": [{"name": "recomp-task"}, {"name": "open"}]}
    client.comments[12].append({"id": 300, "user": {"id": 7, "login": "alice"},
                                "body": "/claim", "created_at": "1970-01-01T00:10:00Z"})
    make_coordinator(config, client, plan, tmp_path).reconcile_once(now=1000)
    transitions = parse_trusted_lease_transitions(client.comments[12], BOT)
    assert [t.phase for t in transitions] == ["claimed"]
    assert transitions[0].claimant_id == 7
    assert transitions[0].generation == 1
    assert transitions[0].expires_at == 7800
    assert client.label_updates[-1] == (12, ["recomp-task", "claimed"])
    make_coordinator(config, client, plan, tmp_path).reconcile_once(now=1000)
    assert len(parse_trusted_lease_transitions(client.comments[12], BOT)) == 1


def test_eligible_pull_request_is_admitted_verified_and_reported(config, github, plan, tmp_path):
    github.add_pr()
    verifier = FakeVerifier()
    result = make_coordinator(config, github, plan, tmp_path, verifier=verifier).reconcile_once(now=1000)
    assert [decision.pr_number for decision in result.admitted] == [5]
    assert result.rejected == ()
    assert len(verifier.keys) == 1
    assert verifier.keys[0].head_sha == "a" * 40
    queued = github.check_runs[0]
    assert queued["head_sha"] == "a" * 40
    assert queued["status"] == "queued"
    _, conclusion = github.check_updates[-1]
    assert conclusion["conclusion"] == "success"
    assert "recovery/out.json" not in json.dumps(conclusion)


def test_only_live_claimant_is_admitted(config, github, plan, tmp_path):
    github.add_pr(author_id=9)
    result = make_coordinator(config, github, plan, tmp_path).reconcile_once(now=1000)
    assert result.admitted == ()
    assert result.rejected[0].code == "not-current-claimant"
    assert github.check_runs == []


def test_expired_lease_is_not_admitted(config, github, plan, tmp_path):
    github.comments[12] = github.comments[12][:1]
    github.set_lease(expires_at=500)
    github.add_pr()
    result = make_coordinator(config, github, plan, tmp_path).reconcile_once(now=1000)
    assert result.rejected[0].code == "lease-expired"


def test_stale_policy_or_task_generation_is_refused(config, github, plan, tmp_path):
    github.add_pr(number=5, body=pr_body(policy=Sha256("9" * 64)))
    github.add_pr(number=6, head="d" * 40, body=pr_body(generation=2))
    result = make_coordinator(config, github, plan, tmp_path).reconcile_once(now=1000)
    assert {decision.code for decision in result.rejected} == {"preflight-failed"}
    assert result.admitted == ()


def test_newest_head_supersedes_older_candidate_for_one_issue(config, github, plan, tmp_path):
    github.add_pr(number=5, head="a" * 40)
    github.add_pr(number=6, head="e" * 40)
    result = make_coordinator(config, github, plan, tmp_path).reconcile_once(now=1100)
    admitted_heads = [decision.candidate_key.head_sha for decision in result.admitted]
    assert admitted_heads == ["e" * 40]
    assert any(decision.code == "superseded" for decision in result.rejected)


def test_per_author_and_global_capacity_limits_apply(config, github, plan, tmp_path):
    github.add_task_issue(issue=13, record=task_record(task_id="strings-0001"))
    github.set_lease(issue=13, claimant_id=7, generation=4, task_id="strings-0001")
    github.add_pr(number=5, issue=12, head="a" * 40)
    github.add_pr(number=6, issue=13, head="e" * 40)
    result = make_coordinator(config, github, plan, tmp_path).reconcile_once(now=1000)
    assert len(result.admitted) == 1
    assert any(decision.code == "author-capacity" for decision in result.rejected)


def test_retry_cap_stops_repeated_infrastructure_failures(config, github, plan, tmp_path):
    github.add_pr()
    builder = FakeBuilder(tmp_path, error=RuntimeError("transient git failure"))
    coordinator = make_coordinator(config, github, plan, tmp_path, builder=builder)
    first = coordinator.reconcile_once(now=1000)
    assert first.admitted[0].code == "infrastructure-error"
    coordinator.reconcile_once(now=1100)
    third = coordinator.reconcile_once(now=1200)
    assert any(decision.code == "retry-exhausted" for decision in third.rejected)
    assert len(builder.calls) == 2
    assert all(update["conclusion"] in ("neutral", "failure")
               for _, update in github.check_updates)


def test_rejected_verification_writes_repair_lease_transition(config, github, plan, tmp_path):
    github.add_pr()
    verifier = FakeVerifier(passed=False, codes=("artifact-mismatch",))
    make_coordinator(config, github, plan, tmp_path, verifier=verifier).reconcile_once(now=1000)
    transitions = [parse_lease_transition_body(comment["body"])
                   for comment in github.comments[12]
                   if comment["body"].startswith("<!-- recomp-lease-v1")]
    assert transitions[-1].verdict == "rejected"
    assert transitions[-1].phase == "claimed"
    _, conclusion = github.check_updates[-1]
    assert conclusion["conclusion"] == "failure"
    assert "artifact-mismatch" in json.dumps(conclusion)


def test_verification_lease_is_appended_before_private_compute(config, github, plan, tmp_path):
    github.add_pr()
    builder = FakeBuilder(tmp_path)
    make_coordinator(config, github, plan, tmp_path, builder=builder).reconcile_once(now=1000)
    verifying = [parse_lease_transition_body(comment["body"])
                 for comment in github.comments[12]
                 if comment["body"].startswith("<!-- recomp-lease-v1")]
    assert any(transition.phase == "verifying" for transition in verifying)


def test_empty_local_cache_reconstructs_queue_from_github(config, github, plan, tmp_path):
    """A deleted cache rebuilds the same queue while work is still outstanding."""

    def crashing(_candidate, _target, _key, *, now, task_args=None, output_rules=()):
        raise RuntimeError("interrupted mid-verification")

    github.add_pr()
    first = make_coordinator(config, github, plan, tmp_path, verifier=crashing,
                             state_path=tmp_path / "a.db").reconcile_once(now=1000)
    second = make_coordinator(config, github, plan, tmp_path, verifier=crashing,
                              state_path=tmp_path / "b.db").reconcile_once(now=1001)
    assert second.pending_keys == first.pending_keys
    assert first.pending_keys


def test_cached_rows_for_closed_pulls_are_deleted(config, github, plan, tmp_path):
    github.add_pr()
    coordinator = make_coordinator(config, github, plan, tmp_path)
    coordinator.reconcile_once(now=1000)
    github.pulls.clear()
    result = coordinator.reconcile_once(now=1100)
    assert result.pending_keys == ()
    with CoordinatorState(config.state_path) as state:
        assert state.rows() == []


def test_rate_limit_is_surfaced_without_crashing_the_loop(config, github, plan, tmp_path):
    github.rate_limited = True
    coordinator = make_coordinator(config, github, plan, tmp_path)
    result = coordinator.reconcile_once(now=1000)
    assert result.rate_limited_until == 1200
    assert result.admitted == ()


def test_health_file_is_atomic_and_schema_versioned(config, github, plan, tmp_path):
    github.add_pr()
    coordinator = make_coordinator(config, github, plan, tmp_path)
    coordinator.reconcile_once(now=1000)
    coordinator.write_health(now=1000)
    health = json.loads(config.health_path.read_text())
    assert health["schema"] == HEALTH_SCHEMA
    assert health["last_reconcile_at"] == 1000
    assert set(health) >= {"schema", "last_reconcile_at", "pending", "admitted_total",
                           "merged_total", "verified_unmerged", "progress_failures"}
    # merge is disabled in this harness, so a verified candidate is exactly the
    # pile an operator has to act on: it never became a merge.
    assert (health["merged_total"], health["verified_unmerged"], health["progress_failures"]) \
        == (0, 1, 0)
    assert not list(config.health_path.parent.glob("*.tmp"))


def test_coordinator_never_opens_a_listener(config, github, plan, tmp_path):
    source = Path("src/recomp/coordinator.py").read_text()
    for forbidden in ("socket.", "HTTPServer", "bind(", "listen("):
        assert forbidden not in source


def test_output_rules_from_the_task_record_reach_the_verifier(config, github, plan, tmp_path):
    """The judge must see the rules the candidate was admitted against."""

    seen = []

    def recording(_candidate, _target, key, *, now, task_args=None, output_rules=()):
        seen.append((dict(task_args or {}), tuple(output_rules)))
        return VerificationAttestation(
            candidate_key=key, verifier_policy_hash=POLICY, mode="static", passed=True,
            evidence={}, reason_codes=(), started_at=now, completed_at=now)

    github.add_pr()
    outcome = make_coordinator(config, github, plan, tmp_path,
                               verifier=recording).reconcile_once(now=1000)
    assert outcome.admitted[0].code == "verified"
    assert seen == [({"offset": 0, "length": 64},
                     ({"path": "recovery/out.json", "media_type": "application/json",
                       "max_bytes": 4096},))]


class FlakyMerge:
    """Fails every attempt in the first pass, then merges: the recovery path."""

    def __init__(self, failures=3):
        self.failures = failures
        self.calls = []

    def __call__(self, github, attestation, *, pr_number, issue_number,
                 trusted_actor_id, now, required_check):
        self.calls.append((pr_number, attestation.candidate_key.head_sha))
        if self.failures > 0:
            self.failures -= 1
            raise GitHubError(502, "bad gateway")
        return {"merged": True, "sha": "f" * 40, "pr_number": pr_number}


def test_verified_but_unmerged_candidate_is_merged_on_a_later_pass(config, github, plan, tmp_path):
    github.add_pr()
    merge = FlakyMerge(failures=3)
    coordinator = make_coordinator(config, github, plan, tmp_path, merge=merge)

    first = coordinator.reconcile_once(now=1000)
    assert first.admitted[0].code == "verified"
    assert first.admitted[0].merge is None
    with CoordinatorState(config.state_path) as state:
        assert [row.status for row in state.rows()] == ["verified"]
    attempts_after_first = len(merge.calls)

    second = coordinator.reconcile_once(now=1100)
    assert second.admitted == (), "a verified candidate is never re-verified"
    assert len(merge.calls) > attempts_after_first, "the later pass must retry the merge"
    assert merge.calls[-1][1] == "a" * 40, "retry must merge exactly the verified head"
    with CoordinatorState(config.state_path) as state:
        assert [row.status for row in state.rows()] == ["merged"]


def test_retry_stops_once_the_pull_request_is_gone(config, github, plan, tmp_path):
    github.add_pr()
    merge = FlakyMerge(failures=99)
    coordinator = make_coordinator(config, github, plan, tmp_path, merge=merge)
    coordinator.reconcile_once(now=1000)
    github.pulls.clear()
    coordinator.reconcile_once(now=1100)
    with CoordinatorState(config.state_path) as state:
        assert state.rows() == [], "a withdrawn submission must not leak a queue row"


def test_refusals_are_published_once_per_head_and_reason(config, plan, tmp_path):
    client = FakeGitHub()
    client.add_task_issue()
    client.set_lease()
    client.add_pr(body="no task reference here")
    coordinator = make_coordinator(config, client, plan, tmp_path)

    coordinator.reconcile_once(now=1000)
    notices = [c for c in client.comments.get(5, []) if "Not admitted" in c["body"]]
    assert len(notices) == 1, "a silent refusal is indistinguishable from a wedged loop"
    assert "no-task-reference" in notices[0]["body"]

    coordinator.reconcile_once(now=1100)
    notices = [c for c in client.comments.get(5, []) if "Not admitted" in c["body"]]
    assert len(notices) == 1, "the same refusal must not repeat every pass"


def test_health_reports_the_running_framework_revision(config, github, plan, tmp_path):
    coordinator = make_coordinator(config, github, plan, tmp_path)
    coordinator.reconcile_once(now=1000)
    payload = json.loads(coordinator.write_health(now=1000).read_text())
    assert payload["framework_revision"], "drift is invisible without the running revision"
