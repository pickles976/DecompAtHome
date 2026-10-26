from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ElementTree

import pytest

from recomp.claims import LeaseTransition, render_lease_transition
from recomp.contracts import CandidateKey, Sha256
from recomp.github_api import GitHubError
from recomp.merge import MergeRefused, merge_verified_pull
from recomp.progress import (
    ProgressSnapshot,
    TaskProgress,
    collect_progress,
    commit_progress_update,
    render_progress_json,
    render_progress_svg,
)
from recomp.task_records import TaskRecord, render_task_record
from recomp.verification import VerificationAttestation

POLICY = Sha256("1" * 64)
TOOLCHAIN = Sha256("2" * 64)
TARGET = Sha256("3" * 64)
BOT = 99
HEAD = "a" * 40
BASE = "b" * 40


def task_record(task_id="strings-0000", generation=3, weight=64):
    return TaskRecord.from_mapping({
        "schema": 1, "task_id": task_id, "kind": "t1-strings",
        "args": {"offset": 0, "length": 64},
        "outputs": [{"path": f"recovery/{task_id}.json", "media_type": "application/json",
                     "max_bytes": 4096}],
        "policy_version": 2, "policy_hash": POLICY.hex, "toolchain_digest": TOOLCHAIN.hex,
        "target_sha256": TARGET.hex, "weight": weight, "generation": generation,
    })


def candidate_key(task_id="strings-0000", generation=4, head=HEAD, base=BASE):
    return CandidateKey(
        task_id=task_id, lease_generation=generation, policy_hash=POLICY,
        base_sha=base, head_sha=head, tree_sha="c" * 40, toolchain_digest=TOOLCHAIN,
    )


def attestation(key=None, passed=True):
    return VerificationAttestation(
        candidate_key=key or candidate_key(), verifier_policy_hash=POLICY, mode="static",
        passed=passed, evidence={"outputs": 1}, reason_codes=() if passed else ("x",),
        started_at=1000, completed_at=1001,
    )


class FakeGitHub:
    def __init__(self):
        self.record = task_record()
        self.lease = LeaseTransition(
            task_id="strings-0000", phase="verifying", claimant_id=7, claimant_login="alice",
            generation=4, issued_at=900, expires_at=99999, last_command_id=10,
            candidate_key=candidate_key(), issue_number=12,
        )
        self.pull = {
            "number": 5, "state": "open", "draft": False, "mergeable_state": "clean",
            "user": {"id": 7}, "head": {"sha": HEAD},
            "base": {"ref": "main", "sha": BASE, "repo": {"full_name": "acme/game"}},
        }
        self.refs = {"heads/main": BASE}
        self.merge_calls = []
        self.label_calls = []
        self.closed = []
        self.created = {"blobs": [], "trees": [], "commits": []}
        self.ref_updates = []
        self.ref_conflicts = 0
        self.merge_error = None
        self.check_conclusion = "success"
        self.issues = []

    def move(self, what):
        if what == "head":
            self.pull["head"]["sha"] = "f" * 40
        elif what == "base":
            self.refs["heads/main"] = "e" * 40
            self.pull["base"]["sha"] = "e" * 40
        elif what == "policy":
            self.record = TaskRecord.from_mapping({
                **json.loads(json.dumps(self.record.to_mapping())),
                "policy_hash": "9" * 64, "policy_version": 3,
            })
        elif what == "lease":
            self.lease = LeaseTransition(
                task_id="strings-0000", phase="claimed", claimant_id=7, claimant_login="alice",
                generation=5, issued_at=950, expires_at=99999, last_command_id=11,
                issue_number=12,
            )
        else:
            raise AssertionError(what)

    # client surface
    def get_pull(self, number):
        return self.pull

    def get_ref(self, ref):
        return {"object": {"sha": self.refs[ref.removeprefix("refs/")]}}

    def list_comments(self, issue_number):
        return iter([
            {"id": 1, "user": {"id": BOT, "login": "app"},
             "body": render_task_record(self.record), "created_at": "1970-01-01T00:00:01Z"},
            {"id": 2, "user": {"id": BOT, "login": "app"},
             "body": render_lease_transition(self.lease), "created_at": "1970-01-01T00:10:00Z"},
        ])

    def list_check_runs(self, head_sha):
        return iter([{"name": "recomp verification", "head_sha": head_sha,
                      "status": "completed", "conclusion": self.check_conclusion}])

    def merge_pull(self, number, expected_head_sha, **body):
        self.merge_calls.append((number, expected_head_sha, body))
        if self.merge_error is not None:
            raise self.merge_error
        return {"merged": True, "sha": "d" * 40}

    def set_issue_labels(self, issue_number, labels):
        self.label_calls.append((issue_number, list(labels)))
        return {"labels": labels}

    def update_issue(self, issue_number, body):
        self.closed.append((issue_number, dict(body)))
        return {"number": issue_number, **dict(body)}

    def create_comment(self, issue_number, text):
        return {"id": 3, "body": text}

    def list_issues(self):
        return iter(list(self.issues))

    def get_tree(self, sha, recursive=False):
        return {"sha": sha, "truncated": False, "tree": []}

    def create_blob(self, body):
        self.created["blobs"].append(dict(body))
        return {"sha": f"blob{len(self.created['blobs']):036x}"}

    def create_tree(self, body):
        self.created["trees"].append(dict(body))
        return {"sha": f"tree{len(self.created['trees']):036x}"}

    def create_commit(self, body):
        self.created["commits"].append(dict(body))
        return {"sha": f"comm{len(self.created['commits']):036x}"}

    def update_ref(self, ref, sha, force=False):
        self.ref_updates.append((ref, sha, force))
        if self.ref_conflicts > 0:
            self.ref_conflicts -= 1
            raise GitHubError(422, "reference cannot be fast-forwarded")
        self.refs[ref.removeprefix("refs/")] = sha
        return {"object": {"sha": sha}}


@pytest.fixture
def github():
    return FakeGitHub()


def test_verified_pull_merges_with_exact_head_then_closes_issue(github):
    result = merge_verified_pull(github, attestation(), pr_number=5, issue_number=12,
                                 trusted_actor_id=BOT, now=2000)
    assert result.merged
    number, expected_head, body = github.merge_calls[0]
    assert (number, expected_head) == (5, HEAD)
    assert body["merge_method"] == "squash"
    assert body["commit_title"] == "strings-0000: t1-strings (#5)"
    assert github.closed == [(12, {"state": "closed"})]
    assert github.label_calls[-1] == (12, ["recomp-task", "done"])


@pytest.mark.parametrize("moved", ["head", "base", "policy", "lease"])
def test_any_verified_input_movement_refuses_merge(github, moved):
    github.move(moved)
    with pytest.raises(MergeRefused, match=moved):
        merge_verified_pull(github, attestation(), pr_number=5, issue_number=12,
                            trusted_actor_id=BOT, now=2000)
    assert github.merge_calls == []
    assert github.closed == []


def test_failed_attestation_never_merges(github):
    with pytest.raises(MergeRefused, match="attestation"):
        merge_verified_pull(github, attestation(passed=False), pr_number=5, issue_number=12,
                            trusted_actor_id=BOT, now=2000)
    assert github.merge_calls == []


def test_failed_required_check_refuses_merge(github):
    github.check_conclusion = "failure"
    with pytest.raises(MergeRefused, match="check"):
        merge_verified_pull(github, attestation(), pr_number=5, issue_number=12,
                            trusted_actor_id=BOT, now=2000)
    assert github.merge_calls == []


def test_closed_pull_or_issue_refuses_merge(github):
    github.pull["state"] = "closed"
    with pytest.raises(MergeRefused, match="open"):
        merge_verified_pull(github, attestation(), pr_number=5, issue_number=12,
                            trusted_actor_id=BOT, now=2000)


@pytest.mark.parametrize("status", [409, 422])
def test_head_movement_during_merge_invalidates_attestation(github, status):
    github.merge_error = GitHubError(status, "head sha mismatch")
    with pytest.raises(MergeRefused, match="invalidated"):
        merge_verified_pull(github, attestation(), pr_number=5, issue_number=12,
                            trusted_actor_id=BOT, now=2000)
    assert github.closed == []


def snapshot():
    return ProgressSnapshot(
        project="Acme <Game> & Co",
        generated_at=2000,
        tasks=(
            TaskProgress(task_id="strings-0001", kind="t1-strings", status="done", weight=64),
            TaskProgress(task_id="strings-0000", kind="t1-strings", status="claimed", weight=64),
            TaskProgress(task_id="strings-0002", kind="t1-strings", status="open", weight=32),
        ),
    )


def test_progress_snapshot_is_canonically_ordered_and_serialized():
    payload = render_progress_json(snapshot())
    assert payload.endswith("\n")
    assert ", " not in payload
    data = json.loads(payload)
    assert [task["task_id"] for task in data["tasks"]] == [
        "strings-0000", "strings-0001", "strings-0002"]
    assert data["totals"] == {"tasks": 3, "done": 1, "claimed": 1, "open": 1,
                              "weight_total": 160, "weight_done": 64}
    assert render_progress_json(snapshot()) == payload


def test_progress_svg_is_deterministic_and_script_free():
    first = render_progress_svg(snapshot())
    second = render_progress_svg(snapshot())
    assert first == second
    lowered = first.lower()
    for forbidden in ("<script", "foreignobject", "@import", "<image", "xlink", "<a "):
        assert forbidden not in lowered
    assert set(re.findall(r"https?://[^\"'\s>]+", first)) == {"http://www.w3.org/2000/svg"}
    root = ElementTree.fromstring(first)
    assert root.tag.endswith("svg")
    text = " ".join(element.text or "" for element in root.iter())
    assert "Acme <Game> & Co" in text
    assert "1/3" in text or "1 / 3" in text


def test_progress_svg_escapes_contributor_controlled_labels():
    hostile = ProgressSnapshot(
        project="ok",
        generated_at=1,
        tasks=(TaskProgress(task_id='</text><script>alert(1)</script>', kind="t1",
                            status="open", weight=1),),
    )
    rendered = render_progress_svg(hostile)
    assert "<script>" not in rendered
    assert "&lt;/text&gt;" in rendered or "&lt;script&gt;" in rendered
    ElementTree.fromstring(rendered)


def test_progress_commit_writes_both_files_in_one_commit(github):
    result = commit_progress_update(github, snapshot(), branch="main", now=2000)
    assert result.commit_sha.startswith("comm")
    paths = {entry["path"] for entry in github.created["trees"][-1]["tree"]}
    assert paths == {"docs/progress.json", "docs/progress.svg"}
    assert len(github.created["commits"]) == 1
    assert github.created["commits"][0]["parents"] == [BASE]
    assert github.ref_updates[-1] == ("heads/main", result.commit_sha, False)


def test_concurrent_ref_movement_retries_from_the_new_base(github):
    github.ref_conflicts = 1
    commit_progress_update(github, snapshot(), branch="main", now=2000)
    assert len(github.ref_updates) == 2
    assert len(github.created["commits"]) == 2


def test_collect_progress_derives_state_from_trusted_records_not_labels(github):
    github.issues = [
        {"number": 12, "state": "open", "user": {"id": BOT},
         "body": "<!-- recomp-task:strings-0000 -->", "labels": [{"name": "open"}]},
        {"number": 99, "state": "open", "user": {"id": 1234},
         "body": "<!-- recomp-task:forged-0000 -->", "labels": [{"name": "done"}]},
    ]
    result = collect_progress(github, project="game", trusted_actor_id=BOT, now=2000)
    assert [task.task_id for task in result.tasks] == ["strings-0000"]
    assert result.tasks[0].status == "verifying"
    assert result.tasks[0].weight == 64
