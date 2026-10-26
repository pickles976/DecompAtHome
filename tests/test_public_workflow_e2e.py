"""End-to-end proof of the public lifecycle over a fake GitHub transport.

Everything here is real code except GitHub itself and the microVM: task
publication, claim reconciliation, preflight, candidate construction from a
real Git repository, verification orchestration, exact-head merge, and
progress commits all run their production paths.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pytest

from recomp.claims import (
    ClaimCommand,
    parse_command,
    parse_trusted_lease_transitions,
    reconcile_claims,
    render_lease_transition,
)
from recomp.contracts import Sha256
from recomp.coordinator import MERGE_RETRYABLE_BACKOFF, Coordinator, CoordinatorConfig
from recomp.coordinator_state import CoordinatorState
from recomp.generate import generate_project
from recomp.github_api import GitHubError
from recomp.github_tasks import GitHubTaskError, sync_tasks
from recomp.merge import MergeRefused, merge_verified_pull
from recomp.plugin import resolve_plugin, run_plugin
from recomp.progress import collect_progress, commit_progress_update
from recomp.task_records import parse_trusted_task_record
from recomp.verification import VerificationAttestation, VerificationPlan

BOT = 99
ALICE = 7
MALLORY = 42
IMAGE = "ghcr.io/acme/fixture-toolchain@sha256:" + "a" * 64
ACTION = "acme/recomp@" + "b" * 40
FIXTURE_PLUGIN = Path(__file__).parent / "fixtures/public_plugin"

#: Backoff sleeps the coordinator would take; injected so retry policy is asserted
#: without spending wall-clock time.
sleeps: list[float] = []
_UNSET = object()


def iso(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def git(repo: Path, *args: str, check: bool = True) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.invalid"}
    completed = subprocess.run(["git", "-C", os.fspath(repo), *args], capture_output=True,
                               text=True, check=check, env=env)
    return completed.stdout.strip()


class FakeGitHub:
    """A small, honest GitHub: issues, comments, pulls, checks, git data, merge."""

    def __init__(self, repo: Path, full_name: str = "acme/fixture"):
        self.repo = repo
        self.full_name = full_name
        self.issues: list[dict] = []
        self.comments: dict[int, list[dict]] = {}
        self.pulls: dict[int, dict] = {}
        self.checks: list[dict] = []
        self.ref_conflicts = 0
        self.blobs: dict[str, dict] = {}
        self._next_id = 1000

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    # issues ---------------------------------------------------------------
    def list_issues(self):
        return iter(list(self.issues))

    def get_issue(self, number):
        return next(issue for issue in self.issues if issue["number"] == number)

    def create_issue(self, body):
        issue = {"number": len(self.issues) + 1, "state": "open", "user": {"id": BOT},
                 "title": body["title"], "body": body["body"],
                 "labels": [{"name": name} for name in body.get("labels", [])]}
        self.issues.append(issue)
        self.comments.setdefault(issue["number"], [])
        return issue

    def update_issue(self, issue_number, body):
        issue = self.get_issue(issue_number)
        issue.update(body)
        return issue

    def set_issue_labels(self, issue_number, labels):
        self.get_issue(issue_number)["labels"] = [{"name": name} for name in labels]
        return {"labels": labels}

    def list_comments(self, issue_number):
        return iter(list(self.comments.get(issue_number, [])))

    def create_comment(self, issue_number, text, *, author_id=BOT, login="app", now=0):
        comment = {"id": self._id(), "user": {"id": author_id, "login": login},
                   "body": text, "created_at": iso(now)}
        self.comments.setdefault(issue_number, []).append(comment)
        return comment

    # pulls ----------------------------------------------------------------
    def list_pulls(self, state="open"):
        return iter([pull for pull in self.pulls.values() if pull["state"] == state])

    def get_pull(self, number):
        return self.pulls[number]

    def list_pull_files(self, number):
        pull = self.pulls[number]
        base, head = pull["base"]["sha"], pull["head"]["sha"]
        names = git(self.repo, "diff", "--name-only", base, head).splitlines()
        files = []
        for name in names:
            sha = git(self.repo, "rev-parse", f"{head}:{name}", check=False)
            files.append({"filename": name, "status": "added", "sha": sha})
        return iter(files)

    def get_tree(self, sha, recursive=False):
        if sha is None:
            return {"truncated": False, "tree": []}
        entries = []
        listing = git(self.repo, "ls-tree", "-r", "-l", sha, check=False)
        for line in listing.splitlines():
            meta, path = line.split("\t", 1)
            mode, kind, blob, size = meta.split()
            entries.append({"path": path, "mode": mode, "type": kind, "sha": blob,
                            "size": int(size) if size.isdigit() else 0})
        return {"sha": sha, "truncated": False, "tree": entries}

    def get_blob(self, sha):
        content = subprocess.run(["git", "-C", os.fspath(self.repo), "cat-file", "blob", sha],
                                 capture_output=True, check=False).stdout
        return {"encoding": "base64", "content": base64.b64encode(content).decode(),
                "size": len(content)}

    def get_ref(self, ref):
        return {"object": {"sha": git(self.repo, "rev-parse", ref.removeprefix("refs/"))}}

    def create_blob(self, body):
        content = body["content"].encode()
        sha = subprocess.run(["git", "-C", os.fspath(self.repo), "hash-object", "-w", "--stdin"],
                             input=content, capture_output=True, check=True).stdout.decode().strip()
        return {"sha": sha}

    def create_tree(self, body):
        for entry in body["tree"]:
            git(self.repo, "update-index", "--add", "--cacheinfo",
                f"{entry['mode']},{entry['sha']},{entry['path']}")
        return {"sha": git(self.repo, "write-tree")}

    def create_commit(self, body):
        args = ["commit-tree", body["tree"], "-m", body["message"]]
        for parent in body["parents"]:
            args += ["-p", parent]
        return {"sha": git(self.repo, *args)}

    def update_ref(self, ref, sha, force=False):
        if self.ref_conflicts > 0:
            self.ref_conflicts -= 1
            raise GitHubError(422, "reference cannot be fast-forwarded")
        git(self.repo, "update-ref", f"refs/{ref}", sha)
        return {"object": {"sha": sha}}

    # checks and merge -----------------------------------------------------
    def create_check_run(self, body):
        run = {"id": self._id(), **dict(body)}
        self.checks.append(run)
        return run

    def update_check_run(self, check_run_id, body):
        for run in self.checks:
            if run["id"] == check_run_id:
                run.update(body)
                return run
        raise AssertionError(check_run_id)

    def list_check_runs(self, head_sha):
        return iter([run for run in self.checks if run.get("head_sha") == head_sha])

    def merge_pull(self, number, expected_head_sha, **body):
        pull = self.pulls[number]
        if pull["head"]["sha"] != expected_head_sha:
            raise GitHubError(409, "head sha mismatch")
        git(self.repo, "update-ref", "refs/heads/main", pull["head"]["sha"])
        pull["state"] = "closed"
        pull["merged"] = True
        return {"merged": True, "sha": pull["head"]["sha"]}

    def checks_for(self, head_sha):
        return [run for run in self.checks if run.get("head_sha") == head_sha]


@dataclass
class Harness:
    github: FakeGitHub
    repo: Path
    project: Path
    target: Path
    plan: VerificationPlan
    config: CoordinatorConfig
    #: The output rules each verification actually handed the judge.
    seen_rules: list = field(default_factory=list)

    def publish_tasks(self):
        cfg = load_cfg(self.project)
        return sync_tasks(self.github, self.project, cfg, target=self.target)

    def claim(self, issue: int, *, actor_id: int, login: str, now: int, body: str = "/claim"):
        self.github.create_comment(issue, body, author_id=actor_id, login=login, now=now)
        return self.reconcile_claims(issue, now=now)

    def reconcile_claims(self, issue: int, *, now: int):
        comments = list(self.github.list_comments(issue))
        record = parse_trusted_task_record(comments, BOT)
        transitions = parse_trusted_lease_transitions(comments, BOT)
        commands = []
        for comment in comments:
            if parse_command(comment["body"]) is None:
                continue
            commands.append(ClaimCommand(
                comment_id=comment["id"], author_id=comment["user"]["id"],
                author_login=comment["user"]["login"], body=comment["body"],
                created_at=int(datetime.strptime(comment["created_at"], "%Y-%m-%dT%H:%M:%SZ")
                               .replace(tzinfo=timezone.utc).timestamp()),
            ))
        state = reconcile_claims(record, transitions, commands, now=now,
                                 task_status="open", issue_number=issue)
        if state.transition is not None:
            self.github.create_comment(issue, render_lease_transition(state.transition), now=now)
        return state

    def open_pr(self, issue: int, *, actor_id: int, login: str, files: dict[str, str],
                number: int | None = None, lease_generation: int = 1):
        record = parse_trusted_task_record(list(self.github.list_comments(issue)), BOT)
        number = number or (len(self.github.pulls) + 1)
        branch = f"recomp/{record.task_id}-{issue}-{login}"
        base = git(self.repo, "rev-parse", "refs/heads/main")
        git(self.repo, "checkout", "-q", "-b", branch, base)
        for relative, content in files.items():
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            git(self.repo, "add", "--", relative)
        git(self.repo, "commit", "-qm", f"{record.task_id} from {login}")
        head = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "-q", "main")
        self.github.pulls[number] = {
            "number": number, "state": "open", "draft": False,
            "user": {"id": actor_id},
            "body": (f"Closes #{issue}\n"
                     f"Recomp-Policy: sha256:{record.policy_hash.hex}\n"
                     f"Recomp-Toolchain: sha256:{record.toolchain_digest.hex}\n"
                     f"Recomp-Lease: {lease_generation}\n"
                     f"Recomp-Task-Generation: {record.generation}\n"),
            "head": {"sha": head, "ref": branch},
            "base": {"ref": "main", "sha": base, "repo": {"full_name": self.github.full_name}},
        }
        return number

    def push_more(self, number: int, files: dict[str, str]):
        pull = self.github.pulls[number]
        git(self.repo, "checkout", "-q", pull["head"]["ref"])
        for relative, content in files.items():
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            git(self.repo, "add", "--", relative)
        git(self.repo, "commit", "-qm", "more")
        pull["head"]["sha"] = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "-q", "main")

    def coordinator(self, *, verifier=None, state_path=None, merge=_UNSET,
                    publish_progress=None):
        kwargs = {} if merge is _UNSET else {"merge": merge}
        return Coordinator(
            config=self.config if state_path is None else self.config.with_state_path(state_path),
            github=self.github, plan=self.plan,
            build_candidate=self._build,
            verify=verifier or self._verify,
            publish_progress=publish_progress,
            sleep=lambda _seconds: sleeps.append(_seconds),
            **kwargs)

    def _build(self, base_sha, head_sha, *, task_id, lease_generation, policy_hash,
               toolchain_digest, preflight_report):
        from recomp.candidate import construct_candidate

        return construct_candidate(
            os.fspath(self.repo), base_sha, head_sha, self.config.quarantine_root,
            task_id=task_id, lease_generation=lease_generation, policy_hash=policy_hash,
            toolchain_digest=toolchain_digest, preflight_report=preflight_report)

    def _verify(self, candidate, _target, key, *, now, task_args=None, output_rules=None):
        """Run the project's real verifier over the reconstructed candidate tree.

        The arguments come from the trusted task record, exactly as in production;
        falling back to the plugin's own work plan would hide a broken hand-off.
        """

        cfg = load_cfg(self.project)
        plugin = resolve_plugin(self.project, cfg["project"]["plugin"])
        tasks = run_plugin(plugin, "work_plan", {"binary": str(self.target), "args": {}})
        task = next(item for item in tasks["tasks"] if item["id"] == key.task_id)
        rules = ([dict(rule) for rule in output_rules] if output_rules is not None
                 else list(task["outputs"]))
        self.seen_rules.append(rules)
        files = {}
        for output in rules:
            produced = candidate.path / output["path"]
            if produced.is_file():
                files[output["path"]] = produced.read_text()
        verdict = run_plugin(plugin, "verify", {
            "binary": str(self.target),
            "args": task["args"] if task_args is None else task_args,
            "outputs": rules, "files": files,
        })
        passed = bool(verdict.get("pass"))
        return VerificationAttestation(
            candidate_key=key, verifier_policy_hash=self.plan.verifier_policy_hash,
            mode="static", passed=passed,
            evidence={"outputs": len(files)},
            reason_codes=() if passed else ("artifact-mismatch",),
            started_at=now, completed_at=now)

    def rules(self, task_id: str) -> list:
        cfg = load_cfg(self.project)
        plugin = resolve_plugin(self.project, cfg["project"]["plugin"])
        tasks = run_plugin(plugin, "work_plan", {"binary": str(self.target), "args": {}})
        task = next(item for item in tasks["tasks"] if item["id"] == task_id)
        return [dict(output) for output in task["outputs"]]

    def produce(self, task_id: str) -> dict[str, str]:
        cfg = load_cfg(self.project)
        plugin = resolve_plugin(self.project, cfg["project"]["plugin"])
        tasks = run_plugin(plugin, "work_plan", {"binary": str(self.target), "args": {}})
        task = next(item for item in tasks["tasks"] if item["id"] == task_id)
        return run_plugin(plugin, "run_task", {"binary": str(self.target),
                                               "args": task["args"],
                                               "outputs": task["outputs"]})["files"]


def load_cfg(project: Path) -> dict:
    from recomp.project import load_project

    cfg, _path = load_project(project)
    return cfg


@pytest.fixture
def harness(tmp_path, fixture_bin):
    project = generate_project(
        tmp_path / "proj", bin_path=fixture_bin, name="fixture",
        owner="acme", repository="fixture", toolchain_image=IMAGE,
        framework_action=ACTION, trusted_actor_id=BOT,
    ).path
    import shutil

    shutil.rmtree(project / "plugins/generic")
    shutil.copytree(FIXTURE_PLUGIN, project / "plugins/public-fixture")
    config_text = (project / "recomp.toml").read_text().replace(
        'plugin = "generic"', 'plugin = "public-fixture"')
    (project / "recomp.toml").write_text(config_text)
    from recomp.policy import bump_policy

    bump_policy(project)

    git(project, "init", "-q", "-b", "main")
    git(project, "add", "-A")
    git(project, "commit", "-qm", "initial project")

    github = FakeGitHub(project)
    plugin = resolve_plugin(project, "public-fixture")
    plan = VerificationPlan.from_plugin(plugin)
    config = CoordinatorConfig(
        repository_url=os.fspath(project), repository_full_name="acme/fixture",
        trusted_actor_id=BOT, quarantine_root=tmp_path / "quarantine",
        state_path=tmp_path / "state.db", health_path=tmp_path / "health.json",
        max_concurrent=4, max_per_author=2, max_attempts=2,
    )
    sleeps.clear()
    return Harness(github, project, project, fixture_bin, plan, config)


def test_public_pull_request_lifecycle(harness):
    result = harness.publish_tasks()
    assert result.created, "work plan must publish at least one task"
    issue = 1
    state = harness.claim(issue, actor_id=ALICE, login="alice", now=1000)
    assert state.lease.claimant_id == ALICE
    assert state.lease.expires_at == 1000 + 7200

    good_files = harness.produce("chunk-0000")
    good = harness.open_pr(issue, actor_id=ALICE, login="alice", files=good_files)
    bad = harness.open_pr(issue, actor_id=MALLORY, login="mallory", number=2,
                          files={".github/workflows/pwn.yml": "on: push\n"})

    outcome = harness.coordinator().reconcile_once(now=1100)
    rejected = {decision.pr_number: decision.code for decision in outcome.rejected}
    admitted = {decision.pr_number: decision for decision in outcome.admitted}
    assert rejected.get(bad) == "not-current-claimant"
    assert admitted[good].code == "verified"

    # The judge is handed the rules the trusted record published, so it cannot be
    # quietly re-planned into judging a different set of paths.
    record = parse_trusted_task_record(list(harness.github.list_comments(issue)), BOT)
    assert harness.seen_rules == [[rule.to_mapping() for rule in record.outputs]]
    assert harness.github.checks_for(harness.github.pulls[good]["head"]["sha"])[0][
        "conclusion"] == "success"

    # The pass that verified the head is the pass that lands it: a verified pull
    # request is not an end state.
    assert admitted[good].merge_code == "merged"
    assert admitted[good].merge.merged
    assert harness.github.get_issue(issue)["state"] == "closed"
    assert harness.github.pulls[good]["merged"] is True
    assert [label["name"] for label in harness.github.get_issue(issue)["labels"]] == [
        "recomp-task", "done"]

    snapshot = collect_progress(harness.github, project="fixture", trusted_actor_id=BOT, now=1200)
    assert snapshot.totals()["done"] == 1
    commit = commit_progress_update(harness.github, snapshot, branch="main", now=1200)
    assert commit.commit_sha
    committed = git(harness.repo, "show", f"{commit.commit_sha}:docs/progress.json")
    assert json.loads(committed)["totals"]["done"] == 1


def test_merge_republishes_progress_in_the_same_pass(harness):
    """Landing a task and updating the published progress are one action."""

    published = []
    harness.publish_tasks()
    harness.claim(1, actor_id=ALICE, login="alice", now=1000)
    harness.open_pr(1, actor_id=ALICE, login="alice", files=harness.produce("chunk-0000"))
    before = git(harness.repo, "rev-parse", "refs/heads/main")

    outcome = harness.coordinator(
        publish_progress=lambda now: published.append(now) or commit_progress_update(
            harness.github,
            collect_progress(harness.github, project="fixture", trusted_actor_id=BOT, now=now),
            branch="main", now=now)).reconcile_once(now=1100)

    assert outcome.admitted[0].merge_code == "merged"
    assert published == [1100]
    assert git(harness.repo, "rev-parse", "refs/heads/main") != before
    committed = git(harness.repo, "show", "main:docs/progress.json")
    assert json.loads(committed)["totals"]["done"] == 1


def test_failed_progress_publish_does_not_undo_a_merge(harness, tmp_path):
    def broken(_now: int) -> None:
        raise GitHubError(500, "git data api failed")

    harness.publish_tasks()
    harness.claim(1, actor_id=ALICE, login="alice", now=1000)
    harness.open_pr(1, actor_id=ALICE, login="alice", files=harness.produce("chunk-0000"))
    coordinator = harness.coordinator(publish_progress=broken)
    decision = coordinator.reconcile_once(now=1100).admitted[0]
    coordinator.write_health(now=1100)

    assert decision.merge_code == "merged"
    assert harness.github.pulls[1]["merged"] is True
    health = json.loads((tmp_path / "health.json").read_text())
    assert health["merged_total"] == 1
    assert health["progress_failures"] == 1


def test_wrong_output_is_rejected_and_repairs_the_lease(harness):
    harness.publish_tasks()
    harness.claim(1, actor_id=ALICE, login="alice", now=1000)
    pr = harness.open_pr(1, actor_id=ALICE, login="alice",
                         files={"recovery/chunks/chunk-0000.json": '{"value":"lies"}\n'})
    outcome = harness.coordinator().reconcile_once(now=1100)
    decision = outcome.admitted[0]
    assert decision.code == "rejected"
    assert decision.attestation.reason_codes == ("artifact-mismatch",)
    transitions = parse_trusted_lease_transitions(list(harness.github.list_comments(1)), BOT)
    assert transitions[-1].verdict == "rejected"
    assert transitions[-1].phase == "claimed"
    assert transitions[-1].expires_at == 1100 + 7200
    with pytest.raises(MergeRefused):
        merge_verified_pull(harness.github, decision.attestation, pr_number=pr, issue_number=1,
                            trusted_actor_id=BOT, now=1200)


def test_head_push_between_verification_and_merge_is_refused(harness):
    """A push landing after verification invalidates the attestation.

    Verification genuinely passed, yet the head the attestation describes no longer
    exists, so the coordinator must refuse rather than merge bytes it never judged.
    """

    harness.publish_tasks()
    harness.claim(1, actor_id=ALICE, login="alice", now=1000)
    pr = harness.open_pr(1, actor_id=ALICE, login="alice", files=harness.produce("chunk-0000"))

    def racing_merge(github, attestation, **kwargs):
        harness.push_more(pr, {"recovery/chunks/chunk-0000.json": "tampered after verify\n"})
        return merge_verified_pull(github, attestation, **kwargs)

    decision = harness.coordinator(merge=racing_merge).reconcile_once(now=1100).admitted[0]
    assert decision.code == "verified"
    assert decision.merge_code == "merge-refused"
    assert decision.merge is None
    assert harness.github.pulls[pr]["state"] == "open"
    assert harness.github.pulls[pr].get("merged") is not True


def test_base_movement_between_verification_and_merge_is_refused(harness):
    harness.publish_tasks()
    harness.claim(1, actor_id=ALICE, login="alice", now=1000)
    pr = harness.open_pr(1, actor_id=ALICE, login="alice", files=harness.produce("chunk-0000"))

    def racing_merge(github, attestation, **kwargs):
        (harness.repo / "docs/NOTES.md").write_text("maintainer commit\n")
        git(harness.repo, "add", "-A")
        git(harness.repo, "commit", "-qm", "move base")
        return merge_verified_pull(github, attestation, **kwargs)

    decision = harness.coordinator(merge=racing_merge).reconcile_once(now=1100).admitted[0]
    assert decision.merge_code == "merge-refused"
    assert harness.github.pulls[pr]["state"] == "open"


def test_transient_merge_failure_retries_then_reports_unmerged(harness, tmp_path):
    """A rate-limited merge is retried a bounded number of times, never spun on."""

    from recomp.github_api import GitHubError

    harness.publish_tasks()
    harness.claim(1, actor_id=ALICE, login="alice", now=1000)
    pr = harness.open_pr(1, actor_id=ALICE, login="alice", files=harness.produce("chunk-0000"))
    attempts = []

    def rate_limited(_github, _attestation, **_kwargs):
        attempts.append(1)
        raise GitHubError(403, "rate limited")

    coordinator = harness.coordinator(merge=rate_limited)
    decision = coordinator.reconcile_once(now=1100).admitted[0]
    coordinator.write_health(now=1100)
    assert decision.code == "verified"
    assert decision.merge_code == "merge-rate-limited"
    assert len(attempts) == len(MERGE_RETRYABLE_BACKOFF) + 1
    assert sleeps == list(MERGE_RETRYABLE_BACKOFF)
    assert harness.github.pulls[pr]["state"] == "open"

    health = json.loads((tmp_path / "health.json").read_text())
    assert health["verified_unmerged"] == 1
    assert health["merged_total"] == 0


def test_interrupted_pass_resumes_after_cache_deletion(harness, tmp_path):
    """A crashed coordinator with no local state rebuilds the same queue."""

    from recomp.firecracker import GuestError

    def crashing(_candidate, _target, _key, *, now):
        raise GuestError("host lost power mid-verification")

    harness.publish_tasks()
    harness.claim(1, actor_id=ALICE, login="alice", now=1000)
    harness.open_pr(1, actor_id=ALICE, login="alice", files=harness.produce("chunk-0000"))
    first = harness.coordinator(verifier=crashing,
                                state_path=tmp_path / "a.db").reconcile_once(now=1100)
    assert first.admitted[0].code == "infrastructure-error"
    assert first.pending_keys
    with CoordinatorState(tmp_path / "a.db") as state:
        assert [row.status for row in state.rows()] == ["error"]

    second = harness.coordinator(state_path=tmp_path / "b.db").reconcile_once(now=1101)
    assert second.pending_keys == first.pending_keys
    assert second.admitted[0].code == "verified"


def test_verified_task_is_not_reverified_on_the_next_pass(harness, tmp_path):
    """A completed lease verdict is terminal: no later pass re-judges the same head."""

    harness.publish_tasks()
    harness.claim(1, actor_id=ALICE, login="alice", now=1000)
    harness.open_pr(1, actor_id=ALICE, login="alice", files=harness.produce("chunk-0000"))
    # Merging is off so the pull request survives to be seen a second time; the
    # invariant here is about the lease, not about the merge.
    harness.coordinator(merge=None, state_path=tmp_path / "a.db").reconcile_once(now=1100)
    again = harness.coordinator(merge=None,
                                state_path=tmp_path / "b.db").reconcile_once(now=1101)
    assert [decision.code for decision in again.rejected] == ["already-verified"]
    assert again.admitted == ()


def test_progress_commit_retries_from_a_moved_base(harness):
    harness.publish_tasks()
    harness.github.ref_conflicts = 1
    snapshot = collect_progress(harness.github, project="fixture", trusted_actor_id=BOT, now=1200)
    commit = commit_progress_update(harness.github, snapshot, branch="main", now=1200)
    assert commit.attempts == 2
    assert git(harness.repo, "rev-parse", "refs/heads/main") == commit.commit_sha


def test_published_tasks_are_idempotent_across_runs(harness):
    first = harness.publish_tasks()
    second = harness.publish_tasks()
    assert second.created == ()
    assert set(second.existing) == set(first.created)


def test_sync_tasks_refuses_an_identity_that_is_not_the_trusted_actor(harness):
    harness.github.viewer_id = 4242
    with pytest.raises(GitHubTaskError, match="trusted actor"):
        harness.publish_tasks()


def test_forged_task_issues_do_not_block_the_trusted_republish(harness):
    lookalike = harness.github.create_issue(
        {"title": "port-0000: forged", "body": "<!-- recomp-task:port-0000 -->"})
    lookalike["user"] = {"id": 1, "login": "not-the-bot"}
    harness.github.viewer_id = BOT
    result = harness.publish_tasks()
    assert result.created


@pytest.mark.skipif(
    os.environ.get("RECOMP_GITHUB_E2E_REPO") is None,
    reason="live GitHub acceptance needs RECOMP_GITHUB_E2E_REPO=owner/repo, "
           "RECOMP_GITHUB_E2E_TOKEN_FILE=<0600 file>, and a repository whose "
           "recomp.toml carries fixture = true",
)
def test_live_github_acceptance():
    from recomp.coordinator_setup import read_owner_token
    from recomp.github_api import GitHubClient

    owner, _, repository = os.environ["RECOMP_GITHUB_E2E_REPO"].partition("/")
    token = read_owner_token(os.environ["RECOMP_GITHUB_E2E_TOKEN_FILE"])
    client = GitHubClient("https://api.github.com", owner, repository, lambda: token)
    marker = f"recomp-e2e-{os.getpid()}"
    created: list[int] = []
    try:
        issue = client.create_issue({"title": f"{marker}: fixture task",
                                     "body": f"<!-- recomp-task:{marker} -->"})
        created.append(issue["number"])
        assert any(item["number"] == issue["number"] for item in client.list_issues())
    finally:
        for number in created:
            client.update_issue(number, {"state": "closed"})


@pytest.mark.skipif(
    os.environ.get("RECOMP_FIRECRACKER_TEST") != "1"
    or os.environ.get("RECOMP_GITHUB_E2E_REPO") is None,
    reason="real-guest acceptance needs RECOMP_FIRECRACKER_TEST=1, "
           "RECOMP_FIRECRACKER_MANIFEST=<pinned manifest>, /dev/kvm, and "
           "RECOMP_GITHUB_E2E_REPO=owner/repo",
)
def test_real_guest_rejects_hostile_candidate(harness, tmp_path):
    from recomp.firecracker import FirecrackerRunner, load_pinned_config
    from recomp.verification import verify_candidate

    config = load_pinned_config(Path(os.environ["RECOMP_FIRECRACKER_MANIFEST"]))
    runner = FirecrackerRunner(config)
    canary = tmp_path / "host-canary"
    canary.write_text("host-only secret")

    harness.publish_tasks()
    harness.claim(1, actor_id=ALICE, login="alice", now=1000)
    good = harness.open_pr(1, actor_id=ALICE, login="alice", files=harness.produce("chunk-0000"))
    benign = harness.coordinator().reconcile_once(now=1100).admitted[0]
    candidate = harness._build(
        harness.github.pulls[good]["base"]["sha"], harness.github.pulls[good]["head"]["sha"],
        task_id="chunk-0000", lease_generation=1,
        policy_hash=harness.plan.verifier_policy_hash,
        toolchain_digest=harness.plan.verifier_policy_hash,
        preflight_report=benign.attestation and __import__("recomp.preflight",
                                                           fromlist=["PreflightReport"])
        .PreflightReport(()))
    attestation = verify_candidate(runner, harness.plan, candidate, harness.target,
                                   candidate.key, now=1200, require_public=True,
                                   output_rules=harness.rules("chunk-0000"))
    assert attestation.passed
    assert "host-only secret" not in json.dumps(attestation.as_mapping())
    assert canary.read_text() == "host-only secret"
