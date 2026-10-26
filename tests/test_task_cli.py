from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from recomp.claims import LeaseTransition, render_lease_transition
from recomp.contracts import Sha256
from recomp.task_cli import TaskCliError, parse_task_url, run_task_command
from recomp.task_records import TaskRecord, render_task_record
from recomp.github_api import GitHubError

POLICY = Sha256("1" * 64)
TOOLCHAIN = Sha256("2" * 64)
IMAGE = "ghcr.io/acme/game-toolchain@sha256:" + "3" * 64
BOT = 99
ME = 7


def task_record(task_id="strings-0000", generation=3, target_sha256=None):
    return TaskRecord.from_mapping({
        "schema": 1, "task_id": task_id, "kind": "t1-strings",
        "args": {"offset": 0, "length": 64},
        "outputs": [{"path": f"recovery/{task_id}.json", "media_type": "application/json",
                     "max_bytes": 4096}],
        "policy_version": 2, "policy_hash": POLICY.hex, "toolchain_digest": TOOLCHAIN.hex,
        "target_sha256": target_sha256 or TARGET_SHA.hex, "weight": 64, "generation": generation,
    })


TARGET_BYTES = b"MZ\x00original-target"
TARGET_SHA = Sha256(hashlib.sha256(TARGET_BYTES).hexdigest())


class FakeGitHub:
    def __init__(self):
        self.issues = []
        self.comments = {}
        self.created_pulls = []
        self.viewer_id = ME
        self.viewer_login = "alice"

    def add_task(self, issue=12, record=None, lease=None, labels=("recomp-task", "open")):
        record = record or task_record()
        self.issues.append({
            "number": issue, "state": "open", "user": {"id": BOT},
            "title": f"{record.task_id}: {record.kind}",
            "body": f"<!-- recomp-task:{record.task_id} -->",
            "labels": [{"name": name} for name in labels],
        })
        self.comments.setdefault(issue, []).append({
            "id": 1, "user": {"id": BOT, "login": "app"},
            "body": render_task_record(record), "created_at": "1970-01-01T00:00:01Z",
        })
        if lease is not None:
            self.append_lease(issue, lease)
        return record

    def append_lease(self, issue, lease):
        self.comments.setdefault(issue, []).append({
            "id": 100 + len(self.comments.get(issue, [])),
            "user": {"id": BOT, "login": "app"},
            "body": render_lease_transition(lease), "created_at": "1970-01-01T00:05:00Z",
        })

    def grant_lease(self, issue=12, task_id="strings-0000", claimant_id=ME, generation=4,
                    expires_at=9000, phase="claimed"):
        self.append_lease(issue, LeaseTransition(
            task_id=task_id, phase=phase, claimant_id=claimant_id, claimant_login="alice",
            generation=generation, issued_at=1000, expires_at=expires_at,
            last_command_id=10, issue_number=issue,
        ))

    # client surface
    def list_issues(self):
        return iter(list(self.issues))

    def get_issue(self, number):
        return next(issue for issue in self.issues if issue["number"] == number)

    def list_comments(self, issue_number):
        return iter(list(self.comments.get(issue_number, [])))

    def create_comment(self, issue_number, text):
        comment = {"id": 500 + len(self.comments.get(issue_number, [])),
                   "user": {"id": ME, "login": "alice"}, "body": text,
                   "created_at": "1970-01-01T00:10:00Z"}
        self.comments.setdefault(issue_number, []).append(comment)
        return comment

    def create_pull(self, body):
        pull = {"number": 31 + len(self.created_pulls), **dict(body)}
        self.created_pulls.append(pull)
        return pull


class FakeGit:
    def __init__(self, root):
        self.root = Path(root)
        self.current_branch = "main"
        self.branches = ["main"]
        self.remotes = {"origin": "https://github.com/acme/game.git"}
        self.pushed = []
        self.changed: list[str] = []
        self.commits = []

    def create_branch(self, name):
        self.branches.append(name)
        self.current_branch = name

    def checkout(self, name):
        self.current_branch = name

    def changed_paths(self, base_ref="main"):
        return tuple(self.changed)

    def commit(self, paths, message):
        self.commits.append((tuple(paths), message))

    def add_remote(self, name, url):
        self.remotes[name] = url

    def push(self, remote, branch):
        self.pushed.append((remote, branch))


class FakeRuntime:
    def __init__(self, exit_code=0):
        self.exit_code = exit_code
        self.calls = []

    def __call__(self, arguments, *, target, project):
        self.calls.append((tuple(arguments), Path(target), Path(project)))
        return self.exit_code


@pytest.fixture
def workspace(tmp_path):
    project = tmp_path / "game"
    (project / "recovery").mkdir(parents=True)
    (project / ".recomp").mkdir()
    target = tmp_path / "game.exe"
    target.write_bytes(TARGET_BYTES)
    return project, target


def invoke(argv, *, github, git, project, now=1000, runtime=None, target=None):
    return run_task_command(
        argv, github=github, git=git, project=project, now=now,
        run_toolchain=runtime or FakeRuntime(), image=IMAGE, target=target,
    )


def test_parse_task_url_accepts_issue_and_repository_links():
    issue = parse_task_url("https://github.com/acme/game/issues/12")
    assert (issue.owner, issue.repository, issue.issue_number) == ("acme", "game", 12)
    repo = parse_task_url("https://github.com/acme/game")
    assert (repo.owner, repo.repository, repo.issue_number) == ("acme", "game", None)
    with pytest.raises(TaskCliError, match="link"):
        parse_task_url("https://evil.example/acme/game/issues/12")


def test_issue_link_start_claims_and_creates_branch(workspace):
    project, target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task()
    github.grant_lease()
    code, out, err = invoke(["start", "https://github.com/acme/game/issues/12"],
                            github=github, git=git, project=project, target=target)
    assert code == 0, err
    assert github.comments[12][-1]["body"] == "/claim"
    assert git.current_branch == "recomp/strings-0000-12"
    context = json.loads((project / ".recomp/task.json").read_text())
    assert context["task_id"] == "strings-0000"
    assert context["lease_generation"] == 4
    assert str(target) not in json.dumps(context)


def test_repository_link_selects_lowest_unclaimed_task(workspace):
    project, target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task(issue=13, record=task_record("strings-0001"))
    github.add_task(issue=12, record=task_record("strings-0000"), labels=("recomp-task", "claimed"))
    github.grant_lease(issue=12, claimant_id=42)
    github.grant_lease(issue=13, task_id="strings-0001", claimant_id=ME, generation=4)
    code, out, err = invoke(["start", "https://github.com/acme/game"],
                            github=github, git=git, project=project, target=target)
    assert code == 0, err
    assert git.current_branch == "recomp/strings-0001-13"


def test_start_refuses_when_target_hash_does_not_match(workspace):
    project, target = workspace
    target.write_bytes(b"different binary")
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task()
    code, _out, err = invoke(["start", "https://github.com/acme/game/issues/12"],
                             github=github, git=git, project=project, target=target)
    assert code != 0
    assert "target" in err
    assert git.current_branch == "main"


def test_start_never_posts_a_claim_when_the_credential_has_no_identity(workspace):
    """An App installation token cannot answer /user. Posting /claim before
    that check left a comment the coordinator folded into a lease for the bot,
    so the task became unclaimable by the contributor who tried."""
    project, target = workspace

    class ViewerlessGitHub(FakeGitHub):
        @property
        def viewer_id(self):
            raise GitHubError(403, "Resource not accessible by integration")

        @viewer_id.setter
        def viewer_id(self, _value):
            pass

    github, git = ViewerlessGitHub(), FakeGit(project)
    github.add_task()
    code, _out, err = invoke(["start", "https://github.com/acme/game/issues/12"],
                             github=github, git=git, project=project, target=target)
    assert code != 0
    assert not any(c["body"] == "/claim" for c in github.comments[12])
    assert "rejected this credential" in err
    assert git.current_branch == "main"


def test_start_refuses_without_a_target(workspace):
    project, _target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task()
    code, _out, err = invoke(["start", "https://github.com/acme/game/issues/12"],
                             github=github, git=git, project=project, target=None)
    assert code != 0 and "target" in err


def test_start_reports_denied_claim_without_creating_a_branch(workspace):
    project, target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task()
    github.grant_lease(claimant_id=42)
    code, _out, err = invoke(["start", "https://github.com/acme/game/issues/12"],
                             github=github, git=git, project=project, target=target)
    assert code != 0
    assert "claim" in err
    assert git.branches == ["main"]


def test_heartbeat_posts_command_and_reports_new_expiry(workspace):
    project, target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task()
    github.grant_lease()
    invoke(["start", "https://github.com/acme/game/issues/12"],
           github=github, git=git, project=project, target=target)
    github.grant_lease(generation=5, expires_at=20000)
    code, out, err = invoke(["heartbeat"], github=github, git=git, project=project,
                            target=target, now=2000)
    assert code == 0, err
    assert any(comment["body"] == "/heartbeat" for comment in github.comments[12])
    assert "20000" in out


def test_run_and_verify_use_the_pinned_launcher(workspace):
    project, target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task()
    github.grant_lease()
    invoke(["start", "https://github.com/acme/game/issues/12"],
           github=github, git=git, project=project, target=target)
    runtime = FakeRuntime()
    assert invoke(["run"], github=github, git=git, project=project, target=target,
                  runtime=runtime)[0] == 0
    assert invoke(["verify"], github=github, git=git, project=project, target=target,
                  runtime=runtime)[0] == 0
    assert [call[0][0] for call in runtime.calls] == ["plugin-run-task", "plugin-verify"]
    assert all(call[1] == target for call in runtime.calls)


def test_submit_refuses_diff_outside_task_outputs(workspace):
    project, target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task()
    github.grant_lease()
    invoke(["start", "https://github.com/acme/game/issues/12"],
           github=github, git=git, project=project, target=target)
    git.changed = ["recovery/strings-0000.json", "plugins/generic/runner.py"]
    code, _out, err = invoke(["submit"], github=github, git=git, project=project, target=target)
    assert code != 0
    assert "outside task output paths" in err
    assert github.created_pulls == []
    assert git.pushed == []


def test_submit_refuses_when_local_verification_fails(workspace):
    project, target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task()
    github.grant_lease()
    invoke(["start", "https://github.com/acme/game/issues/12"],
           github=github, git=git, project=project, target=target)
    git.changed = ["recovery/strings-0000.json"]
    code, _out, err = invoke(["submit"], github=github, git=git, project=project,
                             target=target, runtime=FakeRuntime(exit_code=3))
    assert code != 0 and "verif" in err
    assert github.created_pulls == []


def test_submit_pushes_fork_branch_and_opens_pull_request_with_fields(workspace):
    project, target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task()
    github.grant_lease()
    invoke(["start", "https://github.com/acme/game/issues/12"],
           github=github, git=git, project=project, target=target)
    git.changed = ["recovery/strings-0000.json"]
    code, out, err = invoke(["submit"], github=github, git=git, project=project, target=target)
    assert code == 0, err
    assert git.pushed == [("fork", "recomp/strings-0000-12")]
    assert "fork" in git.remotes
    body = github.created_pulls[0]["body"]
    assert "Closes #12" in body
    assert f"Recomp-Policy: sha256:{POLICY.hex}" in body
    assert f"Recomp-Toolchain: sha256:{TOOLCHAIN.hex}" in body
    assert "Recomp-Lease: 4" in body
    assert "Recomp-Task-Generation: 3" in body
    assert str(target) not in body
    assert github.created_pulls[0]["head"] == "alice:recomp/strings-0000-12"


def test_submit_refuses_after_policy_movement(workspace):
    project, target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task()
    github.grant_lease()
    invoke(["start", "https://github.com/acme/game/issues/12"],
           github=github, git=git, project=project, target=target)
    github.comments[12][0] = {
        **github.comments[12][0],
        "body": render_task_record(task_record(generation=4)),
    }
    git.changed = ["recovery/strings-0000.json"]
    code, _out, err = invoke(["submit"], github=github, git=git, project=project, target=target)
    assert code != 0
    assert "moved" in err or "generation" in err
    assert github.created_pulls == []


def test_status_resumes_from_context_without_leaking_target_path(workspace):
    project, target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task()
    github.grant_lease()
    invoke(["start", "https://github.com/acme/game/issues/12"],
           github=github, git=git, project=project, target=target)
    code, out, err = invoke(["status"], github=github, git=git, project=project, target=target)
    assert code == 0, err
    assert "strings-0000" in out and "#12" in out
    assert str(target) not in out
    assert str(target.parent) not in out


def test_commands_require_an_existing_context(workspace):
    project, target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    for command in ("heartbeat", "run", "verify", "submit", "status"):
        code, _out, err = invoke([command], github=github, git=git, project=project, target=target)
        assert code != 0
        assert "recomp task start" in err


def test_next_lists_open_tasks_deterministically(workspace):
    project, target = workspace
    github, git = FakeGitHub(), FakeGit(project)
    github.add_task(issue=13, record=task_record("strings-0001"))
    github.add_task(issue=12, record=task_record("strings-0000"))
    code, out, err = invoke(["next", "https://github.com/acme/game"],
                            github=github, git=git, project=project, target=target)
    assert code == 0, err
    assert out.index("strings-0000") < out.index("strings-0001")


def test_task_doctor_command_prints_greenlight(monkeypatch, capsys):
    from recomp import cli
    from recomp.contributor_doctor import ContributorFinding, ContributorReport

    seen = {}

    def fake(project_root, *, target=None, **_kwargs):
        seen["project"] = project_root
        seen["target"] = target
        return ContributorReport((
            ContributorFinding("python", "ok", "python 3.11.9", ""),
            ContributorFinding("disk", "warning", "low on space", "free up disk"),
        ))

    monkeypatch.setattr("recomp.contributor_doctor.contributor_doctor", fake)
    args = cli.build_parser().parse_args(
        ["task", "doctor", "--project", "/checkout", "--target", "/me/target.exe"])
    assert args.func(args) == 0
    assert seen == {"project": "/checkout", "target": "/me/target.exe"}
    out = capsys.readouterr().out
    assert "free up disk" in out
    assert out.strip().splitlines()[-1] == "GREENLIGHT"


def test_task_doctor_blocks_on_error_findings(monkeypatch, capsys):
    from recomp import cli
    from recomp.contributor_doctor import ContributorFinding, ContributorReport

    def fake(_project_root, *, target=None, **_kwargs):
        return ContributorReport((
            ContributorFinding("oci-runtime", "error", "docker daemon down", "start docker"),
        ))

    monkeypatch.setattr("recomp.contributor_doctor.contributor_doctor", fake)
    args = cli.build_parser().parse_args(["task", "doctor", "--project", "/checkout"])
    assert args.func(args) == 1
    out = capsys.readouterr().out
    assert out.strip().splitlines()[-1] == "BLOCKED: 1 error(s)"
