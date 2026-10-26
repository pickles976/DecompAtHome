from __future__ import annotations

import base64
import importlib.util
import json
import re
from pathlib import Path

import pytest

from recomp.claims import (
    LeaseTransition,
    render_lease_transition,
)
from recomp.task_records import TaskRecord, render_task_record

ROOT = Path(__file__).parents[1]
PIN_RE = re.compile(r"^[^\s]+@[0-9a-f]{40}$")


def load_action(name):
    path = ROOT / ".github" / "actions" / name / "action.py"
    spec = importlib.util.spec_from_file_location(f"test_{name}_action", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def task_record():
    return TaskRecord.from_mapping({
        "schema": 1,
        "task_id": "strings-0000",
        "kind": "t1-strings",
        "args": {"offset": 0, "length": 64},
        "outputs": [{"path": "recovery/out.json", "media_type": "application/json", "max_bytes": 100}],
        "policy_version": 2,
        "policy_hash": "1" * 64,
        "toolchain_digest": "2" * 64,
        "target_sha256": "3" * 64,
        "weight": 64,
        "generation": 3,
    })


def test_preflight_workflow_is_secret_free_and_not_privileged():
    rendered = (ROOT / "src/recomp/templates/github/preflight.yml").read_text()
    assert "pull_request:" in rendered
    assert "pull_request_target" not in rendered
    assert "self-hosted" not in rendered
    assert "contents: read" in rendered
    assert "persist-credentials: true" not in rendered
    assert "secrets." not in rendered
    assert "checks: write" not in rendered


def test_workflow_uses_are_commit_pinned_and_permissions_explicit():
    for name in ("preflight.yml",):
        text = (ROOT / "src/recomp/templates/github" / name).read_text()
        uses = [line.split("uses:", 1)[1].strip() for line in text.splitlines() if "uses:" in line]
        assert uses and all(PIN_RE.fullmatch(value) for value in uses)
        assert "permissions:" in text
        assert not re.search(r"run:.*\$\{\{\s*github\.event", text)


def test_composite_actions_run_only_their_data_entrypoints():
    for name in ("recomp-preflight",):
        text = (ROOT / ".github/actions" / name / "action.yml").read_text()
        assert 'python3 "$GITHUB_ACTION_PATH/action.py"' in text
        assert "actions/checkout" not in text
        assert "node" not in text.lower()


class FakeGitHub:
    trusted_actor_id = 99

    def __init__(self):
        self.issues = [{
            "number": 42,
            "user": {"id": 99},
            "title": "task",
            "body": "<!-- recomp-task:strings-0000 -->",
            "labels": [{"name": "open"}],
        }]
        self.comments = {42: [
            {"id": 1, "user": {"id": 99, "login": "app"}, "body": render_task_record(task_record()),
             "created_at": "1970-01-01T00:00:01Z"},
            {"id": 10, "user": {"id": 7, "login": "alice"}, "body": "/claim",
             "created_at": "1970-01-01T00:16:40Z"},
        ]}
        self.label_updates = []
        self.created_comments = []
        self.tree = {"truncated": False, "tree": [{
            "path": "recovery/out.json", "mode": "100644", "type": "blob",
            "sha": "c" * 40, "size": 12,
        }]}
        self.files = [{"filename": "recovery/out.json", "status": "modified", "sha": "c" * 40}]
        self.blobs = {"c" * 40: {
            "encoding": "base64",
            "content": base64.b64encode(b'{"ok":true}').decode(),
            "size": 11,
        }}

    def list_issues(self):
        return iter(self.issues)

    def get_issue(self, number):
        return next(issue for issue in self.issues if issue["number"] == number)

    def list_comments(self, issue_number):
        return iter(self.comments[issue_number])

    def create_comment(self, issue_number, body):
        next_id = max(comment["id"] for comment in self.comments[issue_number]) + 1
        comment = {
            "id": next_id,
            "user": {"id": self.trusted_actor_id, "login": "app"},
            "body": body,
            "created_at": "1970-01-01T00:16:40Z",
        }
        self.comments[issue_number].append(comment)
        self.created_comments.append(comment)
        return comment

    def set_issue_labels(self, issue_number, labels):
        self.label_updates.append((issue_number, labels))
        return {"labels": labels}

    def get_tree(self, _sha, recursive=False):
        assert recursive
        return self.tree

    def list_pull_files(self, _number):
        return iter(self.files)

    def get_blob(self, sha):
        return self.blobs[sha]


def pr_event(body=None):
    return {
        "pull_request": {
            "number": 9,
            "user": {"id": 7},
            "body": body or (
                "Closes #42\n"
                "Recomp-Policy: sha256:" + "1" * 64 + "\n"
                "Recomp-Toolchain: sha256:" + "2" * 64 + "\n"
                "Recomp-Lease: 4\n"
                "Recomp-Task-Generation: 3\n"
            ),
            "head": {"sha": "a" * 40},
            "base": {"sha": "b" * 40, "repo": {"full_name": "acme/game"}},
        },
        "repository": {"full_name": "acme/game"},
    }


def add_live_lease(github):
    transition = LeaseTransition(
        task_id="strings-0000", phase="claimed", claimant_id=7,
        claimant_login="alice", generation=4, issued_at=1000,
        expires_at=8200, last_command_id=10, issue_number=42,
    )
    github.comments[42].append({
        "id": 11,
        "user": {"id": 99, "login": "app"},
        "body": render_lease_transition(transition),
        "created_at": "1970-01-01T00:16:40Z",
    })


def test_preflight_action_maps_report_to_stable_output_and_exit_status(tmp_path):
    action = load_action("recomp-preflight")
    github = FakeGitHub()
    add_live_lease(github)
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    assert action.run(
        pr_event(), github, trusted_actor_id=99, now=1100,
        output_path=output, summary_path=summary,
    ) == 0
    assert output.read_text() == "codes=pass\n"
    assert summary.read_text() == "recomp preflight: pass\n"

    github.files = [{"filename": ".github/workflows/pwn.yml", "status": "modified", "sha": "d" * 40}]
    github.tree = {"truncated": False, "tree": [{
        "path": ".github/workflows/pwn.yml", "mode": "100644", "type": "blob",
        "sha": "d" * 40, "size": 6,
    }]}
    github.blobs["d" * 40] = {"encoding": "base64", "content": base64.b64encode(b"secret").decode(), "size": 6}
    assert action.run(
        pr_event(body=pr_event()["pull_request"]["body"] + "attacker-secret"),
        github, trusted_actor_id=99, now=1100,
        output_path=output, summary_path=summary,
    ) == 1
    text = summary.read_text()
    assert "protected-path" in text
    assert "attacker-secret" not in text
    assert all(line.startswith("codes=") for line in output.read_text().splitlines())
