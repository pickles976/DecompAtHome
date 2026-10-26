from __future__ import annotations

from dataclasses import replace

import pytest

from recomp.contracts import PolicyRef, Sha256
from recomp.task_records import (
    OutputRule,
    TaskRecord,
    TaskRecordError,
    parse_task_record_body,
    parse_trusted_task_record,
    publish_task_records,
    render_task_record,
)


def record_mapping(**overrides):
    value = {
        "schema": 1,
        "task_id": "strings-0000",
        "kind": "t1-strings",
        "args": {"offset": 0, "length": 64},
        "outputs": [{
            "path": "recovery/strings/strings-0000.json",
            "media_type": "application/json",
            "max_bytes": 65536,
        }],
        "policy_version": 2,
        "policy_hash": "1" * 64,
        "toolchain_digest": "2" * 64,
        "target_sha256": "3" * 64,
        "weight": 64,
        "generation": 1,
    }
    value.update(overrides)
    return value


def make_record(**overrides):
    return TaskRecord.from_mapping(record_mapping(**overrides))


def test_task_record_round_trips_canonical_bot_comment():
    record = make_record()
    body = render_task_record(record)
    assert parse_task_record_body(body) == record
    assert body.startswith("<!-- recomp-task-v1\n")
    assert body.endswith("\n-->")
    assert '"args":{"length":64,"offset":0}' in body


@pytest.mark.parametrize(
    "path",
    [
        "/recovery/output.json",
        "../recovery/output.json",
        "recovery/../output.json",
        "recovery//output.json",
        "private/output.json",
        "recovery\\output.json",
    ],
)
def test_output_paths_must_be_normalized_public_relative_paths(path):
    with pytest.raises(TaskRecordError, match="output path"):
        make_record(outputs=[{"path": path, "media_type": "application/json", "max_bytes": 10}])


def test_plugin_declared_output_roots_are_supported():
    record = TaskRecord.from_mapping(
        record_mapping(outputs=[{"path": "symbols/unit.json", "media_type": "application/json", "max_bytes": 10}]),
        output_roots=("recovery", "symbols"),
    )
    assert record.outputs[0].path.as_posix() == "symbols/unit.json"


def test_duplicate_outputs_non_positive_bounds_and_unknown_keys_are_rejected():
    duplicate = {"path": "recovery/a.json", "media_type": "application/json", "max_bytes": 10}
    with pytest.raises(TaskRecordError, match="duplicate"):
        make_record(outputs=[duplicate, duplicate])
    with pytest.raises(TaskRecordError, match="positive"):
        make_record(weight=0)
    with pytest.raises(TaskRecordError, match="positive"):
        make_record(outputs=[{**duplicate, "max_bytes": 0}])
    with pytest.raises(TaskRecordError, match="unknown"):
        make_record(untrusted=True)
    with pytest.raises(TaskRecordError, match="unknown"):
        make_record(outputs=[{**duplicate, "extra": "value"}])


def test_wrong_target_or_policy_is_rejected_when_reading_trusted_record():
    comment = {"user": {"id": 99}, "body": render_task_record(make_record())}
    with pytest.raises(TaskRecordError, match="policy"):
        parse_trusted_task_record(
            [comment], 99,
            expected_policy=PolicyRef(3, Sha256("1" * 64)),
            expected_target_sha256=Sha256("3" * 64),
        )
    with pytest.raises(TaskRecordError, match="target"):
        parse_trusted_task_record(
            [comment], 99,
            expected_policy=PolicyRef(2, Sha256("1" * 64)),
            expected_target_sha256=Sha256("4" * 64),
        )


def test_contributor_authored_lookalikes_are_ignored():
    trusted = make_record()
    forged = replace(trusted, generation=99, weight=999)
    comments = [
        {"user": {"id": 7}, "body": render_task_record(forged)},
        {"user": {"id": 99}, "body": render_task_record(trusted)},
    ]
    assert parse_trusted_task_record(comments, 99) == trusted


def test_highest_trusted_generation_wins_and_ambiguous_generation_fails():
    first = make_record()
    second = replace(first, generation=2, weight=32)
    assert parse_trusted_task_record([
        {"user": {"id": 99}, "body": render_task_record(first)},
        {"user": {"id": 99}, "body": render_task_record(second)},
    ], 99) == second
    with pytest.raises(TaskRecordError, match="ambiguous"):
        parse_trusted_task_record([
            {"user": {"id": 99}, "body": render_task_record(second)},
            {"user": {"id": 99}, "body": render_task_record(replace(second, weight=31))},
        ], 99)


class FakeGitHub:
    trusted_actor_id = 99

    def __init__(self):
        self.issues = []
        self.comments = {}
        self.created_issue_count = 0
        self.label_updates = []

    def list_issues(self):
        return iter(self.issues)

    def create_issue(self, body):
        self.created_issue_count += 1
        issue = {"number": len(self.issues) + 1, "user": {"id": self.trusted_actor_id}, **body}
        self.issues.append(issue)
        self.comments[issue["number"]] = []
        return issue

    def list_comments(self, issue_number):
        return iter(self.comments[issue_number])

    def create_comment(self, issue_number, text):
        comment = {"user": {"id": self.trusted_actor_id}, "body": text}
        self.comments[issue_number].append(comment)
        return comment

    def set_issue_labels(self, issue_number, labels):
        self.label_updates.append((issue_number, list(labels)))
        return {"labels": labels}


def test_publication_is_idempotent_by_task_id():
    github = FakeGitHub()
    record = make_record()
    publish_task_records(github, [record])
    publish_task_records(github, [record])
    assert github.created_issue_count == 1
    assert len(github.comments[1]) == 1
    assert "<!-- recomp-task:strings-0000 -->" in github.issues[0]["body"]


def test_publication_ignores_contributor_authored_issue_marker():
    github = FakeGitHub()
    github.issues.append({
        "number": 1,
        "user": {"id": 7},
        "title": "lookalike",
        "body": "<!-- recomp-task:strings-0000 -->",
    })
    github.comments[1] = []
    publish_task_records(github, [make_record()])
    assert github.created_issue_count == 1
    assert github.issues[-1]["user"]["id"] == github.trusted_actor_id


def test_changed_record_appends_trusted_supersession_without_editing_history():
    github = FakeGitHub()
    original = make_record()
    publish_task_records(github, [original])
    old_body = github.comments[1][0]["body"]
    publish_task_records(github, [replace(original, weight=32)])
    assert len(github.comments[1]) == 2
    assert github.comments[1][0]["body"] == old_body
    current = parse_trusted_task_record(github.comments[1], github.trusted_actor_id)
    assert current.weight == 32
    assert current.generation == 2
    assert github.label_updates[-1] == (1, ["recomp-task", "open"])


def test_output_rule_is_frozen_and_binary_defaults_false():
    output = make_record().outputs[0]
    assert isinstance(output, OutputRule)
    assert output.allow_binary is False
    with pytest.raises(AttributeError):
        output.max_bytes = 1
