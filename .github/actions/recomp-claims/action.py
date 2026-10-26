#!/usr/bin/env python3
"""Trusted Issue-command reconciliation action; never checks out contributor code."""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, os.fspath(ROOT / "src"))

from recomp.claims import (  # noqa: E402
    ClaimCommand,
    parse_command,
    parse_trusted_lease_transitions,
    reconcile_claims,
    render_lease_transition,
)
from recomp.github_api import GitHubClient  # noqa: E402
from recomp.task_records import TaskRecordError, parse_trusted_task_record  # noqa: E402


def _timestamp(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


def _issue_numbers(event: dict, github: GitHubClient) -> list[int]:
    issue = event.get("issue")
    if isinstance(issue, dict) and isinstance(issue.get("number"), int):
        return [issue["number"]]
    return [
        issue["number"] for issue in github.list_issues()
        if isinstance(issue.get("number"), int) and "<!-- recomp-task:" in (issue.get("body") or "")
    ]


def run(event: dict, github: GitHubClient, *, trusted_actor_id: int, now: int) -> int:
    for issue_number in _issue_numbers(event, github):
        issue = github.get_issue(issue_number)
        comments = list(github.list_comments(issue_number))
        try:
            task = parse_trusted_task_record(comments, trusted_actor_id)
        except TaskRecordError:
            continue
        transitions = parse_trusted_lease_transitions(comments, trusted_actor_id)
        commands = []
        for comment in comments:
            body = comment.get("body")
            user = comment.get("user")
            if not isinstance(body, str) or parse_command(body) is None or not isinstance(user, dict):
                continue
            try:
                commands.append(ClaimCommand(
                    comment_id=comment["id"],
                    author_id=user["id"],
                    author_login=user["login"],
                    body=body,
                    created_at=_timestamp(comment["created_at"]),
                ))
            except (KeyError, TypeError, ValueError):
                continue
        latest = max(
            transitions,
            key=lambda transition: (transition.generation, transition.issued_at, transition.last_command_id),
            default=None,
        )
        task_status = latest.phase if latest is not None and latest.phase in {"blocked", "done"} else "open"
        state = reconcile_claims(
            task,
            transitions,
            commands,
            now=now,
            task_status=task_status,
            issue_number=issue_number,
            presentation_labels=tuple(
                label.get("name", "") for label in issue.get("labels", []) if isinstance(label, dict)
            ),
        )
        if state.transition is not None:
            github.create_comment(issue_number, render_lease_transition(state.transition))
        effective = state.transition or latest
        if effective is not None and effective.phase == "done":
            labels = ["recomp-task", "done"]
        elif state.lease is not None:
            labels = ["recomp-task", "claimed"]
        else:
            labels = ["recomp-task", "open"]
        github.set_issue_labels(issue_number, labels)
    return 0


def main() -> int:
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        token = os.environ["INPUT_TOKEN"]
        owner = os.environ["INPUT_OWNER"]
        repository = os.environ["INPUT_REPOSITORY"]
        github = GitHubClient(
            os.environ.get("INPUT_API_URL", "https://api.github.com"),
            owner,
            repository,
            lambda: token,
        )
        return run(
            event,
            github,
            trusted_actor_id=int(os.environ["INPUT_TRUSTED_ACTOR_ID"]),
            now=int(time.time()),
        )
    except Exception:
        print("::error::recomp claim reconciliation failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
