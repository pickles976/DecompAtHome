"""Deterministic public progress: canonical JSON plus a static, script-free SVG.

Both files are derived only from trusted task records and trusted lease
transitions, never from labels or contributor-authored text, and they are
committed together through the Git data API so the published state is always
internally consistent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Iterable, Sequence
from xml.sax.saxutils import escape, quoteattr

from recomp.claims import latest_transition, parse_trusted_lease_transitions
from recomp.github_api import GitHubError
from recomp.task_records import TASK_MARKER_PREFIX, TaskRecordError, parse_trusted_task_record

PROGRESS_JSON_PATH = "docs/progress.json"
PROGRESS_SVG_PATH = "docs/progress.svg"
SCHEMA = 1
_IN_PROGRESS = ("claimed", "verifying")
_RETRY_STATUSES = (409, 422)
_WIDTH = 520
_HEIGHT = 120
_BAR_X = 20
_BAR_Y = 70
_BAR_WIDTH = 480
_BAR_HEIGHT = 18
_MAX_LABEL = 64


@dataclass(frozen=True)
class TaskProgress:
    task_id: str
    kind: str
    status: str
    weight: int


@dataclass(frozen=True)
class ProgressSnapshot:
    project: str
    generated_at: int
    tasks: tuple[TaskProgress, ...]

    def sorted_tasks(self) -> tuple[TaskProgress, ...]:
        return tuple(sorted(self.tasks, key=lambda task: task.task_id))

    def totals(self) -> dict[str, int]:
        tasks = self.sorted_tasks()
        done = [task for task in tasks if task.status == "done"]
        claimed = [task for task in tasks if task.status in _IN_PROGRESS]
        return {
            "tasks": len(tasks),
            "done": len(done),
            "claimed": len(claimed),
            "open": len(tasks) - len(done) - len(claimed),
            "weight_total": sum(task.weight for task in tasks),
            "weight_done": sum(task.weight for task in done),
        }


@dataclass(frozen=True)
class ProgressCommit:
    commit_sha: str
    branch: str
    attempts: int


def _newest_readable_record(comments: Any, trusted_actor_id: int):
    """Highest-generation trusted record that parses, ignoring ambiguous twins."""

    from recomp.task_records import parse_task_record_body

    best = None
    for comment in comments:
        user = comment.get("user") if isinstance(comment, Mapping) else None
        if not isinstance(user, Mapping) or user.get("id") != trusted_actor_id:
            continue
        body = comment.get("body")
        if not isinstance(body, str) or TASK_MARKER_PREFIX not in body:
            continue
        try:
            record = parse_task_record_body(body)
        except Exception:
            continue
        if best is None or record.generation >= best.generation:
            best = record
    return best


def collect_progress(github: Any, *, project: str, trusted_actor_id: int,
                     now: int) -> ProgressSnapshot:
    """Derive every task's state from trusted Issue records, never from labels."""

    tasks: dict[str, TaskProgress] = {}
    for issue in github.list_issues():
        if (issue.get("user") or {}).get("id") != trusted_actor_id:
            continue
        if TASK_MARKER_PREFIX not in (issue.get("body") or ""):
            continue
        comments = list(github.list_comments(issue["number"]))
        try:
            record = parse_trusted_task_record(comments, trusted_actor_id)
        except TaskRecordError:
            # An Issue whose trusted records disagree (a republished generation, say)
            # is still a real task: dropping it from the chart hides finished work.
            # The chart is presentation, so it falls back to the newest parseable
            # record; admission and merge keep using the strict parser.
            record = _newest_readable_record(comments, trusted_actor_id)
            if record is None:
                continue
        lease = latest_transition(
            parse_trusted_lease_transitions(comments, trusted_actor_id), record.task_id)
        if lease is not None and lease.phase in ("claimed", "verifying", "done", "blocked"):
            status = lease.phase
        else:
            status = "done" if issue.get("state") == "closed" else "open"
        tasks[record.task_id] = TaskProgress(record.task_id, record.kind, status, record.weight)
    return ProgressSnapshot(project=project, generated_at=now,
                            tasks=tuple(sorted(tasks.values(), key=lambda task: task.task_id)))


def render_progress_json(snapshot: ProgressSnapshot) -> str:
    payload = {
        "schema": SCHEMA,
        "project": snapshot.project,
        "generated_at": snapshot.generated_at,
        "totals": snapshot.totals(),
        "tasks": [
            {"task_id": task.task_id, "kind": task.kind, "status": task.status,
             "weight": task.weight}
            for task in snapshot.sorted_tasks()
        ],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def _label(value: str) -> str:
    text = value if len(value) <= _MAX_LABEL else value[:_MAX_LABEL - 1] + "\u2026"
    return escape(text)


def render_progress_svg(snapshot: ProgressSnapshot) -> str:
    """Render fixed shapes and escaped text only: no script, links, or fonts."""

    totals = snapshot.totals()
    done, count = totals["done"], totals["tasks"]
    weight_total = totals["weight_total"] or 1
    filled = round(_BAR_WIDTH * totals["weight_done"] / weight_total)
    rows = [
        f'<rect x="0" y="0" width="{_WIDTH}" height="{_HEIGHT}" fill="#0d1117"/>',
        f'<text x="20" y="32" fill="#e6edf3" font-size="18" font-family="monospace">'
        f'{_label(snapshot.project)}</text>',
        f'<text x="20" y="56" fill="#9198a1" font-size="13" font-family="monospace">'
        f'tasks {done}/{count} done &#183; weight {totals["weight_done"]}/{totals["weight_total"]}'
        f' &#183; in progress {totals["claimed"]} &#183; open {totals["open"]}</text>',
        f'<rect x="{_BAR_X}" y="{_BAR_Y}" width="{_BAR_WIDTH}" height="{_BAR_HEIGHT}"'
        f' fill="#21262d"/>',
        f'<rect x="{_BAR_X}" y="{_BAR_Y}" width="{filled}" height="{_BAR_HEIGHT}"'
        f' fill="#2ea043"/>',
        f'<text x="20" y="108" fill="#9198a1" font-size="11" font-family="monospace">'
        f'{_label(_first_labels(snapshot.sorted_tasks()))}</text>',
    ]
    body = "".join(rows)
    return (
        f'<svg xmlns={quoteattr("http://www.w3.org/2000/svg")} width="{_WIDTH}"'
        f' height="{_HEIGHT}" viewBox="0 0 {_WIDTH} {_HEIGHT}" role="img">{body}</svg>\n'
    )


def _first_labels(tasks: Sequence[TaskProgress]) -> str:
    return " ".join(f"{task.task_id}:{task.status}" for task in tasks[:3]) or "no tasks yet"


def commit_progress_update(
    github: Any,
    snapshot: ProgressSnapshot,
    *,
    branch: str = "main",
    now: int,
    max_attempts: int = 5,
) -> ProgressCommit:
    """Commit both progress files atomically, retrying from a moved base."""

    last_error: GitHubError | None = None
    for attempt in range(1, max_attempts + 1):
        base_sha = (github.get_ref(f"refs/heads/{branch}").get("object") or {}).get("sha")
        base_tree = github.get_tree(base_sha).get("sha")
        entries = []
        for path, content in (
            (PROGRESS_JSON_PATH, render_progress_json(snapshot)),
            (PROGRESS_SVG_PATH, render_progress_svg(snapshot)),
        ):
            blob = github.create_blob({"content": content, "encoding": "utf-8"})
            entries.append({"path": path, "mode": "100644", "type": "blob",
                            "sha": blob["sha"]})
        tree = github.create_tree({"base_tree": base_tree, "tree": entries})
        commit = github.create_commit({
            "message": f"chore: update recovery progress ({snapshot.totals()['done']} done)",
            "tree": tree["sha"],
            "parents": [base_sha],
        })
        try:
            github.update_ref(f"heads/{branch}", commit["sha"], force=False)
        except GitHubError as error:
            if getattr(error, "status", None) not in _RETRY_STATUSES:
                raise
            last_error = error
            continue
        return ProgressCommit(commit["sha"], branch, attempt)
    raise last_error if last_error is not None else GitHubError(None, "progress commit failed")
