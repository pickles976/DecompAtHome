"""Publish the plugin's work plan as trusted task Issues.

One Issue per task, created by the coordinator App so its author id is the
trust anchor. Publication is idempotent: an Issue already carrying a task's
marker is left alone, so re-running after a policy bump only adds what is new.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from recomp.github_api import GitHubError
from recomp.plugin import PluginError, resolve_plugin, run_plugin
from recomp.policy import compute_policy_hash, load_lock
from recomp.project import ProjectError, validate_target
from recomp.task_records import TASK_MARKER_PREFIX, TaskRecord, render_task_record

LABELS = ("recomp-task", "open", "claimed", "verifying", "done", "blocked")

# Stable colour/description per label so repeated bootstraps never churn.
_LABEL_STYLE: Mapping[str, tuple[str, str]] = {
    "recomp-task": ("0e8a16", "Trusted Recomp@Home task Issue"),
    "open": ("c2e0c6", "Task is unclaimed and available"),
    "claimed": ("fbca04", "Task is leased by a contributor"),
    "verifying": ("1d76db", "Task submission is being verified"),
    "done": ("5319e7", "Task is merged and complete"),
    "blocked": ("b60205", "Task cannot proceed"),
}


class GitHubTaskError(RuntimeError):
    pass


@dataclass(frozen=True)
class SyncResult:
    created: tuple[str, ...]
    existing: tuple[str, ...]


def bootstrap_labels(github: Any) -> tuple[str, ...]:
    """Ensure every trusted label exists; return the ones that had to be created."""

    existing = set()
    for label in github.list_labels():
        if isinstance(label, Mapping) and isinstance(label.get("name"), str):
            existing.add(label["name"])
    created: list[str] = []
    for name in LABELS:
        if name in existing:
            continue
        colour, description = _LABEL_STYLE[name]
        try:
            github.create_label({"name": name, "color": colour, "description": description})
        except GitHubError as exc:
            if exc.status != 422:
                raise
            continue
        created.append(name)
    return tuple(created)


def _published_task_ids(github: Any, trusted_actor_id: int | None) -> set[str]:
    """Task ids published by the trusted actor; lookalike Issues do not count."""

    published = set()
    for issue in github.list_issues():
        if (trusted_actor_id is not None
                and (issue.get("user") or {}).get("id") != trusted_actor_id):
            continue
        body = issue.get("body") or ""
        if TASK_MARKER_PREFIX in body:
            marker = body.split(TASK_MARKER_PREFIX, 1)[1]
            published.add(marker.split(" -->", 1)[0].strip())
    return published


def _work_plan(root: Path, cfg: Mapping[str, Any], target: Path) -> Sequence[Mapping[str, Any]]:
    plugin = resolve_plugin(root, cfg["project"]["plugin"])
    try:
        payload = run_plugin(plugin, "work_plan", {"binary": str(target), "args": {}})
    except PluginError as exc:
        raise GitHubTaskError(f"plugin work_plan failed: {exc}") from exc
    tasks = payload.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise GitHubTaskError("plugin work_plan produced no tasks")
    return tasks


def build_task_record(task: Mapping[str, Any], cfg: Mapping[str, Any],
                      *, policy_version: int, policy_hash: str) -> TaskRecord:
    target = cfg.get("target", {})
    return TaskRecord.from_mapping({
        "schema": 1,
        "task_id": task["id"],
        "kind": task["kind"],
        "args": task.get("args", {}),
        "outputs": task["outputs"],
        "policy_version": policy_version,
        "policy_hash": policy_hash,
        "toolchain_digest": _image_digest(cfg),
        "target_sha256": target["sha256"],
        "weight": task.get("weight", 1),
        "generation": 1,
    })


def _image_digest(cfg: Mapping[str, Any]) -> str:
    image = cfg.get("toolchain", {}).get("image", "")
    if "@sha256:" not in image:
        raise GitHubTaskError("recomp.toml [toolchain] image must be digest-pinned")
    return image.split("@sha256:", 1)[1]


def sync_tasks(github: Any, root: str | Path, cfg: Mapping[str, Any],
               *, target: str | Path | None) -> SyncResult:
    """Create one trusted Issue per unpublished task in the current work plan."""

    project_root = Path(root)
    if target is None:
        raise GitHubTaskError("publishing tasks needs --target: the work plan is "
                              "computed from the pinned target")
    try:
        validate_target(target, dict(cfg))
    except ProjectError as exc:
        raise GitHubTaskError(str(exc)) from exc
    lock = load_lock(project_root)
    if lock is None:
        raise GitHubTaskError("no recomp.lock.toml; run `recomp workflow lock` first")
    if lock.get("hash") != compute_policy_hash(project_root):
        raise GitHubTaskError("policy lock is stale; run `recomp workflow lock` first")

    github_cfg = cfg.get("github") or {}
    raw_trusted = github_cfg.get("trusted_actor_id")
    trusted = int(raw_trusted) if raw_trusted is not None else None
    viewer_id = getattr(github, "viewer_id", None)
    if trusted is not None and viewer_id is not None and int(viewer_id) != trusted:
        raise GitHubTaskError(
            f"publishing as identity {viewer_id}, but the trusted actor for "
            f"{github_cfg.get('owner')}/{github_cfg.get('repository')} is {trusted}; "
            "publish task Issues as the coordinator App (run `recomp coordinator "
            "setup` for this project so the CLI holds its credentials)")
    published = _published_task_ids(github, trusted)
    created, existing = [], []
    for task in _work_plan(project_root, cfg, Path(target)):
        task_id = task.get("id")
        if not isinstance(task_id, str):
            raise GitHubTaskError("plugin work_plan produced a task without an id")
        if task_id in published:
            existing.append(task_id)
            continue
        record = build_task_record(task, cfg, policy_version=int(lock["policy_version"]),
                                   policy_hash=lock["hash"])
        issue = github.create_issue({
            "title": f"{record.task_id}: {record.kind}",
            "body": (f"{TASK_MARKER_PREFIX}{record.task_id} -->\n\n"
                     f"Claim with `/claim`. Claims last two hours; `/heartbeat` renews.\n\n"
                     f"```bash\nrecomp task start <this-issue-url> --target <your-copy>\n```\n"),
            "labels": ["recomp-task", "open"],
        })
        github.create_comment(issue["number"], render_task_record(record))
        created.append(task_id)
    return SyncResult(tuple(created), tuple(existing))
