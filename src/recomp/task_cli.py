"""Link-driven contributor workflow: claim, produce, verify, submit.

A contributor only ever supplies a repository or Issue link plus their own copy
of the target. Everything else is derived from trusted Issue records. The
target path never enters the repository, the pull request body, or `.recomp/`;
only its hash is checked locally.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

from recomp.claims import parse_trusted_lease_transitions
from recomp.contracts import Sha256
from recomp.github_api import GitHubError
from recomp.preflight import is_context_path
from recomp.task_records import TaskRecord, TaskRecordError, parse_trusted_task_record

CONTEXT_PATH = ".recomp/task.json"
CONTEXT_SCHEMA = 1
COMMANDS = ("next", "start", "heartbeat", "run", "verify", "submit", "status")
_URL_RE = re.compile(
    r"https://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?"
    r"(?:/issues/([1-9][0-9]*))?/?$"
)
_READ_CHUNK = 1 << 20
_NO_CONTEXT = ("no active task in this checkout; run `recomp task start "
               "<repository-or-issue-url>` first")


class TaskCliError(RuntimeError):
    pass


@dataclass(frozen=True)
class TaskUrl:
    owner: str
    repository: str
    issue_number: int | None


@dataclass(frozen=True)
class TaskContext:
    schema: int
    owner: str
    repository: str
    issue_number: int
    task_id: str
    task_generation: int
    lease_generation: int
    branch: str
    policy_hash: str
    toolchain_digest: str
    image: str
    target_sha256: str | None = None

    @classmethod
    def load(cls, project: Path) -> "TaskContext":
        path = project / CONTEXT_PATH
        if not path.is_file():
            raise TaskCliError(_NO_CONTEXT)
        try:
            value = json.loads(path.read_text())
            if value.get("schema") != CONTEXT_SCHEMA:
                raise TaskCliError("local task context schema is unsupported")
            return cls(**value)
        except (json.JSONDecodeError, TypeError) as exc:
            raise TaskCliError("local task context is unreadable; delete .recomp/task.json") from exc

    def save(self, project: Path) -> Path:
        path = project / CONTEXT_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), sort_keys=True, indent=2) + "\n")
        return path


def parse_task_url(url: str) -> TaskUrl:
    match = _URL_RE.fullmatch((url or "").strip())
    if match is None:
        raise TaskCliError("expected a github.com repository or Issue link")
    owner, repository, issue = match.groups()
    return TaskUrl(owner, repository, int(issue) if issue else None)


def _file_sha256(path: Path) -> Sha256:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_READ_CHUNK):
            digest.update(chunk)
    return Sha256(digest.hexdigest())


def _require_target(target: str | Path | None, record: TaskRecord) -> Path | None:
    """No-op for targetless projects; otherwise prove the supplied copy matches."""

    if record.target_sha256 is None:
        return None
    if target is None:
        raise TaskCliError("supply your own copy of the target with --target")
    path = Path(target)
    if not path.is_file():
        raise TaskCliError("supply your own copy of the target with --target")
    if _file_sha256(path) != record.target_sha256:
        raise TaskCliError("target file hash does not match this project's pinned target")
    return path


def _trusted_task(github: Any, issue_number: int, trusted_actor_id: int) -> TaskRecord:
    comments = list(github.list_comments(issue_number))
    try:
        return parse_trusted_task_record(comments, trusted_actor_id)
    except TaskRecordError as exc:
        raise TaskCliError(f"issue #{issue_number} has no trusted recomp task record") from exc


def _current_lease(github: Any, issue_number: int, task_id: str, trusted_actor_id: int):
    transitions = [item for item in parse_trusted_lease_transitions(
        list(github.list_comments(issue_number)), trusted_actor_id) if item.task_id == task_id]
    if not transitions:
        return None
    return max(transitions, key=lambda item: (item.generation, item.issued_at,
                                              item.last_command_id))


def _open_tasks(github: Any, trusted_actor_id: int):
    found = []
    for issue in github.list_issues():
        if issue.get("state") != "open" or (issue.get("user") or {}).get("id") != trusted_actor_id:
            continue
        if "<!-- recomp-task:" not in (issue.get("body") or ""):
            continue
        try:
            record = _trusted_task(github, issue["number"], trusted_actor_id)
        except TaskCliError:
            continue
        lease = _current_lease(github, issue["number"], record.task_id, trusted_actor_id)
        found.append((record, issue["number"], lease))
    return sorted(found, key=lambda item: (item[0].task_id, item[1]))


def _other_live_leases(github: Any, trusted_actor_id: int, viewer_id: int,
                       issue_number: int, now: int) -> list[tuple[str, int]]:
    """Tasks this account already holds elsewhere: one claim at a time."""

    held = []
    for record, number, lease in _open_tasks(github, trusted_actor_id):
        if number == issue_number or lease is None:
            continue
        if lease.claimant_id == viewer_id and lease.is_live(now):
            held.append((record.task_id, number))
    return held


def _branch_name(task_id: str, issue_number: int) -> str:
    return f"recomp/{task_id}-{issue_number}"


def _viewer(github: Any) -> tuple[int, str]:
    return getattr(github, "viewer_id", None), getattr(github, "viewer_login", "")


def _fork_url(owner_login: str, url: TaskUrl) -> str:
    return f"https://github.com/{owner_login}/{url.repository}.git"


def cmd_next(github, trusted_actor_id, argv) -> str:
    url = parse_task_url(argv[0]) if argv else None
    if url is None:
        raise TaskCliError("`recomp task next` needs a repository link")
    lines = []
    for record, issue_number, lease in _open_tasks(github, trusted_actor_id):
        state = "open" if lease is None or lease.phase == "open" else lease.phase
        lines.append(f"{record.task_id}\t#{issue_number}\t{record.kind}\t"
                     f"weight={record.weight}\t{state}")
    return "\n".join(lines) + ("\n" if lines else "")


def cmd_start(github, git, project, target, image, trusted_actor_id, now, argv) -> str:
    url = parse_task_url(argv[0]) if argv else None
    if url is None:
        raise TaskCliError("`recomp task start` needs a repository or Issue link")
    # Resolve who we are before touching the Issue: with a credential that
    # cannot answer that (a coordinator App installation token, a revoked PAT)
    # posting /claim first would leave a comment that the coordinator folds
    # into a lease for that identity, silently claiming the task for a bot.
    viewer_id, _login = _viewer(github)
    if url.issue_number is not None:
        record = _trusted_task(github, url.issue_number, trusted_actor_id)
        issue_number = url.issue_number
    else:
        candidates = [
            (record, number, lease) for record, number, lease in _open_tasks(github, trusted_actor_id)
            if lease is None or not lease.is_live(now) or lease.claimant_id == viewer_id
        ]
        if not candidates:
            raise TaskCliError("no unclaimed task is available right now")
        record, issue_number, _lease = candidates[0]
    # One claim at a time: a second lease starves the pool while the first task
    # is unfinished, and the contributor cannot verify two heads at once anyway.
    held = _other_live_leases(github, trusted_actor_id, viewer_id, issue_number, now)
    if held:
        current = ", ".join(f"{task} (#{issue})" for task, issue in held)
        raise TaskCliError(
            f"you already hold a live claim on {current}; finish it, or post /release "
            "on that Issue, before claiming another task")
    target_path = _require_target(target, record)
    github.create_comment(issue_number, "/claim")
    lease = _current_lease(github, issue_number, record.task_id, trusted_actor_id)
    if lease is None or lease.claimant_id != viewer_id or not lease.is_live(now):
        raise TaskCliError(
            "claim was not granted to you; the task is claimed by someone else — "
            "run `recomp task next <repository-url>` for another task")
    branch = _branch_name(record.task_id, issue_number)
    git.create_branch(branch)
    TaskContext(
        schema=CONTEXT_SCHEMA, owner=url.owner, repository=url.repository,
        issue_number=issue_number, task_id=record.task_id,
        task_generation=record.generation, lease_generation=lease.generation,
        branch=branch, policy_hash=record.policy_hash.hex,
        toolchain_digest=record.toolchain_digest.hex,
        target_sha256=record.target_sha256.hex if record.target_sha256 else None,
        image=image,
    ).save(project)
    _ = target_path
    return (f"claimed {record.task_id} (#{issue_number}) until {lease.expires_at}\n"
            f"branch {branch}\n")


def _validated_context(github, project, trusted_actor_id, now) -> tuple[TaskContext, TaskRecord, Any]:
    context = TaskContext.load(project)
    record = _trusted_task(github, context.issue_number, trusted_actor_id)
    if record.task_id != context.task_id:
        raise TaskCliError("this issue now tracks a different task; start again")
    if record.generation != context.task_generation:
        raise TaskCliError("task generation moved; re-read the prompt and start again")
    if record.policy_hash.hex != context.policy_hash:
        raise TaskCliError("policy moved; re-read the prompt and start again")
    lease = _current_lease(github, context.issue_number, context.task_id, trusted_actor_id)
    return context, record, lease


def cmd_heartbeat(github, project, trusted_actor_id, now) -> str:
    context, _record, _lease = _validated_context(github, project, trusted_actor_id, now)
    github.create_comment(context.issue_number, "/heartbeat")
    lease = _current_lease(github, context.issue_number, context.task_id, trusted_actor_id)
    viewer_id, _login = _viewer(github)
    if lease is None or lease.claimant_id != viewer_id or not lease.is_live(now):
        raise TaskCliError("heartbeat was not accepted; your lease has moved on")
    return f"lease generation {lease.generation} valid until {lease.expires_at}\n"


def cmd_run(github, project, target, trusted_actor_id, now, run_toolchain, subcommand) -> str:
    context, record, _lease = _validated_context(github, project, trusted_actor_id, now)
    target_path = _require_target(target, record)
    status = run_toolchain([subcommand, context.task_id], target=target_path, project=project)
    if status != 0:
        raise TaskCliError(f"{subcommand} failed inside the pinned toolchain (status {status})")
    return f"{subcommand} completed for {context.task_id}\n"


def cmd_submit(github, git, project, target, trusted_actor_id, now, run_toolchain) -> str:
    context, record, lease = _validated_context(github, project, trusted_actor_id, now)
    viewer_id, login = _viewer(github)
    if lease is None or lease.claimant_id != viewer_id or not lease.is_live(now):
        raise TaskCliError("your lease is no longer live; claim the task again")
    if lease.generation != context.lease_generation:
        raise TaskCliError("lease generation moved; claim the task again")
    allowed = {rule.path.as_posix() for rule in record.outputs}
    changed = tuple(git.changed_paths())
    # Contributor context (mulch records, SUMMARY.md) rides along unverified: the
    # verifier ignores it and preflight admits it, so blocking it here would only
    # push contributors into hand-built pull requests.
    outside = sorted(path for path in changed
                     if path not in allowed and not is_context_path(path))
    if outside:
        raise TaskCliError(
            "refusing to submit changes outside task output paths: " + ", ".join(outside))
    if not any(path in allowed for path in changed):
        raise TaskCliError("nothing to submit: no task output files changed")
    target_path = _require_target(target, record)
    status = run_toolchain(["plugin-verify", context.task_id],
                           target=target_path, project=project)
    if status != 0:
        raise TaskCliError(f"local verification failed (status {status}); nothing was pushed")
    git.commit(changed, f"{context.task_id}: {record.kind}")
    if "fork" not in getattr(git, "remotes", {}):
        git.add_remote("fork", _fork_url(login, TaskUrl(context.owner, context.repository, None)))
    git.push("fork", context.branch)
    pull = github.create_pull({
        "title": f"{context.task_id}: {record.kind}",
        "head": f"{login}:{context.branch}",
        "base": "main",
        "maintainer_can_modify": False,
        "body": _pull_body(context, record, lease),
    })
    return f"opened pull request #{pull['number']} for {context.task_id}\n"


def _pull_body(context: TaskContext, record: TaskRecord, lease) -> str:
    return (
        f"Closes #{context.issue_number}\n\n"
        f"Recomp-Policy: sha256:{record.policy_hash.hex}\n"
        f"Recomp-Toolchain: sha256:{record.toolchain_digest.hex}\n"
        f"Recomp-Lease: {lease.generation}\n"
        f"Recomp-Task-Generation: {record.generation}\n"
        f"Recomp-Image: {context.image}\n\n"
        f"Produced in the pinned toolchain image from a locally supplied target.\n"
    )


def cmd_status(github, project, trusted_actor_id, now) -> str:
    context, record, lease = _validated_context(github, project, trusted_actor_id, now)
    phase = lease.phase if lease is not None else "open"
    expires = lease.expires_at if lease is not None else None
    return (f"task {context.task_id} (#{context.issue_number}) kind {record.kind}\n"
            f"branch {context.branch} lease {phase} generation "
            f"{lease.generation if lease else '-'} expires {expires}\n")


def run_task_command(
    argv: Sequence[str],
    *,
    github: Any,
    git: Any,
    project: str | Path,
    now: int,
    run_toolchain: Callable[..., int],
    image: str,
    target: str | Path | None = None,
    trusted_actor_id: int = 99,
) -> tuple[int, str, str]:
    """Execute one `recomp task` subcommand; returns (status, stdout, stderr)."""

    if not argv or argv[0] not in COMMANDS:
        return 2, "", f"usage: recomp task {{{'|'.join(COMMANDS)}}}\n"
    command, rest = argv[0], list(argv[1:])
    project_path = Path(project)
    try:
        if command == "next":
            return 0, cmd_next(github, trusted_actor_id, rest), ""
        if command == "start":
            return 0, cmd_start(github, git, project_path, target, image,
                                trusted_actor_id, now, rest), ""
        if command == "heartbeat":
            return 0, cmd_heartbeat(github, project_path, trusted_actor_id, now), ""
        if command in ("run", "verify"):
            subcommand = "plugin-run-task" if command == "run" else "plugin-verify"
            return 0, cmd_run(github, project_path, target, trusted_actor_id, now,
                              run_toolchain, subcommand), ""
        if command == "submit":
            return 0, cmd_submit(github, git, project_path, target, trusted_actor_id, now,
                                 run_toolchain), ""
        return 0, cmd_status(github, project_path, trusted_actor_id, now), ""
    except TaskCliError as error:
        return 1, "", f"error: {error}\n"
    except GitHubError as error:
        if error.status == 403:
            return 1, "", ("error: GitHub rejected this credential: "
                           f"{error}\n")
        return 1, "", f"error: GitHub call failed: {error}\n"


class Git:
    """Minimal argv-only Git porcelain for the contributor's own checkout."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def _run(self, *args: str, check: bool = True) -> str:
        completed = subprocess.run(
            ["git", "-C", os.fspath(self.root), *args],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, check=False,
        )
        if check and completed.returncode != 0:
            raise TaskCliError(f"git {args[0]} failed")
        return completed.stdout.strip()

    @property
    def current_branch(self) -> str:
        return self._run("rev-parse", "--abbrev-ref", "HEAD")

    @property
    def remotes(self) -> dict[str, str]:
        output = self._run("remote", "-v")
        return {line.split("\t")[0]: line.split("\t")[1].split(" ")[0]
                for line in output.splitlines() if "\t" in line}

    def create_branch(self, name: str) -> None:
        self._run("checkout", "-b", name)

    def checkout(self, name: str) -> None:
        self._run("checkout", name)

    def changed_paths(self, base_ref: str = "HEAD") -> tuple[str, ...]:
        tracked = self._run("diff", "--name-only", base_ref)
        untracked = self._run("ls-files", "--others", "--exclude-standard")
        paths = [line for line in (tracked + "\n" + untracked).splitlines() if line]
        return tuple(sorted({PurePosixPath(path).as_posix() for path in paths}))

    def commit(self, paths: Sequence[str], message: str) -> None:
        self._run("add", "--", *paths)
        self._run("commit", "-m", message)

    def add_remote(self, name: str, url: str) -> None:
        self._run("remote", "add", name, url)

    def push(self, remote: str, branch: str) -> None:
        self._run("push", "--set-upstream", remote, branch)
