#!/usr/bin/env python3
"""Secret-free pull-request preflight action; fetches data without checkout."""

from __future__ import annotations

import json
import os
import sys
import time
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, os.fspath(ROOT / "src"))

from recomp.claims import parse_trusted_lease_transitions  # noqa: E402
from recomp.github_api import GitHubClient  # noqa: E402
from recomp.preflight import (  # noqa: E402
    PullRequestFacts,
    check_preflight,
    collect_tree_entries,
    parse_pull_request_body,
)
from recomp.project import protected_paths  # noqa: E402
from recomp.task_records import parse_trusted_task_record  # noqa: E402


def _protected_paths(environ: Mapping[str, str]) -> tuple[str, ...]:
    """Maintainer-owned paths the workflow passes in, or those in a checked-out config."""

    declared = environ.get("INPUT_PROTECTED_PATHS", "")
    values = [item.strip() for item in declared.replace("\n", ",").split(",")]
    paths = tuple(item for item in values if item)
    if paths:
        return paths
    manifest = Path(environ.get("GITHUB_WORKSPACE", "")) / "recomp.toml"
    if not manifest.is_file():
        return ()
    try:
        return protected_paths(tomllib.loads(manifest.read_text()))
    except (OSError, tomllib.TOMLDecodeError):
        return ()


def _write_result(codes: tuple[str, ...], output_path: Path, summary_path: Path) -> None:
    stable = "pass" if not codes else ",".join(sorted(set(codes)))
    output_path.write_text(f"codes={stable}\n")
    summary_path.write_text(f"recomp preflight: {stable}\n")


def run(
    event: dict,
    github: GitHubClient,
    *,
    trusted_actor_id: int,
    now: int,
    output_path: Path,
    summary_path: Path,
    protected_paths: Sequence[str] = (),
) -> int:
    try:
        pull = event["pull_request"]
        metadata = parse_pull_request_body(pull.get("body"))
        issue_number = metadata.issue_number
        comments = list(github.list_comments(issue_number)) if issue_number is not None else []
        task = parse_trusted_task_record(comments, trusted_actor_id)
        transitions = parse_trusted_lease_transitions(comments, trusted_actor_id)
        lease = max(
            (transition for transition in transitions if transition.task_id == task.task_id),
            key=lambda transition: (transition.generation, transition.issued_at,
                                    transition.last_command_id),
            default=None,
        )
        head_sha = pull.get("head", {}).get("sha")
        rules = {rule.path.as_posix(): rule for rule in task.outputs}
        entries, truncated = collect_tree_entries(github, pull["number"], head_sha, rules)
        current_generation = lease.generation if lease is not None else None
        declared = metadata.lease_generation
        report = check_preflight(
            task,
            PullRequestFacts(
                author_id=pull.get("user", {}).get("id"),
                head_sha=head_sha,
                base_sha=pull.get("base", {}).get("sha"),
                base_repository=pull.get("base", {}).get("repo", {}).get("full_name"),
                expected_repository=event.get("repository", {}).get("full_name"),
                referenced_issue_numbers=metadata.issue_numbers,
                task_issue_number=issue_number,
                lease_claimant_id=lease.claimant_id if lease is not None else None,
                lease_generation=declared if declared == current_generation else 0,
                lease_expires_at=lease.expires_at if lease is not None else None,
                now=now,
                task_generation=metadata.task_generation,
                policy_hash=metadata.policy_hash,
                toolchain_digest=metadata.toolchain_digest,
                tree_truncated=truncated,
            ),
            entries,
            protected_paths=protected_paths,
        )
        _write_result(report.codes, output_path, summary_path)
        return 0 if report.passed else 1
    except Exception as exc:
        # A bare `missing-evidence` on every pull request is indistinguishable from
        # a broken deployment: name the actual failure for the run log while keeping
        # the stable code for tooling.
        print(f"recomp preflight internal error: {type(exc).__name__}: {exc}",
              flush=True)
        _write_result(("missing-evidence",), output_path, summary_path)
        return 1


def main() -> int:
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        token = os.environ["INPUT_TOKEN"]
        github = GitHubClient(
            os.environ.get("INPUT_API_URL", "https://api.github.com"),
            os.environ["INPUT_OWNER"],
            os.environ["INPUT_REPOSITORY"],
            lambda: token,
        )
        return run(
            event,
            github,
            trusted_actor_id=int(os.environ["INPUT_TRUSTED_ACTOR_ID"]),
            now=int(time.time()),
            output_path=Path(os.environ["GITHUB_OUTPUT"]),
            summary_path=Path(os.environ["GITHUB_STEP_SUMMARY"]),
            protected_paths=_protected_paths(os.environ),
        )
    except Exception:
        print("::error::recomp preflight failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
