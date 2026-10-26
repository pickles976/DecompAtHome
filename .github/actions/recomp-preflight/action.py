#!/usr/bin/env python3
"""Secret-free pull-request preflight action; fetches data without checkout."""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, os.fspath(ROOT / "src"))

from recomp.claims import parse_trusted_lease_transitions  # noqa: E402
from recomp.contracts import Sha256  # noqa: E402
from recomp.github_api import GitHubClient  # noqa: E402
from recomp.preflight import PullRequestFacts, TreeEntry, check_preflight  # noqa: E402
from recomp.task_records import parse_trusted_task_record  # noqa: E402

_ISSUE_RE = re.compile(r"(?im)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+#(\d+)\b")
_FIELD_PATTERNS = {
    "policy": re.compile(r"(?im)^Recomp-Policy:\s*sha256:([0-9a-f]{64})\s*$"),
    "toolchain": re.compile(r"(?im)^Recomp-Toolchain:\s*sha256:([0-9a-f]{64})\s*$"),
    "lease": re.compile(r"(?im)^Recomp-Lease:\s*([1-9][0-9]*)\s*$"),
    "task_generation": re.compile(r"(?im)^Recomp-Task-Generation:\s*([1-9][0-9]*)\s*$"),
}


def _field(body: str, name: str) -> str | None:
    matches = _FIELD_PATTERNS[name].findall(body)
    return matches[0] if len(matches) == 1 else None


def _write_result(codes: tuple[str, ...], output_path: Path, summary_path: Path) -> None:
    stable = "pass" if not codes else ",".join(sorted(set(codes)))
    output_path.write_text(f"codes={stable}\n")
    summary_path.write_text(f"recomp preflight: {stable}\n")


def _decode_blob(blob: dict) -> bytes | None:
    if blob.get("encoding") != "base64" or not isinstance(blob.get("content"), str):
        return None
    try:
        return base64.b64decode(blob["content"], validate=True)
    except (ValueError, TypeError):
        return None


def run(
    event: dict,
    github: GitHubClient,
    *,
    trusted_actor_id: int,
    now: int,
    output_path: Path,
    summary_path: Path,
) -> int:
    try:
        pull = event["pull_request"]
        body = pull.get("body") or ""
        issue_numbers = tuple(int(value) for value in _ISSUE_RE.findall(body))
        issue_number = issue_numbers[0] if len(issue_numbers) == 1 else None
        comments = list(github.list_comments(issue_number)) if issue_number is not None else []
        task = parse_trusted_task_record(comments, trusted_actor_id)
        transitions = parse_trusted_lease_transitions(comments, trusted_actor_id)
        lease = max(
            (transition for transition in transitions if transition.task_id == task.task_id),
            key=lambda transition: (transition.generation, transition.issued_at, transition.last_command_id),
            default=None,
        )
        head_sha = pull.get("head", {}).get("sha")
        tree_data = github.get_tree(head_sha, recursive=True) if isinstance(head_sha, str) else {"tree": []}
        tree_by_path = {
            item.get("path"): item for item in tree_data.get("tree", [])
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        }
        rules = {rule.path.as_posix(): rule for rule in task.outputs}
        entries = []
        for changed in github.list_pull_files(pull["number"]):
            path = changed.get("filename")
            tree_item = tree_by_path.get(path, {})
            status = changed.get("status", "modified")
            sha = tree_item.get("sha") or changed.get("sha")
            blob = github.get_blob(sha) if status != "removed" and isinstance(sha, str) else {}
            content = _decode_blob(blob)
            rule = rules.get(path)
            entries.append(TreeEntry(
                path=path,
                mode=tree_item.get("mode", "000000"),
                kind=tree_item.get("type", "blob"),
                sha=sha,
                size=blob.get("size") if isinstance(blob, dict) else None,
                status="deleted" if status == "removed" else status,
                prefix=None if content is None else content[:4096],
                media_type=rule.media_type if rule is not None else "application/octet-stream",
            ))
        declared_lease = _field(body, "lease")
        policy = _field(body, "policy")
        toolchain = _field(body, "toolchain")
        task_generation = _field(body, "task_generation")
        current_generation = lease.generation if lease is not None else None
        lease_generation = int(declared_lease) if declared_lease is not None else None
        if current_generation is None or lease_generation != current_generation:
            lease_generation = 0
        report = check_preflight(
            task,
            PullRequestFacts(
                author_id=pull.get("user", {}).get("id"),
                head_sha=head_sha,
                base_sha=pull.get("base", {}).get("sha"),
                base_repository=pull.get("base", {}).get("repo", {}).get("full_name"),
                expected_repository=event.get("repository", {}).get("full_name"),
                referenced_issue_numbers=issue_numbers,
                task_issue_number=issue_number,
                lease_claimant_id=lease.claimant_id if lease is not None else None,
                lease_generation=lease_generation,
                lease_expires_at=lease.expires_at if lease is not None else None,
                now=now,
                task_generation=int(task_generation) if task_generation is not None else None,
                policy_hash=Sha256(policy) if policy is not None else None,
                toolchain_digest=Sha256(toolchain) if toolchain is not None else None,
                tree_truncated=tree_data.get("truncated") if isinstance(tree_data, dict) else None,
            ),
            entries,
        )
        _write_result(report.codes, output_path, summary_path)
        return 0 if report.passed else 1
    except Exception:
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
        )
    except Exception:
        print("::error::recomp preflight failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
