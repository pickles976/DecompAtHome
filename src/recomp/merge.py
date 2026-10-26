"""Exact-head merge of a verified candidate.

An attestation is only valid for the exact inputs it was computed from. Before
merging, every one of those inputs is refetched and compared; anything that
moved invalidates the attestation instead of being retried. GitHub performs the
final head check itself through `expected_head_sha`, so a race between our
recheck and the merge cannot merge an unverified head.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from recomp.claims import latest_transition, parse_trusted_lease_transitions
from recomp.github_api import GitHubError
from recomp.task_records import TaskRecordError, parse_trusted_task_record
from recomp.verification import VerificationAttestation

CHECK_NAME = "recomp verification"
_INVALIDATING_STATUSES = (409, 422)
#: Transient API responses: the attestation stays valid for a bounded window, so the
#: caller may retry a merge that failed for transport reasons, but never one that
#: GitHub rejected because the verified inputs moved.
MERGE_RETRYABLE = (403, 429, 500, 502, 503, 504)


class MergeRefused(RuntimeError):
    """The verified inputs no longer describe the current repository state."""


@dataclass(frozen=True)
class MergeResult:
    merged: bool
    merge_sha: str
    pr_number: int
    issue_number: int
    task_id: str


def merge_verified_pull(
    github: Any,
    attestation: VerificationAttestation,
    *,
    pr_number: int,
    issue_number: int,
    trusted_actor_id: int,
    now: int,
    required_check: str = CHECK_NAME,
) -> MergeResult:
    """Recheck every verified input, then merge exactly the verified head."""

    if not attestation.passed:
        raise MergeRefused("attestation did not pass verification")
    key = attestation.candidate_key

    pull = github.get_pull(pr_number)
    if pull.get("state") != "open" or pull.get("draft"):
        raise MergeRefused("pull request is no longer open")
    if (pull.get("head") or {}).get("sha") != key.head_sha:
        raise MergeRefused("head moved since verification")

    base = pull.get("base") or {}
    base_ref = base.get("ref") or "main"
    current_base = (github.get_ref(f"refs/heads/{base_ref}").get("object") or {}).get("sha")
    if current_base != key.base_sha or base.get("sha") != key.base_sha:
        raise MergeRefused("base moved since verification")

    comments = list(github.list_comments(issue_number))
    try:
        record = parse_trusted_task_record(comments, trusted_actor_id)
    except TaskRecordError as exc:
        raise MergeRefused("task record is no longer readable") from exc
    if record.task_id != key.task_id:
        raise MergeRefused("task record no longer matches the verified task")
    if record.policy_hash != key.policy_hash:
        raise MergeRefused("policy moved since verification")
    if record.toolchain_digest != key.toolchain_digest:
        raise MergeRefused("toolchain moved since verification")

    lease = _current_lease(comments, trusted_actor_id, key.task_id)
    if lease is None or lease.generation != key.lease_generation:
        raise MergeRefused("lease moved since verification")
    if lease.phase not in ("verifying", "done"):
        raise MergeRefused("lease is no longer in a verifying state")
    if lease.candidate_key is not None and lease.candidate_key != key:
        raise MergeRefused("lease candidate no longer matches the attestation")

    if not _required_check_succeeded(github, key.head_sha, required_check):
        raise MergeRefused(f"required check {required_check!r} is not successful")

    try:
        merged = github.merge_pull(
            pr_number,
            key.head_sha,
            merge_method="squash",
            commit_title=f"{record.task_id}: {record.kind} (#{pr_number})",
            commit_message=_commit_message(attestation),
        )
    except GitHubError as exc:
        if getattr(exc, "status", None) in _INVALIDATING_STATUSES:
            raise MergeRefused("attestation invalidated by concurrent head movement") from exc
        raise

    if not merged.get("merged"):
        raise MergeRefused("GitHub did not confirm the merge")

    github.set_issue_labels(issue_number, ["recomp-task", "done"])
    github.update_issue(issue_number, {"state": "closed"})
    return MergeResult(True, merged.get("sha", ""), pr_number, issue_number, record.task_id)


def _current_lease(comments, trusted_actor_id: int, task_id: str):
    return latest_transition(parse_trusted_lease_transitions(comments, trusted_actor_id), task_id)


def _required_check_succeeded(github: Any, head_sha: str, name: str) -> bool:
    for run in github.list_check_runs(head_sha):
        if run.get("name") != name:
            continue
        if run.get("status") == "completed" and run.get("conclusion") == "success":
            return True
    return False


def _commit_message(attestation: VerificationAttestation) -> str:
    key = attestation.candidate_key
    return (
        f"Recomp-Task: {key.task_id}\n"
        f"Recomp-Lease: {key.lease_generation}\n"
        f"Recomp-Policy: sha256:{key.policy_hash.hex}\n"
        f"Recomp-Toolchain: sha256:{key.toolchain_digest.hex}\n"
        f"Recomp-Tree: {key.tree_sha}\n"
        f"Recomp-Verifier: sha256:{attestation.verifier_policy_hash.hex}\n"
        f"Recomp-Mode: {attestation.mode}\n"
    )
