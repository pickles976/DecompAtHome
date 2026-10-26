"""Coordinator: admit public pull requests, verify them privately, report publicly.

GitHub is authoritative. Every pass re-derives eligibility from Issues, trusted
lease transitions, and the pull request's current head; the local queue only
remembers attempts and quarantine paths. Nothing a contributor writes reaches
the host outside a disposable guest, and nothing leaves verification except
stable reason codes and counts.
"""

from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import signal
import time
from datetime import datetime
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from recomp.candidate import CandidateTree, construct_candidate
from recomp.claims import (
    ClaimCommand,
    ClaimError,
    LeaseTransition,
    begin_verification,
    complete_verification,
    latest_transition,
    parse_command,
    parse_trusted_lease_transitions,
    reconcile_claims,
    render_lease_transition,
)
from recomp.contracts import CandidateKey, Sha256
from recomp.coordinator_state import CoordinatorState
from recomp.github_api import GitHubError
from recomp.merge import MERGE_RETRYABLE, MergeRefused, merge_verified_pull
from recomp.preflight import (
    PullRequestFacts,
    check_preflight,
    collect_tree_entries,
    parse_pull_request_body,
)
from recomp.task_records import TaskRecordError, parse_trusted_task_record
from recomp.verification import VerificationAttestation, VerificationPlan, verify_candidate

CHECK_NAME = "recomp verification"
VERIFICATION_TTL_SECONDS = 30 * 60
HEALTH_SCHEMA = 3
MERGE_RETRYABLE_BACKOFF = (2.0, 8.0)
_MAX_BACKOFF_SECONDS = 300
#: Refusals that are routine bookkeeping rather than something a contributor can
#: act on; announcing them would be noise on every pass of a healthy queue.
_SILENT_REFUSALS = frozenset({"superseded", "already-verified", "global-capacity",
                              "author-capacity"})
_REFUSAL_MESSAGES = {
    "no-task-reference": "the body has no `Closes #<issue>` reference to a task Issue",
    "no-task-record": "the referenced Issue carries no trusted task record",
    "no-lease": "no trusted lease exists for this task",
    "lease-expired": "the task lease expired before this pass",
    "not-current-claimant": "the pull-request author does not hold the current lease",
    "verifier-not-public": "this project's verifier is not public",
    "preflight-failed": "preflight rejected the head",
    "retry-exhausted": "the verification attempt limit for this head is exhausted",
    "infrastructure-error": "verification could not run; the coordinator will retry",
}


def _refusal_comment(code: str, findings: "Sequence[str]" = ()) -> str:
    reason = _REFUSAL_MESSAGES.get(code, code)
    detail = ("\n\nFindings: " + ", ".join(f"`{item}`" for item in sorted(set(findings)))
              if findings else "")
    return (
        f"**Not admitted for verification** (`{code}`): {reason}.{detail}\n\n"
        "Fix the cause and push a new commit, or ask on the task Issue if this looks "
        "wrong. Posted once per head and reason."
    )


@dataclass(frozen=True)
class CoordinatorConfig:
    repository_url: str
    repository_full_name: str
    trusted_actor_id: int
    quarantine_root: Path
    state_path: Path
    health_path: Path
    max_concurrent: int = 4
    max_per_author: int = 2
    max_attempts: int = 3
    poll_interval_seconds: int = 60
    #: Extra maintainer-owned paths from `recomp.toml [policy] protected_paths`.
    protected_paths: tuple[str, ...] = ()

    def with_state_path(self, path: str | Path) -> "CoordinatorConfig":
        return replace(self, state_path=Path(path))


@dataclass(frozen=True)
class AdmissionDecision:
    pr_number: int
    issue_number: int | None
    code: str
    queue_key: str | None = None
    candidate_key: CandidateKey | None = None
    attestation: VerificationAttestation | None = None
    merge: Any = None
    merge_code: str | None = None
    #: Head the decision was made about, so a refusal is announced once per head.
    head_sha: str | None = None
    #: Preflight findings behind a `preflight-failed` refusal.
    findings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReconcileResult:
    admitted: tuple[AdmissionDecision, ...]
    rejected: tuple[AdmissionDecision, ...]
    pending_keys: tuple[str, ...]
    rate_limited_until: int | None = None


@dataclass(frozen=True)
class _Eligible:
    pr_number: int
    issue_number: int
    author_id: int
    head_sha: str
    base_sha: str
    task_id: str
    policy_hash: Sha256
    toolchain_digest: Sha256
    lease: LeaseTransition
    preflight: Any
    queue_key: str
    #: Trusted arguments from the published task record, handed to every guest.
    task_args: Mapping[str, Any] = field(default_factory=dict)
    #: The record's output rules: the guest must know which submitted paths count.
    output_rules: tuple = ()


def _comment_epoch(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


def framework_revision() -> str:
    """Which framework build this loop actually runs.

    The pinned revision in a project's `recomp.toml` describes what contributors
    install; it says nothing about the code producing verdicts here. Publishing the
    running revision is what makes that drift visible instead of silent.
    """

    package_root = Path(__file__).resolve().parent.parent.parent
    git_dir = package_root / ".git"
    if git_dir.exists():
        try:
            head = subprocess.run(
                ["git", "-C", os.fspath(package_root), "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=5, check=True).stdout.strip()
            if head:
                return head
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        from importlib.metadata import PackageNotFoundError, version
        try:
            return f"version:{version('recomp-at-home')}"
        except PackageNotFoundError:
            return "unknown"
    except ImportError:  # pragma: no cover - importlib.metadata is stdlib
        return "unknown"


def _queue_key(task_id: str, generation: int, head_sha: str) -> str:
    return f"{task_id}:{generation}:{head_sha}"


class Coordinator:
    """One reconcile pass: derive truth from GitHub, verify, report, forget."""

    def __init__(
        self,
        *,
        config: CoordinatorConfig,
        github: Any,
        plan: VerificationPlan,
        build_candidate: Callable[..., CandidateTree] | None = None,
        verify: Callable[..., VerificationAttestation] | None = None,
        runner: Any = None,
        target: str | Path | None = None,
        merge: Callable[..., Any] | None = merge_verified_pull,
        publish_progress: Callable[[int], Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.github = github
        self.plan = plan
        self.runner = runner
        self.target = Path(target) if target is not None else None
        self._build = build_candidate or self._default_build
        self._verify = verify or self._default_verify
        #: A verified candidate that never lands is theatre, so merging is on by
        #: default; `merge=None` is for callers that only want to audit verdicts.
        self._merge = merge
        self._publish_progress = publish_progress
        self._sleep = sleep
        self._admitted_total = 0
        self._merged_total = 0
        self._progress_failures = 0
        self._last_pending: tuple[str, ...] = ()
        self._last_counts: Mapping[str, int] = {}
        self._stopping = False

    # Default production wiring -------------------------------------------------
    def _default_build(self, base_sha, head_sha, *, task_id, lease_generation, policy_hash,
                       toolchain_digest, preflight_report) -> CandidateTree:
        return construct_candidate(
            self.config.repository_url, base_sha, head_sha, self.config.quarantine_root,
            task_id=task_id, lease_generation=lease_generation, policy_hash=policy_hash,
            toolchain_digest=toolchain_digest, preflight_report=preflight_report,
        )

    def _default_verify(self, candidate, target, key, *, now,
                        task_args: Mapping[str, Any] | None = None,
                        output_rules: Sequence[Mapping[str, Any]] = ()) -> VerificationAttestation:
        if self.runner is None:
            raise RuntimeError("coordinator requires a guest runner for verification")
        return verify_candidate(self.runner, self.plan, candidate, target, key,
                                now=now, require_public=True, task_args=task_args,
                                output_rules=output_rules)

    # Reconciliation ------------------------------------------------------------
    def reconcile_once(self, *, now: int) -> ReconcileResult:
        state = CoordinatorState(self.config.state_path)
        try:
            try:
                pulls = list(self.github.list_pulls())
            except GitHubError as error:
                return ReconcileResult((), (), self._last_pending,
                                       rate_limited_until=getattr(error, "rate_limit_reset", None))
            try:
                self._reconcile_issue_commands(now)
            except GitHubError as error:
                return ReconcileResult((), (), self._last_pending,
                                       rate_limited_until=getattr(error, "rate_limit_reset", None))
            eligible, rejected = self._classify(pulls, now)
            eligible, superseded = self._supersede(eligible)
            rejected.extend(superseded)
            # A verified candidate whose merge failed keeps its row even though its
            # closed lease makes the pull request ineligible for a second verdict:
            # that row is the only record that a published verdict still owes a
            # merge. It is kept only while the pull request is open, so a withdrawn
            # submission cannot leak a row forever.
            open_pulls = {pull.get("number") for pull in pulls
                          if pull.get("state") == "open"}
            keep = {item.queue_key for item in eligible}
            keep.update(row.candidate_key for row in state.verified_unmerged()
                        if row.pr_number in open_pulls)
            state.prune_except(keep)
            # Retrying here is what stops a verified head from sitting open until a
            # human notices it; the verdict is published either way.
            self._retry_verified_unmerged(state, now)
            admitted, capacity_rejected = self._admit(state, eligible, now)
            rejected.extend(capacity_rejected)
            self._publish_refusals(state, rejected, now)
            pending = tuple(sorted(item.queue_key for item in eligible))
            self._last_pending = pending
            self._last_counts = state.counts_by_status()
            return ReconcileResult(tuple(admitted), tuple(rejected), pending)
        finally:
            state.close()

    def _reconcile_issue_commands(self, now: int) -> None:
        """Grant and renew leases from Issue commands, as the trusted actor.

        The coordinator App is the sole lease authority: contributors and
        admission both parse transitions only from `trusted_actor_id`, so the
        same process that anchors task records must fold `/claim` and
        `/heartbeat` into transitions. Lookalike authors, stale comment ids,
        and non-task Issues are filtered by the same trusted parsers used
        everywhere else; `reconcile_claims` does the sequencing.
        """

        for issue in self.github.list_issues():
            number = issue.get("number")
            if not isinstance(number, int) or issue.get("state") != "open":
                continue
            if (issue.get("user") or {}).get("id") != self.config.trusted_actor_id:
                continue
            comments = list(self.github.list_comments(number))
            try:
                record = parse_trusted_task_record(comments, self.config.trusted_actor_id)
            except TaskRecordError:
                continue
            transitions = parse_trusted_lease_transitions(comments, self.config.trusted_actor_id)
            commands = []
            for comment in comments:
                body = comment.get("body")
                user = comment.get("user")
                if (not isinstance(body, str) or parse_command(body) is None
                        or not isinstance(user, dict)):
                    continue
                try:
                    commands.append(ClaimCommand(
                        comment_id=int(comment["id"]),
                        author_id=int(user["id"]),
                        author_login=str(user.get("login", "")),
                        body=body,
                        created_at=_comment_epoch(str(comment.get("created_at", ""))),
                    ))
                except (KeyError, TypeError, ValueError):
                    continue
            latest = latest_transition(transitions, record.task_id)
            task_status = (latest.phase if latest is not None
                           and latest.phase in {"blocked", "done"} else "open")
            try:
                state = reconcile_claims(record, transitions, commands, now=now,
                                         task_status=task_status, issue_number=number)
            except ClaimError:
                continue
            if state.transition is not None:
                self._comment_transition(number, state.transition)
            effective = state.transition or latest
            if effective is not None and effective.phase == "done":
                labels = ["recomp-task", "done"]
            elif state.lease is not None:
                labels = ["recomp-task", "claimed"]
            else:
                labels = ["recomp-task", "open"]
            try:
                self.github.set_issue_labels(number, labels)
            except GitHubError:
                pass


    def _classify(self, pulls: Iterable[Mapping[str, Any]], now: int):
        eligible: list[_Eligible] = []
        rejected: list[AdmissionDecision] = []
        for pull in pulls:
            number = pull.get("number")
            if pull.get("state") != "open" or pull.get("draft"):
                continue
            metadata = parse_pull_request_body(pull.get("body"))
            issue_number = metadata.issue_number
            pull_head = (pull.get("head") or {}).get("sha")
            if issue_number is None:
                rejected.append(AdmissionDecision(number, None, "no-task-reference",
                                                  head_sha=pull_head))
                continue
            comments = list(self.github.list_comments(issue_number))
            try:
                record = parse_trusted_task_record(comments, self.config.trusted_actor_id)
            except TaskRecordError:
                rejected.append(AdmissionDecision(number, issue_number, "no-task-record",
                                                  head_sha=pull_head))
                continue
            lease = self._current_lease(comments, record.task_id)
            author_id = (pull.get("user") or {}).get("id")
            if lease is None:
                rejected.append(AdmissionDecision(number, issue_number, "no-lease",
                                                  head_sha=pull_head))
                continue
            if lease.expires_at is not None and lease.expires_at <= now:
                rejected.append(AdmissionDecision(number, issue_number, "lease-expired",
                                                  head_sha=pull_head))
                continue
            if lease.phase == "done":
                rejected.append(AdmissionDecision(number, issue_number, "already-verified",
                                                  head_sha=pull_head))
                continue
            if lease.claimant_id != author_id:
                rejected.append(AdmissionDecision(number, issue_number, "not-current-claimant",
                                                  head_sha=pull_head))
                continue
            if not self.plan.public:
                rejected.append(AdmissionDecision(number, issue_number, "verifier-not-public",
                                                  head_sha=pull_head))
                continue
            head_sha = (pull.get("head") or {}).get("sha")
            base = pull.get("base") or {}
            rules = {rule.path.as_posix(): rule for rule in record.outputs}
            entries, truncated = collect_tree_entries(self.github, number, head_sha, rules)
            report = check_preflight(record, PullRequestFacts(
                author_id=author_id,
                head_sha=head_sha,
                base_sha=base.get("sha"),
                base_repository=(base.get("repo") or {}).get("full_name"),
                expected_repository=self.config.repository_full_name,
                referenced_issue_numbers=metadata.issue_numbers,
                task_issue_number=issue_number,
                lease_claimant_id=lease.claimant_id,
                lease_generation=(metadata.lease_generation
                                  if metadata.lease_generation == lease.generation else 0),
                lease_expires_at=lease.expires_at,
                now=now,
                task_generation=metadata.task_generation,
                policy_hash=metadata.policy_hash,
                toolchain_digest=metadata.toolchain_digest,
                tree_truncated=truncated,
            ), entries, protected_paths=self.config.protected_paths)
            if not report.passed:
                rejected.append(AdmissionDecision(number, issue_number, "preflight-failed",
                                                  head_sha=pull_head,
                                                  findings=tuple(report.codes)))
                continue
            eligible.append(_Eligible(
                pr_number=number, issue_number=issue_number, author_id=author_id,
                head_sha=head_sha, base_sha=base.get("sha"), task_id=record.task_id,
                policy_hash=record.policy_hash, toolchain_digest=record.toolchain_digest,
                lease=lease, preflight=report, task_args=record.args,
                output_rules=tuple(rule.to_mapping() for rule in record.outputs),
                queue_key=_queue_key(record.task_id, lease.generation, head_sha),
            ))
        return eligible, rejected

    def _current_lease(self, comments, task_id: str) -> LeaseTransition | None:
        return latest_transition(
            parse_trusted_lease_transitions(comments, self.config.trusted_actor_id), task_id)

    @staticmethod
    def _supersede(eligible: Sequence[_Eligible]):
        newest: dict[int, _Eligible] = {}
        for item in eligible:
            current = newest.get(item.issue_number)
            if current is None or item.pr_number > current.pr_number:
                newest[item.issue_number] = item
        kept = [item for item in eligible if newest[item.issue_number] is item]
        superseded = [AdmissionDecision(item.pr_number, item.issue_number, "superseded",
                                        head_sha=item.head_sha)
                      for item in eligible if newest[item.issue_number] is not item]
        return kept, superseded

    def _admit(self, state: CoordinatorState, eligible: Sequence[_Eligible], now: int):
        admitted: list[AdmissionDecision] = []
        rejected: list[AdmissionDecision] = []
        active, per_author = state.active_counts()
        for item in sorted(eligible, key=lambda value: value.pr_number):
            row = state.get(item.queue_key)
            if row is not None and row.attempts >= self.config.max_attempts:
                rejected.append(AdmissionDecision(item.pr_number, item.issue_number,
                                                  "retry-exhausted", item.queue_key,
                                                  head_sha=item.head_sha))
                continue
            if row is not None and row.status in ("verified", "rejected", "merged"):
                continue
            if active >= self.config.max_concurrent:
                rejected.append(AdmissionDecision(item.pr_number, item.issue_number,
                                                  "global-capacity", item.queue_key,
                                                  head_sha=item.head_sha))
                continue
            if per_author.get(item.author_id, 0) >= self.config.max_per_author:
                rejected.append(AdmissionDecision(item.pr_number, item.issue_number,
                                                  "author-capacity", item.queue_key,
                                                  head_sha=item.head_sha))
                continue
            state.upsert(candidate_key=item.queue_key, task_id=item.task_id,
                         issue_number=item.issue_number, pr_number=item.pr_number,
                         head_sha=item.head_sha, author_id=item.author_id,
                         status="queued", now=now)
            active += 1
            per_author[item.author_id] = per_author.get(item.author_id, 0) + 1
            admitted.append(self._process(state, item, now))
            self._admitted_total += 1
        return admitted, rejected

    def _process(self, state: CoordinatorState, item: _Eligible, now: int) -> AdmissionDecision:
        check = self.github.create_check_run({
            "name": CHECK_NAME,
            "head_sha": item.head_sha,
            "status": "queued",
            "output": {"title": "recomp verification queued",
                       "summary": f"task {item.task_id} generation {item.lease.generation}"},
        })
        check_id = check.get("id")
        state.record_attempt(item.queue_key, now)
        candidate = None
        try:
            candidate = self._build(
                item.base_sha, item.head_sha,
                task_id=item.task_id, lease_generation=item.lease.generation,
                policy_hash=item.policy_hash,
                toolchain_digest=item.toolchain_digest,
                preflight_report=item.preflight,
            )
            verifying = begin_verification(item.lease, candidate.key, now=now,
                                           ttl_seconds=VERIFICATION_TTL_SECONDS)
            self._comment_transition(item.issue_number, verifying)
            state.set_status(item.queue_key, "verifying", now, quarantine=str(candidate.path))
            attestation = self._verify(candidate, self.target, candidate.key, now=now,
                                       task_args=item.task_args,
                                       output_rules=item.output_rules)
        except Exception:
            state.set_status(item.queue_key, "error", now)
            self._conclude(check_id, "neutral", "verification could not run",
                           ("infrastructure-error",))
            self._discard(candidate)
            return AdmissionDecision(item.pr_number, item.issue_number, "infrastructure-error",
                                     item.queue_key, head_sha=item.head_sha)
        # The lease closes before anything else: a rejected verification returns the
        # task to its claimant with a fresh expiry, a passed one records the verdict,
        # and either way a later pass cannot re-run work under someone else's lease.
        verdict = "accepted" if attestation.passed else "rejected"
        self._comment_transition(item.issue_number,
                                 complete_verification(verifying, verdict, now=now))
        if not attestation.passed:
            state.set_status(item.queue_key, "rejected", now)
        # The check run has to read `success` before the merge is attempted:
        # merge_verified_pull refuses any head whose required check has not
        # completed successfully, so the conclusion is the merge's precondition.
        self._conclude(
            check_id,
            "success" if attestation.passed else "failure",
            "verification passed" if attestation.passed else "verification failed",
            attestation.reason_codes,
            evidence=attestation.evidence,
        )
        merge_result, merge_code = (self._merge_verified(state, item, attestation, now)
                                    if attestation.passed else (None, None))
        self._discard(candidate)
        return AdmissionDecision(item.pr_number, item.issue_number,
                                 "verified" if attestation.passed else "rejected",
                                 item.queue_key, candidate.key, attestation,
                                 merge_result, merge_code)

    def _merge_verified(self, state: CoordinatorState, item: _Eligible,
                        attestation: VerificationAttestation,
                        now: int) -> tuple[Any, str]:
        """Merge exactly the verified head, then republish progress.

        A refusal is a recorded outcome, never an exception: one stale lease or moved
        base must not end the pass for every other candidate. Transient API failures
        are retried a bounded number of times inside this same pass, because the lease
        and the verification record only stay valid while they are fresh. A candidate
        that still cannot be merged stays `verified` in the queue and shows up as
        `verified_unmerged` in the health file, where an operator can act on it.
        """

        if self._merge is None:
            state.set_status(item.queue_key, "verified", now)
            return None, "merge-disabled"
        attempts = 1 + len(MERGE_RETRYABLE_BACKOFF)
        for attempt in range(attempts):
            try:
                result = self._merge(
                    self.github, attestation,
                    pr_number=item.pr_number, issue_number=item.issue_number,
                    trusted_actor_id=self.config.trusted_actor_id, now=now,
                    required_check=CHECK_NAME)
            except MergeRefused:
                state.set_status(item.queue_key, "verified", now)
                return None, "merge-refused"
            except GitHubError as error:
                if getattr(error, "status", None) not in MERGE_RETRYABLE:
                    state.set_status(item.queue_key, "verified", now)
                    return None, "merge-api-error"
                if attempt + 1 >= attempts:
                    state.set_status(item.queue_key, "verified", now)
                    return None, "merge-rate-limited"
                self._sleep(MERGE_RETRYABLE_BACKOFF[attempt])
                continue
            except Exception:
                state.set_status(item.queue_key, "verified", now)
                return None, "merge-failed"
            state.set_status(item.queue_key, "merged", now)
            self._merged_total += 1
            self._publish_progress_best_effort(now)
            return result, "merged"
        return None, "merge-rate-limited"

    def _retry_verified_unmerged(self, state: CoordinatorState, now: int) -> None:
        """Re-attempt merges for candidates whose verdict passed in an earlier pass.

        Driven by queue rows rather than by eligibility: completing a verdict closes
        the lease, which makes the pull request ineligible for admission, so an
        eligibility-driven retry would skip exactly the candidates that need it. The
        attestation is not cached either — it is rebuilt from the trusted lease
        transition the coordinator itself published, which carries the exact
        candidate key the verdict was computed over. Anything that moved since makes
        `merge_verified_pull` refuse, as it would on the first attempt.
        """

        if self._merge is None:
            return
        for row in state.verified_unmerged():
            try:
                comments = list(self.github.list_comments(row.issue_number))
            except GitHubError:
                continue
            lease = self._current_lease(comments, row.task_id)
            key = getattr(lease, "candidate_key", None)
            if (lease is None or key is None or lease.phase != "done"
                    or lease.verdict != "accepted" or key.head_sha != row.head_sha):
                continue
            attestation = VerificationAttestation(
                candidate_key=key,
                verifier_policy_hash=self.plan.verifier_policy_hash,
                mode=self.plan.mode,
                passed=True,
                evidence={"retry": "verified-unmerged"},
                reason_codes=(),
                started_at=now,
                completed_at=now,
            )
            item = _Eligible(
                pr_number=row.pr_number, issue_number=row.issue_number,
                author_id=row.author_id, head_sha=row.head_sha, base_sha=key.base_sha,
                task_id=row.task_id, policy_hash=key.policy_hash,
                toolchain_digest=key.toolchain_digest, lease=lease, preflight=None,
                queue_key=row.candidate_key,
            )
            _, code = self._merge_verified(state, item, attestation, now)
            if code != "merged":
                state.claim_notice(pr_number=row.pr_number, head_sha=row.head_sha,
                                   reason=code or "merge-failed", now=now)

    def _publish_refusals(self, state: CoordinatorState,
                          rejected: "Sequence[AdmissionDecision]", now: int) -> None:
        """Say why a pull request was refused, once per pull request, head and reason.

        A silent refusal is indistinguishable from a wedged loop and costs a
        contributor hours. The codes are already stable and public, so publishing
        them tells an attacker nothing new.
        """

        for decision in rejected:
            head = decision.head_sha
            if (not isinstance(decision.pr_number, int) or not isinstance(head, str)
                    or not head or decision.code in _SILENT_REFUSALS):
                continue
            try:
                if not state.claim_notice(pr_number=decision.pr_number, head_sha=head,
                                          reason=decision.code, now=now):
                    continue
                self.github.create_comment(
                    decision.pr_number, _refusal_comment(decision.code, decision.findings))
            except GitHubError:
                continue

    def _publish_progress_best_effort(self, now: int) -> None:
        """Republish progress charts; failing to publish never undoes a merge."""

        if self._publish_progress is None:
            return
        try:
            self._publish_progress(now)
        except Exception:
            self._progress_failures += 1

    def _comment_transition(self, issue_number: int, transition: LeaseTransition) -> None:
        from recomp.claims import render_lease_transition

        self.github.create_comment(issue_number, render_lease_transition(transition))

    def _conclude(self, check_id: int | None, conclusion: str, title: str,
                  codes: Sequence[str], *, evidence: Mapping[str, Any] | None = None) -> None:
        if check_id is None:
            return
        summary = {"codes": sorted(set(codes)), "evidence": dict(sorted((evidence or {}).items()))}
        self.github.update_check_run(check_id, {
            "status": "completed",
            "conclusion": conclusion,
            "output": {"title": title,
                       "summary": json.dumps(summary, sort_keys=True, separators=(",", ":"))},
        })

    @staticmethod
    def _discard(candidate: CandidateTree | None) -> None:
        if candidate is not None:
            shutil.rmtree(candidate.path, ignore_errors=True)

    # Health and loop -----------------------------------------------------------
    def write_health(self, *, now: int) -> Path:
        path = Path(self.config.health_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({
            "schema": HEALTH_SCHEMA,
            "last_reconcile_at": now,
            "pending": len(self._last_pending),
            "admitted_total": self._admitted_total,
            "merged_total": self._merged_total,
            "verified_unmerged": self._last_counts.get("verified", 0),
            "progress_failures": self._progress_failures,
            "framework_revision": framework_revision(),
        }, sort_keys=True, separators=(",", ":")).encode()
        temporary = path.with_name(path.name + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        return path

    def request_stop(self, *_signal: Any) -> None:
        self._stopping = True

    def run_loop(self, *, max_passes: int | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> int:
        """Poll GitHub with capped jittered backoff; never opens an inbound port."""

        for name in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(name, self.request_stop)
            except ValueError:
                pass
        passes = 0
        delay = float(self.config.poll_interval_seconds)
        while not self._stopping and (max_passes is None or passes < max_passes):
            started = clock()
            now = int(time.time())
            result = self.reconcile_once(now=now)
            self.write_health(now=now)
            passes += 1
            if result.rate_limited_until is not None:
                delay = max(1.0, float(result.rate_limited_until) - now)
            elif result.admitted:
                delay = float(self.config.poll_interval_seconds)
            else:
                delay = min(_MAX_BACKOFF_SECONDS, delay * 2)
            jitter = random.uniform(0, min(5.0, delay / 4))
            elapsed = clock() - started
            sleep(max(0.0, delay + jitter - elapsed))
        return passes
