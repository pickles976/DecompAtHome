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
import signal
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from recomp.candidate import CandidateTree, construct_candidate
from recomp.claims import (
    LeaseTransition,
    begin_verification,
    complete_verification,
    parse_trusted_lease_transitions,
)
from recomp.contracts import CandidateKey
from recomp.coordinator_state import CoordinatorState
from recomp.github_api import GitHubError
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
HEALTH_SCHEMA = 1
_MAX_BACKOFF_SECONDS = 300


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
    lease: LeaseTransition
    preflight: Any
    queue_key: str


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
    ) -> None:
        self.config = config
        self.github = github
        self.plan = plan
        self.runner = runner
        self.target = Path(target) if target is not None else None
        self._build = build_candidate or self._default_build
        self._verify = verify or self._default_verify
        self._admitted_total = 0
        self._last_pending: tuple[str, ...] = ()
        self._stopping = False

    # Default production wiring -------------------------------------------------
    def _default_build(self, base_sha, head_sha, *, task_id, lease_generation, policy_hash,
                       toolchain_digest, preflight_report) -> CandidateTree:
        return construct_candidate(
            self.config.repository_url, base_sha, head_sha, self.config.quarantine_root,
            task_id=task_id, lease_generation=lease_generation, policy_hash=policy_hash,
            toolchain_digest=toolchain_digest, preflight_report=preflight_report,
        )

    def _default_verify(self, candidate, target, key, *, now) -> VerificationAttestation:
        if self.runner is None:
            raise RuntimeError("coordinator requires a guest runner for verification")
        return verify_candidate(self.runner, self.plan, candidate, target, key,
                                now=now, require_public=True)

    # Reconciliation ------------------------------------------------------------
    def reconcile_once(self, *, now: int) -> ReconcileResult:
        state = CoordinatorState(self.config.state_path)
        try:
            try:
                pulls = list(self.github.list_pulls())
            except GitHubError as error:
                return ReconcileResult((), (), self._last_pending,
                                       rate_limited_until=getattr(error, "rate_limit_reset", None))
            eligible, rejected = self._classify(pulls, now)
            eligible, superseded = self._supersede(eligible)
            rejected.extend(superseded)
            state.prune_except(item.queue_key for item in eligible)
            admitted, capacity_rejected = self._admit(state, eligible, now)
            rejected.extend(capacity_rejected)
            pending = tuple(sorted(item.queue_key for item in eligible))
            self._last_pending = pending
            return ReconcileResult(tuple(admitted), tuple(rejected), pending)
        finally:
            state.close()

    def _classify(self, pulls: Iterable[Mapping[str, Any]], now: int):
        eligible: list[_Eligible] = []
        rejected: list[AdmissionDecision] = []
        for pull in pulls:
            number = pull.get("number")
            if pull.get("state") != "open" or pull.get("draft"):
                continue
            metadata = parse_pull_request_body(pull.get("body"))
            issue_number = metadata.issue_number
            if issue_number is None:
                rejected.append(AdmissionDecision(number, None, "no-task-reference"))
                continue
            comments = list(self.github.list_comments(issue_number))
            try:
                record = parse_trusted_task_record(comments, self.config.trusted_actor_id)
            except TaskRecordError:
                rejected.append(AdmissionDecision(number, issue_number, "no-task-record"))
                continue
            lease = self._current_lease(comments, record.task_id)
            author_id = (pull.get("user") or {}).get("id")
            if lease is None:
                rejected.append(AdmissionDecision(number, issue_number, "no-lease"))
                continue
            if lease.expires_at is not None and lease.expires_at <= now:
                rejected.append(AdmissionDecision(number, issue_number, "lease-expired"))
                continue
            if lease.claimant_id != author_id:
                rejected.append(AdmissionDecision(number, issue_number, "not-current-claimant"))
                continue
            if not self.plan.public:
                rejected.append(AdmissionDecision(number, issue_number, "verifier-not-public"))
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
            ), entries)
            if not report.passed:
                rejected.append(AdmissionDecision(number, issue_number, "preflight-failed"))
                continue
            eligible.append(_Eligible(
                pr_number=number, issue_number=issue_number, author_id=author_id,
                head_sha=head_sha, base_sha=base.get("sha"), task_id=record.task_id,
                lease=lease, preflight=report,
                queue_key=_queue_key(record.task_id, lease.generation, head_sha),
            ))
        return eligible, rejected

    def _current_lease(self, comments, task_id: str) -> LeaseTransition | None:
        transitions = [transition
                       for transition in parse_trusted_lease_transitions(
                           comments, self.config.trusted_actor_id)
                       if transition.task_id == task_id]
        if not transitions:
            return None
        return max(transitions, key=lambda item: (item.generation, item.issued_at,
                                                  item.last_command_id))

    @staticmethod
    def _supersede(eligible: Sequence[_Eligible]):
        newest: dict[int, _Eligible] = {}
        for item in eligible:
            current = newest.get(item.issue_number)
            if current is None or item.pr_number > current.pr_number:
                newest[item.issue_number] = item
        kept = [item for item in eligible if newest[item.issue_number] is item]
        superseded = [AdmissionDecision(item.pr_number, item.issue_number, "superseded")
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
                                                  "retry-exhausted", item.queue_key))
                continue
            if row is not None and row.status in ("verified", "rejected"):
                continue
            if active >= self.config.max_concurrent:
                rejected.append(AdmissionDecision(item.pr_number, item.issue_number,
                                                  "global-capacity", item.queue_key))
                continue
            if per_author.get(item.author_id, 0) >= self.config.max_per_author:
                rejected.append(AdmissionDecision(item.pr_number, item.issue_number,
                                                  "author-capacity", item.queue_key))
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
                policy_hash=item.lease.candidate_key.policy_hash
                if item.lease.candidate_key is not None else self.plan.verifier_policy_hash,
                toolchain_digest=self.plan.verifier_policy_hash,
                preflight_report=item.preflight,
            )
            verifying = begin_verification(item.lease, candidate.key, now=now,
                                           ttl_seconds=VERIFICATION_TTL_SECONDS)
            self._comment_transition(item.issue_number, verifying)
            state.set_status(item.queue_key, "verifying", now, quarantine=str(candidate.path))
            attestation = self._verify(candidate, self.target, candidate.key, now=now)
        except Exception:
            state.set_status(item.queue_key, "error", now)
            self._conclude(check_id, "neutral", "verification could not run",
                           ("infrastructure-error",))
            self._discard(candidate)
            return AdmissionDecision(item.pr_number, item.issue_number, "infrastructure-error",
                                     item.queue_key)
        verdict = "accepted" if attestation.passed else "rejected"
        self._comment_transition(item.issue_number,
                                 complete_verification(verifying, verdict, now=now))
        state.set_status(item.queue_key, "verified" if attestation.passed else "rejected", now)
        self._conclude(
            check_id,
            "success" if attestation.passed else "failure",
            "verification passed" if attestation.passed else "verification failed",
            attestation.reason_codes,
            evidence=attestation.evidence,
        )
        self._discard(candidate)
        return AdmissionDecision(item.pr_number, item.issue_number,
                                 "verified" if attestation.passed else "rejected",
                                 item.queue_key, candidate.key, attestation)

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
