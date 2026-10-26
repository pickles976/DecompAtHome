"""Deterministic GitHub Issue claim and verification lease reconciliation."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable, Sequence

from recomp.contracts import CandidateKey
from recomp.task_records import TaskRecord

CLAIM_TTL_SECONDS = 2 * 60 * 60
MAX_CLOCK_SKEW_SECONDS = 5 * 60
_VALID_PHASES = {"open", "claimed", "verifying", "done", "blocked"}
_VALID_VERDICTS = {"accepted", "rejected", "inconclusive"}


class ClaimError(ValueError):
    pass


def parse_command(body: str) -> str | None:
    command = body.strip()
    return command if command in {"/claim", "/heartbeat"} else None


@dataclass(frozen=True)
class ClaimCommand:
    comment_id: int
    author_id: int
    author_login: str
    body: str
    created_at: int

    def __post_init__(self) -> None:
        for value, name in ((self.comment_id, "comment id"), (self.author_id, "author id"),
                            (self.created_at, "created_at")):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ClaimError(f"{name} must be a non-negative integer")
        if not isinstance(self.author_login, str) or not self.author_login:
            raise ClaimError("author login must be non-empty")
        if not isinstance(self.body, str):
            raise ClaimError("command body must be text")


@dataclass(frozen=True)
class LeaseTransition:
    task_id: str
    phase: str
    claimant_id: int | None
    claimant_login: str | None
    generation: int
    issued_at: int
    expires_at: int | None
    last_command_id: int
    candidate_key: CandidateKey | None = None
    verdict: str | None = None
    issue_number: int | None = None

    def __post_init__(self) -> None:
        if self.phase not in _VALID_PHASES:
            raise ClaimError(f"unknown lease phase {self.phase!r}")
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) or self.generation < 0:
            raise ClaimError("lease generation must be a non-negative integer")
        if (isinstance(self.last_command_id, bool) or not isinstance(self.last_command_id, int)
                or self.last_command_id < 0):
            raise ClaimError("last command id must be a non-negative integer")
        if self.phase in {"claimed", "verifying"}:
            if self.claimant_id is None or self.claimant_login is None or self.expires_at is None:
                raise ClaimError(f"{self.phase} transition requires claimant and expiry")
        if self.verdict is not None and self.verdict not in _VALID_VERDICTS:
            raise ClaimError(f"unknown verification verdict {self.verdict!r}")

    def is_live(self, now: int) -> bool:
        return self.phase in {"claimed", "verifying"} and self.expires_at is not None and now < self.expires_at


@dataclass(frozen=True)
class LeaseState:
    lease: LeaseTransition | None
    transition: LeaseTransition | None
    task_status: str


def _latest_transition(
    task: TaskRecord,
    transitions: Iterable[LeaseTransition],
) -> LeaseTransition | None:
    matching = [transition for transition in transitions if transition.task_id == task.task_id]
    if not matching:
        return None
    return max(matching, key=lambda item: (item.generation, item.issued_at, item.last_command_id))


def _deduplicate_commands(commands: Iterable[ClaimCommand]) -> list[ClaimCommand]:
    by_id: dict[int, ClaimCommand] = {}
    for command in commands:
        existing = by_id.get(command.comment_id)
        if existing is not None and existing != command:
            raise ClaimError(f"ambiguous replay for comment {command.comment_id}")
        by_id.setdefault(command.comment_id, command)
    return sorted(by_id.values(), key=lambda item: (item.created_at, item.comment_id))


def _consume_ignored(
    current: LeaseTransition | None,
    task: TaskRecord,
    command: ClaimCommand,
    *,
    issue_number: int | None,
) -> LeaseTransition:
    if current is None:
        return LeaseTransition(
            task_id=task.task_id,
            phase="open",
            claimant_id=None,
            claimant_login=None,
            generation=0,
            issued_at=command.created_at,
            expires_at=None,
            last_command_id=command.comment_id,
            issue_number=issue_number,
        )
    return replace(current, last_command_id=command.comment_id,
                   issue_number=current.issue_number if current.issue_number is not None else issue_number)


def reconcile_claims(
    task: TaskRecord,
    trusted_transitions: Iterable[LeaseTransition],
    commands: Iterable[ClaimCommand],
    *,
    now: int,
    task_status: str = "open",
    issue_number: int | None = None,
    presentation_labels: Sequence[str] = (),
) -> LeaseState:
    """Fold complete Issue history into one optional trusted transition."""

    del presentation_labels  # Labels are presentation, never authority.
    if task_status not in {"open", "blocked", "done"}:
        raise ClaimError(f"unknown task status {task_status!r}")
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        raise ClaimError("now must be a non-negative integer")
    current = _latest_transition(task, trusted_transitions)
    if task_status in {"blocked", "done"}:
        return LeaseState(None, None, task_status)

    last_command_id = current.last_command_id if current is not None else -1
    ordered = _deduplicate_commands(commands)
    new_transition: LeaseTransition | None = None
    for command in ordered:
        if command.comment_id <= last_command_id:
            continue
        parsed = parse_command(command.body)
        if parsed is None:
            continue
        if command.created_at > now + MAX_CLOCK_SKEW_SECONDS:
            raise ClaimError(
                f"command {command.comment_id} exceeds allowed clock skew of {MAX_CLOCK_SKEW_SECONDS} seconds")
        event_time = min(command.created_at, now)
        live = current is not None and current.is_live(event_time)
        if parsed == "/claim" and not live:
            generation = (current.generation if current is not None else 0) + 1
            current = LeaseTransition(
                task_id=task.task_id,
                phase="claimed",
                claimant_id=command.author_id,
                claimant_login=command.author_login,
                generation=generation,
                issued_at=event_time,
                expires_at=event_time + CLAIM_TTL_SECONDS,
                last_command_id=command.comment_id,
                issue_number=issue_number,
            )
        elif (parsed == "/heartbeat" and live and current is not None
              and current.phase == "claimed" and current.claimant_id == command.author_id):
            current = replace(
                current,
                claimant_login=command.author_login,
                issued_at=event_time,
                expires_at=event_time + CLAIM_TTL_SECONDS,
                last_command_id=command.comment_id,
                issue_number=current.issue_number if current.issue_number is not None else issue_number,
            )
        else:
            current = _consume_ignored(
                current, task, command, issue_number=issue_number)
        last_command_id = command.comment_id
        new_transition = current

    lease = current if current is not None and current.is_live(now) else None
    status = "done" if current is not None and current.phase == "done" else "open"
    return LeaseState(lease, new_transition, status)


def begin_verification(
    lease: LeaseTransition,
    candidate_key: CandidateKey,
    *,
    now: int,
    ttl_seconds: int,
) -> LeaseTransition:
    if lease.phase not in {"claimed", "verifying"}:
        raise ClaimError("verification requires a claimed or verifying lease")
    if not lease.is_live(now):
        raise ClaimError("verification requires a live lease")
    if candidate_key.task_id != lease.task_id:
        raise ClaimError("verification candidate task does not match lease")
    if candidate_key.lease_generation != lease.generation:
        raise ClaimError("verification candidate generation does not match lease generation")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 1:
        raise ClaimError("verification ttl_seconds must be positive")
    return replace(
        lease,
        phase="verifying",
        issued_at=now,
        expires_at=now + ttl_seconds,
        candidate_key=candidate_key,
        verdict=None,
    )


def complete_verification(
    transition: LeaseTransition,
    verdict: str,
    *,
    now: int,
) -> LeaseTransition:
    if transition.phase != "verifying" or transition.candidate_key is None:
        raise ClaimError("verification completion requires a verifying transition")
    if verdict not in _VALID_VERDICTS:
        raise ClaimError(f"invalid verification verdict {verdict!r}")
    if verdict == "accepted":
        return replace(
            transition,
            phase="done",
            issued_at=now,
            expires_at=None,
            verdict=verdict,
        )
    return replace(
        transition,
        phase="claimed",
        issued_at=now,
        expires_at=now + CLAIM_TTL_SECONDS,
        verdict=verdict,
    )
