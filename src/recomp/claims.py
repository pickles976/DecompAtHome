"""Deterministic GitHub Issue claim and verification lease reconciliation."""

from __future__ import annotations
import json

from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping, Sequence

from recomp.contracts import CandidateKey, Sha256
from recomp.task_records import TaskRecord

CLAIM_TTL_SECONDS = 2 * 60 * 60
MAX_CLOCK_SKEW_SECONDS = 5 * 60
_VALID_PHASES = {"open", "claimed", "verifying", "done", "blocked"}
_VALID_VERDICTS = {"accepted", "rejected", "inconclusive"}


class ClaimError(ValueError):
    pass


def parse_command(body: str) -> str | None:
    command = body.strip()
    return command if command in {"/claim", "/heartbeat", "/release"} else None


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
        elif (parsed == "/release" and live and current is not None
              and current.phase == "claimed" and current.claimant_id == command.author_id):
            # Releasing expires the lease in place so the task returns to the pool at
            # once instead of blocking the queue for the rest of its TTL. Only the
            # current claimant may release, and only a claimed lease: a verifying
            # candidate must run to its verdict.
            current = replace(
                current,
                claimant_login=command.author_login,
                issued_at=event_time,
                expires_at=event_time,
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


_LEASE_PREFIX = "<!-- recomp-lease-v1\n"
_LEASE_SUFFIX = "\n-->"
_LEASE_KEYS = {
    "schema", "task_id", "phase", "claimant_id", "claimant_login",
    "generation", "issued_at", "expires_at", "last_command_id",
    "candidate_key", "verdict", "issue_number",
}


def _transition_mapping(transition: LeaseTransition) -> dict[str, Any]:
    return {
        "schema": 1,
        "task_id": transition.task_id,
        "phase": transition.phase,
        "claimant_id": transition.claimant_id,
        "claimant_login": transition.claimant_login,
        "generation": transition.generation,
        "issued_at": transition.issued_at,
        "expires_at": transition.expires_at,
        "last_command_id": transition.last_command_id,
        "candidate_key": (
            transition.candidate_key.canonical()
            if transition.candidate_key is not None else None
        ),
        "verdict": transition.verdict,
        "issue_number": transition.issue_number,
    }


def render_lease_transition(transition: LeaseTransition) -> str:
    payload = json.dumps(_transition_mapping(transition), sort_keys=True, separators=(",", ":"))
    return f"{_LEASE_PREFIX}{payload}{_LEASE_SUFFIX}"


def parse_lease_transition_body(body: str) -> LeaseTransition:
    if not isinstance(body, str) or not body.startswith(_LEASE_PREFIX) or not body.endswith(_LEASE_SUFFIX):
        raise ClaimError("comment is not a recomp lease transition")
    try:
        value = json.loads(body[len(_LEASE_PREFIX):-len(_LEASE_SUFFIX)])
    except json.JSONDecodeError as exc:
        raise ClaimError("lease transition contains invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != _LEASE_KEYS or value.get("schema") != 1:
        raise ClaimError("lease transition schema is invalid")
    candidate_value = value["candidate_key"]
    if candidate_value is None:
        candidate = None
    elif isinstance(candidate_value, dict):
        try:
            candidate = CandidateKey(
                task_id=candidate_value["task_id"],
                lease_generation=candidate_value["lease_generation"],
                policy_hash=Sha256(candidate_value["policy_hash"]),
                base_sha=candidate_value["base_sha"],
                head_sha=candidate_value["head_sha"],
                tree_sha=candidate_value["tree_sha"],
                toolchain_digest=Sha256(candidate_value["toolchain_digest"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ClaimError("lease candidate key is invalid") from exc
    else:
        raise ClaimError("lease candidate key is invalid")
    try:
        return LeaseTransition(
            task_id=value["task_id"],
            phase=value["phase"],
            claimant_id=value["claimant_id"],
            claimant_login=value["claimant_login"],
            generation=value["generation"],
            issued_at=value["issued_at"],
            expires_at=value["expires_at"],
            last_command_id=value["last_command_id"],
            candidate_key=candidate,
            verdict=value["verdict"],
            issue_number=value["issue_number"],
        )
    except (TypeError, ValueError) as exc:
        raise ClaimError("lease transition fields are invalid") from exc


def latest_transition(
    transitions: Sequence[LeaseTransition],
    task_id: str | None = None,
) -> LeaseTransition | None:
    """Pick the newest transition, breaking ties by document order.

    Two transitions written in the same second (for example `verifying` then
    `done`) tie on generation, issue time, and command id; the one appended
    later is the newer one, so position is the final tiebreaker.
    """

    matching = [(index, item) for index, item in enumerate(transitions)
                if task_id is None or item.task_id == task_id]
    if not matching:
        return None
    return max(matching, key=lambda pair: (pair[1].generation, pair[1].issued_at,
                                           pair[1].last_command_id, pair[0]))[1]


def parse_trusted_lease_transitions(
    comments: Iterable[Mapping[str, Any]],
    trusted_actor_id: int,
) -> tuple[LeaseTransition, ...]:
    transitions = []
    for comment in comments:
        user = comment.get("user") if isinstance(comment, Mapping) else None
        if not isinstance(user, Mapping) or user.get("id") != trusted_actor_id:
            continue
        body = comment.get("body")
        if not isinstance(body, str) or not body.startswith(_LEASE_PREFIX):
            continue
        transitions.append(parse_lease_transition_body(body))
    return tuple(transitions)
