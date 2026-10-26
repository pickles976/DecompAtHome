"""Candidate/oracle separated verification.

The rule this module exists to enforce: untrusted contributor code and the
original target never occupy the same guest. Candidate work runs in a
target-free microVM; the original is only ever read by trusted verifier code in
a separate oracle microVM; the host control process compares nothing but
bounded, schema-checked digests.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from recomp.contracts import CandidateKey, Sha256
from recomp.firecracker import GuestError, GuestLimits, GuestSpec
from recomp.plugin import Plugin, VerifyManifest, plugin_file_hashes

MODES = ("static", "bytematch", "behavioral")
PROTOCOL_VERSION = 1
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_DEFAULT_MEMORY_MIB = 1024
_DEFAULT_VCPUS = 1
_DEFAULT_PIDS = 256
_DEFAULT_NOFILE = 256
_MAX_RESULT_BYTES = 1 << 20
MAX_TASK_ARGS_BYTES = 64 << 10
#: Host-authored keys in a guest job payload; a task record may not shadow them.
_RESERVED_JOB_KEYS = frozenset(
    {"task_id", "policy_hash", "cases", "protocol_version", "outputs"})
MAX_OUTPUT_RULES_BYTES = 16 << 10
_REQUIRED_COMMANDS = {
    "static": (),
    "bytematch": ("candidate_build", "oracle_run"),
    "behavioral": ("candidate_build", "candidate_run", "oracle_run"),
}


class VerificationError(ValueError):
    pass


@dataclass(frozen=True)
class VerificationPlan:
    """A trusted, separable description of how a candidate may be judged."""

    mode: str
    public: bool
    timeout_seconds: int
    max_artifact_bytes: int
    cases: tuple[str, ...]
    command_id: str
    verifier_policy_hash: Sha256

    @classmethod
    def from_plugin(cls, plugin: Plugin) -> "VerificationPlan":
        manifest: VerifyManifest = plugin.verify
        if manifest.mode not in MODES:
            raise VerificationError(f"unknown verification mode {manifest.mode!r}")
        if manifest.timeout_seconds is None:
            raise VerificationError("[verify] timeout_seconds is required")
        if manifest.max_artifact_bytes is None:
            raise VerificationError("[verify] max_artifact_bytes is required")
        for key in _REQUIRED_COMMANDS[manifest.mode]:
            if key not in manifest.commands:
                raise VerificationError(f"[verify] {manifest.mode} mode requires {key}")
        cases: tuple[str, ...] = ()
        if manifest.mode == "behavioral":
            protocol = manifest.protocol
            if protocol.get("version") != PROTOCOL_VERSION:
                raise VerificationError(
                    f"[verify.protocol] version must be {PROTOCOL_VERSION}")
            raw_cases = protocol.get("cases")
            if (not isinstance(raw_cases, list) or not raw_cases
                    or any(not isinstance(case, str) or not case for case in raw_cases)):
                raise VerificationError("[verify.protocol] cases must be a non-empty string list")
            cases = tuple(raw_cases)
        return cls(
            mode=manifest.mode,
            public=manifest.public,
            timeout_seconds=manifest.timeout_seconds,
            max_artifact_bytes=manifest.max_artifact_bytes,
            cases=cases,
            command_id=f"{plugin.name}.{manifest.mode}",
            verifier_policy_hash=_verifier_policy_hash(plugin),
        )

    def limits(self) -> GuestLimits:
        return GuestLimits(
            wall_seconds=self.timeout_seconds,
            memory_mib=_DEFAULT_MEMORY_MIB,
            vcpus=_DEFAULT_VCPUS,
            result_bytes=min(self.max_artifact_bytes, _MAX_RESULT_BYTES),
            pids=_DEFAULT_PIDS,
            nofile=_DEFAULT_NOFILE,
        )


def _verifier_policy_hash(plugin: Plugin) -> Sha256:
    payload = json.dumps(
        {"name": plugin.name, "files": plugin_file_hashes(plugin)},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    return Sha256(hashlib.sha256(payload).hexdigest())


@dataclass(frozen=True)
class VerificationAttestation:
    """Everything a merge decision may rely on, and nothing else."""

    candidate_key: CandidateKey
    verifier_policy_hash: Sha256
    mode: str
    passed: bool
    evidence: Mapping[str, Any]
    reason_codes: tuple[str, ...]
    started_at: int
    completed_at: int

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "candidate_key": self.candidate_key.canonical(),
            "verifier_policy_hash": self.verifier_policy_hash.hex,
            "mode": self.mode,
            "passed": self.passed,
            "evidence": dict(sorted(self.evidence.items())),
            "reason_codes": list(self.reason_codes),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


def _digests(verdict: Mapping[str, Any]) -> dict[str, str]:
    outputs = verdict.get("outputs", {})
    if not isinstance(outputs, Mapping):
        raise VerificationError("verdict outputs must be a mapping")
    for name, digest in outputs.items():
        if (not isinstance(name, str) or not isinstance(digest, str)
                or _SHA256_RE.fullmatch(digest) is None):
            raise VerificationError("verdict outputs must map names to sha256 digests")
    return dict(outputs)


def _validated_task_args(task_args: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate the trusted task arguments handed to every guest job.

    These come from the coordinator-published task record, so they are trusted, but
    they cross into a guest alongside keys the host itself writes: a task record
    that could overwrite `task_id` or `cases` would let a plugin author redefine what
    the verifier compares. Size and JSON-serializability are checked here rather than
    in the runner so a bad record fails as a stable reason code, not a transport error.
    """

    if task_args is None:
        return {}
    if not isinstance(task_args, Mapping):
        raise VerificationError("task arguments must be a mapping")
    collisions = sorted(set(task_args) & _RESERVED_JOB_KEYS)
    if collisions:
        raise VerificationError(
            "task arguments collide with host job keys: " + ", ".join(collisions))
    try:
        encoded = json.dumps(dict(task_args), sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise VerificationError(f"task arguments must be JSON-serializable: {exc}") from exc
    if len(encoded.encode()) > MAX_TASK_ARGS_BYTES:
        raise VerificationError(
            f"task arguments exceed {MAX_TASK_ARGS_BYTES} bytes")
    return json.loads(encoded)


def _validated_output_rules(rules: Sequence[Mapping[str, Any]] | None) -> list[dict[str, Any]]:
    """Normalize the task record's output rules for the guest job payload.

    A guest that cannot see which submitted paths the host already accepted cannot
    tell a submitted artifact from scratch space, so `static` and `bytematch`
    plugins would have to guess. The rules come from the trusted task record, but
    they cross the same boundary as task arguments, so they are bounded and
    shape-checked here.
    """

    if rules is None:
        return []
    if isinstance(rules, (str, bytes)) or not isinstance(rules, Sequence):
        raise VerificationError("output rules must be a sequence of objects")
    normalized: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, Mapping):
            raise VerificationError("each output rule must be an object")
        path = rule.get("path")
        if not isinstance(path, str) or not path or path.startswith("/"):
            raise VerificationError("each output rule needs a relative path")
        normalized.append({str(key): value for key, value in sorted(rule.items())})
    try:
        encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise VerificationError(f"output rules must be JSON-serializable: {exc}") from exc
    if len(encoded.encode()) > MAX_OUTPUT_RULES_BYTES:
        raise VerificationError(f"output rules exceed {MAX_OUTPUT_RULES_BYTES} bytes")
    return normalized


def _spec(plan: VerificationPlan, key: CandidateKey, operation: str, index: int,
          *, input_dir: Path | None, target: Path | None,
          payload: Mapping[str, Any], task_args: Mapping[str, Any] | None = None,
          output_rules: Sequence[Mapping[str, Any]] = (),
          ) -> GuestSpec:
    guest_id = f"g-{key.tree_sha[:12]}-{index}-{operation}"
    job: dict[str, Any] = {"task_id": key.task_id, "policy_hash": key.policy_hash.hex}
    if task_args:
        job["args"] = dict(task_args)
    if output_rules:
        job["outputs"] = [dict(rule) for rule in output_rules]
    job.update(payload)
    return GuestSpec(
        guest_id=guest_id,
        operation=operation,
        command_id=plan.command_id,
        job=job,
        limits=plan.limits(),
        input_dir=input_dir,
        target_path=target,
    )


def verify_candidate(
    runner: Any,
    plan: VerificationPlan,
    candidate: Any,
    target: str | Path | None,
    key: CandidateKey | None,
    *,
    now: int,
    require_public: bool = False,
    task_args: Mapping[str, Any] | None = None,
    output_rules: Sequence[Mapping[str, Any]] | None = None,
) -> VerificationAttestation:
    """Judge one immutable candidate, keeping candidate and target apart."""

    if require_public and not plan.public:
        raise VerificationError(
            "plugin has no separable public verification plan; it is maintainer-only")
    if candidate is None or key is None or candidate.key != key:
        raise VerificationError("candidate key does not match the constructed candidate tree")
    target_path = Path(target) if target is not None else None
    arguments = _validated_task_args(task_args)
    rules = _validated_output_rules(output_rules)
    evidence: dict[str, Any] = {"verifier_mode": plan.mode}
    try:
        if plan.mode == "static":
            passed, codes, extra = _run_static(runner, plan, candidate, target_path, key,
                                               arguments, rules)
        elif plan.mode == "bytematch":
            passed, codes, extra = _run_bytematch(runner, plan, candidate, target_path, key,
                                                  arguments, rules)
        else:
            passed, codes, extra = _run_behavioral(runner, plan, candidate, target_path, key,
                                                   arguments, rules)
        evidence.update(extra)
    except GuestError:
        passed, codes = False, ("guest-failed",)
    except VerificationError:
        passed, codes = False, ("verdict-invalid",)
    return VerificationAttestation(
        candidate_key=key,
        verifier_policy_hash=plan.verifier_policy_hash,
        mode=plan.mode,
        passed=passed,
        evidence=evidence,
        reason_codes=tuple(codes),
        started_at=now,
        completed_at=now,
    )


def _accepted(verdict: Mapping[str, Any]) -> bool:
    return verdict.get("status") == "accepted"


def _run_static(runner, plan, candidate, target, key, task_args, output_rules=()):
    """Trusted verifier code reads the target; submitted files are inert data."""

    result = runner.run(_spec(plan, key, "static-verify", 0,
                              input_dir=candidate.path, target=target, payload={},
                              task_args=task_args, output_rules=output_rules))
    digests = _digests(result.verdict)
    passed = _accepted(result.verdict)
    return passed, () if passed else ("static-verify-failed",), {"outputs": len(digests)}


def _run_bytematch(runner, plan, candidate, target, key, task_args, output_rules=()):
    """Build without the target, then compare digests computed by trusted code."""

    build = runner.run(_spec(plan, key, "candidate-build", 0,
                             input_dir=candidate.path, target=None, payload={},
                             task_args=task_args, output_rules=output_rules))
    if not _accepted(build.verdict):
        return False, ("candidate-build-failed",), {"candidate_build": "rejected"}
    candidate_digests = _digests(build.verdict)
    oracle = runner.run(_spec(plan, key, "oracle-extract", 1,
                              input_dir=None, target=target, payload={},
                              task_args=task_args, output_rules=output_rules))
    if not _accepted(oracle.verdict):
        return False, ("oracle-failed",), {"oracle": "rejected"}
    oracle_digests = _digests(oracle.verdict)
    artifact = candidate_digests.get("artifact")
    expected = oracle_digests.get("artifact")
    if artifact is None or expected is None:
        return False, ("artifact-missing",), {}
    evidence = {"artifact_digest": artifact, "oracle_digest": expected}
    if artifact != expected:
        return False, ("artifact-mismatch",), evidence
    return True, (), evidence


def _run_behavioral(runner, plan, candidate, target, key, task_args, output_rules=()):
    """Candidate and original run in separate guests over identical cases."""

    payload = {"cases": list(plan.cases), "protocol_version": PROTOCOL_VERSION}
    build = runner.run(_spec(plan, key, "candidate-build", 0,
                             input_dir=candidate.path, target=None, payload=payload,
                             task_args=task_args, output_rules=output_rules))
    if not _accepted(build.verdict):
        return False, ("candidate-build-failed",), {"candidate_build": "rejected"}
    run = runner.run(_spec(plan, key, "candidate-run", 1,
                           input_dir=candidate.path, target=None, payload=payload,
                           task_args=task_args, output_rules=output_rules))
    if not _accepted(run.verdict):
        return False, ("candidate-run-failed",), {}
    oracle = runner.run(_spec(plan, key, "oracle-run", 2,
                              input_dir=None, target=target, payload=payload,
                              task_args=task_args, output_rules=output_rules))
    if not _accepted(oracle.verdict):
        return False, ("oracle-failed",), {}
    candidate_cases = _digests(run.verdict)
    oracle_cases = _digests(oracle.verdict)
    missing = [case for case in plan.cases
               if case not in candidate_cases or case not in oracle_cases]
    diverged = [case for case in plan.cases
                if case not in missing and candidate_cases[case] != oracle_cases[case]]
    evidence = {
        "cases_compared": len(plan.cases) - len(missing),
        "cases_diverged": len(diverged),
        "cases_missing": len(missing),
    }
    if missing:
        return False, ("case-missing",), evidence
    if diverged:
        return False, ("behavior-divergence",), evidence
    return True, (), evidence
