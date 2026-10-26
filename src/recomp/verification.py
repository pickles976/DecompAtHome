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


def _spec(plan: VerificationPlan, key: CandidateKey, operation: str, index: int,
          *, input_dir: Path | None, target: Path | None,
          payload: Mapping[str, Any]) -> GuestSpec:
    guest_id = f"g-{key.tree_sha[:12]}-{index}-{operation}"
    return GuestSpec(
        guest_id=guest_id,
        operation=operation,
        command_id=plan.command_id,
        job={"task_id": key.task_id, "policy_hash": key.policy_hash.hex, **dict(payload)},
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
) -> VerificationAttestation:
    """Judge one immutable candidate, keeping candidate and target apart."""

    if require_public and not plan.public:
        raise VerificationError(
            "plugin has no separable public verification plan; it is maintainer-only")
    if candidate is None or key is None or candidate.key != key:
        raise VerificationError("candidate key does not match the constructed candidate tree")
    target_path = Path(target) if target is not None else None
    evidence: dict[str, Any] = {"verifier_mode": plan.mode}
    try:
        if plan.mode == "static":
            passed, codes, extra = _run_static(runner, plan, candidate, target_path, key)
        elif plan.mode == "bytematch":
            passed, codes, extra = _run_bytematch(runner, plan, candidate, target_path, key)
        else:
            passed, codes, extra = _run_behavioral(runner, plan, candidate, target_path, key)
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


def _run_static(runner, plan, candidate, target, key):
    """Trusted verifier code reads the target; submitted files are inert data."""

    result = runner.run(_spec(plan, key, "static-verify", 0,
                              input_dir=candidate.path, target=target, payload={}))
    digests = _digests(result.verdict)
    passed = _accepted(result.verdict)
    return passed, () if passed else ("static-verify-failed",), {"outputs": len(digests)}


def _run_bytematch(runner, plan, candidate, target, key):
    """Build without the target, then compare digests computed by trusted code."""

    build = runner.run(_spec(plan, key, "candidate-build", 0,
                             input_dir=candidate.path, target=None, payload={}))
    if not _accepted(build.verdict):
        return False, ("candidate-build-failed",), {"candidate_build": "rejected"}
    candidate_digests = _digests(build.verdict)
    oracle = runner.run(_spec(plan, key, "oracle-extract", 1,
                              input_dir=None, target=target, payload={}))
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


def _run_behavioral(runner, plan, candidate, target, key):
    """Candidate and original run in separate guests over identical cases."""

    payload = {"cases": list(plan.cases), "protocol_version": PROTOCOL_VERSION}
    build = runner.run(_spec(plan, key, "candidate-build", 0,
                             input_dir=candidate.path, target=None, payload=payload))
    if not _accepted(build.verdict):
        return False, ("candidate-build-failed",), {"candidate_build": "rejected"}
    run = runner.run(_spec(plan, key, "candidate-run", 1,
                           input_dir=candidate.path, target=None, payload=payload))
    if not _accepted(run.verdict):
        return False, ("candidate-run-failed",), {}
    oracle = runner.run(_spec(plan, key, "oracle-run", 2,
                              input_dir=None, target=target, payload=payload))
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
