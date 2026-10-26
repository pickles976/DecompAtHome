from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from recomp.candidate import CandidateTree
from recomp.contracts import CandidateKey, Sha256
from recomp.firecracker import GuestError, GuestResult
from recomp.plugin import PluginError, load_plugin
from recomp.verification import (
    VerificationError,
    VerificationPlan,
    verify_candidate,
)

POLICY = Sha256("1" * 64)
TOOLCHAIN = Sha256("2" * 64)
ARTIFACT = Sha256("3" * 64)
CASE_DIGEST = Sha256("4" * 64)

STATIC = """
[plugin]
name = "static-plug"
version = "0.1.0"
capabilities = ["verify"]

[verify]
mode = "static"
public = true
timeout_seconds = 30
max_artifact_bytes = 1048576

[commands]
verify = ["python3", "runner.py", "verify"]
"""

BYTEMATCH = """
[plugin]
name = "bytematch-plug"
version = "0.1.0"
capabilities = ["verify"]

[verify]
mode = "bytematch"
public = true
timeout_seconds = 120
max_artifact_bytes = 1048576
candidate_build = ["python3", "runner.py", "build"]
oracle_run = ["python3", "runner.py", "extract"]

[commands]
verify = ["python3", "runner.py", "verify"]
"""

BEHAVIORAL = """
[plugin]
name = "behavioral-plug"
version = "0.1.0"
capabilities = ["verify"]

[verify]
mode = "behavioral"
public = true
timeout_seconds = 120
max_artifact_bytes = 1048576
candidate_build = ["python3", "runner.py", "build"]
candidate_run = ["python3", "runner.py", "run"]
oracle_run = ["python3", "runner.py", "oracle"]

[verify.protocol]
version = 1
cases = ["case-a", "case-b"]

[commands]
verify = ["python3", "runner.py", "verify"]
"""


def make_plugin(tmp_path, manifest, name="plug"):
    root = tmp_path / name
    root.mkdir(parents=True)
    (root / "recomp.plugin.toml").write_text(manifest)
    (root / "runner.py").write_text("#!/usr/bin/env python3\n")
    return load_plugin(root)


def plan_for(tmp_path, manifest, name="plug"):
    return VerificationPlan.from_plugin(make_plugin(tmp_path, manifest, name))


@pytest.fixture
def candidate(tmp_path):
    path = tmp_path / "candidate"
    path.mkdir()
    (path / "out.json").write_text("{}")
    key = CandidateKey(
        task_id="strings-0000", lease_generation=4, policy_hash=POLICY,
        base_sha="a" * 40, head_sha="b" * 40, tree_sha="c" * 40,
        toolchain_digest=TOOLCHAIN,
    )
    return CandidateTree(key, path)


@pytest.fixture
def target(tmp_path):
    path = tmp_path / "game.exe"
    path.write_bytes(b"MZ\x00original")
    return path


class FakeRunner:
    """Captures every GuestSpec and replays verdicts by operation."""

    def __init__(self, verdicts=None, error=None):
        self.specs = []
        self.error = error
        self.verdicts = verdicts or {}

    def run(self, spec):
        self.specs.append(spec)
        if self.error is not None:
            raise self.error
        verdict = self.verdicts.get(spec.operation)
        if verdict is None:
            verdict = {"schema": 1, "status": "accepted", "outputs": {}, "diagnostic_code": 0}
        return GuestResult(dict(verdict), spec.guest_id)


def verdict(status="accepted", outputs=None, code=0):
    return {"schema": 1, "status": status, "outputs": outputs or {}, "diagnostic_code": code}


def test_static_verifier_treats_submission_as_data(tmp_path, candidate, target):
    runner = FakeRunner({"static-verify": verdict(outputs={"recovery/out.json": ARTIFACT.hex})})
    attestation = verify_candidate(runner, plan_for(tmp_path, STATIC), candidate, target,
                                   candidate.key, now=1000)
    assert len(runner.specs) == 1
    spec = runner.specs[0]
    assert spec.operation == "static-verify"
    assert spec.target_path == target
    assert spec.input_dir == candidate.path
    assert attestation.passed
    assert attestation.mode == "static"
    assert attestation.candidate_key == candidate.key


def test_bytematch_candidate_guest_never_receives_target(tmp_path, candidate, target):
    runner = FakeRunner({
        "candidate-build": verdict(outputs={"artifact": ARTIFACT.hex}),
        "oracle-extract": verdict(outputs={"artifact": ARTIFACT.hex}),
    })
    attestation = verify_candidate(runner, plan_for(tmp_path, BYTEMATCH), candidate, target,
                                   candidate.key, now=1000)
    build, oracle = runner.specs
    assert build.target_path is None
    assert build.input_dir == candidate.path
    assert oracle.target_path == target
    assert oracle.input_dir is None
    assert attestation.passed


def test_bytematch_digest_divergence_fails_without_leaking_bytes(tmp_path, candidate, target):
    runner = FakeRunner({
        "candidate-build": verdict(outputs={"artifact": ARTIFACT.hex}),
        "oracle-extract": verdict(outputs={"artifact": "9" * 64}),
    })
    attestation = verify_candidate(runner, plan_for(tmp_path, BYTEMATCH), candidate, target,
                                   candidate.key, now=1000)
    assert not attestation.passed
    assert "artifact-mismatch" in attestation.reason_codes
    serialized = json.dumps(attestation.as_mapping())
    assert "game.exe" not in serialized
    assert str(target) not in serialized
    assert str(candidate.path) not in serialized


def test_behavioral_runs_candidate_and_oracle_in_separate_guests(tmp_path, candidate, target):
    outputs = {"case-a": CASE_DIGEST.hex, "case-b": ARTIFACT.hex}
    runner = FakeRunner({
        "candidate-build": verdict(outputs={"artifact": ARTIFACT.hex}),
        "candidate-run": verdict(outputs=outputs),
        "oracle-run": verdict(outputs=outputs),
    })
    attestation = verify_candidate(runner, plan_for(tmp_path, BEHAVIORAL), candidate, target,
                                   candidate.key, now=1000)
    build, run, oracle = runner.specs
    assert [spec.operation for spec in runner.specs] == [
        "candidate-build", "candidate-run", "oracle-run"]
    assert build.target_path is None and run.target_path is None
    assert oracle.target_path == target
    assert oracle.input_dir is None, "oracle guest must not hold the candidate executable"
    assert run.job["cases"] == ["case-a", "case-b"]
    assert oracle.job["cases"] == ["case-a", "case-b"]
    assert len({spec.guest_id for spec in runner.specs}) == 3
    assert attestation.passed
    assert attestation.evidence["cases_compared"] == 2


def test_behavioral_divergence_reports_case_count_only(tmp_path, candidate, target):
    runner = FakeRunner({
        "candidate-build": verdict(outputs={"artifact": ARTIFACT.hex}),
        "candidate-run": verdict(outputs={"case-a": CASE_DIGEST.hex, "case-b": "9" * 64}),
        "oracle-run": verdict(outputs={"case-a": CASE_DIGEST.hex, "case-b": ARTIFACT.hex}),
    })
    attestation = verify_candidate(runner, plan_for(tmp_path, BEHAVIORAL), candidate, target,
                                   candidate.key, now=1000)
    assert not attestation.passed
    assert "behavior-divergence" in attestation.reason_codes
    assert attestation.evidence["cases_diverged"] == 1


def test_untrusted_candidate_build_failure_is_a_verdict_not_a_crash(tmp_path, candidate, target):
    runner = FakeRunner({"candidate-build": verdict(status="rejected", code=2)})
    attestation = verify_candidate(runner, plan_for(tmp_path, BEHAVIORAL), candidate, target,
                                   candidate.key, now=1000)
    assert not attestation.passed
    assert "candidate-build-failed" in attestation.reason_codes
    assert len(runner.specs) == 1, "a failed build must not reach the oracle guest"


def test_guest_failure_becomes_sanitized_inconclusive_attestation(tmp_path, candidate, target):
    runner = FakeRunner(error=GuestError("jail /home/sebas/secret exploded"))
    attestation = verify_candidate(runner, plan_for(tmp_path, STATIC), candidate, target,
                                   candidate.key, now=1000)
    assert not attestation.passed
    assert attestation.reason_codes == ("guest-failed",)
    assert "secret" not in json.dumps(attestation.as_mapping())


def test_malformed_guest_outputs_are_rejected(tmp_path, candidate, target):
    runner = FakeRunner({"candidate-build": verdict(outputs={"artifact": "not-a-digest"})})
    attestation = verify_candidate(runner, plan_for(tmp_path, BYTEMATCH), candidate, target,
                                   candidate.key, now=1000)
    assert not attestation.passed
    assert "verdict-invalid" in attestation.reason_codes


def test_candidate_key_must_match_the_constructed_tree(tmp_path, candidate, target):
    other = CandidateKey(
        task_id="strings-0001", lease_generation=4, policy_hash=POLICY,
        base_sha="a" * 40, head_sha="b" * 40, tree_sha="c" * 40, toolchain_digest=TOOLCHAIN,
    )
    with pytest.raises(VerificationError, match="candidate key"):
        verify_candidate(FakeRunner(), plan_for(tmp_path, STATIC), candidate, target, other,
                         now=1000)


def test_attestation_binds_key_policy_mode_and_times(tmp_path, candidate, target):
    runner = FakeRunner({"static-verify": verdict()})
    plan = plan_for(tmp_path, STATIC)
    attestation = verify_candidate(runner, plan, candidate, target, candidate.key, now=1000)
    mapping = attestation.as_mapping()
    assert mapping["candidate_key"] == candidate.key.canonical()
    assert mapping["verifier_policy_hash"] == plan.verifier_policy_hash.hex
    assert mapping["mode"] == "static"
    assert mapping["started_at"] == 1000 and mapping["completed_at"] >= 1000
    assert set(mapping) == {
        "schema", "candidate_key", "verifier_policy_hash", "mode", "passed",
        "evidence", "reason_codes", "started_at", "completed_at",
    }


def test_timeout_and_artifact_limits_flow_into_guest_limits(tmp_path, candidate, target):
    runner = FakeRunner({"static-verify": verdict()})
    verify_candidate(runner, plan_for(tmp_path, STATIC), candidate, target, candidate.key, now=1)
    limits = runner.specs[0].limits
    assert limits.wall_seconds == 30
    assert limits.result_bytes <= 1048576



def test_the_trusted_output_rules_reach_every_guest_job(tmp_path, candidate, target):
    """A guest cannot judge a submission if it cannot see which paths count."""

    runner = FakeRunner({"candidate-build": verdict(outputs={"artifact": "a" * 64}),
                         "oracle-extract": verdict(outputs={"artifact": "a" * 64})})
    rules = [{"path": "recovery/strings.json", "media_type": "application/json",
              "max_bytes": 4096}]
    verify_candidate(runner, plan_for(tmp_path, BYTEMATCH), candidate, target,
                     candidate.key, now=1, output_rules=rules)
    assert [spec.job.get("outputs") for spec in runner.specs] == [rules, rules]


def test_a_task_record_may_not_shadow_the_host_output_rules(tmp_path, candidate, target):
    runner = FakeRunner()
    with pytest.raises(VerificationError, match="outputs"):
        verify_candidate(runner, plan_for(tmp_path, STATIC), candidate, target,
                         candidate.key, now=1, task_args={"outputs": []})


def test_malformed_output_rules_are_refused_before_any_guest_boots(tmp_path, candidate, target):
    runner = FakeRunner()
    for index, rules in enumerate(({"media_type": "application/json"},
                                   [{"path": "/abs/path"}], "nope")):
        with pytest.raises(VerificationError):
            verify_candidate(runner, plan_for(tmp_path / f"rules-{index}", STATIC), candidate,
                             target, candidate.key, now=1, output_rules=rules)
    wide = [{"path": f"recovery/{'x' * 200}/{index}.json"} for index in range(200)]
    with pytest.raises(VerificationError, match="bytes"):
        verify_candidate(runner, plan_for(tmp_path / "rules-wide", STATIC), candidate,
                         target, candidate.key, now=1, output_rules=wide)
    assert runner.specs == []


def test_plan_rejects_unknown_mode_missing_limits_and_shell_strings(tmp_path):
    for manifest, message in (
        (STATIC.replace('mode = "static"', 'mode = "yolo"'), "mode"),
        (STATIC.replace("timeout_seconds = 30\n", ""), "timeout_seconds"),
        (STATIC.replace("max_artifact_bytes = 1048576\n", ""), "max_artifact_bytes"),
        (BYTEMATCH.replace('candidate_build = ["python3", "runner.py", "build"]',
                           'candidate_build = "python3 runner.py build"'), "argv"),
        (BEHAVIORAL.replace('oracle_run = ["python3", "runner.py", "oracle"]\n', ""), "oracle_run"),
        (BEHAVIORAL.replace("version = 1", "version = 99"), "protocol"),
        (BEHAVIORAL.replace('cases = ["case-a", "case-b"]', "cases = []"), "cases"),
    ):
        with pytest.raises((PluginError, VerificationError), match=message):
            plan_for(tmp_path / message, manifest)


def test_public_plan_may_not_colocate_candidate_and_target(tmp_path):
    manifest = BEHAVIORAL.replace("public = true", "public = true\ncandidate_reads_target = true")
    with pytest.raises((PluginError, VerificationError), match="co-locat|candidate_reads_target"):
        plan_for(tmp_path, manifest)


def test_plugin_without_separable_plan_is_maintainer_only(tmp_path):
    manifest = STATIC.replace("public = true", "public = false")
    plan = plan_for(tmp_path, manifest)
    assert not plan.public
    with pytest.raises(VerificationError, match="public"):
        verify_candidate(FakeRunner(), plan, None, None, None, now=1, require_public=True)


def test_generic_builtin_yields_a_complete_public_static_plan(project):
    from recomp.plugin import resolve_plugin

    plan = VerificationPlan.from_plugin(resolve_plugin(project.path, "generic"))
    assert plan.public is True
    assert plan.mode == "static"
    assert plan.timeout_seconds == 30
    assert plan.max_artifact_bytes == 1048576
