"""Unit tests for the in-guest runner's drive contract and verdict bounds."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from recomp import guest


def _write_job(tmp_path: Path, drives: dict[str, str]) -> guest.GuestJob:
    document = {
        "schema": guest.SCHEMA,
        "operation": "oracle-run",
        "command_id": "oracle.run",
        "limits": {"wall_seconds": 60, "memory_mib": 512, "vcpus": 1,
                   "result_bytes": 1024, "pids": 32, "nofile": 64},
        "drives": drives,
        "payload": {},
    }
    path = tmp_path / "job.json"
    path.write_text(json.dumps(document))
    return guest.load_job(path)


def test_oracle_job_without_input_passes_target_device(tmp_path):
    job = _write_job(tmp_path, {"result": "/dev/vdc", "target": "/dev/vde"})
    argv = guest.guest_argv(("/opt/recomp/bin/oracle",), job)
    assert argv == ["/opt/recomp/bin/oracle", "--job", "/job/job.json",
                    "--target", "/dev/vde"]
    assert "--input" not in argv
    assert [entry[1] for entry in guest.mount_plan(job)] == [guest.RESULT_MOUNT]


def test_candidate_job_mounts_input_and_has_no_target(tmp_path):
    job = _write_job(tmp_path, {"result": "/dev/vdc", "input": "/dev/vdd"})
    argv = guest.guest_argv(("/opt/recomp/bin/candidate",), job)
    assert argv == ["/opt/recomp/bin/candidate", "--job", "/job/job.json",
                    "--input", "/input"]
    assert "--target" not in argv
    plan = guest.mount_plan(job)
    assert [(entry[0], entry[1]) for entry in plan] == [
        ("/dev/vdd", guest.INPUT_MOUNT),
        ("/dev/vdc", guest.RESULT_MOUNT),
    ]
    assert all(entry[2] == "ext4" for entry in plan)
    assert plan[0][3].startswith("ro,")


def test_target_drive_is_never_mounted(tmp_path):
    job = _write_job(tmp_path, {"result": "/dev/vdc", "target": "/dev/vde"})
    assert all(entry[0] != "/dev/vde" for entry in guest.mount_plan(job))


def test_build_verdict_keeps_well_formed_probes():
    verdict = guest.build_verdict(
        status="accepted", outputs={}, diagnostic_code=0,
        probes={"network": False, "retries": 3, "notes": ["a", "b"], "ratio": 0.5,
                "absent": None},
    )
    assert verdict["probes"] == {"network": False, "retries": 3,
                                 "notes": ["a", "b"], "ratio": 0.5, "absent": None}


def test_build_verdict_drops_malformed_probes():
    assert "probes" not in guest.build_verdict(
        status="accepted", outputs={}, diagnostic_code=0, probes=["not", "a", "map"])
    assert "probes" not in guest.build_verdict(
        status="accepted", outputs={}, diagnostic_code=0,
        probes={"nested": {"too": "deep"}})
    assert "probes" not in guest.build_verdict(
        status="accepted", outputs={}, diagnostic_code=0,
        probes={"list": [{"bad": 1}]})


def test_build_verdict_drops_probes_exceeding_caps():
    too_many = {f"k{index}": index for index in range(guest.MAX_PROBE_KEYS + 1)}
    assert "probes" not in guest.build_verdict(
        status="accepted", outputs={}, diagnostic_code=0, probes=too_many)
    too_long = {"leak": "x" * (guest.MAX_PROBE_STRING + 1)}
    assert "probes" not in guest.build_verdict(
        status="accepted", outputs={}, diagnostic_code=0, probes=too_long)
    long_item = {"leak": ["x" * (guest.MAX_PROBE_STRING + 1)]}
    assert "probes" not in guest.build_verdict(
        status="accepted", outputs={}, diagnostic_code=0, probes=long_item)


def test_write_verdict_refuses_oversized_document(tmp_path):
    digest = "0" * 64
    verdict = guest.build_verdict(
        status="accepted",
        outputs={f"path/{index}": digest for index in range(2048)},
        diagnostic_code=0,
    )
    with pytest.raises(guest.GuestJobError):
        guest.write_verdict(tmp_path, verdict)
    assert not list(tmp_path.iterdir())
