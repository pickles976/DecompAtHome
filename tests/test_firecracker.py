from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from recomp.firecracker import (
    FirecrackerConfig,
    FirecrackerRunner,
    GuestDrive,
    GuestError,
    GuestLimits,
    GuestSpec,
)
from recomp.guest import GuestJobError, build_verdict, load_job, resolve_command, write_verdict

VERDICT = {"schema": 1, "status": "accepted", "outputs": {"recovery/out.json": "a" * 64},
           "diagnostic_code": 0}


def digest_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FakeHost:
    """Replays every external command the runner is allowed to invoke."""

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.staged_dirs: list[tuple[str, list[tuple[str, str]]]] = []
        self.calls: list[list[str]] = []
        self.result_bytes = json.dumps(VERDICT).encode()
        self.boot_returncode = 0
        self.timeout = False
        self.machine_config: dict | None = None
        self.jail_removed = False
        self.jail = tmp_path / "jail"
        self.jail.mkdir(mode=0o700)
        for name in ("firecracker", "jailer", "mke2fs", "debugfs"):
            binary = tmp_path / name
            binary.write_bytes(name.encode())
            binary.chmod(0o755)
        self.kvm = tmp_path / "kvm"
        self.kvm.write_bytes(b"")
        self.kernel = tmp_path / "vmlinux"
        self.kernel.write_bytes(b"kernel")
        self.rootfs = tmp_path / "rootfs.ext4"
        self.rootfs.write_bytes(b"rootfs")

    @property
    def config(self) -> FirecrackerConfig:
        return FirecrackerConfig(
            firecracker=self.tmp_path / "firecracker",
            jailer=self.tmp_path / "jailer",
            kernel=self.kernel,
            rootfs=self.rootfs,
            jail_root=self.jail,
            uid=os.geteuid(),
            gid=os.getegid(),
            firecracker_sha256=digest_of(self.tmp_path / "firecracker"),
            jailer_sha256=digest_of(self.tmp_path / "jailer"),
            kernel_sha256=digest_of(self.kernel),
            rootfs_sha256=digest_of(self.rootfs),
            kvm_device=self.kvm,
            mke2fs=self.tmp_path / "mke2fs",
            debugfs=self.tmp_path / "debugfs",
        )

    def __call__(self, argv, timeout=None, capture=False, **_kwargs):
        self.calls.append(list(argv))
        program = Path(argv[0]).name
        if program == "mke2fs" and "-d" in argv:
            staged = Path(argv[argv.index("-d") + 1])
            self.staged_dirs.append((argv[-2], sorted(
                (item.relative_to(staged).as_posix(), item.read_text())
                for item in staged.rglob("*") if item.is_file()
            )))
        if program == "jailer":
            base = Path(argv[argv.index("--chroot-base-dir") + 1])
            guest_id = argv[argv.index("--id") + 1]
            in_jail = argv[argv.index("--config-file") + 1]
            host_config = base / "firecracker" / guest_id / "root" / in_jail.lstrip("/")
            self.machine_config = json.loads(host_config.read_text())
            self.booted_config_path = host_config
            if self.timeout:
                raise subprocess.TimeoutExpired(argv, timeout or 0)
            return subprocess.CompletedProcess(argv, self.boot_returncode, b"", b"")
        if program == "debugfs":
            return subprocess.CompletedProcess(argv, 0, self.result_bytes, b"")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def cleanup_observer(self, path: Path) -> None:
        self.jail_removed = True


def make_spec(tmp_path, **overrides):
    candidate = tmp_path / "candidate"
    candidate.mkdir(exist_ok=True)
    (candidate / "out.json").write_text("{}")
    defaults = dict(
        guest_id="guest-0001",
        operation="static-verify",
        command_id="generic.verify",
        input_dir=candidate,
        job={"task_id": "strings-0000", "policy_version": 2},
        limits=GuestLimits(wall_seconds=60, memory_mib=512, vcpus=1,
                           result_bytes=65536, pids=128, nofile=256),
    )
    defaults.update(overrides)
    return GuestSpec(**defaults)


@pytest.fixture
def host(tmp_path):
    return FakeHost(tmp_path)


def run(host, spec=None, **kwargs):
    runner = FirecrackerRunner(host.config, run_command=host, on_cleanup=host.cleanup_observer, **kwargs)
    return runner.run(spec if spec is not None else make_spec(host.tmp_path))


def test_public_guest_has_no_network_vsock_or_host_mounts(host, tmp_path):
    result = run(host)
    machine = host.machine_config
    assert "network-interfaces" not in machine
    assert "vsock" not in machine
    assert machine["machine-config"]["smt"] is False
    jail_root = host.jail / "firecracker" / "guest-0001" / "root"
    for drive in machine["drives"]:
        in_jail = jail_root / drive["path_on_host"].lstrip("/")
        assert in_jail.is_relative_to(jail_root)
    assert result.verdict == VERDICT
    assert host.jail_removed


def test_input_and_job_drives_are_read_only_and_result_is_writable(host):
    run(host)
    drives = {drive["drive_id"]: drive for drive in host.machine_config["drives"]}
    assert drives["job"]["is_read_only"] is True
    assert drives["input"]["is_read_only"] is True
    assert drives["result"]["is_read_only"] is False
    assert drives["rootfs"]["is_root_device"] is True
    assert "init=/usr/bin/recomp-guest" in host.machine_config["boot-source"]["boot_args"]


def test_job_description_carries_no_shell_string(host):
    run(host)
    staged = next(files for image, files in host.staged_dirs if image.endswith("job.img"))
    job = json.loads(dict(staged)["job.json"])
    assert job["operation"] == "static-verify"
    assert job["command_id"] == "generic.verify"
    assert job["limits"]["pids"] == 128
    assert set(job) == {"schema", "operation", "command_id", "limits", "drives", "payload"}
    assert not any(isinstance(value, str) and (" " in value or ";" in value)
                   for value in job["drives"].values())


def test_result_is_bounded_and_schema_validated(host):
    host.result_bytes = b"x" * 70000
    with pytest.raises(GuestError, match="result exceeds"):
        run(host)
    assert host.jail_removed


def test_malformed_or_off_schema_verdicts_are_rejected(host):
    host.result_bytes = b"{not json"
    with pytest.raises(GuestError, match="verdict"):
        run(host)
    host.result_bytes = json.dumps({"schema": 99, "status": "accepted"}).encode()
    with pytest.raises(GuestError, match="schema"):
        run(host)
    host.result_bytes = json.dumps({"schema": 1, "status": "elevated"}).encode()
    with pytest.raises(GuestError, match="status"):
        run(host)


def test_missing_kvm_fails_closed_before_any_command(host):
    host.kvm.unlink()
    with pytest.raises(GuestError, match="KVM"):
        run(host)
    assert host.calls == []


def test_checksum_mismatch_fails_closed(host, tmp_path):
    (tmp_path / "firecracker").write_bytes(b"tampered")
    config = host.config
    tampered = FirecrackerConfig(**{**config.__dict__, "firecracker_sha256": "0" * 64})
    with pytest.raises(GuestError, match="checksum"):
        FirecrackerRunner(tampered, run_command=host, on_cleanup=host.cleanup_observer).run(
            make_spec(tmp_path))
    assert host.calls == []


def test_jail_root_must_be_private_to_the_coordinator(host):
    host.jail.chmod(0o755)
    with pytest.raises(GuestError, match="jail root"):
        run(host)
    assert host.calls == []


def test_timeout_kills_guest_and_removes_jail(host):
    host.timeout = True
    with pytest.raises(GuestError, match="timed out"):
        run(host)
    assert host.jail_removed


def test_nonzero_boot_status_is_surfaced_not_treated_as_verdict(host):
    host.boot_returncode = 7
    with pytest.raises(GuestError, match="exit"):
        run(host)
    assert host.jail_removed


def test_concurrent_guest_ids_never_share_a_jail(host, tmp_path):
    run(host, make_spec(tmp_path, guest_id="guest-0001"))
    first = host.booted_config_path
    run(host, make_spec(tmp_path, guest_id="guest-0002"))
    assert first != host.booted_config_path
    assert "guest-0002" in str(host.booted_config_path)


def test_guest_id_must_be_a_safe_identifier(host, tmp_path):
    with pytest.raises(GuestError, match="guest id"):
        run(host, make_spec(tmp_path, guest_id="../escape"))
    assert host.calls == []


def test_unknown_operation_or_command_is_refused(host, tmp_path):
    with pytest.raises(GuestError, match="operation"):
        run(host, make_spec(tmp_path, operation="shell"))
    with pytest.raises(GuestError, match="command"):
        run(host, make_spec(tmp_path, command_id="rm -rf /"))
    assert host.calls == []


def test_guest_resolves_only_manifest_commands():
    manifest = {"schema": 1, "commands": {"generic.verify": ["/usr/bin/recomp", "plugin", "verify"]}}
    assert resolve_command(manifest, "generic.verify") == ("/usr/bin/recomp", "plugin", "verify")
    with pytest.raises(GuestJobError, match="command"):
        resolve_command(manifest, "generic.unknown")
    with pytest.raises(GuestJobError, match="command"):
        resolve_command({"schema": 1, "commands": {"x": "sh -c evil"}}, "x")


def test_guest_job_loading_rejects_shell_payloads(tmp_path):
    job_path = tmp_path / "job.json"
    job_path.write_text(json.dumps({
        "schema": 1, "operation": "static-verify", "command_id": "generic.verify",
        "limits": {"wall_seconds": 60, "memory_mib": 512, "vcpus": 1,
                   "result_bytes": 4096, "pids": 64, "nofile": 128},
        "drives": {"input": "/dev/vdb", "result": "/dev/vdc"},
        "payload": {"task_id": "strings-0000"},
    }))
    job = load_job(job_path)
    assert job.command_id == "generic.verify"
    job_path.write_text(json.dumps({"schema": 1, "operation": "static-verify",
                                    "command_id": ["sh", "-c", "evil"]}))
    with pytest.raises(GuestJobError):
        load_job(job_path)


def test_guest_verdict_is_bounded_and_excludes_raw_output(tmp_path):
    verdict = build_verdict(status="rejected", outputs={"recovery/out.json": "b" * 64},
                            diagnostic_code=12, stderr=b"secret host canary" * 1000)
    assert verdict["diagnostic_code"] == 12
    assert "secret" not in json.dumps(verdict)
    path = write_verdict(tmp_path, verdict, max_bytes=65536)
    assert json.loads(path.read_text()) == verdict
    assert not list(tmp_path.glob("*.tmp"))
    with pytest.raises(GuestJobError, match="exceeds"):
        write_verdict(tmp_path, {"schema": 1, "status": "accepted",
                                 "outputs": {"p": "c" * 64}, "diagnostic_code": 0},
                      max_bytes=8)


@pytest.mark.skipif(
    os.environ.get("RECOMP_FIRECRACKER_TEST") != "1",
    reason="real-KVM guest test requires RECOMP_FIRECRACKER_TEST=1, /dev/kvm, and the "
           "pinned firecracker/jailer/kernel/rootfs fixture",
)
def test_real_guest_isolates_target_and_network(tmp_path):
    from recomp.firecracker import load_pinned_config

    config = load_pinned_config(Path(os.environ["RECOMP_FIRECRACKER_MANIFEST"]))
    canary = tmp_path / "host-canary"
    canary.write_text("host-only secret")
    spec = make_spec(tmp_path, command_id="generic.selftest")
    result = FirecrackerRunner(config).run(spec)
    assert result.verdict["schema"] == 1
    assert result.verdict["probes"]["network_interfaces"] == ["lo"]
    assert result.verdict["probes"]["input_drive_read_only"] is True
    assert result.verdict["probes"]["host_canary_readable"] is False
    second = FirecrackerRunner(config).run(make_spec(tmp_path, guest_id="guest-0002",
                                                     command_id="generic.selftest"))
    assert second.verdict["probes"]["previous_run_residue"] is False
