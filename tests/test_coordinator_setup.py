from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from recomp.coordinator_setup import (
    CoordinatorPaths,
    DoctorReport,
    SetupError,
    doctor,
    read_owner_token,
    render_service_unit,
    write_coordinator_config,
)


class FakeHost:
    """Observable stand-in for the Linux prerequisites doctor inspects."""

    def __init__(self, tmp_path):
        self.platform = "linux"
        self.paths = {}
        self.versions = {"git": "2.43.0", "openssl": "3.0.13", "mke2fs": "1.47.0",
                         "docker": "25.0.3"}
        self.tmp_path = tmp_path
        for name in ("kvm", "firecracker", "jailer", "kernel", "rootfs"):
            path = tmp_path / name
            path.write_bytes(name.encode())
            self.paths[name] = path
        self.readable_writable = {self.paths["kvm"]}

    def remove(self, name):
        self.paths[name].unlink()

    def exists(self, path):
        return Path(path).exists()

    def access(self, path, mode):
        return Path(path) in self.readable_writable

    def version(self, program):
        return self.versions.get(program)


@pytest.fixture
def host(tmp_path):
    return FakeHost(tmp_path)


@pytest.fixture
def paths(tmp_path):
    return CoordinatorPaths.for_repository("acme", "game", home=tmp_path)


def run_doctor(host, paths, **overrides):
    settings = {
        "platform": host.platform,
        "kvm_device": host.paths.get("kvm", Path("/dev/kvm")),
        "firecracker": host.paths.get("firecracker"),
        "jailer": host.paths.get("jailer"),
        "kernel": host.paths.get("kernel"),
        "rootfs": host.paths.get("rootfs"),
        "app_key_path": paths.app_key,
        "exists": host.exists,
        "access": host.access,
        "version": host.version,
    }
    settings.update(overrides)
    return doctor(paths=paths, **settings)


def test_paths_follow_xdg_layout_and_are_private(paths, tmp_path):
    assert paths.config == tmp_path / ".config/recomp/coordinators/acme__game/config.toml"
    assert paths.app_key == tmp_path / ".config/recomp/coordinators/acme__game/app-private-key.pem"
    assert paths.state == tmp_path / ".local/state/recomp/coordinators/acme__game"
    assert paths.cache == tmp_path / ".cache/recomp/coordinators/acme__game"
    paths.create()
    for directory in (paths.config.parent, paths.state, paths.cache):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_public_doctor_fails_closed_without_kvm(host, paths):
    host.remove("kvm")
    report = run_doctor(host, paths)
    assert not report.ok
    finding = report.finding("kvm")
    assert finding.severity == "error"
    assert finding.remediation == (
        "Enable KVM and grant the coordinator account read/write access to /dev/kvm.")


def test_doctor_rejects_non_linux_hosts_before_anything_else(host, paths):
    report = run_doctor(host, paths, platform="darwin")
    assert not report.ok
    assert report.finding("platform").severity == "error"
    assert [finding.check_id for finding in report.findings][0] == "platform"


def test_doctor_reports_unreadable_kvm_distinctly_from_missing(host, paths):
    host.readable_writable.clear()
    report = run_doctor(host, paths)
    assert not report.ok
    assert "read/write" in report.finding("kvm").observed


def test_doctor_requires_pinned_guest_binaries(host, paths):
    host.remove("firecracker")
    report = run_doctor(host, paths)
    assert report.finding("firecracker").severity == "error"
    assert "firecracker" in report.finding("firecracker").remediation


def test_doctor_requires_minimum_tool_versions(host, paths):
    host.versions["git"] = "2.30.0"
    report = run_doctor(host, paths)
    assert report.finding("git").severity == "error"
    assert "2.38" in report.finding("git").remediation


def test_doctor_flags_group_or_world_readable_app_key(host, paths):
    paths.create()
    paths.app_key.write_text("-----BEGIN PRIVATE KEY-----\n")
    paths.app_key.chmod(0o644)
    report = run_doctor(host, paths)
    assert report.finding("app-key").severity == "error"
    assert oct(0o644)[-3:] in report.finding("app-key").observed


def test_healthy_host_passes_with_no_error_findings(host, paths):
    paths.create()
    paths.app_key.write_text("-----BEGIN PRIVATE KEY-----\n")
    paths.app_key.chmod(0o600)
    report = run_doctor(host, paths)
    assert report.ok, [finding.check_id for finding in report.findings if finding.severity == "error"]
    assert isinstance(report, DoctorReport)


def test_doctor_report_is_json_serializable_and_sanitized(host, paths):
    report = run_doctor(host, paths)
    payload = report.as_mapping()
    assert payload["schema"] == 1
    assert all(set(item) == {"check_id", "severity", "observed", "remediation"}
               for item in payload["findings"])
    assert str(paths.app_key) not in str(payload)


def test_setup_never_writes_app_key_or_token_into_the_project(tmp_path, paths):
    project = tmp_path / "project"
    project.mkdir()
    write_coordinator_config(paths, {
        "owner": "acme", "repository": "game", "app_id": 12345,
        "installation_id": 67890, "trusted_actor_id": 99,
        "image": "ghcr.io/acme/game-toolchain@sha256:" + "a" * 64,
    })
    assert not any(project.rglob("*.pem"))
    assert stat.S_IMODE(paths.config.stat().st_mode) == 0o600
    text = paths.config.read_text()
    assert "app_id = 12345" in text
    assert "BEGIN" not in text
    assert "token" not in text


def test_config_write_is_idempotent_and_refuses_symlink_targets(paths, tmp_path):
    settings = {"owner": "acme", "repository": "game", "app_id": 1, "installation_id": 2,
                "trusted_actor_id": 99, "image": "ghcr.io/a/b@sha256:" + "c" * 64}
    write_coordinator_config(paths, settings)
    write_coordinator_config(paths, settings)
    assert stat.S_IMODE(paths.config.stat().st_mode) == 0o600
    paths.config.unlink()
    paths.config.symlink_to(tmp_path / "elsewhere.toml")
    with pytest.raises(SetupError, match="symlink"):
        write_coordinator_config(paths, settings)


def test_owner_token_is_read_from_a_private_file_never_argv(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("ghp_example\n")
    token_file.chmod(0o600)
    assert read_owner_token(token_file) == "ghp_example"
    token_file.chmod(0o644)
    with pytest.raises(SetupError, match="0600"):
        read_owner_token(token_file)


def test_owner_token_falls_back_to_gh_auth_token(tmp_path):
    calls = []

    def fake_gh(argv):
        calls.append(list(argv))
        return "ghs_from_gh\n"

    assert read_owner_token(None, gh_token=fake_gh) == "ghs_from_gh"
    assert calls == [["gh", "auth", "token"]]


def test_service_unit_is_hardened_and_uses_credentials(paths):
    unit = render_service_unit(paths, user="recomp", owner="acme", repository="game")
    for directive in (
        "NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectSystem=strict",
        "ProtectHome=yes", "RestrictSUIDSGID=yes", "Restart=on-failure",
        "DeviceAllow=/dev/kvm rw", "DevicePolicy=closed", "User=recomp",
    ):
        assert directive in unit
    assert f"LoadCredential=app-key:{paths.app_key}" in unit
    assert f"ReadWritePaths={paths.state} {paths.cache}" in unit
    assert "ExecStart=" in unit
    assert "coordinator run" in unit
    assert str(paths.app_key) in unit
    assert "token" not in unit.lower()
