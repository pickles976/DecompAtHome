from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from recomp.coordinator_setup import (
    CoordinatorPaths,
    DoctorReport,
    MicrovmPins,
    SetupError,
    doctor,
    microvm_pins,
    read_coordinator_config,
    read_owner_token,
    render_service_unit,
    setup_coordinator,
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
        self.jail = tmp_path / "jail"
        self.jail.mkdir()
        self.jail.chmod(0o700)

    def remove(self, name):
        self.paths[name].unlink()

    def tamper(self, name):
        """Replace a pinned artifact with different bytes at the same path."""
        self.paths[name].write_bytes(b"swapped binary")

    def exists(self, path):
        return Path(path).exists()

    def access(self, path, mode):
        return Path(path) in self.readable_writable

    def version(self, program):
        return self.versions.get(program)

    def pin_table(self):
        """The `[firecracker]` table a completed `coordinator setup` would write."""

        table = {}
        for name in ("firecracker", "jailer", "kernel", "rootfs"):
            table[name] = str(self.paths[name])
            table[f"{name}_sha256"] = hashlib.sha256(name.encode()).hexdigest()
        table["jail_root"] = str(self.jail)
        table["uid"] = os.getuid()
        table["gid"] = os.getgid()
        return table

    def config(self):
        return {
            "coordinator": {
                "owner": "acme", "repository": "game", "app_id": 1, "installation_id": 2,
                "trusted_actor_id": 3, "image": "ghcr.io/acme/game@sha256:" + "a" * 64,
                "project_root": str(self.tmp_path / "project"),
            },
            "firecracker": self.pin_table(),
        }

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
    """Doctor with the config a real setup would have written — no path overrides.

    Every pinned artifact is resolved through `config.toml`, which is how the CLI
    calls it; overriding paths here would hide a broken config.
    """

    settings = {
        "platform": host.platform,
        "config": host.config(),
        "kvm_device": host.paths.get("kvm", Path("/dev/kvm")),
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
    assert str(host.paths["firecracker"]) in report.finding("firecracker").observed


def test_doctor_reports_artifact_that_does_not_match_its_pin(host, paths):
    """A present binary at the right path is not the pinned binary."""

    host.tamper("jailer")
    report = run_doctor(host, paths)
    assert report.finding("jailer").severity == "error"
    assert "does not match its pin" in report.finding("jailer").observed


def test_doctor_requires_a_digest_for_every_pin(host, paths):
    config = host.config()
    del config["firecracker"]["kernel_sha256"]
    report = run_doctor(host, paths, config=config)
    assert report.finding("kernel").severity == "error"
    assert "kernel_sha256" in report.finding("kernel").remediation


def test_doctor_without_a_config_names_the_missing_setup(host, paths):
    report = run_doctor(host, paths, config=None)
    for check_id in ("firecracker", "jailer", "kernel", "rootfs", "jail-root"):
        assert report.finding(check_id).severity == "error"
    assert "coordinator setup" in report.finding("firecracker").remediation


def test_doctor_requires_a_private_jail_root(host, paths):
    """The runner refuses a jail root that is world-writable or missing."""

    host.jail.chmod(0o755)
    report = run_doctor(host, paths)
    assert report.finding("jail-root").severity == "error"
    assert "755" in report.finding("jail-root").observed

    host.jail.chmod(0o700)
    host.jail.rmdir()
    report = run_doctor(host, paths)
    assert report.finding("jail-root").severity == "error"
    assert "mkdir -p" in report.finding("jail-root").remediation


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


def _setup_kwargs(tmp_path, host):
    return dict(
        owner="acme", repository="game", app_id=5474942, installation_id=175333454,
        trusted_actor_id=99, image="ghcr.io/acme/game-toolchain@sha256:" + "a" * 64,
        project_root=tmp_path / "project",
        firecracker=host.paths["firecracker"], jailer=host.paths["jailer"],
        kernel=host.paths["kernel"], rootfs=host.paths["rootfs"],
        jail_root=tmp_path / "fresh-jail")


def test_setup_computes_pins_that_read_and_doctor_agree_on(tmp_path, host, paths):
    """`setup` measures the artifacts itself; `doctor` re-measures them later."""

    (tmp_path / "project").mkdir()
    written = setup_coordinator(paths, **_setup_kwargs(tmp_path, host))
    assert stat.S_IMODE(written.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "fresh-jail").stat().st_mode) == 0o700

    config = read_coordinator_config(written)
    assert config["coordinator"]["app_id"] == 5474942
    assert config["coordinator"]["installation_id"] == 175333454
    pins = microvm_pins(config)
    assert isinstance(pins, MicrovmPins)
    assert pins.jail_root == tmp_path / "fresh-jail"
    for name in ("firecracker", "jailer", "kernel", "rootfs"):
        assert pins.paths[name] == host.paths[name]
        assert pins.digests[name] == hashlib.sha256(host.paths[name].read_bytes()).hexdigest()

    report = doctor(paths=paths, config=config, platform="linux",
                    kvm_device=host.paths["kvm"], app_key_path=tmp_path / "absent.pem",
                    exists=host.exists, access=host.access, version=host.version)
    offenders = [finding.check_id for finding in report.findings
                 if finding.severity == "error" and finding.check_id != "app-key"]
    assert offenders == [], offenders


def test_setup_requires_digest_pinned_image_and_real_artifacts(tmp_path, host, paths):
    (tmp_path / "project").mkdir()
    loose = _setup_kwargs(tmp_path, host)
    loose["image"] = "ghcr.io/acme/game-toolchain:build-1"
    with pytest.raises(SetupError, match="digest-pinned"):
        setup_coordinator(paths, **loose)

    missing = _setup_kwargs(tmp_path, host)
    missing["kernel"] = tmp_path / "no-such-kernel"
    with pytest.raises(SetupError, match="does not exist"):
        setup_coordinator(paths, **missing)

    weak = _setup_kwargs(tmp_path, host)
    weak["trusted_actor_id"] = 0
    with pytest.raises(SetupError, match="trusted_actor_id"):
        setup_coordinator(paths, **weak)


def test_read_coordinator_config_refuses_loose_modes_and_gaps(paths):
    paths.create()
    paths.config.write_text("[coordinator]\nowner = \"acme\"\n")
    paths.config.chmod(0o644)
    with pytest.raises(SetupError, match="0600"):
        read_coordinator_config(paths.config)
    paths.config.chmod(0o600)
    with pytest.raises(SetupError, match="trusted_actor_id"):
        read_coordinator_config(paths.config)

    elsewhere = paths.config.parent / "elsewhere.toml"
    elsewhere.write_text("[coordinator]\nowner = \"acme\"\n")
    paths.config.unlink()
    paths.config.symlink_to(elsewhere)
    with pytest.raises(SetupError, match="symlink"):
        read_coordinator_config(paths.config)


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
        "ProtectHome=yes", "RestrictSUIDSGID=yes", "Restart=always",
        "DeviceAllow=/dev/kvm rw", "DevicePolicy=closed", "User=recomp",
    ):
        assert directive in unit
    assert f"LoadCredential=app-key:{paths.app_key}" in unit
    assert f"ReadWritePaths={paths.state} {paths.cache}" in unit
    assert "ExecStart=" in unit
    assert "coordinator run" in unit
    # The graceful SIGTERM handler exits 0; on-failure would strand the unit dead.
    assert "Restart=on-failure" not in unit
    assert str(paths.app_key) in unit
    assert "token" not in unit.lower()


def test_service_unit_covers_jail_and_project_when_run_by_the_owner(paths):
    """The runner writes its jail under the owner's home; the unit must allow it."""

    jail = "/home/sebas/.local/share/recomp/jail"
    project = "/home/sebas/Projects/sage-recomp"
    unit = render_service_unit(paths, user="sebas", owner="acme", repository="game",
                               jail_root=jail, project_root=project,
                               protect_home="read-only")
    assert "User=sebas" in unit
    assert "ProtectHome=read-only" in unit
    writable = next(line for line in unit.splitlines() if line.startswith("ReadWritePaths="))
    for path in (paths.state, paths.cache, jail, project):
        assert str(path) in writable
    assert "ProtectHome=yes" not in unit


def test_service_unit_rejects_an_unknown_protect_home(paths):
    with pytest.raises(SetupError, match="protect_home"):
        render_service_unit(paths, user="u", owner="a", repository="r", protect_home="maybe")


def test_default_version_probe_runs_host_tools_directly():
    from recomp.coordinator_setup import _default_version

    assert _default_version("git") is not None
    assert _default_version("recomp-definitely-missing-tool") is None


def test_coordinator_setup_parser_accepts_poll_interval():
    from recomp import cli

    args = cli.build_parser().parse_args([
        "coordinator", "setup", "--owner", "a", "--repository", "r",
        "--poll-interval", "30"])
    assert args.poll_interval == 30


def test_service_unit_grants_the_jailer_its_required_capabilities(paths):
    """A non-root coordinator must still boot Firecracker jails."""

    unit = render_service_unit(paths, user="u", owner="a", repository="r")
    caps = "CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_NET_ADMIN CAP_MKNOD"
    assert f"AmbientCapabilities={caps}" in unit
    assert f"CapabilityBoundingSet={caps}" in unit


def test_machine_setup_script_pins_upstream_digests_and_parses(tmp_path):
    import shutil
    import subprocess

    from recomp.templates import coordinator_machine_setup

    script = coordinator_machine_setup()
    assert script.startswith("#!/usr/bin/env bash")
    assert 'FIRECRACKER_VERSION="1.10.1"' in script
    for digest in ("36112969952b0e34fadcfca769d48a55dc22cbba99af17e02bd0e24fc35adc77",
                   "96d25e000e5fcbf5b11dca0e1275b5d7dc0922ff8b8206aeaed98e515a8468dc",
                   "8965e9ee855537561ac3adaf0b086a3882456fdc55472691f3bbe489199014ce",
                   "49ba99a5299444ac59dda2efc3569cc2d58a5d72ea6475a6bfc37aa0bf322e54"):
        assert digest in script
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")
    script_path = tmp_path / "setup.sh"
    script_path.write_text(script)
    result = subprocess.run([bash, "-n", str(script_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, result.stderr


def test_machine_setup_cli_writes_executable_script(tmp_path):
    from recomp import cli

    out = tmp_path / "coordinator-machine-setup.sh"
    args = cli.build_parser().parse_args(
        ["coordinator", "machine-setup", "--owner", "a", "--repository", "r",
         "--output", str(out)])
    assert args.func(args) == 0
    assert out.stat().st_mode & 0o111
    assert "FIRECRACKER_VERSION" in out.read_text()


def test_app_token_source_matches_the_recorded_coordinator_config(tmp_path, host, paths):
    """`recomp github` can only publish tasks through the coordinator App."""

    from recomp.coordinator_run import app_token_source

    assert app_token_source("acme", "game", home=tmp_path, environ={}) is None
    (tmp_path / "project").mkdir()
    setup_coordinator(paths, **_setup_kwargs(tmp_path, host))
    with pytest.raises(SetupError, match="private key"):
        app_token_source("acme", "game", home=tmp_path, environ={})
    paths.app_key.write_text("-----BEGIN PRIVATE KEY-----\n")
    paths.app_key.chmod(0o600)
    token_source, installation_id = app_token_source("acme", "game", home=tmp_path,
                                                     environ={})
    assert installation_id == 175333454
    assert callable(token_source)
