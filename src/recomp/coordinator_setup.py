"""Owner-side installation: private paths, exact diagnostics, hardened service.

Secrets never travel on argv and never land in the project repository. The
GitHub App key stays in the owner's XDG config directory at 0600 and reaches
the service only through systemd's `LoadCredential=`.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

REPORT_SCHEMA = 1
MIN_VERSIONS = {"git": (2, 38), "openssl": (3, 0), "mke2fs": (1, 46)}
_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_SERVICE_NAME = "recomp-coordinator"


class SetupError(RuntimeError):
    pass


@dataclass(frozen=True)
class CoordinatorPaths:
    config: Path
    app_key: Path
    state: Path
    cache: Path

    @classmethod
    def for_repository(cls, owner: str, repository: str, *,
                       home: str | Path | None = None) -> "CoordinatorPaths":
        base = Path(home) if home is not None else Path.home()
        slug = f"{owner}__{repository}"
        config_dir = base / ".config/recomp/coordinators" / slug
        return cls(
            config=config_dir / "config.toml",
            app_key=config_dir / "app-private-key.pem",
            state=base / ".local/state/recomp/coordinators" / slug,
            cache=base / ".cache/recomp/coordinators" / slug,
        )

    def create(self) -> None:
        for directory in (self.config.parent, self.state, self.cache):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)


@dataclass(frozen=True)
class DoctorFinding:
    check_id: str
    severity: str
    observed: str
    remediation: str


@dataclass(frozen=True)
class DoctorReport:
    findings: tuple[DoctorFinding, ...]

    @property
    def ok(self) -> bool:
        return not any(finding.severity == "error" for finding in self.findings)

    def finding(self, check_id: str) -> DoctorFinding:
        for finding in self.findings:
            if finding.check_id == check_id:
                return finding
        raise KeyError(check_id)

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": REPORT_SCHEMA,
            "ok": self.ok,
            "findings": [
                {"check_id": finding.check_id, "severity": finding.severity,
                 "observed": finding.observed, "remediation": finding.remediation}
                for finding in self.findings
            ],
        }


def _version_tuple(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    match = _VERSION_RE.search(value)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups() if part is not None)


def _default_version(program: str) -> str | None:
    try:
        completed = subprocess.run([program, "--version"], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   text=True, check=False)
    except FileNotFoundError:
        return None
    return completed.stdout.strip() or None


def doctor(
    *,
    paths: CoordinatorPaths,
    platform: str | None = None,
    kvm_device: Path = Path("/dev/kvm"),
    firecracker: Path | None = None,
    jailer: Path | None = None,
    kernel: Path | None = None,
    rootfs: Path | None = None,
    app_key_path: Path | None = None,
    exists: Callable[[Path], bool] = lambda path: Path(path).exists(),
    access: Callable[[Path, int], bool] = lambda path, mode: os.access(path, mode),
    version: Callable[[str], str | None] = _default_version,
) -> DoctorReport:
    """Return stable check IDs with exact remediation; fail closed on Linux-only needs."""

    import sys as _sys

    findings: list[DoctorFinding] = []
    system = platform if platform is not None else _sys.platform
    if not str(system).startswith("linux"):
        findings.append(DoctorFinding(
            "platform", "error", f"host platform is {system!r}",
            "Run the coordinator on Linux; public verification requires KVM."))
        return DoctorReport(tuple(findings))
    findings.append(DoctorFinding("platform", "ok", "linux", ""))

    if not exists(kvm_device):
        findings.append(DoctorFinding(
            "kvm", "error", f"{kvm_device} is missing",
            "Enable KVM and grant the coordinator account read/write access to /dev/kvm."))
    elif not access(kvm_device, os.R_OK | os.W_OK):
        findings.append(DoctorFinding(
            "kvm", "error", f"{kvm_device} is not read/write for this account",
            "Enable KVM and grant the coordinator account read/write access to /dev/kvm."))
    else:
        findings.append(DoctorFinding("kvm", "ok", "available", ""))

    for check_id, path in (("firecracker", firecracker), ("jailer", jailer),
                           ("kernel", kernel), ("rootfs", rootfs)):
        if path is None or not exists(path):
            findings.append(DoctorFinding(
                check_id, "error", f"pinned {check_id} is missing",
                f"Install the pinned {check_id} and record its sha256 in the coordinator "
                f"config before enabling public verification."))
        else:
            findings.append(DoctorFinding(check_id, "ok", "present", ""))

    for program, minimum in MIN_VERSIONS.items():
        found = _version_tuple(version(program))
        wanted = ".".join(str(part) for part in minimum)
        if found is None:
            findings.append(DoctorFinding(
                program, "error", f"{program} is not installed",
                f"Install {program} {wanted} or newer."))
        elif found[:len(minimum)] < minimum:
            findings.append(DoctorFinding(
                program, "error",
                f"{program} {'.'.join(str(part) for part in found)} is too old",
                f"Install {program} {wanted} or newer."))
        else:
            findings.append(DoctorFinding(program, "ok", "satisfied", ""))

    key_path = app_key_path if app_key_path is not None else paths.app_key
    if not Path(key_path).is_file():
        findings.append(DoctorFinding(
            "app-key", "warning", "GitHub App private key is not installed yet",
            "Run `recomp coordinator setup` and store the App key at the printed path."))
    else:
        mode = stat.S_IMODE(Path(key_path).stat().st_mode)
        if mode & 0o077:
            findings.append(DoctorFinding(
                "app-key", "error", f"App key mode is {oct(mode)[-3:]}",
                "chmod 600 the GitHub App private key; it must not be group or world readable."))
        else:
            findings.append(DoctorFinding("app-key", "ok", "0600", ""))
    return DoctorReport(tuple(findings))


def read_owner_token(
    token_file: str | Path | None,
    *,
    gh_token: Callable[[Sequence[str]], str] | None = None,
) -> str:
    """Accept the temporary owner token from a 0600 file or `gh auth token` only."""

    if token_file is not None:
        path = Path(token_file)
        if not path.is_file():
            raise SetupError("owner token file does not exist")
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise SetupError("owner token file must be 0600")
        token = path.read_text().strip()
        if not token:
            raise SetupError("owner token file is empty")
        return token
    runner = gh_token or _gh_auth_token
    token = runner(["gh", "auth", "token"]).strip()
    if not token:
        raise SetupError("`gh auth token` produced no token; run `gh auth login` first")
    return token


def _gh_auth_token(argv: Sequence[str]) -> str:
    completed = subprocess.run(list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True, check=False)
    if completed.returncode != 0:
        raise SetupError("`gh auth token` failed; run `gh auth login` first")
    return completed.stdout


def _format_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_coordinator_config(paths: CoordinatorPaths, settings: Mapping[str, Any]) -> Path:
    """Write public identifiers only, 0600, refusing to follow symlinks."""

    forbidden = {key for key in settings if "token" in key.lower() or "secret" in key.lower()}
    if forbidden:
        raise SetupError(f"coordinator config must not contain secrets: {sorted(forbidden)}")
    paths.create()
    path = paths.config
    if path.is_symlink():
        raise SetupError("coordinator config path is a symlink; refusing to write")
    body = "[coordinator]\n" + "".join(
        f"{key} = {_format_value(value)}\n" for key, value in sorted(settings.items())
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, body.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)
    return path


def render_service_unit(paths: CoordinatorPaths, *, user: str, owner: str,
                        repository: str, executable: str = "/usr/local/bin/recomp") -> str:
    """Render the hardened systemd unit; the App key arrives via LoadCredential."""

    from recomp.templates import systemd_unit

    return (systemd_unit()
            .replace("{{OWNER}}", owner)
            .replace("{{REPOSITORY}}", repository)
            .replace("{{USER}}", user)
            .replace("{{EXECUTABLE}}", executable)
            .replace("{{APP_KEY}}", str(paths.app_key))
            .replace("{{CONFIG}}", str(paths.config))
            .replace("{{STATE}}", str(paths.state))
            .replace("{{CACHE}}", str(paths.cache)))


def install_commands(unit_path: str | Path = f"/etc/systemd/system/{_SERVICE_NAME}.service") -> tuple[str, ...]:
    return (
        f"sudo install -m 0644 {unit_path} /etc/systemd/system/{_SERVICE_NAME}.service",
        "sudo systemctl daemon-reload",
        f"sudo systemctl enable --now {_SERVICE_NAME}.service",
    )
