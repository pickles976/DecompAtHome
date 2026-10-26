"""Owner-side installation: private paths, exact diagnostics, hardened service.

Secrets never travel on argv and never land in the project repository. The
GitHub App key stays in the owner's XDG config directory at 0600 and reaches
the service only through systemd's `LoadCredential=`.
"""

from __future__ import annotations

import hashlib
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


_VERSION_ARGV = {
    "git": ("git", "--version"),
    "openssl": ("openssl", "version"),
    "mke2fs": ("mke2fs", "-V"),
}


def _default_version(program: str) -> str | None:
    """Probe a tool's version; mke2fs prints to stderr, openssl rejects --version."""

    argv = _VERSION_ARGV.get(program, (program, "--version"))
    try:
        completed = subprocess.run(list(argv), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, check=False)
    except (FileNotFoundError, PermissionError):
        return None
    return completed.stdout.strip() or None

COORDINATOR_REQUIRED = ("owner", "repository", "app_id", "installation_id",
                        "trusted_actor_id", "image", "project_root")
FIRECRACKER_REQUIRED = ("firecracker", "jailer", "kernel", "rootfs", "jail_root",
                        "uid", "gid", "firecracker_sha256", "jailer_sha256",
                        "kernel_sha256", "rootfs_sha256")
#: The four artifacts `FirecrackerRunner` refuses to boot without.
_PINS = ("firecracker", "jailer", "kernel", "rootfs")


@dataclass(frozen=True)
class MicrovmPins:
    """What `config.toml`'s `[firecracker]` table says about the verification guest."""

    paths: Mapping[str, Path]
    digests: Mapping[str, str]
    jail_root: Path | None = None
    uid: int = 0
    gid: int = 0


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def read_coordinator_config(path: str | Path) -> dict[str, Any]:
    """Load the coordinator config; refuse symlinks, loose modes, and half-setups."""

    import tomllib

    location = Path(path)
    if location.is_symlink():
        raise SetupError("coordinator config is a symlink; refusing to read")
    if not location.is_file():
        raise SetupError(f"coordinator config does not exist: {location}")
    mode = stat.S_IMODE(location.stat().st_mode)
    if mode & 0o077:
        raise SetupError(
            f"coordinator config mode is {oct(mode)[-3:]}; it must be 0600")
    try:
        data = tomllib.loads(location.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise SetupError(f"coordinator config is not valid TOML: {exc}") from exc
    coordinator = data.get("coordinator")
    if not isinstance(coordinator, dict):
        raise SetupError("coordinator config requires a [coordinator] table")
    missing = [key for key in COORDINATOR_REQUIRED if key not in coordinator]
    if missing:
        raise SetupError(
            "coordinator config [coordinator] is missing: " + ", ".join(missing)
            + "; run `recomp coordinator setup` to record them")
    return {"coordinator": coordinator, "firecracker": data.get("firecracker") or {}}


def microvm_pins(config: Mapping[str, Any]) -> MicrovmPins | None:
    """Resolve the pinned guest artifacts recorded in `[firecracker]`, if any."""

    section = config.get("firecracker")
    if not isinstance(section, Mapping) or not section:
        return None
    paths = {name: Path(section[name]) for name in _PINS if section.get(name)}
    digests = {name: str(section[f"{name}_sha256"])
               for name in _PINS if section.get(f"{name}_sha256")}
    jail_root = Path(section["jail_root"]) if section.get("jail_root") else None
    try:
        uid = int(section.get("uid", 0) or 0)
        gid = int(section.get("gid", 0) or 0)
    except (TypeError, ValueError) as exc:
        raise SetupError("coordinator config [firecracker] uid/gid must be integers") from exc
    return MicrovmPins(paths, digests, jail_root, uid, gid)


def doctor(
    *,
    paths: CoordinatorPaths,
    config: Mapping[str, Any] | None = None,
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
    file_digest: Callable[[Path], str] = _file_sha256,
    geteuid: Callable[[], int] = os.geteuid,
    get_stat: Callable[[Path], os.stat_result] = os.stat,
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

    # An explicit path argument always wins over the config: the CLI passes none,
    # so the config is the only source, while a test or a one-off probe can point
    # the check at a specific artifact without rewriting `config.toml`.
    pins = microvm_pins(config) if config is not None else None
    explicit = {"firecracker": firecracker, "jailer": jailer,
                "kernel": kernel, "rootfs": rootfs}
    configured = pins is not None
    for check_id in _PINS:
        path = explicit[check_id]
        if path is None and pins is not None:
            path = pins.paths.get(check_id)
        if path is None:
            findings.append(DoctorFinding(
                check_id, "error",
                ("pinned %s is not recorded in %s" % (check_id, paths.config)) if configured
                else f"no {check_id} is configured (no coordinator config yet)",
                (f"Record {check_id} and {check_id}_sha256 in the [firecracker] table of "
                 f"{paths.config}, or run `recomp coordinator setup` with "
                 f"--{check_id} <path> before enabling public verification.")
                if configured else
                "Run `recomp coordinator setup --owner <owner> --repository <repo> "
                "--firecracker <path> --jailer <path> --kernel <path> --rootfs <path>` "
                "to pin the verification guest."))
            continue
        if not exists(path):
            findings.append(DoctorFinding(
                check_id, "error", f"pinned {check_id} is missing at {path}",
                f"Install the pinned {check_id} at {path} and record its sha256 in the "
                f"coordinator config before enabling public verification."))
            continue
        expected = pins.digests.get(check_id) if pins is not None else None
        if expected is None:
            findings.append(DoctorFinding(
                check_id, "error", f"{check_id} is present at {path} but unpinned",
                f"Record {check_id}_sha256 in the [firecracker] table of {paths.config}; "
                f"the guest refuses to boot an artifact whose digest is not pinned."))
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            findings.append(DoctorFinding(
                check_id, "error", f"{check_id}_sha256 is not a sha256",
                f"Set {check_id}_sha256 to 64 lowercase hex characters in {paths.config}."))
            continue
        if file_digest(path) != expected:
            findings.append(DoctorFinding(
                check_id, "error", f"{check_id} digest does not match its pin",
                f"{path} is not the artifact pinned as {check_id}_sha256; restore it or "
                f"re-pin it with `recomp coordinator setup`."))
            continue
        findings.append(DoctorFinding(check_id, "ok", "present at pinned digest", ""))

    # FirecrackerRunner enforces these at every boot; surfacing them here is the
    # difference between a setup that fails now and one that fails on the first
    # real verification, after a contributor has already spent a lease.
    jail_root = pins.jail_root if pins is not None else None
    if jail_root is None:
        findings.append(DoctorFinding(
            "jail-root", "error", "no jail_root is configured",
            f"Set jail_root in the [firecracker] table of {paths.config}; it must be a "
            "private 0700 directory owned by the coordinator account."))
    else:
        try:
            info = get_stat(jail_root)
        except OSError:
            findings.append(DoctorFinding(
                "jail-root", "error", f"jail_root {jail_root} does not exist",
                f"mkdir -p {jail_root} && chmod 700 {jail_root}"))
        else:
            mode = stat.S_IMODE(info.st_mode)
            if not stat.S_ISDIR(info.st_mode):
                findings.append(DoctorFinding(
                    "jail-root", "error", f"jail_root {jail_root} is not a directory",
                    f"Replace it with a directory and chmod it 700."))
            elif mode != 0o700:
                findings.append(DoctorFinding(
                    "jail-root", "error", f"jail_root mode is {oct(mode)[-3:]}",
                    f"chmod 700 {jail_root}; the runner refuses any other mode."))
            elif info.st_uid != geteuid():
                findings.append(DoctorFinding(
                    "jail-root", "error", f"jail_root is not owned by this account",
                    f"chown {geteuid()} {jail_root}; the runner refuses a jail root it "
                    f"does not own."))
            else:
                findings.append(DoctorFinding("jail-root", "ok", "0700, owned", ""))

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


def _reject_secret_names(table: str, values: Mapping[str, Any]) -> None:
    forbidden = {key for key in values
                 if "token" in str(key).lower() or "secret" in str(key).lower()}
    if forbidden:
        raise SetupError(
            f"coordinator config [{table}] must not contain secrets: {sorted(forbidden)}")


def write_coordinator_config(paths: CoordinatorPaths, settings: Mapping[str, Any]) -> Path:
    """Write public identifiers and guest pins only: 0600, never via a symlink.

    A value that is itself a mapping becomes a table, so the same call can emit
    both `[coordinator]` (identifiers) and `[firecracker]` (artifact pins). The
    App private key is never part of this file — it is a separate 0600 file that
    systemd hands to the service through `LoadCredential=`.
    """

    _reject_secret_names("coordinator", settings)
    scalar = {key: value for key, value in settings.items() if not isinstance(value, Mapping)}
    tables = {key: value for key, value in settings.items() if isinstance(value, Mapping)}
    for name, table in tables.items():
        _reject_secret_names(name, table)
    paths.create()
    path = paths.config
    if path.is_symlink():
        raise SetupError("coordinator config path is a symlink; refusing to write")
    body = "[coordinator]\n" + "".join(
        f"{key} = {_format_value(value)}\n" for key, value in sorted(scalar.items())
    )
    for name in sorted(tables):
        body += f"\n[{name}]\n" + "".join(
            f"{key} = {_format_value(value)}\n"
            for key, value in sorted(tables[name].items()))
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, body.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)
    return path


def setup_coordinator(
    paths: CoordinatorPaths,
    *,
    owner: str,
    repository: str,
    app_id: int,
    installation_id: int,
    trusted_actor_id: int,
    image: str,
    project_root: str | Path,
    firecracker: str | Path,
    jailer: str | Path,
    kernel: str | Path,
    rootfs: str | Path,
    jail_root: str | Path,
    target: str | Path | None = None,
    kvm_device: str | Path | None = None,
    mke2fs: str | Path | None = None,
    debugfs: str | Path | None = None,
    branch: str = "main",
    uid: int | None = None,
    gid: int | None = None,
    poll_interval_seconds: int = 60,
    api_url: str = "https://api.github.com",
    file_digest: Callable[[Path], str] = _file_sha256,
) -> Path:
    """Record the identifiers and pin the guest artifacts by content hash.

    Digests are computed here rather than typed in: a pin transcribed by hand is a
    pin that silently accepts a different binary, and `FirecrackerRunner` would then
    only discover the mismatch on the first real verification.
    """

    from recomp.contracts import ImageRef

    for name, value in (("app_id", app_id), ("installation_id", installation_id),
                        ("trusted_actor_id", trusted_actor_id)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise SetupError(f"{name} must be a positive integer (got {value!r})")
    try:
        parsed_image = ImageRef.parse(image)
    except ValueError as exc:
        raise SetupError(f"toolchain image must be digest-pinned: {exc}") from exc
    if isinstance(poll_interval_seconds, bool) or not isinstance(poll_interval_seconds, int) \
            or poll_interval_seconds < 1:
        raise SetupError("poll_interval_seconds must be a positive integer")

    pins: dict[str, Any] = {}
    for name, supplied in (("firecracker", firecracker), ("jailer", jailer),
                           ("kernel", kernel), ("rootfs", rootfs)):
        path = Path(supplied)
        if not path.is_file():
            raise SetupError(f"{name} artifact does not exist: {path}")
        pins[name] = str(path)
        pins[f"{name}_sha256"] = file_digest(path)

    jail = Path(jail_root)
    if not jail.exists():
        jail.mkdir(parents=True, exist_ok=True)
    if not jail.is_dir():
        raise SetupError(f"jail_root is not a directory: {jail}")
    jail.chmod(0o700)
    pins["jail_root"] = str(jail)
    for name, supplied in (("kvm_device", kvm_device), ("mke2fs", mke2fs),
                           ("debugfs", debugfs)):
        if supplied is not None:
            pins[name] = str(Path(supplied))
    pins["uid"] = int(os.getuid() if uid is None else uid)
    pins["gid"] = int(os.getgid() if gid is None else gid)

    return write_coordinator_config(paths, {
        "owner": owner,
        "repository": repository,
        "app_id": int(app_id),
        "installation_id": int(installation_id),
        "trusted_actor_id": int(trusted_actor_id),
        "image": str(parsed_image),
        "project_root": str(Path(project_root)),
        "repository_url": f"https://github.com/{owner}/{repository}.git",
        "api_url": api_url,
        "branch": branch,
        "poll_interval_seconds": int(poll_interval_seconds),
        **({"target": str(Path(target))} if target is not None else {}),
        "firecracker": pins,
    })


_PROTECT_HOME = ("yes", "no", "read-only", "tmpfs")


def render_service_unit(
    paths: CoordinatorPaths,
    *,
    user: str,
    owner: str,
    repository: str,
    executable: str = "/usr/local/bin/recomp",
    jail_root: str | Path | None = None,
    project_root: str | Path | None = None,
    protect_home: str = "yes",
) -> str:
    """Render the hardened systemd unit; the App key arrives via LoadCredential.

    `ReadWritePaths` is the complete writable set, and it has to be: the runner
    creates its jail inside `jail_root` and reads the pinned kernel/rootfs from the
    project, so a unit that omits them fails on the first verification rather than at
    start-up. `ProtectHome=yes` hides everything under a home directory, which is
    where a single-owner install keeps those artifacts, so an install that runs as
    its owner must pass `protect_home="read-only"`; `ReadWritePaths` then re-opens
    exactly the paths that need writes and nothing else.
    """

    from recomp.templates import systemd_unit

    if protect_home not in _PROTECT_HOME:
        raise SetupError(f"protect_home must be one of {', '.join(_PROTECT_HOME)}")
    writable = [paths.state, paths.cache]
    for extra in (jail_root, project_root):
        if extra is not None and Path(extra) not in writable:
            writable.append(Path(extra))
    return (systemd_unit()
            .replace("{{OWNER}}", owner)
            .replace("{{REPOSITORY}}", repository)
            .replace("{{USER}}", user)
            .replace("{{EXECUTABLE}}", executable)
            .replace("{{APP_KEY}}", str(paths.app_key))
            .replace("{{CONFIG}}", str(paths.config))
            .replace("{{STATE}}", str(paths.state))
            .replace("{{CACHE}}", str(paths.cache))
            .replace("{{READWRITE}}", " ".join(str(Path(path)) for path in writable))
            .replace("{{PROTECT_HOME}}", protect_home))


def install_commands(unit_path: str | Path = f"/etc/systemd/system/{_SERVICE_NAME}.service") -> tuple[str, ...]:
    return (
        f"sudo install -m 0644 {unit_path} /etc/systemd/system/{_SERVICE_NAME}.service",
        "sudo systemctl daemon-reload",
        f"sudo systemctl enable --now {_SERVICE_NAME}.service",
    )
