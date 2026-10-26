"""Disposable Firecracker microVM execution for public candidate verification.

This is the coordinator's isolation boundary: untrusted contributor output runs
in a fresh guest with no network, no vsock, no host filesystem passthrough, and
exactly one bounded result channel - a small ext4 drive holding `verdict.json`.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from recomp.guest import OPERATIONS, SCHEMA, VERDICT_STATUSES

_GUEST_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_COMMAND_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_BLOCK_SIZE = 1024
_READ_CHUNK = 1 << 20
_BOOT_ARGS = (
    "console=none reboot=k panic=1 pci=off i8042.nokbd i8042.noaux "
    "random.trust_cpu=on init=/usr/bin/recomp-guest"
)
_DRIVE_DEVICES = {"job": "/dev/vdb", "input": "/dev/vdc", "result": "/dev/vdd",
                  "target": "/dev/vde"}


class GuestError(RuntimeError):
    pass


@dataclass(frozen=True)
class GuestLimits:
    wall_seconds: int
    memory_mib: int
    vcpus: int
    result_bytes: int
    pids: int
    nofile: int

    def __post_init__(self) -> None:
        for name in ("wall_seconds", "memory_mib", "vcpus", "result_bytes", "pids", "nofile"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise GuestError(f"guest limit {name} must be a positive integer")

    def as_mapping(self) -> dict[str, int]:
        return {
            "wall_seconds": self.wall_seconds, "memory_mib": self.memory_mib,
            "vcpus": self.vcpus, "result_bytes": self.result_bytes,
            "pids": self.pids, "nofile": self.nofile,
        }


@dataclass(frozen=True)
class GuestDrive:
    drive_id: str
    path_in_jail: str
    read_only: bool
    is_root: bool = False

    def as_mapping(self) -> dict[str, Any]:
        return {
            "drive_id": self.drive_id,
            "path_on_host": self.path_in_jail,
            "is_root_device": self.is_root,
            "is_read_only": self.read_only,
        }


@dataclass(frozen=True)
class GuestSpec:
    guest_id: str
    operation: str
    command_id: str
    job: Mapping[str, Any]
    limits: GuestLimits
    input_dir: Path | None = None
    target_path: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.guest_id, str) or _GUEST_ID_RE.fullmatch(self.guest_id) is None:
            raise GuestError("guest id must be a short lowercase identifier")
        if self.operation not in OPERATIONS:
            raise GuestError(f"guest operation {self.operation!r} is not a known enum value")
        if (not isinstance(self.command_id, str)
                or _COMMAND_ID_RE.fullmatch(self.command_id) is None):
            raise GuestError("guest command id must be a trusted manifest identifier")
        if not isinstance(self.job, Mapping):
            raise GuestError("guest job payload must be a mapping")


@dataclass(frozen=True)
class GuestResult:
    verdict: dict[str, Any]
    guest_id: str


@dataclass
class FirecrackerConfig:
    firecracker: Path
    jailer: Path
    kernel: Path
    rootfs: Path
    jail_root: Path
    uid: int
    gid: int
    firecracker_sha256: str
    jailer_sha256: str
    kernel_sha256: str
    rootfs_sha256: str
    kvm_device: Path = Path("/dev/kvm")
    mke2fs: Path = Path("/sbin/mke2fs")
    debugfs: Path = Path("/sbin/debugfs")


def load_pinned_config(path: str | Path) -> FirecrackerConfig:
    """Load the owner's pinned kernel/rootfs/binary manifest."""

    try:
        data = tomllib.loads(Path(path).read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise GuestError("firecracker manifest is unreadable or malformed") from exc
    section = data.get("firecracker")
    if not isinstance(section, Mapping):
        raise GuestError("firecracker manifest requires a [firecracker] table")
    try:
        return FirecrackerConfig(
            firecracker=Path(section["firecracker"]),
            jailer=Path(section["jailer"]),
            kernel=Path(section["kernel"]),
            rootfs=Path(section["rootfs"]),
            jail_root=Path(section["jail_root"]),
            uid=int(section["uid"]),
            gid=int(section["gid"]),
            firecracker_sha256=section["firecracker_sha256"],
            jailer_sha256=section["jailer_sha256"],
            kernel_sha256=section["kernel_sha256"],
            rootfs_sha256=section["rootfs_sha256"],
            kvm_device=Path(section.get("kvm_device", "/dev/kvm")),
            mke2fs=Path(section.get("mke2fs", "/sbin/mke2fs")),
            debugfs=Path(section.get("debugfs", "/sbin/debugfs")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise GuestError("firecracker manifest is missing required pins") from exc


def _default_run_command(argv: Sequence[str], timeout: float | None = None,
                         capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=timeout,
        start_new_session=True,
        check=False,
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_READ_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


class FirecrackerRunner:
    """Boots one disposable guest per candidate and destroys it afterwards."""

    def __init__(
        self,
        config: FirecrackerConfig,
        *,
        run_command: Callable[..., subprocess.CompletedProcess] = _default_run_command,
        on_cleanup: Callable[[Path], None] | None = None,
    ) -> None:
        self.config = config
        self._run = run_command
        self._on_cleanup = on_cleanup

    def run(self, spec: GuestSpec) -> GuestResult:
        self._validate_host()
        input_dir = Path(spec.input_dir) if spec.input_dir is not None else None
        if input_dir is not None and not input_dir.is_dir():
            raise GuestError("candidate input directory does not exist")
        target = Path(spec.target_path) if spec.target_path is not None else None
        if target is not None and not target.is_file():
            raise GuestError("oracle target file does not exist")
        jail_dir = self.config.jail_root / "firecracker" / spec.guest_id
        if jail_dir.exists():
            raise GuestError(f"jail for guest {spec.guest_id!r} already exists")
        root = jail_dir / "root"
        drives_dir = root / "drives"
        try:
            drives_dir.mkdir(parents=True, mode=0o700)
            self._stage_images(root, drives_dir, spec, input_dir, target)
            config_path = self._write_machine_config(root, spec)
            self._boot(spec, jail_dir, config_path)
            return GuestResult(self._extract_verdict(drives_dir / "result.img", spec.limits),
                               spec.guest_id)
        finally:
            shutil.rmtree(jail_dir, ignore_errors=True)
            if self._on_cleanup is not None:
                self._on_cleanup(jail_dir)

    def _validate_host(self) -> None:
        config = self.config
        if not config.kvm_device.exists():
            raise GuestError("KVM is unavailable: /dev/kvm is missing")
        if not os.access(config.kvm_device, os.R_OK | os.W_OK):
            raise GuestError("KVM is unavailable: /dev/kvm is not readable and writable")
        for path, expected, what in (
            (config.firecracker, config.firecracker_sha256, "firecracker"),
            (config.jailer, config.jailer_sha256, "jailer"),
            (config.kernel, config.kernel_sha256, "kernel"),
            (config.rootfs, config.rootfs_sha256, "rootfs"),
        ):
            if not path.is_file():
                raise GuestError(f"pinned {what} is missing at {path}")
            if _SHA256_RE.fullmatch(expected or "") is None or _file_sha256(path) != expected:
                raise GuestError(f"pinned {what} checksum does not match the manifest")
        try:
            info = config.jail_root.stat()
        except OSError as exc:
            raise GuestError("jail root does not exist") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
            raise GuestError("jail root must be a private 0700 directory")
        if info.st_uid != os.geteuid():
            raise GuestError("jail root must be owned by the coordinator account")

    def _make_image(self, image: Path, blocks: int, source: Path | None) -> None:
        argv = [str(self.config.mke2fs), "-q", "-t", "ext4", "-b", str(_BLOCK_SIZE), "-F"]
        if source is not None:
            argv += ["-d", str(source)]
        argv += [str(image), str(blocks)]
        result = self._run(argv, capture=True)
        if result.returncode != 0:
            raise GuestError(f"could not build guest image {image.name}")

    def _stage_images(self, root: Path, drives_dir: Path, spec: GuestSpec,
                      input_dir: Path | None, target: Path | None) -> None:
        job_dir = root / "job"
        job_dir.mkdir(mode=0o700)
        drives = {name: device for name, device in _DRIVE_DEVICES.items()
                  if (name != "input" or input_dir is not None)
                  and (name != "target" or target is not None)}
        (job_dir / "job.json").write_text(json.dumps({
            "schema": SCHEMA,
            "operation": spec.operation,
            "command_id": spec.command_id,
            "limits": spec.limits.as_mapping(),
            "drives": drives,
            "payload": dict(spec.job),
        }, sort_keys=True, separators=(",", ":")))
        result_blocks = max(256, math.ceil(spec.limits.result_bytes / _BLOCK_SIZE) * 2)
        self._make_image(drives_dir / "job.img", 512, job_dir)
        if input_dir is not None:
            self._make_image(drives_dir / "input.img",
                             max(1024, self._directory_blocks(input_dir) * 2), input_dir)
        self._make_image(drives_dir / "result.img", result_blocks, None)
        if target is not None:
            shutil.copyfile(target, drives_dir / "target.img")
        shutil.rmtree(job_dir)
        shutil.copyfile(self.config.rootfs, root / "rootfs.ext4")
        shutil.copyfile(self.config.kernel, root / "vmlinux")

    @staticmethod
    def _directory_blocks(directory: Path) -> int:
        total = 0
        for path in directory.rglob("*"):
            if path.is_file() and not path.is_symlink():
                total += math.ceil(path.stat().st_size / _BLOCK_SIZE) + 1
        return total

    def _write_machine_config(self, root: Path, spec: GuestSpec) -> Path:
        drives = [
            GuestDrive("rootfs", "/rootfs.ext4", read_only=False, is_root=True),
            GuestDrive("job", "/drives/job.img", read_only=True),
            GuestDrive("result", "/drives/result.img", read_only=False),
        ]
        if spec.input_dir is not None:
            drives.insert(2, GuestDrive("input", "/drives/input.img", read_only=True))
        if spec.target_path is not None:
            drives.append(GuestDrive("target", "/drives/target.img", read_only=True))
        machine = {
            "boot-source": {"kernel_image_path": "/vmlinux", "boot_args": _BOOT_ARGS},
            "drives": [drive.as_mapping() for drive in drives],
            "machine-config": {
                "vcpu_count": spec.limits.vcpus,
                "mem_size_mib": spec.limits.memory_mib,
                "smt": False,
                "track_dirty_pages": False,
            },
        }
        path = root / "machine-config.json"
        path.write_text(json.dumps(machine, sort_keys=True, separators=(",", ":")))
        return path

    def _boot(self, spec: GuestSpec, jail_dir: Path, config_path: Path) -> None:
        argv = [
            str(self.config.jailer),
            "--id", spec.guest_id,
            "--uid", str(self.config.uid),
            "--gid", str(self.config.gid),
            "--exec-file", str(self.config.firecracker),
            "--chroot-base-dir", str(self.config.jail_root),
            "--",
            "--no-api",
            "--config-file", "/" + config_path.name,
        ]
        try:
            result = self._run(argv, timeout=spec.limits.wall_seconds, capture=True)
        except subprocess.TimeoutExpired as exc:
            raise GuestError("guest timed out and was terminated") from exc
        if result.returncode != 0:
            raise GuestError(f"guest exited with status {result.returncode}")

    def _extract_verdict(self, image: Path, limits: GuestLimits) -> dict[str, Any]:
        result = self._run(
            [str(self.config.debugfs), "-R", "cat /verdict.json", str(image)],
            capture=True,
        )
        if result.returncode != 0:
            raise GuestError("could not read the guest result drive")
        raw = result.stdout if isinstance(result.stdout, bytes) else (result.stdout or "").encode()
        if len(raw) > limits.result_bytes:
            raise GuestError("guest result exceeds the configured result budget")
        return _validate_verdict(raw)


def _validate_verdict(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise GuestError("guest verdict is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise GuestError("guest verdict must be a JSON object")
    if value.get("schema") != SCHEMA:
        raise GuestError("guest verdict schema version is unsupported")
    if value.get("status") not in VERDICT_STATUSES:
        raise GuestError("guest verdict status is not a known enum value")
    outputs = value.get("outputs", {})
    if (not isinstance(outputs, Mapping)
            or any(not isinstance(path, str) or not isinstance(digest, str)
                   or _SHA256_RE.fullmatch(digest) is None
                   for path, digest in outputs.items())):
        raise GuestError("guest verdict outputs must map paths to sha256 digests")
    code = value.get("diagnostic_code", 0)
    if isinstance(code, bool) or not isinstance(code, int):
        raise GuestError("guest verdict diagnostic code must be an integer")
    return dict(value)
