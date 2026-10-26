"""Minimal in-guest runner: PID 1 inside the disposable verification microVM.

Nothing here trusts the job payload beyond a fixed schema: the operation is an
enum, the command is an identifier resolved against the image's trusted
manifest, and the verdict leaving the guest is a bounded, schema-checked JSON
document that never carries raw contributor or host output.

Drive contract (driven purely by what the host staged in ``job.drives``):

* ``input``  -- optional ext4 candidate drive, mounted read-only at ``/input``.
  ``/input`` is always created as a directory, but ``--input`` is passed to the
  trusted command ONLY when an input drive exists.  The command therefore tells
  "no candidate input at all" (no ``--input`` argument) apart from "an empty
  candidate input" (``--input /input`` over an empty drive).
* ``target`` -- optional pinned target drive.  It is a RAW COPY of the target
  file, not a filesystem, so it is never mounted: the block device path itself
  is handed to the trusted command as ``--target /dev/vdX``.
* ``result`` -- required ext4 drive, mounted read-write at ``/result``.
"""

from __future__ import annotations

import json
import os
import re
import resource
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA = 1
VERDICT_STATUSES = ("accepted", "rejected", "inconclusive")
MANIFEST_PATH = Path("/opt/recomp/guest/commands.json")
OPERATIONS = ("static-verify", "candidate-build", "candidate-run", "oracle-extract",
              "oracle-run", "selftest")
JOB_MOUNT = Path("/job")
INPUT_MOUNT = Path("/input")
RESULT_MOUNT = Path("/result")
MAX_VERDICT_BYTES = 65536
MAX_PROBE_KEYS = 32
MAX_PROBE_STRING = 256
_COMMAND_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_DEVICE_RE = re.compile(r"/dev/vd[a-z]")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_LIMIT_KEYS = ("wall_seconds", "memory_mib", "vcpus", "result_bytes", "pids", "nofile")


class GuestJobError(ValueError):
    pass


@dataclass(frozen=True)
class GuestJob:
    operation: str
    command_id: str
    limits: dict[str, int]
    drives: dict[str, str]
    payload: dict[str, Any]


def load_job(path: str | Path) -> GuestJob:
    """Parse the read-only job description; reject anything shell-shaped."""

    try:
        value = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise GuestJobError("job description is unreadable or malformed") from exc
    if not isinstance(value, Mapping) or value.get("schema") != SCHEMA:
        raise GuestJobError("job schema is invalid")
    operation = value.get("operation")
    command_id = value.get("command_id")
    if operation not in OPERATIONS:
        raise GuestJobError("job operation is not a known enum value")
    if not isinstance(command_id, str) or _COMMAND_ID_RE.fullmatch(command_id) is None:
        raise GuestJobError("job command id is not a trusted manifest identifier")
    limits = value.get("limits")
    if (not isinstance(limits, Mapping) or set(limits) != set(_LIMIT_KEYS)
            or any(isinstance(limits[key], bool) or not isinstance(limits[key], int)
                   or limits[key] <= 0 for key in _LIMIT_KEYS)):
        raise GuestJobError("job limits are invalid")
    drives = value.get("drives")
    if (not isinstance(drives, Mapping)
            or any(not isinstance(name, str) or not isinstance(device, str)
                   or _DEVICE_RE.fullmatch(device) is None
                   for name, device in drives.items())):
        raise GuestJobError("job drive mapping is invalid")
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        raise GuestJobError("job payload must be an object")
    return GuestJob(operation, command_id, dict(limits), dict(drives), dict(payload))


def resolve_command(manifest: Mapping[str, Any], command_id: str) -> tuple[str, ...]:
    """Map an identifier to the image's trusted argv; never build a shell string."""

    if not isinstance(manifest, Mapping) or manifest.get("schema") != SCHEMA:
        raise GuestJobError("guest command manifest schema is invalid")
    commands = manifest.get("commands")
    if not isinstance(commands, Mapping) or command_id not in commands:
        raise GuestJobError(f"command {command_id!r} is not in the trusted manifest")
    argv = commands[command_id]
    if (not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)) or not argv
            or any(not isinstance(item, str) or not item for item in argv)
            or not argv[0].startswith("/")):
        raise GuestJobError(f"command {command_id!r} is not an absolute argv list")
    return tuple(argv)


def _bounded_probes(value: Any, *, max_keys: int = MAX_PROBE_KEYS,
                    max_len: int = MAX_PROBE_STRING) -> dict[str, Any] | None:
    """Return a bounded copy of a probes mapping, or None if it is not one."""

    if not isinstance(value, Mapping) or len(value) > max_keys:
        return None
    checked: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or len(key) > max_len:
            return None
        if isinstance(item, list):
            if len(item) > max_keys or any(not _is_bounded_scalar(e, max_len) for e in item):
                return None
            checked[key] = list(item)
        elif _is_bounded_scalar(item, max_len):
            checked[key] = item
        else:
            return None
    return checked


def _is_bounded_scalar(value: Any, max_len: int) -> bool:
    if value is None or isinstance(value, (bool, int, float)):
        return True
    return isinstance(value, str) and len(value) <= max_len


def build_verdict(
    *,
    status: str,
    outputs: Mapping[str, str],
    diagnostic_code: int,
    stderr: bytes = b"",
    probes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the only document allowed to leave the guest."""

    if status not in VERDICT_STATUSES:
        raise GuestJobError("verdict status is not a known enum value")
    if isinstance(diagnostic_code, bool) or not isinstance(diagnostic_code, int):
        raise GuestJobError("diagnostic code must be an integer")
    checked = {}
    for path, digest in outputs.items():
        if not isinstance(path, str) or not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise GuestJobError("verdict outputs must map paths to sha256 digests")
        checked[path] = digest
    verdict = {
        "schema": SCHEMA,
        "status": status,
        "outputs": dict(sorted(checked.items())),
        "diagnostic_code": diagnostic_code,
        "stderr_bytes": len(stderr),
    }
    bounded = _bounded_probes(probes) if probes is not None else None
    if bounded is not None:
        verdict["probes"] = bounded
    return verdict


def write_verdict(directory: str | Path, verdict: Mapping[str, Any],
                  *, max_bytes: int = MAX_VERDICT_BYTES) -> Path:
    """Atomically write a bounded verdict, leaving no partial file behind."""

    payload = json.dumps(verdict, sort_keys=True, separators=(",", ":")).encode()
    if len(payload) > max_bytes:
        raise GuestJobError("verdict exceeds the result drive budget")
    root = Path(directory)
    final = root / "verdict.json"
    temporary = root / "verdict.json.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, final)
    return final


def _apply_limits(limits: Mapping[str, int]) -> None:
    resource.setrlimit(resource.RLIMIT_NPROC, (limits["pids"], limits["pids"]))
    resource.setrlimit(resource.RLIMIT_NOFILE, (limits["nofile"], limits["nofile"]))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _mount(source: str, target: Path, filesystem: str, flags: str) -> None:
    target.mkdir(parents=True, exist_ok=True)
    subprocess.run(["/bin/mount", "-t", filesystem, "-o", flags, source, str(target)],
                   check=True, stdin=subprocess.DEVNULL)


def mount_plan(job: GuestJob) -> tuple[tuple[str, Path, str, str], ...]:
    """Mounts for a job: input only when staged, target never mounted."""

    plan: list[tuple[str, Path, str, str]] = []
    if "input" in job.drives:
        plan.append((job.drives["input"], INPUT_MOUNT, "ext4", "ro,nosuid,nodev,noexec"))
    plan.append((job.drives["result"], RESULT_MOUNT, "ext4", "rw,nosuid,nodev,noexec"))
    return tuple(plan)


def guest_argv(command: Sequence[str], job: GuestJob) -> list[str]:
    """Argv for the trusted command: --input only if staged, --target as device."""

    argv = [*command, "--job", str(JOB_MOUNT / "job.json")]
    if "input" in job.drives:
        argv += ["--input", str(INPUT_MOUNT)]
    if "target" in job.drives:
        argv += ["--target", job.drives["target"]]
    return argv


def main(argv: list[str] | None = None) -> int:
    """Run as PID 1: mount fixed drives, execute one trusted command, power off."""

    status, diagnostic_code, outputs, stderr = "inconclusive", 0, {}, b""
    probes: Any = None
    try:
        _mount("proc", Path("/proc"), "proc", "nosuid,nodev,noexec")
        job = load_job(JOB_MOUNT / "job.json") if JOB_MOUNT.joinpath("job.json").exists() else None
        if job is None:
            _mount(os.environ.get("RECOMP_JOB_DEVICE", "/dev/vdb"), JOB_MOUNT, "ext4", "ro,nosuid,nodev")
            job = load_job(JOB_MOUNT / "job.json")
        INPUT_MOUNT.mkdir(parents=True, exist_ok=True)
        for source, target, filesystem, flags in mount_plan(job):
            _mount(source, target, filesystem, flags)
        command = resolve_command(json.loads(MANIFEST_PATH.read_text()), job.command_id)
        _apply_limits(job.limits)
        completed = subprocess.run(
            guest_argv(command, job),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=job.limits["wall_seconds"],
            check=False,
        )
        stderr = completed.stderr or b""
        diagnostic_code = completed.returncode
        produced = json.loads(completed.stdout or b"{}")
        status = produced.get("status", "inconclusive")
        outputs = produced.get("outputs", {})
        probes = produced.get("probes") if isinstance(produced, Mapping) else None
    except GuestJobError:
        status, diagnostic_code = "inconclusive", 64
    except subprocess.TimeoutExpired:
        status, diagnostic_code = "inconclusive", 65
    except Exception:
        status, diagnostic_code = "inconclusive", 66
    try:
        write_verdict(RESULT_MOUNT, build_verdict(status=status, outputs=outputs,
                                                  diagnostic_code=diagnostic_code,
                                                  stderr=stderr, probes=probes))
    except Exception:
        write_verdict(RESULT_MOUNT, build_verdict(status="inconclusive", outputs={},
                                                  diagnostic_code=67))
    os.sync()
    if os.getpid() == 1:
        import ctypes

        ctypes.CDLL(None, use_errno=True).reboot(0x4321FEDC)  # RB_POWER_OFF
    return 0


if __name__ == "__main__":
    sys.exit(main())
