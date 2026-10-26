"""Contributor-side readiness check: one greenlight before any work starts.

A contributor is usually an agent driving a human's machine. It clones a
generated project and starts working, then discovers on the first
`recomp task run` that Docker Desktop is stopped, or — worse — after an hour
of analysis that its copy of the game is a different build than the one the
project pins. This module answers "may I start?" up front, on Linux *and*
Windows (Docker Desktop / WSL2), without KVM, firecracker, root, or network.

The report deliberately mirrors the *shape* of the owner-side
`coordinator_setup.DoctorReport` (stable `check_id`, `severity`, `observed`,
`remediation`; `as_mapping()` carrying a `schema`; `ok` means no finding of
severity `error`) but uses its own types, so the owner report can evolve
without silently changing what contributors are told.

Every external interaction is injectable, so the checks are testable with no
container runtime and no network.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from recomp.contracts import ImageRef, Sha256
from recomp.policy import check_policy
from recomp.project import ProjectError, load_project
from recomp.toolchain import RUNTIME_NAMES, OciRuntime, ToolchainError, inspect_image_digest

CONTRIBUTOR_REPORT_SCHEMA = 1

#: Check identifiers, in report order. Stable: agents branch on these.
CHECK_IDS = (
    "platform",
    "python",
    "git",
    "oci-runtime",
    "toolchain-image",
    "project",
    "target",
    "disk",
    "workspace",
)

MIN_PYTHON = (3, 11)
MIN_GIT = (2, 38)
MIN_FREE_BYTES = 20 * 1024**3
SUPPORTED_PLATFORMS = "Linux (including WSL2) or Windows"

_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_READ_CHUNK = 1 << 20
_SHA_PREFIX = 16
# `[target]` keys that identify the file itself; everything else in that table
# is descriptive provenance written by the project owner and is surfaced
# verbatim so the agent can tell its human exactly which build to obtain.
_TARGET_IDENTITY_KEYS = frozenset({"filename", "sha256", "size"})
_PROVENANCE_KEYS = ("provenance", "description")


@dataclass(frozen=True)
class ContributorFinding:
    check_id: str
    severity: str  # "ok" | "warning" | "error"
    observed: str
    remediation: str


@dataclass(frozen=True)
class ContributorReport:
    findings: tuple[ContributorFinding, ...]

    @property
    def ok(self) -> bool:
        return not any(finding.severity == "error" for finding in self.findings)

    @property
    def error_count(self) -> int:
        return sum(1 for finding in self.findings if finding.severity == "error")

    def finding(self, check_id: str) -> ContributorFinding:
        for finding in self.findings:
            if finding.check_id == check_id:
                return finding
        raise KeyError(check_id)

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": CONTRIBUTOR_REPORT_SCHEMA,
            "ok": self.ok,
            "findings": [
                {"check_id": finding.check_id, "severity": finding.severity,
                 "observed": finding.observed, "remediation": finding.remediation}
                for finding in self.findings
            ],
        }


@dataclass(frozen=True)
class WorkspaceStatus:
    """What the checkout looks like from outside: no host paths are reported."""

    is_work_tree: bool
    remotes: tuple[str, ...] = ()
    writable: bool = False


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
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, check=False)
    except (FileNotFoundError, PermissionError, OSError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _default_server_version(runtime: OciRuntime) -> str | None:
    """Ask the daemon, not PATH: a stopped Docker Desktop still has a client."""

    try:
        completed = runtime._invoke(["version", "--format", "{{.Server.Version}}"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (FileNotFoundError, PermissionError, OSError):
        return None
    if completed.returncode != 0:
        return None
    return (completed.stdout or "").strip() or None


def _default_workspace(root: Path) -> WorkspaceStatus:
    def git(*args: str) -> str | None:
        try:
            completed = subprocess.run(["git", "-C", os.fspath(root), *args],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, text=True, check=False)
        except (FileNotFoundError, PermissionError, OSError):
            return None
        if completed.returncode != 0:
            return None
        return completed.stdout.strip()

    inside = git("rev-parse", "--is-inside-work-tree") == "true"
    remotes = tuple(line.strip() for line in (git("remote") or "").splitlines() if line.strip())
    writable = False
    try:
        with tempfile.NamedTemporaryFile(dir=root, prefix=".recomp-doctor-"):
            writable = True
    except OSError:
        writable = False
    return WorkspaceStatus(is_work_tree=inside, remotes=remotes, writable=writable)


def _default_disk_free(root: Path) -> int | None:
    try:
        return shutil.disk_usage(root).free
    except OSError:
        return None


def _default_digest_file(path: Path) -> tuple[str, int]:
    """Hash the contributor's copy without ever reading its bytes into a report."""

    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        while chunk := stream.read(_READ_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


@dataclass(frozen=True)
class _WindowsOciRuntime(OciRuntime):
    """`shutil.which('docker')` yields `docker.exe` on native Windows."""

    def __post_init__(self) -> None:
        if not isinstance(self.executable, Path) or not self.executable.is_absolute():
            raise ToolchainError("OCI runtime executable must be an absolute path")
        if self.executable.stem not in RUNTIME_NAMES or self.executable.suffix.lower() != ".exe":
            raise ToolchainError("OCI runtime must be docker or podman")


def _discover_runtime(lookup: Callable[[str], str | None],
                      windows: bool) -> OciRuntime | None:
    try:
        return OciRuntime.discover(lookup=lookup)
    except ToolchainError:
        pass
    if not windows:
        return None
    for name in RUNTIME_NAMES:
        found = lookup(name) or lookup(f"{name}.exe")
        if not found:
            continue
        try:
            return _WindowsOciRuntime(Path(found))
        except ToolchainError:
            continue
    return None


def _human_bytes(value: int) -> str:
    gib = value / float(1024**3)
    return f"{gib:.1f} GiB"


def target_provenance(target_cfg: Mapping[str, Any]) -> str:
    """Surface the owner's descriptive `[target]` keys verbatim, in a stable order."""

    parts: list[str] = []
    for key in _PROVENANCE_KEYS:
        value = target_cfg.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
    extras = []
    for key in sorted(target_cfg):
        if key in _TARGET_IDENTITY_KEYS or key in _PROVENANCE_KEYS:
            continue
        value = target_cfg[key]
        if value in (None, "", [], {}):
            continue
        extras.append(f"{key}={value}")
    if extras:
        parts.append(", ".join(extras))
    return "; ".join(parts)


def _target_remediation(filename: str, size: Any, sha256: str, provenance: str) -> str:
    size_text = f"{size} bytes" if isinstance(size, int) else "size not pinned"
    tail = provenance or "no provenance recorded in recomp.toml [target]"
    return (f"Obtain exactly this build and pass it with --target: filename {filename}, "
            f"{size_text}, sha256 {sha256}. Provenance: {tail}. "
            f"Keep the file outside the checkout; recomp never copies or commits target bytes.")


def _platform_finding(system: str, release: str) -> tuple[ContributorFinding, bool]:
    lowered = (system or "").lower()
    if lowered.startswith("linux"):
        wsl = "microsoft" in (release or "").lower()
        observed = "linux (WSL2)" if wsl else "linux"
        return ContributorFinding("platform", "ok", observed, ""), False
    if lowered.startswith(("win32", "windows", "cygwin", "msys")):
        return ContributorFinding("platform", "ok", "windows", ""), True
    return ContributorFinding(
        "platform", "error", f"host platform is {system!r}",
        f"Contributor work is supported on {SUPPORTED_PLATFORMS}; "
        f"run the task on such a machine (Docker Desktop with the WSL2 backend on Windows)."
    ), False


def contributor_doctor(
    project_root: str | Path,
    *,
    target: str | Path | None = None,
    platform: str | None = None,
    platform_release: str | None = None,
    python_version: Sequence[int] | None = None,
    version: Callable[[str], str | None] = _default_version,
    lookup: Callable[[str], str | None] = shutil.which,
    server_version: Callable[[OciRuntime], str | None] = _default_server_version,
    image_digest: Callable[[OciRuntime, ImageRef], Sha256] = inspect_image_digest,
    policy_status: Callable[[Path], tuple[str, dict | None]] = check_policy,
    workspace: Callable[[Path], WorkspaceStatus] = _default_workspace,
    disk_free: Callable[[Path], int | None] = _default_disk_free,
    minimum_free_bytes: int = MIN_FREE_BYTES,
    digest_file: Callable[[Path], tuple[str, int]] = _default_digest_file,
) -> ContributorReport:
    """Decide whether this machine may start contributor work, and say why not."""

    import sys as _sys
    import platform as _platform

    root = Path(project_root)
    findings: list[ContributorFinding] = []

    system = platform if platform is not None else _sys.platform
    release = platform_release if platform_release is not None else _platform.release()
    platform_finding, windows = _platform_finding(str(system), str(release))
    findings.append(platform_finding)

    running = tuple(python_version) if python_version is not None else tuple(_sys.version_info[:3])
    wanted_python = ".".join(str(part) for part in MIN_PYTHON)
    if tuple(running[:len(MIN_PYTHON)]) < MIN_PYTHON:
        findings.append(ContributorFinding(
            "python", "error",
            f"python {'.'.join(str(part) for part in running)} is too old",
            f"Install Python {wanted_python} or newer and re-run recomp from it."))
    else:
        findings.append(ContributorFinding(
            "python", "ok", f"python {'.'.join(str(part) for part in running)}", ""))

    git_found = _version_tuple(version("git"))
    wanted_git = ".".join(str(part) for part in MIN_GIT)
    if git_found is None:
        findings.append(ContributorFinding(
            "git", "error", "git is not installed",
            f"Install git {wanted_git} or newer and make sure it is on PATH."))
    elif git_found[:len(MIN_GIT)] < MIN_GIT:
        findings.append(ContributorFinding(
            "git", "error",
            f"git {'.'.join(str(part) for part in git_found)} is too old",
            f"Install git {wanted_git} or newer."))
    else:
        findings.append(ContributorFinding(
            "git", "ok", f"git {'.'.join(str(part) for part in git_found)}", ""))

    runtime = _discover_runtime(lookup, windows)
    runtime_ready = False
    if runtime is None:
        findings.append(ContributorFinding(
            "oci-runtime", "error", "neither docker nor podman is on PATH",
            "Install Docker (Docker Desktop with the WSL2 backend on Windows) or podman; "
            "all contributor work runs inside the pinned toolchain image."))
    else:
        name = runtime.executable.stem or runtime.executable.name
        server = server_version(runtime)
        if server:
            runtime_ready = True
            findings.append(ContributorFinding(
                "oci-runtime", "ok", f"{name} server {server}", ""))
        else:
            findings.append(ContributorFinding(
                "oci-runtime", "error",
                f"{name} is installed but its daemon is not responding",
                f"Start the container runtime and wait until it is ready "
                f"(Docker Desktop: start the app; Linux: `systemctl --user start docker` or "
                f"`sudo systemctl start docker`), then re-run the doctor. "
                f"`{name} version` must report a Server version."))

    try:
        cfg, _ = load_project(root)
    except ProjectError as exc:
        cfg = None
        project_error = str(exc)
    else:
        project_error = ""

    image_ref: ImageRef | None = None
    image_text = ""
    if cfg is not None:
        image_text = str(cfg.get("toolchain", {}).get("image", "") or "")
        if image_text:
            try:
                image_ref = ImageRef.parse(image_text)
            except ValueError:
                image_ref = None

    if cfg is None:
        findings.append(ContributorFinding(
            "toolchain-image", "error", "no pinned toolchain image is readable",
            "Fix recomp.toml first; the toolchain image is pinned in its [toolchain] table."))
    elif image_ref is None:
        findings.append(ContributorFinding(
            "toolchain-image", "error",
            f"[toolchain] image is missing or not digest-pinned: {image_text!r}",
            "Re-clone the project repository; its [toolchain] image must be "
            "registry-qualified and digest-pinned (name@sha256:<64hex>)."))
    elif not runtime_ready:
        findings.append(ContributorFinding(
            "toolchain-image", "warning",
            "not checked: no responding container runtime",
            f"After the container runtime is up, run `docker pull {image_ref}`."))
    else:
        state, detail = _inspect_image(runtime, image_ref, image_digest)
        if state == "present":
            findings.append(ContributorFinding(
                "toolchain-image", "ok", f"present at pinned digest {image_ref.digest.hex[:_SHA_PREFIX]}…", ""))
        elif state == "absent":
            findings.append(ContributorFinding(
                "toolchain-image", "error", "pinned toolchain image is not present locally",
                f"Run `docker pull {image_ref}` (podman: `podman pull {image_ref}`)."))
        else:
            findings.append(ContributorFinding(
                "toolchain-image", "error",
                f"local image does not carry the pinned digest: {detail}",
                f"Run `docker pull {image_ref}`; the pinned digest is the only image "
                f"contributor work may run in."))

    if cfg is None:
        findings.append(ContributorFinding(
            "project", "error", f"recomp.toml is unusable: {project_error}",
            "Run the doctor from the root of a cloned recomp project repository."))
    else:
        state, lock = policy_status(root)
        if state == "missing":
            findings.append(ContributorFinding(
                "project", "error", "recomp.lock.toml is missing",
                "Re-clone the project repository; the policy lock is part of it."))
        elif state == "stale":
            version_text = (lock or {}).get("policy_version", "?")
            findings.append(ContributorFinding(
                "project", "error",
                f"policy lock is stale (recorded policy_version {version_text})",
                "Run `git pull` before claiming anything; a submission produced under a "
                "stale policy fails preflight and the lease is wasted."))
        else:
            version_text = (lock or {}).get("policy_version", "?")
            findings.append(ContributorFinding(
                "project", "ok",
                f"{cfg.get('project', {}).get('name', root.name)} at policy_version {version_text}", ""))

    findings.append(_target_finding(cfg, target, digest_file))

    free = disk_free(root)
    if free is None:
        findings.append(ContributorFinding(
            "disk", "warning", "free space could not be measured",
            f"Make sure at least {_human_bytes(minimum_free_bytes)} is free for the "
            f"toolchain image and build artifacts."))
    elif free < minimum_free_bytes:
        findings.append(ContributorFinding(
            "disk", "warning",
            f"{_human_bytes(free)} free, {_human_bytes(minimum_free_bytes)} recommended",
            f"Free up space: the pinned toolchain image plus build artifacts need about "
            f"{_human_bytes(minimum_free_bytes)}."))
    else:
        findings.append(ContributorFinding("disk", "ok", f"{_human_bytes(free)} free", ""))

    status = workspace(root)
    if not status.is_work_tree:
        findings.append(ContributorFinding(
            "workspace", "error", "the project directory is not a git work tree",
            "Clone the project repository with git (not a zip download); recomp submits "
            "work as a branch and a pull request."))
    elif not status.remotes:
        findings.append(ContributorFinding(
            "workspace", "error", "the checkout has no git remote",
            "Add the project repository (or your fork) as a remote; recomp pushes the "
            "task branch there."))
    elif not status.writable:
        findings.append(ContributorFinding(
            "workspace", "error", "the checkout is not writable by this account",
            "Run as an account that can write to the checkout; task work writes under "
            "recovery/ and .recomp/."))
    else:
        findings.append(ContributorFinding(
            "workspace", "ok",
            f"git work tree, remotes: {', '.join(status.remotes)}", ""))

    return ContributorReport(tuple(findings))


def _inspect_image(runtime: OciRuntime, image: ImageRef,
                   image_digest: Callable[[OciRuntime, ImageRef], Sha256]) -> tuple[str, str]:
    try:
        image_digest(runtime, image)
    except ToolchainError as exc:
        detail = str(exc)
        # `inspect_image_digest` fails closed for both "no such image" and
        # "wrong digest"; only the former means a pull is all that is missing.
        return ("absent" if "could not inspect" in detail else "mismatch"), detail
    return "present", ""


def _target_finding(cfg: Mapping[str, Any] | None, target: str | Path | None,
                    digest_file: Callable[[Path], tuple[str, int]]) -> ContributorFinding:
    """Three distinguishable outcomes: not supplied, wrong build, correct build."""

    if cfg is None:
        return ContributorFinding(
            "target", "error", "the required target is unknown: recomp.toml is unusable",
            "Run the doctor from the root of a cloned recomp project repository.")
    target_cfg = cfg.get("target", {}) or {}
    filename = str(target_cfg.get("filename", "") or "the pinned target file")
    required = str(target_cfg.get("sha256", "") or "")
    size = target_cfg.get("size")
    provenance = target_provenance(target_cfg)
    if not required:
        return ContributorFinding(
            "target", "ok", "this project pins no target binary; --target is not needed", "")
    remediation = _target_remediation(filename, size, required, provenance)
    if target is None:
        return ContributorFinding(
            "target", "error", "no target copy supplied", remediation)
    path = Path(target)
    if not path.is_file():
        return ContributorFinding(
            "target", "error", "the supplied target path is not a readable file", remediation)
    try:
        observed_sha, observed_size = digest_file(path)
    except OSError:
        return ContributorFinding(
            "target", "error", "the supplied target could not be read", remediation)
    if observed_sha != required or (isinstance(size, int) and observed_size != size):
        expected_size = f"{size} bytes" if isinstance(size, int) else "unpinned size"
        return ContributorFinding(
            "target", "error",
            f"supplied copy is a different build: sha256 {observed_sha[:_SHA_PREFIX]}… "
            f"({observed_size} bytes), required sha256 {required[:_SHA_PREFIX]}… "
            f"({expected_size})"
            + (f"; required build: {provenance}" if provenance else ""),
            remediation)
    return ContributorFinding(
        "target", "ok",
        f"{filename} matches the pinned target ({observed_size} bytes, "
        f"sha256 {required[:_SHA_PREFIX]}…)", "")


_SEVERITY_LABEL = {"ok": "ok   ", "warning": "warn ", "error": "ERROR"}


def render_text(report: ContributorReport) -> str:
    """Human/agent summary whose last line is exactly GREENLIGHT or BLOCKED: n error(s)."""

    width = max((len(finding.check_id) for finding in report.findings), default=0)
    lines = ["recomp contributor doctor"]
    for finding in report.findings:
        label = _SEVERITY_LABEL.get(finding.severity, finding.severity)
        lines.append(f"  [{label}] {finding.check_id.ljust(width)}  {finding.observed}")
        if finding.remediation:
            lines.append(f"           {' ' * width}  -> {finding.remediation}")
    lines.append("")
    lines.append("GREENLIGHT" if report.ok else f"BLOCKED: {report.error_count} error(s)")
    return "\n".join(lines)
