"""Build the microVM root filesystem from the pinned toolchain image.

One image is the single policy source: the contributor's container lane and the
coordinator's disposable guest both come from the same digest, so "the toolchain
that produced this candidate" and "the toolchain that verified it" cannot drift
apart. The contributor never sees the guest rootfs; both sides derive it from the
image they can independently resolve.

The export is flattened (`docker export`), never imported: the guest is a
single ext4 root device plus scratch devices, with no container runtime, no
network, and no ability to re-enter the image's entrypoint. Everything the guest
contract requires — `/usr/bin/recomp-guest` as the `init=` target and
`/opt/recomp/guest/commands.json` as the trusted argv table — is checked here,
before the image is ever booted, so a toolchain that cannot verify fails at build
time with a named reason instead of as an anonymous guest exit.

Nothing is trusted from the image: paths in `commands.json` must resolve inside
the exported tree, and the local image must carry exactly the pinned repository
digest before a single byte is exported.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import posixpath
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

from recomp.contracts import ImageRef, Sha256
from recomp.guest import GuestJobError, resolve_command
from recomp.toolchain import OciRuntime, ToolchainError, inspect_image_digest

#: The guest's `init=` target inside the image (see `firecracker._BOOT_ARGS`).
GUEST_INIT = "usr/bin/recomp-guest"
#: The trusted argv table the host addresses by `<plugin>.<mode>` (see `guest.py`).
GUEST_COMMANDS = "opt/recomp/guest/commands.json"

_BLOCK_SIZE = 1024
_MIB = 1024 * 1024
_MIN_BLOCKS = 128 * 1024          # 128 MiB floor: enough for a real toolchain
_MAX_BLOCKS = 6 * 1024 * 1024     # 6 GiB ceiling: a runaway image must fail closed
_READ_CHUNK = 1 << 20


class RootfsError(RuntimeError):
    """A pinned image cannot become a bootable guest root filesystem."""


def _file_sha256(path: Path) -> Sha256:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_READ_CHUNK):
            digest.update(chunk)
    return Sha256(digest.hexdigest())


def _output_text(raw: Any) -> str:
    if isinstance(raw, (bytes, bytearray)):
        return raw.decode("utf-8", "replace")
    return raw if isinstance(raw, str) else ""


def _stderr_tail(result: subprocess.CompletedProcess) -> str:
    text = " ".join(_output_text(result.stderr).split())
    return text[:240]


def _invoke(runtime: OciRuntime, arguments: Sequence[str], *,
            stdout: Any = subprocess.PIPE) -> subprocess.CompletedProcess:
    return runtime._invoke(list(arguments), stdout=stdout, stderr=subprocess.PIPE)


def flatten_image(runtime: OciRuntime, image: ImageRef, destination: Path) -> None:
    """Export the image's filesystem layers into one tar, then remove the container."""

    created = _invoke(runtime, ["create", str(image)])
    if created.returncode != 0:
        raise RootfsError(
            f"the OCI runtime could not create a container from {image.repository}: "
            f"{_stderr_tail(created) or 'no output'}")
    lines = _output_text(created.stdout).split()
    if not lines:
        raise RootfsError("the OCI runtime returned no container id")
    container = lines[-1].strip()
    try:
        with destination.open("wb") as sink:
            exported = runtime._invoke(["export", container], stdout=sink,
                                       stderr=subprocess.PIPE)
        if exported.returncode != 0:
            reason = _stderr_tail(exported) or "no output"
            raise RootfsError(f"the OCI runtime could not export the image: {reason}")
    finally:
        _invoke(runtime, ["rm", "-f", container], stdout=subprocess.DEVNULL)


def _rootfs_filter(member: tarfile.TarInfo, destination: str) -> tarfile.TarInfo | None:
    """Apply the data filter after rebasing guest-absolute links into the tree."""

    if member.issym() and PurePosixPath(member.linkname).is_absolute():
        parent = PurePosixPath(member.name).parent.as_posix()
        target = PurePosixPath(member.linkname).as_posix().lstrip("/")
        member = member.replace(linkname=posixpath.relpath(target, parent))
    elif member.islnk() and PurePosixPath(member.linkname).is_absolute():
        member = member.replace(linkname=member.linkname.lstrip("/"))
    return tarfile.data_filter(member, destination)


def _extract(export_path: Path, staging: Path) -> int:
    """Unpack the flattened image; device nodes are skipped, everything else kept."""

    staging.mkdir(parents=True, exist_ok=True)
    with tarfile.open(export_path) as archive:
        members = archive.getmembers()
        # The data filter refuses traversal and drops devices/sockets. Standard
        # image-absolute links are first rebased so they resolve inside this
        # guest tree rather than escaping into the coordinator host.
        archive.extractall(path=staging, members=members, filter=_rootfs_filter)
    skipped = sum(1 for member in members
                  if not (member.isfile() or member.isdir() or member.issym()))
    return skipped


def validate_guest_tree(staging: Path) -> None:
    """Fail if this tree cannot satisfy the host↔guest contract."""

    init = staging / GUEST_INIT
    if not init.is_file():
        raise RootfsError(
            f"the image has no /{GUEST_INIT}, which the microVM boots as init; the "
            "toolchain Containerfile must install the guest entry point")
    if not os.access(init, os.X_OK):
        raise RootfsError(f"/{GUEST_INIT} is not executable")

    manifest_path = staging / GUEST_COMMANDS
    if not manifest_path.is_file():
        raise RootfsError(
            f"the image has no /{GUEST_COMMANDS}, so the host cannot name a command "
            "for the guest to run; add the plugin's commands.json to the image")
    try:
        manifest: Mapping[str, Any] = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RootfsError(f"/{GUEST_COMMANDS} is not readable JSON: {exc}") from exc

    for command_id in sorted(manifest.get("commands", {}) if isinstance(
            manifest.get("commands"), Mapping) else []):
        try:
            argv = resolve_command(manifest, command_id)
        except GuestJobError as exc:
            raise RootfsError(f"/{GUEST_COMMANDS}: {exc}") from exc
        program = PurePosixPath(argv[0])
        relative = program.relative_to("/") if program.is_absolute() else program
        if ".." in relative.parts:
            raise RootfsError(
                f"/{GUEST_COMMANDS}: command {command_id!r} runs {argv[0]}, which "
                "escapes the guest root")
        if not (staging / relative).exists():
            raise RootfsError(
                f"/{GUEST_COMMANDS}: command {command_id!r} runs {argv[0]}, which the "
                "image does not contain")


def _size_plan(staging: Path) -> tuple[int, int]:
    """Return (block count, inode count) sized to the exported tree."""

    blocks = 0
    inodes = 0
    for path in staging.rglob("*"):
        if path.is_symlink():
            inodes += 1
            blocks += 1
            continue
        if path.is_dir():
            inodes += 1
            blocks += 1
            continue
        if path.is_file():
            inodes += 1
            blocks += math.ceil(path.stat().st_size / _BLOCK_SIZE) + 1
    inodes = max(2048, inodes * 2)
    inode_table = math.ceil(inodes * 256 / _BLOCK_SIZE)
    total = blocks + inode_table + 16384          # journal, bitmaps, superblocks
    total = math.ceil(total * 1.15)
    return max(_MIN_BLOCKS, min(total, _MAX_BLOCKS)), inodes


def _make_ext4(mke2fs: Path, image: Path, staging: Path, blocks: int, inodes: int) -> str:
    argv = [str(mke2fs), "-q", "-t", "ext4", "-b", str(_BLOCK_SIZE), "-m", "0",
            "-L", "recomp-guest", "-N", str(inodes), "-d", str(staging),
            str(image), str(blocks)]
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as handle:
        handle.truncate(blocks * _BLOCK_SIZE)
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False)
    if result.returncode != 0:
        return _stderr_tail(result) or f"mke2fs exited {result.returncode}"
    return ""


def build_rootfs(image: ImageRef | str, output: str | Path, *,
                 runtime: OciRuntime | None = None,
                 workdir: str | Path | None = None,
                 mke2fs: str | Path = "/sbin/mke2fs",
                 keep_workdir: bool = False) -> Sha256:
    """Flatten the pinned image into an ext4 rootfs; return its sha256."""

    parsed = image if isinstance(image, ImageRef) else ImageRef.parse(str(image))
    if runtime is None:
        runtime = OciRuntime.discover()
    try:
        inspect_image_digest(runtime, parsed)
    except ToolchainError as exc:
        raise RootfsError(
            f"the local image does not satisfy the pin: {exc}; pull the pinned digest "
            "before building the guest rootfs") from exc

    tool = Path(mke2fs)
    if not tool.is_file():
        raise RootfsError(f"mke2fs is unavailable at {tool}")

    destination = Path(output)
    if destination.is_symlink():
        raise RootfsError(f"refusing to write through a symlink: {destination}")

    owned = workdir is None
    work = Path(tempfile.mkdtemp(prefix="recomp-rootfs-", dir=(
        str(Path(workdir)) if workdir is not None else None))) if owned else Path(workdir)
    try:
        export_path = work / "image.tar"
        staging = work / "tree"
        flatten_image(runtime, parsed, export_path)
        _extract(export_path, staging)
        export_path.unlink()
        validate_guest_tree(staging)

        blocks, inodes = _size_plan(staging)
        failure = ""
        for _attempt in range(3):
            failure = _make_ext4(tool, destination, staging, blocks, inodes)
            if not failure:
                break
            if blocks >= _MAX_BLOCKS:
                break
            blocks = min(_MAX_BLOCKS, blocks * 2)
        if failure:
            destination.unlink(missing_ok=True)
            raise RootfsError(f"could not build the guest rootfs: {failure}")
        return _file_sha256(destination)
    finally:
        if owned and not keep_workdir:
            shutil.rmtree(work, ignore_errors=True)


def build_rootfs_from_image(reference: str, output: str | Path, *,
                            runtime: str | None = None, **kwargs) -> Sha256:
    """CLI entry: resolve the runtime by name if one was requested."""

    chosen = OciRuntime.discover(preferred=runtime) if runtime else None
    return build_rootfs(reference, output, runtime=chosen, **kwargs)
