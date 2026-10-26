"""Digest-pinned OCI toolchain execution for contributors.

This container is a convenience and reproducibility boundary for contributor
machines. It is never the coordinator's isolation boundary for public
verification; that boundary is the Firecracker guest.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from recomp.contracts import ImageRef, Sha256

RUNTIME_NAMES = ("docker", "podman")
TARGET_MOUNT = "/recomp/target"
WORKSPACE_MOUNT = "/workspace"
_MEMORY_LIMIT = "4g"
_PIDS_LIMIT = "512"
_CPU_LIMIT = "2"
_READ_CHUNK = 1 << 20


class ToolchainError(RuntimeError):
    pass


def _default_runner(argv: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(argv),
        stdin=subprocess.DEVNULL,
        text=True,
        check=False,
        **kwargs,
    )


@dataclass(frozen=True)
class OciRuntime:
    executable: Path
    runner: Callable[..., subprocess.CompletedProcess] = field(default=_default_runner, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.executable, Path) or not self.executable.is_absolute():
            raise ToolchainError("OCI runtime executable must be an absolute path")
        if self.executable.name not in RUNTIME_NAMES:
            raise ToolchainError("OCI runtime must be docker or podman")

    @classmethod
    def discover(
        cls,
        *,
        preferred: str | None = None,
        lookup: Callable[[str], str | None] = shutil.which,
    ) -> "OciRuntime":
        if preferred is not None and preferred not in RUNTIME_NAMES:
            raise ToolchainError("OCI runtime must be docker or podman")
        for name in (preferred,) if preferred else RUNTIME_NAMES:
            found = lookup(name)
            if found is None:
                continue
            path = Path(found)
            if not path.is_absolute():
                raise ToolchainError("discovered OCI runtime path must be absolute")
            return cls(path)
        raise ToolchainError("no OCI runtime found: install docker or podman")

    def _invoke(self, args: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
        return self.runner([str(self.executable), *args], **kwargs)


def _mount_path(path: Path, what: str) -> str:
    text = str(path)
    if ":" in text or "\n" in text or "," in text or "\x00" in text:
        raise ToolchainError(f"{what} mount path must not contain ':', ',', or newlines")
    return text


def _repo_digests(runtime: OciRuntime, reference: str) -> list[str]:
    result = runtime._invoke(
        ["image", "inspect", "--format", "{{json .RepoDigests}}", reference],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise ToolchainError(f"OCI runtime could not inspect image {reference!r}")
    try:
        digests = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ToolchainError("OCI runtime returned malformed inspect output") from exc
    if digests is None:
        digests = []
    if not isinstance(digests, list) or not all(isinstance(item, str) for item in digests):
        raise ToolchainError("OCI runtime returned malformed repository digests")
    return digests


def _digest_for_repository(digests: Sequence[str], repository: str) -> Sha256:
    matching = set()
    for entry in digests:
        repo, separator, digest = entry.partition("@sha256:")
        if separator and repo == repository:
            matching.add(digest)
    if not matching:
        raise ToolchainError(f"no sha256 repository digest for {repository!r}")
    if len(matching) > 1:
        raise ToolchainError(f"ambiguous repository digests for {repository!r}")
    return Sha256(matching.pop())


def inspect_image_digest(runtime: OciRuntime, image: ImageRef) -> Sha256:
    """Require the locally present image to carry exactly the configured digest."""

    digest = _digest_for_repository(_repo_digests(runtime, str(image)), image.repository)
    if digest != image.digest:
        raise ToolchainError(
            f"image {image.repository!r} resolves to digest {digest.hex} but "
            f"{image.digest.hex} is pinned"
        )
    return digest


def _file_sha256(path: Path) -> Sha256:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_READ_CHUNK):
            digest.update(chunk)
    return Sha256(digest.hexdigest())


def run_toolchain(
    runtime: OciRuntime,
    image: ImageRef,
    project: str | Path,
    target: str | Path | None,
    arguments: Sequence[str],
    *,
    target_sha256: Sha256 | None = None,
) -> int:
    """Run `recomp <arguments>` in the pinned image; a target is mounted read-only
    only when the project pins one."""

    project_path = Path(project)
    target_path = Path(target) if target is not None else None
    if not project_path.is_dir():
        raise ToolchainError("project directory does not exist")
    if target_path is not None and not target_path.is_file():
        raise ToolchainError("target file does not exist")
    if not arguments or any(not isinstance(item, str) or not item or item.startswith("-")
                            or "\x00" in item for item in arguments):
        raise ToolchainError("task argument list must be non-empty and contain no options")
    project_mount = _mount_path(project_path.resolve(), "project")
    target_argv: list[str] = []
    if target_path is not None:
        target_mount = _mount_path(target_path.resolve(), "target")
        if target_sha256 is not None and _file_sha256(target_path) != target_sha256:
            raise ToolchainError("target hash does not match the project's pinned target hash")
        target_argv = ["-v", f"{target_mount}:{TARGET_MOUNT}:ro",
                       f"--env=RECOMP_TARGET={TARGET_MOUNT}"]
    argv = [
        "run", "--rm", "--network=none",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        f"--pids-limit={_PIDS_LIMIT}", f"--memory={_MEMORY_LIMIT}", f"--cpus={_CPU_LIMIT}",
        "--read-only", "--tmpfs=/tmp:rw,exec,nosuid,nodev,size=256m",
        "--workdir", WORKSPACE_MOUNT,
        "-v", f"{project_mount}:{WORKSPACE_MOUNT}:rw",
        *target_argv,
        str(image), *arguments,
    ]
    return runtime._invoke(argv).returncode


def build_and_push_toolchain(
    runtime: OciRuntime,
    source: str | Path,
    base_image: str,
    destination: str,
) -> ImageRef:
    """Build from a pinned base, push the transient tag, return the registry digest."""

    base = ImageRef.parse(base_image) if "@sha256:" in str(base_image) else None
    if base is None:
        raise ToolchainError("base image must be digest-pinned (repository@sha256:<64hex>)")
    source_path = Path(source)
    if not source_path.is_dir():
        raise ToolchainError("build context directory does not exist")
    repository, separator, tag = destination.rpartition(":")
    if not separator or "/" not in repository or not tag or "@" in destination:
        raise ToolchainError("destination must be a registry-qualified repository:tag")
    build = runtime._invoke([
        "build", "--pull=false", "--build-arg", f"BASE_IMAGE={base}",
        "-f", str(source_path / "Containerfile"), "-t", destination, str(source_path),
    ], env={**os.environ, "BUILDX_NO_DEFAULT_ATTESTATIONS": "1"})
    if build.returncode != 0:
        raise ToolchainError("toolchain image build failed")
    push = runtime._invoke(["push", destination])
    if push.returncode != 0:
        raise ToolchainError("toolchain image push failed")
    digest = _digest_for_repository(_repo_digests(runtime, destination), repository)
    return ImageRef(repository, digest)


def render_launcher(image: ImageRef) -> str:
    """Render the POSIX launcher that pins exactly one immutable image."""

    from recomp.templates import toolchain_launcher

    return toolchain_launcher(image)
