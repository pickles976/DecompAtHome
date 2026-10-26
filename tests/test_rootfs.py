"""The pinned OCI image becomes a bootable guest rootfs, or the build refuses.

`mke2fs` and `debugfs` are exercised for real: a rootfs that `debugfs` cannot
read is a rootfs the coordinator cannot inspect a verdict in, so sizing and
layout bugs must fail here rather than as an anonymous guest boot failure.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from recomp.contracts import ImageRef, Sha256
from recomp.rootfs import (
    GUEST_COMMANDS,
    GUEST_INIT,
    RootfsError,
    build_rootfs,
    flatten_image,
    validate_guest_tree,
)
from recomp.toolchain import OciRuntime

DIGEST = "a" * 64
REPOSITORY = "ghcr.io/acme/game-toolchain"
IMAGE = ImageRef(REPOSITORY, Sha256(DIGEST))
COMMANDS = {
    "schema": 1,
    "commands": {
        "lotr.behavioral": ["/usr/bin/python3", "/opt/recomp/guest/run.py"],
    },
}


def make_tree(root: Path, *, commands: dict | None = COMMANDS,
              with_init: bool = True, with_python: bool = True) -> Path:
    tree = root / "flat"
    (tree / "usr/bin").mkdir(parents=True)
    (tree / "opt/recomp/guest").mkdir(parents=True)
    if with_init:
        init = tree / GUEST_INIT
        init.write_text("#!/bin/sh\nexit 0\n")
        init.chmod(0o755)
    if with_python:
        (tree / "usr/bin/python3").write_text("interpreter\n")
        (tree / "opt/recomp/guest/run.py").write_text("print(1)\n")
    if commands is not None:
        (tree / GUEST_COMMANDS).write_text(json.dumps(commands))
    return tree


def runner_for(tree: Path, *, digest: str = DIGEST, calls: list | None = None):
    def runner(argv, **kwargs):
        if calls is not None:
            calls.append(list(argv))
        arguments = list(argv)[1:]
        if arguments[:2] == ["image", "inspect"]:
            payload = json.dumps([f"{REPOSITORY}@sha256:{digest}"])
            return subprocess.CompletedProcess(argv, 0, payload.encode(), b"")
        if arguments[0] == "create":
            return subprocess.CompletedProcess(argv, 0, b"cafef00d\n", b"")
        if arguments[0] == "export":
            sink = kwargs.get("stdout")
            with tarfile.open(fileobj=sink, mode="w") as archive:
                archive.add(tree, arcname=".")
            return subprocess.CompletedProcess(argv, 0, None, b"")
        if arguments[0] == "rm":
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError(f"unexpected runtime invocation: {arguments}")

    return runner


def runtime_for(tree: Path, *, digest: str = DIGEST, calls: list | None = None) -> OciRuntime:
    return OciRuntime(executable=Path("/usr/bin/docker"),
                      runner=runner_for(tree, digest=digest, calls=calls))


def test_flatten_accepts_default_runtime_text_output(tmp_path):
    calls: list[list[str]] = []

    def text_runner(argv, **kwargs):
        calls.append(list(argv))
        arguments = list(argv)[1:]
        if arguments[0] == "create":
            return subprocess.CompletedProcess(argv, 0, "cafef00d\n", "")
        if arguments[0] == "export":
            kwargs["stdout"].write(b"flattened")
            return subprocess.CompletedProcess(argv, 0, None, "")
        if arguments[0] == "rm":
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(f"unexpected runtime invocation: {arguments}")

    destination = tmp_path / "rootfs.tar"
    flatten_image(
        OciRuntime(executable=Path("/usr/bin/docker"), runner=text_runner),
        IMAGE,
        destination,
    )

    assert destination.read_bytes() == b"flattened"
    assert ["rm", "-f", "cafef00d"] in [call[1:] for call in calls]

def debugfs(image: Path, request: str) -> str:
    result = subprocess.run(["/sbin/debugfs", "-R", request, str(image)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return result.stdout.decode() + result.stderr.decode()


def test_build_produces_an_ext4_rootfs_that_holds_the_guest_contract(tmp_path):
    tree = make_tree(tmp_path)
    output = tmp_path / "guest-rootfs.ext4"

    digest = build_rootfs(IMAGE, output, runtime=runtime_for(tree))

    assert digest.hex == hashlib.sha256(output.read_bytes()).hexdigest()
    listing = debugfs(output, "ls -l /usr/bin")
    assert "recomp-guest" in listing
    assert "commands.json" in debugfs(output, f"ls -l /{GUEST_COMMANDS.rsplit('/', 1)[0]}")
    assert output.stat().st_size % 1024 == 0

def test_build_rebases_absolute_symlink_within_the_guest_root(tmp_path):
    tree = make_tree(tmp_path)
    link = tree / "usr/bin/python-link"
    link.symlink_to("/usr/bin/python3")
    output = tmp_path / "guest-rootfs.ext4"

    build_rootfs(IMAGE, output, runtime=runtime_for(tree))

    details = debugfs(output, "stat /usr/bin/python-link")
    assert 'Fast link dest: "python3"' in details


def test_the_container_is_removed_even_when_export_fails(tmp_path):
    tree = make_tree(tmp_path)
    calls: list = []

    def broken_runner(argv, **kwargs):
        calls.append(list(argv))
        arguments = list(argv)[1:]
        if arguments[:2] == ["image", "inspect"]:
            payload = json.dumps([f"{REPOSITORY}@sha256:{DIGEST}"])
            return subprocess.CompletedProcess(argv, 0, payload.encode(), b"")
        if arguments[0] == "create":
            return subprocess.CompletedProcess(argv, 0, b"cafef00d\n", b"")
        if arguments[0] == "export":
            return subprocess.CompletedProcess(argv, 1, None, b"export failed")
        if arguments[0] == "rm":
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError(f"unexpected runtime invocation: {arguments}")

    runtime = OciRuntime(executable=Path("/usr/bin/docker"), runner=broken_runner)
    with pytest.raises(RootfsError, match="could not export"):
        build_rootfs(IMAGE, tmp_path / "out.ext4", runtime=runtime)

    assert ["rm", "-f", "cafef00d"] in [call[1:] for call in calls]


def test_an_image_without_the_guest_init_is_refused_before_anything_is_written(tmp_path):
    tree = make_tree(tmp_path, with_init=False)
    output = tmp_path / "out.ext4"

    with pytest.raises(RootfsError, match="/usr/bin/recomp-guest"):
        build_rootfs(IMAGE, output, runtime=runtime_for(tree))

    assert not output.exists()


def test_a_command_naming_an_absent_program_is_refused(tmp_path):
    tree = make_tree(tmp_path, with_python=False)

    with pytest.raises(RootfsError, match="lotr.behavioral.*does not contain"):
        build_rootfs(IMAGE, tmp_path / "out.ext4", runtime=runtime_for(tree))


def test_a_local_image_at_the_wrong_digest_is_refused_before_export(tmp_path):
    tree = make_tree(tmp_path)
    calls: list = []

    with pytest.raises(RootfsError, match="does not satisfy the pin"):
        build_rootfs(IMAGE, tmp_path / "out.ext4",
                     runtime=runtime_for(tree, digest="b" * 64, calls=calls))

    invoked = [["docker", *call[1:2]] for call in calls]
    assert invoked == [["docker", "image"]], invoked


def test_validate_rejects_a_command_that_walks_out_of_the_root(tmp_path):
    tree = make_tree(tmp_path)
    (tree / GUEST_COMMANDS).write_text(json.dumps(
        {"schema": 1, "commands": {"generic.static": ["/usr/bin/../../../etc/sh"]}}))

    with pytest.raises(RootfsError, match="escapes the guest root"):
        validate_guest_tree(tree)


def test_a_missing_mkfs_is_reported_without_touching_the_registry(tmp_path):
    tree = make_tree(tmp_path)
    with pytest.raises(RootfsError, match="mke2fs is unavailable"):
        build_rootfs(IMAGE, tmp_path / "out.ext4", runtime=runtime_for(tree),
                     mke2fs=tmp_path / "no-such-mke2fs")


@pytest.mark.skipif(shutil.which("mke2fs") is None, reason="e2fsprogs is unavailable")
def test_thousands_of_small_files_do_not_exhaust_the_filesystem(tmp_path):
    """The real sizing hazard: a toolchain sysroot is mostly tiny files."""

    tree = make_tree(tmp_path)
    sysroot = tree / "usr/share/sysroot"
    sysroot.mkdir(parents=True)
    for index in range(4000):
        (sysroot / f"library{index}.rs").write_text("fn main() {}\n")
    output = tmp_path / "many.ext4"

    build_rootfs(IMAGE, output, runtime=runtime_for(tree))

    assert "library3999.rs" in debugfs(output, "ls /usr/share/sysroot")
