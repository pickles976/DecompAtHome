from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from recomp.contracts import ImageRef, Sha256
from recomp.toolchain import (
    OciRuntime,
    ToolchainError,
    build_and_push_toolchain,
    inspect_image_digest,
    render_launcher,
    run_toolchain,
)

IMAGE = ImageRef.parse("ghcr.io/acme/game-toolchain@sha256:" + "a" * 64)
BASE = "docker.io/library/python@sha256:" + "b" * 64
PUSHED = "c" * 64


class FakeRuntime:
    """Records argv and replays canned results without touching a real runtime."""

    def __init__(self, repo_digests=None, exit_code=0):
        self.calls: list[list[str]] = []
        self.call_kwargs: list[dict] = []
        self.repo_digests = repo_digests
        self.exit_code = exit_code

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        self.call_kwargs.append(dict(kwargs))
        stdout = ""
        if "inspect" in argv:
            digests = self.repo_digests
            if digests is None:
                digests = [f"{IMAGE.repository}@sha256:{IMAGE.digest.hex}"]
            stdout = json.dumps(digests)
        return subprocess.CompletedProcess(argv, self.exit_code, stdout, "")

    @property
    def argv(self) -> list[str]:
        return self.calls[-1]


def runtime(executable="docker", **kwargs):
    fake = FakeRuntime(**kwargs)
    return OciRuntime(Path("/usr/bin") / executable, fake), fake


def make_target(tmp_path, name="game.exe", data=b"MZ\x00target"):
    target = tmp_path / name
    target.write_bytes(data)
    return target, Sha256(hashlib.sha256(data).hexdigest())


def test_launcher_contains_only_digest_pinned_image(tmp_path):
    text = render_launcher(IMAGE)
    assert str(IMAGE) in text
    assert ":latest" not in text
    assert "eval " not in text
    assert '"$@"' in text
    assert text.startswith("#!/bin/sh\n")
    assert "set -eu" in text


def test_launcher_accepts_only_known_runtime_override():
    text = render_launcher(IMAGE)
    assert 'RECOMP_OCI_RUNTIME' in text
    assert 'docker|podman' in text


def test_launcher_tmpfs_mount_is_executable():
    text = render_launcher(IMAGE)
    assert "--tmpfs=/tmp:rw,exec" in text


def test_toolchain_mounts_target_read_only(tmp_path):
    oci, fake = runtime()
    project = tmp_path / "project"
    project.mkdir()
    target, digest = make_target(tmp_path)
    assert run_toolchain(oci, IMAGE, project, target, ["task", "run", "#12"],
                         target_sha256=digest) == 0
    argv = fake.argv
    assert f"{target}:/recomp/target:ro" in argv
    assert f"{project}:/workspace:rw" in argv
    assert "--network=none" in argv
    assert "--rm" in argv
    assert "--security-opt=no-new-privileges" in argv
    assert "--cap-drop=ALL" in argv
    assert argv[0] == "/usr/bin/docker"
    assert argv[-4:] == [str(IMAGE), "task", "run", "#12"]
    assert sum(1 for item in argv if item in ("-v", "--volume")) == 2


def test_container_tmpfs_mount_is_executable(tmp_path):
    oci, fake = runtime()
    project = tmp_path / "project"
    project.mkdir()
    target, digest = make_target(tmp_path)
    run_toolchain(oci, IMAGE, project, target, ["task", "run", "#12"],
                  target_sha256=digest)
    tmpfs = [item for item in fake.argv if item.startswith("--tmpfs=/tmp:")]
    assert len(tmpfs) == 1
    assert tmpfs[0].endswith(",size=256m")
    assert "rw,exec" in tmpfs[0]


def test_build_returns_registry_digest_not_transient_tag(tmp_path):
    oci, fake = runtime(repo_digests=[f"ghcr.io/acme/game-toolchain@sha256:{PUSHED}"])
    source = tmp_path / "ctx"
    source.mkdir()
    (source / "Containerfile").write_text("FROM scratch\n")
    result = build_and_push_toolchain(oci, source, BASE, "ghcr.io/acme/game-toolchain:build-7")
    assert str(result) == "ghcr.io/acme/game-toolchain@sha256:" + PUSHED
    build = fake.calls[0]
    assert f"BASE_IMAGE={BASE}" in build
    assert "--build-arg" in build
    assert any(call[1] == "push" for call in fake.calls)


def test_build_subprocess_disables_default_attestations(tmp_path):
    oci, fake = runtime(repo_digests=[f"ghcr.io/acme/game-toolchain@sha256:{PUSHED}"])
    source = tmp_path / "ctx"
    source.mkdir()
    (source / "Containerfile").write_text("FROM scratch\n")
    build_and_push_toolchain(oci, source, BASE, "ghcr.io/acme/game-toolchain:build-7")
    build_index = next(i for i, call in enumerate(fake.calls) if call[1] == "build")
    env = fake.call_kwargs[build_index]["env"]
    assert env["BUILDX_NO_DEFAULT_ATTESTATIONS"] == "1"
    assert all(env.get(key) == value for key, value in os.environ.items())


def test_build_refuses_unpinned_base_image(tmp_path):
    oci, fake = runtime()
    source = tmp_path / "ctx"
    source.mkdir()
    with pytest.raises(ToolchainError, match="digest-pinned"):
        build_and_push_toolchain(oci, source, "python:3.12", "ghcr.io/acme/game-toolchain:build-7")
    assert fake.calls == []


def test_build_without_registry_digest_yields_no_configuration(tmp_path):
    oci, fake = runtime(repo_digests=[])
    source = tmp_path / "ctx"
    source.mkdir()
    with pytest.raises(ToolchainError, match="digest"):
        build_and_push_toolchain(oci, source, BASE, "ghcr.io/acme/game-toolchain:build-7")


def test_build_refuses_ambiguous_repo_digests(tmp_path):
    oci, _ = runtime(repo_digests=[
        f"ghcr.io/acme/game-toolchain@sha256:{PUSHED}",
        "ghcr.io/acme/game-toolchain@sha256:" + "d" * 64,
    ])
    source = tmp_path / "ctx"
    source.mkdir()
    with pytest.raises(ToolchainError, match="ambiguous"):
        build_and_push_toolchain(oci, source, BASE, "ghcr.io/acme/game-toolchain:build-7")


def test_inspect_rejects_digest_mismatch():
    oci, _ = runtime(repo_digests=["ghcr.io/acme/game-toolchain@sha256:" + "e" * 64])
    with pytest.raises(ToolchainError, match="digest"):
        inspect_image_digest(oci, IMAGE)


def test_inspect_rejects_tagged_reference_without_digest():
    oci, _ = runtime(repo_digests=["ghcr.io/acme/game-toolchain:latest"])
    with pytest.raises(ToolchainError, match="digest"):
        inspect_image_digest(oci, IMAGE)


def test_inspect_returns_configured_digest():
    oci, fake = runtime()
    assert inspect_image_digest(oci, IMAGE) == IMAGE.digest
    assert "--format" in fake.argv


def test_runtime_discovery_accepts_only_docker_or_podman(tmp_path):
    found = {"docker": "/usr/bin/docker", "podman": "/usr/bin/podman"}
    assert OciRuntime.discover(lookup=found.get).executable == Path("/usr/bin/docker")
    assert OciRuntime.discover(preferred="podman", lookup=found.get).executable == Path("/usr/bin/podman")
    with pytest.raises(ToolchainError, match="docker or podman"):
        OciRuntime.discover(preferred="kubectl", lookup=found.get)
    with pytest.raises(ToolchainError, match="no OCI runtime"):
        OciRuntime.discover(lookup=lambda _name: None)
    with pytest.raises(ToolchainError, match="absolute"):
        OciRuntime.discover(lookup=lambda _name: "docker")


def test_missing_or_mismatched_target_never_starts_a_container(tmp_path):
    oci, fake = runtime()
    project = tmp_path / "project"
    project.mkdir()
    target, digest = make_target(tmp_path)
    with pytest.raises(ToolchainError, match="target"):
        run_toolchain(oci, IMAGE, project, tmp_path / "absent.exe", ["task", "run"],
                      target_sha256=digest)
    with pytest.raises(ToolchainError, match="hash"):
        run_toolchain(oci, IMAGE, project, target, ["task", "run"],
                      target_sha256=Sha256("f" * 64))
    assert fake.calls == []


def test_paths_with_spaces_pass_through_as_single_arguments(tmp_path):
    oci, fake = runtime()
    project = tmp_path / "my project"
    project.mkdir()
    target, digest = make_target(tmp_path, name="my game.exe")
    assert run_toolchain(oci, IMAGE, project, target, ["task", "verify"],
                         target_sha256=digest) == 0
    assert f"{project}:/workspace:rw" in fake.argv
    assert f"{target}:/recomp/target:ro" in fake.argv


def test_paths_with_newline_or_colon_are_refused(tmp_path):
    oci, fake = runtime()
    project = tmp_path / "bad:project"
    project.mkdir()
    target, digest = make_target(tmp_path)
    with pytest.raises(ToolchainError, match="mount path"):
        run_toolchain(oci, IMAGE, project, target, ["task", "run"], target_sha256=digest)
    assert fake.calls == []


def test_nonzero_container_exit_is_propagated(tmp_path):
    oci, _ = runtime(exit_code=3)
    project = tmp_path / "project"
    project.mkdir()
    target, digest = make_target(tmp_path)
    assert run_toolchain(oci, IMAGE, project, target, ["task", "run"],
                         target_sha256=digest) == 3


def test_container_argv_rejects_option_like_task_arguments(tmp_path):
    oci, fake = runtime()
    project = tmp_path / "project"
    project.mkdir()
    target, digest = make_target(tmp_path)
    with pytest.raises(ToolchainError, match="task argument"):
        run_toolchain(oci, IMAGE, project, target, ["--privileged"], target_sha256=digest)
    with pytest.raises(ToolchainError, match="task argument"):
        run_toolchain(oci, IMAGE, project, target,
                      ["plugin", "verify", "t-0", "--target", "/recomp/target"],
                      target_sha256=digest)
    assert fake.calls == []


def test_container_discovers_mounted_target_via_environment(tmp_path):
    """The task-argument guard forbids option-like argv; the image must learn
    the fixed target mount from the environment instead."""

    oci, fake = runtime()
    project = tmp_path / "project"
    project.mkdir()
    target, digest = make_target(tmp_path)
    assert run_toolchain(oci, IMAGE, project, target,
                         ["plugin", "run-task", "port-0000"], target_sha256=digest) == 0
    argv = fake.argv
    assert "--env=RECOMP_TARGET=/recomp/target" in argv
    assert argv.index("--env=RECOMP_TARGET=/recomp/target") < argv.index(str(IMAGE))
    assert argv[-4:] == [str(IMAGE), "plugin", "run-task", "port-0000"]


def test_containerfile_requires_pinned_base_and_no_network_fetch():
    text = (Path(__file__).parents[1] / "src/recomp/templates/toolchain/Containerfile").read_text()
    assert "ARG BASE_IMAGE" in text
    assert "FROM ${BASE_IMAGE}" in text
    assert 'ENTRYPOINT ["recomp"]' in text
    assert "curl" not in text
    assert "pip install" in text and "--no-index" in text
