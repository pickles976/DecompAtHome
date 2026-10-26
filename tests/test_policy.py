from recomp.policy import (
    bump_policy,
    check_policy,
    compute_policy_hash,
    load_lock,
)


def test_lock_matches_current_files(project):
    status, lock = check_policy(project.path)
    assert status == "ok", lock
    assert lock["policy_version"] == 1


def test_plugin_edit_makes_policy_stale(project):
    runner = project.path / "plugins" / "generic" / "runner.py"
    runner.write_text(runner.read_text() + "\n# host agent tweak\n")
    status, _ = check_policy(project.path)
    assert status == "stale"


def test_bump_relocks_and_increments_version(project):
    runner = project.path / "plugins" / "generic" / "runner.py"
    runner.write_text(runner.read_text() + "\n# host agent tweak\n")
    lock = bump_policy(project.path)
    assert lock["policy_version"] == 2
    status, lock2 = check_policy(project.path)
    assert status == "ok"
    assert lock2["hash"] == lock["hash"]


def test_hash_is_content_addressed(project):
    h1 = compute_policy_hash(project.path)
    assert h1 == compute_policy_hash(project.path)
    (project.path / "plugins" / "generic" / "runner.py").write_text("# changed\n")
    assert compute_policy_hash(project.path) != h1


def test_lock_ignores_py_cache(project):
    bump_policy(project.path)
    cache = project.path / "plugins" / "generic" / "__pycache__"
    cache.mkdir(exist_ok=True)
    (cache / "runner.cpython-312.pyc").write_bytes(b"\x00")
    status, _ = check_policy(project.path)
    assert status == "ok"


def test_toolchain_source_changes_policy_hash(project):
    before = compute_policy_hash(project.path)
    toolchain = project.path / "toolchain"
    toolchain.mkdir(exist_ok=True)
    (toolchain / "Containerfile").write_text("ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n")
    after_add = compute_policy_hash(project.path)
    assert after_add != before
    (toolchain / "Containerfile").write_text("ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n# tweak\n")
    assert compute_policy_hash(project.path) != after_add


def test_protected_launcher_changes_policy_hash(project):
    before = compute_policy_hash(project.path)
    (project.path / "recomp-launcher").write_text(
        '#!/bin/sh\nexec podman run image "$@"\n')
    assert compute_policy_hash(project.path) != before
