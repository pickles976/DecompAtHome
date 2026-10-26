import os
import subprocess
import sys
from pathlib import Path


ENV = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}


def run_cli(*args, cwd=None, extra_env=None):
    environment = dict(ENV)
    if extra_env:
        environment.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "recomp", *args],
        capture_output=True, text=True, cwd=cwd, env=environment,
    )


def test_cli_help_exits_zero():
    r = run_cli("--help")
    assert r.returncode == 0
    for cmd in ("init", "detect", "plugin", "workflow", "toolchain", "github", "task",
                "coordinator"):
        assert cmd in r.stdout
    for removed in ("serve", "join", "admin"):
        assert removed not in r.stdout


def test_cli_detect_reports_format(fixture_bin):
    r = run_cli("detect", str(fixture_bin))
    assert r.returncode == 0
    assert "pe" in r.stdout


def test_cli_init_then_plugin_new_and_workflow(project, tmp_path):
    r = run_cli("plugin", "new", "myengine", "--capability", "scan", cwd=str(project.path))
    assert r.returncode == 0, r.stderr
    assert (project.path / "plugins" / "myengine" / "recomp.plugin.toml").exists()

    r = run_cli("plugin", "check", "myengine", cwd=str(project.path))
    assert r.returncode == 0, r.stderr

    r = run_cli("workflow", "show", cwd=str(project.path))
    assert r.returncode == 0
    assert "policy_version" in r.stdout

    r = run_cli("plugin", "new", "bad!", cwd=str(project.path))
    assert r.returncode != 0, "invalid plugin name must be refused"


def test_cli_exposes_toolchain_command():
    r = run_cli("--help")
    assert "toolchain" in r.stdout
    assert run_cli("toolchain", "--help").returncode == 0


def test_cli_toolchain_refuses_unpinned_references(tmp_path):
    r = run_cli("toolchain", "inspect", "ghcr.io/acme/game-toolchain:latest")
    assert r.returncode != 0
    assert r.stdout == ""
    assert "digest-pinned" in r.stderr

    r = run_cli("toolchain", "build", "--source", str(tmp_path),
                "--base-image", "python:3.12",
                "--destination", "ghcr.io/acme/game-toolchain:build-1")
    assert r.returncode != 0
    assert r.stdout == ""
    assert "digest" in r.stderr


def test_cli_exposes_contributor_task_command():
    assert "task" in run_cli("--help").stdout
    help_text = run_cli("task", "--help").stdout
    for action in ("doctor", "next", "start", "heartbeat", "run", "verify", "submit",
                   "status"):
        assert action in help_text
    assert "--target" in help_text


def test_cli_exposes_coordinator_command(tmp_path):
    assert "coordinator" in run_cli("--help").stdout
    help_text = run_cli("coordinator", "--help").stdout
    for action in ("setup", "doctor", "install-service", "run"):
        assert action in help_text
    for flag in ("--rootfs", "--jail-root", "--trusted-actor-id", "--protect-home"):
        assert flag in help_text


def test_cli_warns_before_publishing_tasks_with_an_untrusted_identity(project, tmp_path,
                                                                       fixture_bin):
    """A PAT-authored task Issue would be invisible to every contributor."""

    r = run_cli("github", "sync-tasks", "--target", str(fixture_bin),
                cwd=str(project.path),
                extra_env={"GITHUB_TOKEN": "not-a-real-token", "HOME": str(tmp_path)})
    assert r.returncode != 0
    assert "warning:" in r.stderr and "coordinator setup" in r.stderr


def test_cli_refuses_to_render_a_service_unit_without_a_pinned_config(tmp_path):
    """An unpinned unit would point the coordinator at artifacts nobody hashed."""

    isolated = {"HOME": str(tmp_path), "XDG_CONFIG_HOME": str(tmp_path / ".config")}
    r = run_cli("coordinator", "install-service", "--owner", "acme", "--repository", "game",
                "--output", str(tmp_path / "unit.service"), extra_env=isolated)
    assert r.returncode == 1, r.stdout
    assert "recomp coordinator setup" in r.stderr
    assert not (tmp_path / "unit.service").exists()
