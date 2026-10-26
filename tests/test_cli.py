import os
import subprocess
import sys
from pathlib import Path


ENV = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}


def run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "recomp", *args],
        capture_output=True, text=True, cwd=cwd, env=ENV,
    )


def test_cli_help_exits_zero():
    r = run_cli("--help")
    assert r.returncode == 0
    for cmd in ("init", "detect", "plugin", "workflow", "serve", "join", "work", "admin"):
        assert cmd in r.stdout


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
