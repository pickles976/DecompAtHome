from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = (
    ROOT / "README.md",
    ROOT / "AGENTS.md",
    ROOT / "docs/coordinator-setup.md",
    ROOT / "docs/security-model.md",
    ROOT / "docs/contributor-workflow.md",
)
REMOVED = ("recomp serve", "recomp join", "recomp work --loop", "recomp admin token",
           "invite token", "base_seats", "fast lane", "/api/submit", "127.0.0.1:7331")


def read(path: Path) -> str:
    return path.read_text()


def test_framework_readme_leads_with_the_fork_model():
    text = read(ROOT / "README.md")
    for phrase in ("Fork Recomp@Home", "separate", "Linux", "KVM", "GitHub App",
                   "coordinator doctor", "Issue link"):
        assert phrase in text, phrase


@pytest.mark.parametrize("path", DOCS, ids=lambda path: path.name)
def test_docs_contain_no_removed_workflow_instructions(path):
    text = read(path)
    for removed in REMOVED:
        assert removed not in text, f"{path.name} still documents {removed!r}"


def test_every_guide_exists_and_is_linked_from_the_readme():
    readme = read(ROOT / "README.md")
    for guide in ("docs/coordinator-setup.md", "docs/security-model.md",
                  "docs/contributor-workflow.md"):
        assert (ROOT / guide).is_file()
        assert guide in readme


def test_security_model_covers_the_isolation_claims():
    text = read(ROOT / "docs/security-model.md")
    for phrase in ("candidate", "oracle", "Firecracker", "expected_head_sha",
                   "pull_request_target", "Residual risk", "revert"):
        assert phrase in text, phrase
    assert "https://securitylab.github.com" in text


def test_contributor_guide_starts_from_a_link_and_covers_the_loop():
    text = read(ROOT / "docs/contributor-workflow.md")
    for phrase in ("recomp task next", "recomp task start", "recomp task heartbeat",
                   "recomp task submit", "two hours", "outside task output paths",
                   "repair lease"):
        assert phrase in text, phrase


def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "recomp", *args], capture_output=True,
                          text=True, cwd=ROOT,
                          env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"})


@pytest.mark.parametrize("command", ["init", "github", "task", "coordinator", "toolchain"])
def test_documented_commands_expose_their_help(command):
    result = run_cli(command, "--help")
    assert result.returncode == 0, result.stderr


def test_documented_options_exist_in_the_cli():
    init_help = run_cli("init", "--help").stdout
    for option in ("--bin", "--toolchain-image", "--framework-action", "--owner",
                   "--repository", "--trusted-actor-id", "--goal"):
        assert option in init_help, option
    coordinator_help = run_cli("coordinator", "--help").stdout
    for option in ("--owner", "--repository", "--user", "--output"):
        assert option in coordinator_help, option
    assert "--target" in run_cli("github", "--help").stdout


def test_documented_commands_appear_in_the_guides():
    setup = read(ROOT / "docs/coordinator-setup.md")
    commands = set(re.findall(r"recomp ([a-z-]+)(?: ([a-z-]+))?", setup))
    documented = {first for first, _second in commands}
    assert {"init", "plugin", "workflow", "toolchain", "github", "coordinator"} <= documented
    assert "serve" not in documented and "join" not in documented
