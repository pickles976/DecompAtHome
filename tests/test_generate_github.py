from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path

import pytest

from recomp.generate import generate_project
from recomp.project import ProjectError, load_project, validate_target

IMAGE = "ghcr.io/acme/game-toolchain@sha256:" + "a" * 64
ACTION = "acme/recomp@" + "b" * 40


@pytest.fixture
def github_project(tmp_path, fixture_bin):
    return generate_project(
        tmp_path / "proj", bin_path=fixture_bin, name="demo",
        toolchain_image=IMAGE, framework_action=ACTION,
    )


def test_generated_project_is_github_ready_without_target_copy(github_project, fixture_bin):
    root = github_project.path
    assert not (root / "bin").exists()
    assert not (root / "server").exists()
    assert not any(root.rglob(fixture_bin.name))
    assert (root / ".github/workflows/recomp-preflight.yml").is_file()
    assert not (root / ".github/workflows/recomp-issue-commands.yml").exists()
    assert (root / ".github/pull_request_template.md").is_file()
    assert (root / ".github/CODEOWNERS").is_file()
    assert (root / "docs/progress.svg").is_file()
    assert (root / "docs/progress.json").is_file()
    assert (root / "CONTRIBUTING.md").is_file()
    assert "Give this repository or an Issue link" in (root / "README.md").read_text()
    assert "Fork Recomp@Home" not in (root / "README.md").read_text()


def test_recomp_toml_pins_target_by_hash_without_a_local_path(github_project, fixture_bin):
    cfg, _path = load_project(github_project.path)
    target = cfg["target"]
    assert target["filename"] == fixture_bin.name
    assert target["sha256"] == hashlib.sha256(fixture_bin.read_bytes()).hexdigest()
    assert target["size"] == fixture_bin.stat().st_size
    assert "binary" not in target
    text = (github_project.path / "recomp.toml").read_text()
    assert str(fixture_bin.parent) not in text
    assert cfg["toolchain"]["image"] == IMAGE
    assert cfg["github"]["framework_action"] == ACTION


def test_generator_requires_digest_pinned_image_and_sha_pinned_action(tmp_path, fixture_bin):
    with pytest.raises(ValueError, match="image"):
        generate_project(tmp_path / "a", bin_path=fixture_bin,
                         toolchain_image="ghcr.io/acme/game:latest", framework_action=ACTION)
    with pytest.raises(ValueError, match="action"):
        generate_project(tmp_path / "b", bin_path=fixture_bin,
                         toolchain_image=IMAGE, framework_action="acme/recomp@main")


def test_workflows_embed_the_pinned_action_and_stay_fork_safe(github_project):
    root = github_project.path
    for name in ("recomp-preflight.yml",):
        text = (root / ".github/workflows" / name).read_text()
        assert ACTION.split("@")[1] in text
        assert "__RECOMP_ACTION_REPOSITORY__" not in text
        assert "pull_request_target" not in text
        assert "secrets." not in text


def test_launcher_is_generated_executable_and_digest_pinned(github_project):
    launcher = github_project.path / "recomp-launcher"
    assert launcher.is_file()
    assert launcher.stat().st_mode & 0o111
    text = launcher.read_text()
    assert IMAGE in text
    assert ":latest" not in text


def test_initial_progress_is_empty_but_valid(github_project):
    data = json.loads((github_project.path / "docs/progress.json").read_text())
    assert data["schema"] == 1
    assert data["tasks"] == []
    assert data["totals"]["tasks"] == 0
    svg = (github_project.path / "docs/progress.svg").read_text()
    assert svg.startswith("<svg") and "<script" not in svg


def test_gitignore_excludes_local_state_and_targets(github_project):
    ignored = (github_project.path / ".gitignore").read_text()
    for entry in (".recomp/", "__pycache__/", "*.exe", "*.bin"):
        assert entry in ignored


def test_codeowners_protects_every_trusted_root(github_project):
    text = (github_project.path / ".github/CODEOWNERS").read_text()
    for protected in (".github/", "plugins/", "toolchain/", "recomp.toml", "recomp-launcher"):
        assert protected in text


def test_pull_request_template_requests_exactly_one_issue_and_evidence(github_project):
    text = (github_project.path / ".github/pull_request_template.md").read_text()
    assert "Closes #" in text
    for field in ("Recomp-Policy:", "Recomp-Toolchain:", "Recomp-Lease:",
                  "Recomp-Task-Generation:"):
        assert field in text


def test_generated_agents_md_states_the_github_rules(github_project):
    text = (github_project.path / "AGENTS.md").read_text()
    assert "/claim" in text
    assert "two hours" in text
    assert "recomp task start" in text
    assert "recomp serve" not in text
    assert "recomp join" not in text


def test_validate_target_accepts_only_the_pinned_target(github_project, fixture_bin, tmp_path):
    cfg, _path = load_project(github_project.path)
    reference = validate_target(fixture_bin, cfg)
    assert reference.filename == fixture_bin.name
    other = tmp_path / "other.exe"
    other.write_bytes(b"not the target")
    with pytest.raises(ProjectError, match="hash"):
        validate_target(other, cfg)
    with pytest.raises(ProjectError, match="exist"):
        validate_target(tmp_path / "absent.exe", cfg)


def test_policy_covers_launcher_and_toolchain_sources(github_project):
    from recomp.policy import check_policy, compute_policy_hash

    before = compute_policy_hash(github_project.path)
    launcher = github_project.path / "recomp-launcher"
    launcher.write_text(launcher.read_text() + "# tamper\n")
    assert compute_policy_hash(github_project.path) != before
    status, _ = check_policy(github_project.path)
    assert status == "stale"


def test_no_runtime_secrets_or_server_state_are_generated(github_project):
    root = github_project.path
    assert not any(root.rglob("*.pem"))
    assert not any(root.rglob("*.key"))
    assert not any(root.rglob("*.db"))
    text = " ".join(path.read_text(errors="ignore") for path in root.rglob("*")
                    if path.is_file() and path.suffix in (".md", ".toml", ".yml"))
    for removed in ("recomp serve", "recomp join", "invite token", "seat"):
        assert removed not in text


class FakeLabelRepo:
    """Minimal GitHub double tracking only the repository's label set."""

    def __init__(self, names=(), *, fail_422=()):
        self.labels = [{"name": name} for name in names]
        self.created = []
        self.fail_422 = set(fail_422)

    def list_labels(self):
        return iter(list(self.labels))

    def create_label(self, payload):
        from recomp.github_api import GitHubError

        self.created.append(payload)
        if payload["name"] in self.fail_422:
            raise GitHubError(422, "already_exists")
        self.labels.append({"name": payload["name"]})
        return {"name": payload["name"]}


def test_bootstrap_labels_creates_only_the_missing_labels_and_is_idempotent():
    from recomp.github_tasks import LABELS, bootstrap_labels

    repo = FakeLabelRepo(("open", "done", "unrelated"))
    created = bootstrap_labels(repo)
    assert created == tuple(name for name in LABELS if name not in {"open", "done"})
    assert [payload["name"] for payload in repo.created] == list(created)
    for payload in repo.created:
        assert len(payload["color"]) == 6 and int(payload["color"], 16) >= 0
        assert payload["description"]
    assert {label["name"] for label in repo.labels} >= set(LABELS)

    first_payloads = list(repo.created)
    assert bootstrap_labels(repo) == ()
    assert repo.created == first_payloads


def test_bootstrap_labels_creates_every_label_on_a_fresh_repository():
    from recomp.github_tasks import LABELS, bootstrap_labels

    repo = FakeLabelRepo()
    assert bootstrap_labels(repo) == LABELS


def test_bootstrap_labels_swallows_a_concurrent_422_but_not_other_errors():
    from recomp.github_api import GitHubError
    from recomp.github_tasks import LABELS, bootstrap_labels

    repo = FakeLabelRepo(fail_422=("claimed",))
    created = bootstrap_labels(repo)
    assert "claimed" not in created
    assert created == tuple(name for name in LABELS if name != "claimed")

    class Exploding(FakeLabelRepo):
        def create_label(self, payload):
            raise GitHubError(403, "forbidden")

    with pytest.raises(GitHubError):
        bootstrap_labels(Exploding())
