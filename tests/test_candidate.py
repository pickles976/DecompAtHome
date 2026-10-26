from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from recomp.candidate import CandidateError, construct_candidate
from recomp.contracts import Sha256
from recomp.preflight import PreflightReport


def git(repo, *args, env=None, input=None):
    merged = os.environ.copy()
    merged.update({
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    })
    if env:
        merged.update(env)
    return subprocess.run(
        ["git", "-C", os.fspath(repo), *args],
        input=input,
        text=True,
        capture_output=True,
        check=True,
        env=merged,
    ).stdout.strip()


@dataclass
class RepoFixture:
    url: str
    repo: Path
    base: str
    head: str
    expected_merge_tree: str
    side_effect: Path | None = None

def make_repo(tmp_path, *, malicious=False):
    repo = tmp_path / "source"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("base\n")
    git(repo, "add", "README.md")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-qb", "contribution")
    (repo / "recovery").mkdir()
    (repo / "recovery/out.json").write_text("{}")
    side_effect = tmp_path / "filter-ran"
    if malicious:
        (repo / ".gitattributes").write_text("recovery/out.json filter=evil\n")
        git(repo, "config", "filter.evil.smudge", f"touch {side_effect}")
        git(repo, "config", "filter.evil.clean", "cat")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "output")
    head = git(repo, "rev-parse", "HEAD")
    expected = git(repo, "merge-tree", "--write-tree", base, head).splitlines()[0]
    return RepoFixture(os.fspath(repo), repo, base, head, expected, side_effect)


def kwargs():
    return {
        "task_id": "strings-0000",
        "lease_generation": 4,
        "policy_hash": Sha256("1" * 64),
        "toolchain_digest": Sha256("2" * 64),
        "preflight_report": PreflightReport(()),
    }


def test_candidate_tree_binds_base_head_and_merge_tree(tmp_path):
    fixture = make_repo(tmp_path)
    result = construct_candidate(fixture.url, fixture.base, fixture.head, tmp_path / "quarantine", **kwargs())
    assert result.key.base_sha == fixture.base
    assert result.key.head_sha == fixture.head
    assert result.key.tree_sha == fixture.expected_merge_tree
    assert (result.path / "recovery/out.json").read_text() == "{}"
    assert (result.path / "recovery/out.json").stat().st_mode & 0o777 == 0o600


def test_materialization_does_not_run_filters_or_hooks(tmp_path):
    fixture = make_repo(tmp_path, malicious=True)
    construct_candidate(fixture.url, fixture.base, fixture.head, tmp_path / "quarantine", **kwargs())
    assert not fixture.side_effect.exists()


def test_failed_preflight_never_fetches_or_materializes(tmp_path):
    fixture = make_repo(tmp_path)
    with pytest.raises(CandidateError, match="preflight"):
        construct_candidate(
            fixture.url, fixture.base, fixture.head, tmp_path / "quarantine",
            **{**kwargs(), "preflight_report": PreflightReport((object(),))},
        )
    assert not (tmp_path / "quarantine").exists()

def test_merge_conflict_is_rejected_and_partial_directory_removed(tmp_path):
    fixture = make_repo(tmp_path)
    repo = fixture.repo
    git(repo, "checkout", "-q", "main")
    (repo / "README.md").write_text("base-side\n")
    git(repo, "commit", "-qam", "base side")
    conflicting_base = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-q", "contribution")
    (repo / "README.md").write_text("head-side\n")
    git(repo, "commit", "-qam", "head side")
    conflicting_head = git(repo, "rev-parse", "HEAD")
    quarantine = tmp_path / "quarantine"
    with pytest.raises(CandidateError, match="merge"):
        construct_candidate(fixture.url, conflicting_base, conflicting_head, quarantine, **kwargs())
    assert not list(quarantine.glob(".candidate-*"))


@pytest.mark.parametrize("kind", ["symlink", "gitlink", "weird-name"])
def test_special_or_weird_tree_entries_are_rejected(tmp_path, kind):
    fixture = make_repo(tmp_path)
    repo = fixture.repo
    git(repo, "checkout", "-q", "contribution")
    if kind == "symlink":
        os.symlink("out.json", repo / "recovery/link")
        git(repo, "add", "recovery/link")
    elif kind == "gitlink":
        git(repo, "update-index", "--add", "--cacheinfo", "160000," + fixture.base + ",recovery/submodule")
    else:
        (repo / "recovery/bad\nname").write_text("bad")
        git(repo, "add", "recovery/bad\nname")
    git(repo, "commit", "-qm", kind)
    head = git(repo, "rev-parse", "HEAD")
    quarantine = tmp_path / f"quarantine-{kind}"
    with pytest.raises(CandidateError, match="tree"):
        construct_candidate(fixture.url, fixture.base, head, quarantine, **kwargs())
    assert not list(quarantine.glob(".candidate-*"))


def test_oversized_blob_is_rejected(tmp_path):
    fixture = make_repo(tmp_path)
    with pytest.raises(CandidateError, match="blob"):
        construct_candidate(
            fixture.url, fixture.base, fixture.head, tmp_path / "quarantine",
            max_blob_bytes=1,
            **kwargs(),
        )


def test_inherited_git_configuration_and_alternates_are_ignored(tmp_path, monkeypatch):
    fixture = make_repo(tmp_path)
    hostile_home = tmp_path / "hostile-home"
    hostile_home.mkdir()
    marker = tmp_path / "global-hook"
    (hostile_home / ".gitconfig").write_text(
        "[core]\n  hooksPath = " + os.fspath(tmp_path / "hooks") + "\n"
        "[filter \"evil\"]\n  smudge = touch " + os.fspath(marker) + "\n"
    )
    monkeypatch.setenv("HOME", os.fspath(hostile_home))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", os.fspath(tmp_path / "missing-objects"))
    result = construct_candidate(fixture.url, fixture.base, fixture.head, tmp_path / "quarantine", **kwargs())
    assert result.path.is_dir()
    assert not marker.exists()


@pytest.mark.parametrize("url", [
    "https://user:token@github.com/acme/game.git",
    "ssh://git@github.com/acme/game.git",
    "git@github.com:acme/game.git",
    "--upload-pack=touch /tmp/pwned",
])
def test_unsafe_repository_urls_are_rejected_before_any_fetch(tmp_path, url):
    fixture = make_repo(tmp_path)
    quarantine = tmp_path / "quarantine"
    with pytest.raises(CandidateError, match="repository URL"):
        construct_candidate(url, fixture.base, fixture.head, quarantine, **kwargs())
    assert not quarantine.exists()
