"""A project without a pinned target, and maintainer-declared protected paths.

Every check here runs against the public API a contributor or owner touches:
no target is supplied anywhere, and nothing may ask for one.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from recomp.contracts import ImageRef, Sha256
from recomp.contributor_doctor import WorkspaceStatus, contributor_doctor, render_text
from recomp.github_tasks import sync_tasks
from recomp.policy import bump_policy
from recomp.preflight import PullRequestFacts, TreeEntry, check_preflight
from recomp.project import has_target, load_project, protected_paths, save_project, validate_target
from recomp.task_cli import TaskCliError, _require_target
from recomp.task_records import (
    TaskRecord,
    TaskRecordError,
    parse_trusted_task_record,
    render_task_record,
)
from recomp.toolchain import OciRuntime, run_toolchain

IMAGE = "ghcr.io/acme/port-toolchain@sha256:" + "a" * 64
FIXTURE_PLUGIN = Path(__file__).parent / "fixtures/targetless_plugin"
PROTECTED = ["goldens/", "reference/", "tools/", "scripts/"]


def make_project(root: Path, *, policy: list[str] | None = PROTECTED) -> Path:
    """A targetless project: `[target]` is absent, not empty."""

    root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(FIXTURE_PLUGIN, root / "plugins/targetless")
    (root / "recovery/ports").mkdir(parents=True)
    cfg = {
        "project": {"name": "port", "goal": "structure", "plugin": "targetless"},
        "toolchain": {"image": IMAGE},
        "github": {"owner": "acme", "repository": "port", "trusted_actor_id": 99},
        "assets": {"extract": []},
    }
    if policy is not None:
        cfg["policy"] = {"protected_paths": policy}
    save_project(cfg, root / "recomp.toml")
    assert bump_policy(root)["policy_version"] == 1
    return root


class FakeGitHub:
    def __init__(self, viewer_id: int = 99):
        self.viewer_id = viewer_id
        self.issues: list[dict] = []
        self.comments: dict[int, list[dict]] = {}

    def list_issues(self):
        return iter(list(self.issues))

    def create_issue(self, body):
        issue = {"number": len(self.issues) + 1, "state": "open",
                 "user": {"id": self.viewer_id}, "title": body["title"],
                 "body": body["body"], "labels": [{"name": n} for n in body.get("labels", ())]}
        self.issues.append(issue)
        return issue

    def create_comment(self, issue_number, text):
        comment = {"id": 1000 + issue_number, "user": {"id": self.viewer_id}, "body": text}
        self.comments.setdefault(issue_number, []).append(comment)
        return comment

    def list_comments(self, issue_number):
        return iter(list(self.comments.get(issue_number, [])))

    def set_issue_labels(self, issue_number, labels):
        for issue in self.issues:
            if issue["number"] == issue_number:
                issue["labels"] = [{"name": name} for name in labels]
                return issue
        raise KeyError(issue_number)


class FakeRuntime(OciRuntime):
    def __init__(self):
        self.argv: list[str] = []

    def _invoke(self, argv, **_kwargs):
        self.argv = list(argv)

        class Completed:
            returncode = 0

        return Completed()


def record_mapping(**overrides):
    mapping = {
        "schema": 1,
        "task_id": "port-0001",
        "kind": "cpp-port",
        "args": {"unit": "md5"},
        "outputs": [{"path": "recovery/ports/md5.json",
                     "media_type": "application/json", "max_bytes": 4096}],
        "policy_version": 1,
        "policy_hash": "c" * 64,
        "toolchain_digest": "a" * 64,
        "weight": 1,
        "generation": 1,
    }
    mapping.update(overrides)
    return mapping


# recomp.toml ---------------------------------------------------------------
def test_validate_target_returns_none_when_no_target_is_pinned(tmp_path):
    root = make_project(tmp_path / "proj")
    cfg, _ = load_project(root)
    assert has_target(cfg) is False
    assert validate_target(tmp_path / "does-not-exist", cfg) is None
    assert "target" not in cfg


def test_validate_target_still_refuses_a_wrong_copy_when_a_target_is_pinned(tmp_path, project):
    from recomp.project import ProjectError

    cfg, _ = load_project(project.path)
    assert has_target(cfg) is True
    wrong = tmp_path / "other.exe"
    wrong.write_bytes(b"not the pinned build")
    with pytest.raises(ProjectError, match="hash does not match"):
        validate_target(wrong, cfg)
    with pytest.raises(ProjectError, match="does not exist"):
        validate_target(tmp_path / "absent.exe", cfg)


def test_empty_target_table_counts_as_targetless(tmp_path):
    root = make_project(tmp_path / "proj")
    (root / "recomp.toml").write_text(
        (root / "recomp.toml").read_text() + '\n[target]\nfilename = ""\n')
    cfg, _ = load_project(root)
    assert has_target(cfg) is False
    assert validate_target(tmp_path / "anything", cfg) is None


# task records --------------------------------------------------------------
def test_task_record_round_trips_without_target_sha256():
    record = TaskRecord.from_mapping(record_mapping())
    assert record.target_sha256 is None
    assert "target_sha256" not in record.to_mapping()
    rendered = render_task_record(record)
    parsed = parse_trusted_task_record([{"user": {"id": 99}, "body": rendered}], 99)
    assert parsed == record
    assert parsed.semantic_mapping() == record.semantic_mapping()


def test_task_record_accepts_an_explicit_null_target_and_keeps_strict_keys():
    record = TaskRecord.from_mapping(record_mapping(target_sha256=None))
    assert record.target_sha256 is None
    pinned = TaskRecord.from_mapping(record_mapping(target_sha256="b" * 64))
    assert pinned.target_sha256 == Sha256("b" * 64)
    assert pinned.to_mapping()["target_sha256"] == "b" * 64
    with pytest.raises(TaskRecordError, match="unknown keys"):
        TaskRecord.from_mapping(record_mapping(target="whatever"))
    with pytest.raises(TaskRecordError):
        TaskRecord.from_mapping(record_mapping(target_sha256="B" * 64))
    with pytest.raises(TaskRecordError):
        TaskRecord.from_mapping(record_mapping(target_sha256="deadbeef"))


# publishing ----------------------------------------------------------------
def test_sync_tasks_publishes_without_a_target(tmp_path):
    root = make_project(tmp_path / "proj")
    cfg, _ = load_project(root)
    github = FakeGitHub()
    result = sync_tasks(github, root, cfg, target=None)

    assert result.created == ("port-0001", "port-0002")
    assert len(github.issues) == 2
    for issue in github.issues:
        assert "--target" not in issue["body"]
    record = parse_trusted_task_record(list(github.list_comments(1)), 99)
    assert record.target_sha256 is None
    assert record.kind == "cpp-port"

    again = sync_tasks(github, root, cfg, target=None)
    assert again.created == () and again.existing == ("port-0001", "port-0002")


def test_sync_tasks_supersedes_task_records_after_a_policy_bump(tmp_path):
    """A policy bump changes every record's policy hash, so the published
    record no longer matches the lock. Publication must move each Issue to a
    new generation instead of leaving it unclaimable forever."""
    root = make_project(tmp_path / "proj")
    cfg, _ = load_project(root)
    github = FakeGitHub()
    first = sync_tasks(github, root, cfg, target=None)
    assert first.created == ("port-0001", "port-0002")
    stale = parse_trusted_task_record(list(github.list_comments(1)), 99)

    cfg["policy"]["protected_paths"] = list(cfg["policy"]["protected_paths"]) + ["docs"]
    save_project(cfg, root / "recomp.toml")
    lock = bump_policy(root)
    assert lock["policy_version"] == 2

    github.set_issue_labels(1, ["recomp-task", "claimed"])

    second = sync_tasks(github, root, cfg, target=None)
    assert second.created == ("port-0001", "port-0002")
    assert second.existing == ()
    assert len(github.issues) == 2
    current = parse_trusted_task_record(list(github.list_comments(1)), 99)
    assert current.policy_hash != stale.policy_hash
    assert current.policy_hash.hex == lock["hash"]
    assert current.generation == stale.generation + 1
    assert [label["name"] for label in github.issues[0]["labels"]] == ["recomp-task", "open"]


def test_sync_tasks_still_demands_a_target_when_one_is_pinned(project):
    from recomp.github_tasks import GitHubTaskError

    cfg, _ = load_project(project.path)
    with pytest.raises(GitHubTaskError, match="needs --target"):
        sync_tasks(FakeGitHub(viewer_id=0), project.path, cfg, target=None)


# contributor CLI -----------------------------------------------------------
def test_require_target_is_a_noop_for_a_targetless_record():
    record = TaskRecord.from_mapping(record_mapping())
    assert _require_target(None, record) is None
    assert _require_target("/not/read", record) is None

    pinned = TaskRecord.from_mapping(record_mapping(target_sha256="b" * 64))
    with pytest.raises(TaskCliError, match="--target"):
        _require_target(None, pinned)


def test_task_context_tolerates_a_missing_target_sha256(tmp_path):
    from recomp.task_cli import CONTEXT_SCHEMA, TaskContext

    context = TaskContext(
        schema=CONTEXT_SCHEMA, owner="acme", repository="port", issue_number=1,
        task_id="port-0001", task_generation=1, lease_generation=1,
        branch="recomp/port-0001-1", policy_hash="c" * 64, toolchain_digest="a" * 64,
        image=IMAGE)
    assert context.target_sha256 is None
    context.save(tmp_path)
    stored = json.loads((tmp_path / ".recomp/task.json").read_text())
    assert stored["target_sha256"] is None
    del stored["target_sha256"]
    (tmp_path / ".recomp/task.json").write_text(json.dumps(stored))
    assert TaskContext.load(tmp_path) == context


def test_run_works_without_a_target(tmp_path, monkeypatch):
    from recomp import task_cli

    project = tmp_path / "checkout"
    (project / ".recomp").mkdir(parents=True)
    record = TaskRecord.from_mapping(record_mapping())
    context = task_cli.TaskContext(
        schema=task_cli.CONTEXT_SCHEMA, owner="acme", repository="port", issue_number=1,
        task_id="port-0001", task_generation=1, lease_generation=1,
        branch="recomp/port-0001-1", policy_hash="c" * 64, toolchain_digest="a" * 64,
        image=IMAGE)
    context.save(project)

    lease = type("Lease", (), {"claimant_id": 7, "generation": 1,
                               "is_live": lambda self, now: True,
                               "phase": "claimed", "expires_at": 9999})()
    monkeypatch.setattr(task_cli, "_validated_context", lambda *a, **k: (context, record, lease))

    seen = []

    def launch(arguments, *, target, project):
        seen.append((tuple(arguments), target))
        return 0

    out = task_cli.cmd_run(None, project, None, 99, 0, launch, "plugin-run")
    assert "port-0001" in out
    assert seen == [(("plugin-run", "port-0001"), None)]


# toolchain -----------------------------------------------------------------
def test_run_toolchain_mounts_no_target_when_there_is_none(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    runtime = FakeRuntime()
    assert run_toolchain(runtime, ImageRef.parse(IMAGE), project, None,
                         ["plugin", "run-task", "port-0001"]) == 0
    assert not any("/recomp/target" in item for item in runtime.argv)
    assert not any(item.startswith("--env=RECOMP_TARGET") for item in runtime.argv)
    assert f"{project}:/workspace:rw" in runtime.argv


# contributor doctor --------------------------------------------------------
def doctor_report(root: Path, **overrides):
    settings = {
        "platform": "linux",
        "platform_release": "6.8.0",
        "python_version": (3, 12, 0),
        "version": lambda program: "2.43.0",
        "lookup": lambda program: "/usr/bin/docker" if program == "docker" else None,
        "server_version": lambda runtime: "25.0.3",
        "image_digest": lambda runtime, image: image.digest,
        "policy_status": lambda path: ("current", {"policy_version": 1}),
        "workspace": lambda path: WorkspaceStatus(True, ("origin",), True),
        "disk_free": lambda path: 100 << 30,
    }
    settings.update(overrides)
    return contributor_doctor(root, **settings)


def test_doctor_greenlights_a_targetless_project_with_no_target_flag(tmp_path):
    root = make_project(tmp_path / "proj")
    report = doctor_report(root)
    finding = report.finding("target")
    assert finding.severity == "ok"
    assert "pins no target binary" in finding.observed
    assert finding.remediation == ""
    assert report.ok
    assert render_text(report).strip().splitlines()[-1] == "GREENLIGHT"


def test_doctor_still_blocks_a_pinned_project_without_a_copy(project):
    report = doctor_report(project.path)
    assert report.finding("target").severity == "error"
    assert not report.ok
    assert render_text(report).strip().splitlines()[-1].startswith("BLOCKED")


# coordinator ---------------------------------------------------------------
def test_load_wiring_needs_no_target_for_a_targetless_project(tmp_path, monkeypatch):
    from recomp import coordinator_run
    from recomp.coordinator_setup import CoordinatorPaths, write_coordinator_config

    root = make_project(tmp_path / "proj")
    paths = CoordinatorPaths.for_repository("acme", "port", home=tmp_path)
    write_coordinator_config(paths, {
        "owner": "acme", "repository": "port", "app_id": 1, "installation_id": 2,
        "trusted_actor_id": 99, "image": IMAGE, "project_root": str(root),
    })
    paths.app_key.write_text("-----BEGIN PRIVATE KEY-----\n")
    paths.app_key.chmod(0o600)
    monkeypatch.setattr(coordinator_run, "load_pinned_config", lambda path: {})
    monkeypatch.setattr(coordinator_run, "FirecrackerRunner", lambda config: object())

    wiring = coordinator_run.load_wiring(owner="acme", repository="port", home=tmp_path,
                                         environ={})
    assert wiring.target is None
    assert wiring.coordinator.target is None
    assert wiring.coordinator.config.protected_paths == tuple(PROTECTED)


# preflight -----------------------------------------------------------------
def entry(path="recovery/ports/md5.json", **overrides):
    values = {"path": path, "status": "added", "mode": "100644", "kind": "blob",
              "sha": "c" * 40, "size": 12, "prefix": b'{"unit":1}\n',
              "media_type": "application/json"}
    values.update(overrides)
    return TreeEntry(**values)


def facts(**overrides):
    values = {"author_id": 7, "head_sha": "a" * 40, "base_sha": "b" * 40,
              "base_repository": "acme/port", "expected_repository": "acme/port",
              "referenced_issue_numbers": (1,), "task_issue_number": 1,
              "lease_claimant_id": 7, "lease_generation": 1, "lease_expires_at": 100,
              "now": 50, "task_generation": 1, "policy_hash": Sha256("c" * 64),
              "toolchain_digest": Sha256("a" * 64), "tree_truncated": False}
    values.update(overrides)
    return PullRequestFacts(**values)


def test_project_protected_paths_are_read_from_the_policy_table(tmp_path):
    root = make_project(tmp_path / "proj")
    cfg, _ = load_project(root)
    assert protected_paths(cfg) == tuple(PROTECTED)
    bare, _ = load_project(make_project(tmp_path / "bare", policy=None))
    assert protected_paths(bare) == ()


@pytest.mark.parametrize("path", ["goldens/port-0001.json", "reference/harness/common.hpp",
                                  "tools/mint_goldens.py", "scripts/run.sh"])
def test_declared_protected_paths_produce_the_protected_path_finding(path):
    record = TaskRecord.from_mapping(record_mapping())
    entries = [entry(), entry(path, sha="d" * 40)]
    assert "protected-path" not in check_preflight(record, facts(), entries).codes
    assert "protected-path" in check_preflight(
        record, facts(), entries, protected_paths=PROTECTED).codes


def test_builtin_protected_paths_survive_a_declared_list():
    record = TaskRecord.from_mapping(record_mapping())
    entries = [entry(), entry("recomp.toml", sha="d" * 40)]
    assert "protected-path" in check_preflight(
        record, facts(), entries, protected_paths=["goldens/"]).codes


def test_declared_single_files_are_protected_too():
    record = TaskRecord.from_mapping(record_mapping())
    entries = [entry(), entry("Cargo.lock", sha="d" * 40)]
    assert "protected-path" not in check_preflight(record, facts(), entries).codes
    assert "protected-path" in check_preflight(
        record, facts(), entries, protected_paths=["Cargo.lock"]).codes


def test_declared_paths_never_touch_the_declared_outputs():
    record = TaskRecord.from_mapping(record_mapping())
    report = check_preflight(record, facts(), [entry()], protected_paths=["recovery/ports/"])
    assert "protected-path" in report.codes

    clean = check_preflight(record, facts(), [entry()], protected_paths=PROTECTED)
    assert clean.passed


def test_preflight_action_reads_declared_paths(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "recomp_preflight_action",
        Path(__file__).resolve().parents[1] / ".github/actions/recomp-preflight/action.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module._protected_paths({"INPUT_PROTECTED_PATHS": "goldens/, tools/\nreference/"}) == (
        "goldens/", "tools/", "reference/")
    root = make_project(tmp_path / "proj")
    assert module._protected_paths({"GITHUB_WORKSPACE": str(root)}) == tuple(PROTECTED)
    assert module._protected_paths({}) == ()


# generator -----------------------------------------------------------------
def test_generate_writes_no_target_table_and_records_protected_paths(tmp_path):
    from recomp.generate import generate_project

    generated = generate_project(
        tmp_path / "proj", None, name="port",
        toolchain_image=IMAGE, framework_action="acme/recomp@" + "b" * 40,
        protected_paths=PROTECTED)
    text = (generated.path / "recomp.toml").read_text()
    assert "[target]" not in text
    cfg, _ = load_project(generated.path)
    assert has_target(cfg) is False
    assert protected_paths(cfg) == tuple(PROTECTED)
    workflow = (generated.path / ".github/workflows/recomp-preflight.yml").read_text()
    assert 'protected-paths: "goldens/,reference/,tools/,scripts/"' in workflow
    assert "__RECOMP_PROTECTED_PATHS__" not in workflow


def test_cli_init_no_target(tmp_path, capsys):
    from recomp import cli

    args = cli.build_parser().parse_args([
        "init", str(tmp_path / "proj"), "--no-target",
        "--toolchain-image", IMAGE,
        "--framework-action", "acme/recomp@" + "b" * 40,
        "--protected-path", "goldens/", "--protected-path", "tools/"])
    assert args.func(args) == 0
    out = capsys.readouterr().out
    assert "--target" not in out
    cfg, _ = load_project(tmp_path / "proj")
    assert has_target(cfg) is False
    assert protected_paths(cfg) == ("goldens/", "tools/")


def test_cli_init_rejects_contradictory_target_flags(tmp_path, fixture_bin, capsys):
    from recomp import cli

    parser = cli.build_parser()
    args = parser.parse_args([
        "init", str(tmp_path / "a"), "--no-target", "--bin", str(fixture_bin),
        "--toolchain-image", IMAGE, "--framework-action", "acme/recomp@" + "b" * 40])
    assert args.func(args) == 1
    assert "mutually exclusive" in capsys.readouterr().err

    args = parser.parse_args([
        "init", str(tmp_path / "b"),
        "--toolchain-image", IMAGE, "--framework-action", "acme/recomp@" + "b" * 40])
    assert args.func(args) == 1
    assert "--no-target" in capsys.readouterr().err
