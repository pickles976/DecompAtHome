import json
import threading
import time

import subprocess
import urllib.error
import urllib.request

import pytest


def call(base, method, path, body=None, key=None):
    req = urllib.request.Request(base + path, method=method)
    if key:
        req.add_header("Authorization", "Bearer " + key)
    data = json.dumps(body).encode() if body is not None else None
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, data=data) as resp:
        return resp.status, json.loads(resp.read().decode())


@pytest.fixture
def server(project):
    from recomp.server import RecompServer
    srv = RecompServer(project.path, host="127.0.0.1", port=0)
    base = srv.start_background()
    yield srv, base
    srv.stop()


def enroll_worker(base, srv, name):
    _, tok = call(base, "POST", "/api/admin/keys", {"action": "mint-token"}, key=srv.owner_key)
    _, enrolled = call(base, "POST", "/api/enroll", {"token": tok["token"], "name": name})
    return enrolled["key"]


def do_submission(base, key, fixture_bin, project):
    from recomp.plugin import resolve_plugin, run_plugin
    from recomp.project import load_project
    cfg, _ = load_project(project.path)
    plugin = resolve_plugin(project.path, cfg["project"]["plugin"])
    _, claim = call(base, "POST", "/api/claim", {}, key=key)
    out = run_plugin(plugin, "run_task", {"binary": str(fixture_bin), "args": claim["task"]["args"]})
    return claim, call(base, "POST", "/api/submit", {
        "work_id": claim["work_id"], "generation": claim["generation"],
        "policy_version": claim["policy_version"], "files": out["files"],
    }, key=key)


def test_available_work_expands_seats_and_blocks_surplus_agent(server, project):
    srv, base = server
    _, progress = call(base, "GET", "/api/progress")
    assert progress["open"] > 1
    for index in range(progress["open"]):
        enroll_worker(base, srv, f"worker-{index}")
    with pytest.raises(urllib.error.HTTPError) as exc:
        enroll_worker(base, srv, "surplus")
    assert exc.value.code == 403
    assert b"seats" in exc.value.read()


def test_first_verified_merge_promotes_to_collaborator(server, project, fixture_bin):
    srv, base = server
    key = enroll_worker(base, srv, "alice")
    assert not srv.store.is_trusted(key)
    claim, (status, verdict) = do_submission(base, key, fixture_bin, project)
    assert verdict["status"] == "merged"
    assert srv.store.is_trusted(key), "first verified merge must promote the seat (collaborator)"
    _, prog = call(base, "GET", "/api/progress")
    assert prog["merged"] == 1


def _make_fastbad_plugin(project):
    """Plugin whose verify command always fails; fast_lane=true means trusted
    workers merge optimistically, then async re-verify must revert."""
    manifest = project.path / "plugins" / "generic" / "recomp.plugin.toml"
    manifest.write_text(manifest.read_text() + '\n[verify]\nfast_lane = true\n')
    runner = project.path / "plugins" / "generic" / "runner.py"
    runner.write_text(runner.read_text().replace(
        'def cmd_verify(p):',
        'def cmd_verify(p):\n    raise RuntimeError("verify deliberately fails")'))
    from recomp.policy import bump_policy
    bump_policy(project.path)


def test_fast_lane_merges_then_reverts_and_untrusts(project, fixture_bin):
    from recomp.server import RecompServer
    _make_fastbad_plugin(project)
    srv = RecompServer(project.path, host="127.0.0.1", port=0)
    base = srv.start_background()
    try:
        key = enroll_worker(base, srv, "alice")
        _, tok = call(base, "POST", "/api/admin/keys", {"action": "mint-token"}, key=srv.owner_key)
        srv.store.promote(srv.store.worker_id(key))  # owner trusts alice directly
        claim1, (s1, v1) = do_submission(base, key, fixture_bin, project)
        assert v1["status"] == "merged", "fast lane merges optimistically"
        assert v1["attestation"].get("fast_lane") is True
        out_path = project.path / "recovery" / claim1["task"]["args"]["out"]
        assert out_path.exists()

        reverted = srv.drain_reverify()
        assert reverted >= 1, "failed async verification must revert the merge"
        assert not out_path.exists(), "reverted artifact must be removed"
        assert not srv.store.is_trusted(key), "failed re-verify must untrust the seat"
        _, prog = call(base, "GET", "/api/progress")
        assert prog["merged"] == 0 and prog["open"] >= 1, "item reopens for other agents"
    finally:
        srv.stop()


def test_pending_fast_lane_reverification_survives_server_restart(
        project, fixture_bin):
    from recomp.server import RecompServer
    _make_fastbad_plugin(project)
    first = RecompServer(project.path, host="127.0.0.1", port=0)
    base = first.start_background()
    key = enroll_worker(base, first, "alice")
    first.store.promote(first.store.worker_id(key))
    claim, (_, verdict) = do_submission(base, key, fixture_bin, project)
    assert verdict["status"] == "merged"
    out_path = project.path / "recovery" / claim["task"]["args"]["out"]
    first.stop()
    restarted = RecompServer(project.path, host="127.0.0.1", port=0)
    try:
        assert restarted.drain_reverify() == 1
        assert not out_path.exists()
        assert not restarted.store.is_trusted(key)
    finally:
        restarted.stop()

def test_foreground_server_runs_automatic_fast_lane_reverification(
        project, fixture_bin):
    from recomp.server import RecompServer
    _make_fastbad_plugin(project)
    srv = RecompServer(project.path, host="127.0.0.1", port=0)
    thread = threading.Thread(
        target=srv.serve_forever, kwargs={"host": "127.0.0.1", "port": 0},
        daemon=True)
    thread.start()
    try:
        deadline = time.time() + 2
        while srv._http is None and time.time() < deadline:
            time.sleep(0.01)
        assert srv._http is not None
        base = f"http://127.0.0.1:{srv._http.server_address[1]}"
        key = enroll_worker(base, srv, "alice")
        srv.store.promote(srv.store.worker_id(key))
        claim, (_, verdict) = do_submission(base, key, fixture_bin, project)
        assert verdict["status"] == "merged"
        out_path = project.path / "recovery" / claim["task"]["args"]["out"]
        deadline = time.time() + 5
        while (out_path.exists() or srv.store.is_trusted(key)) and time.time() < deadline:
            time.sleep(0.05)
        assert not out_path.exists(), (
            "foreground `recomp serve` must run deferred re-verification")
        assert not srv.store.is_trusted(key)
    finally:
        srv.stop()
        thread.join(timeout=2)

def test_untrusted_worker_gets_synchronous_verify_even_with_fast_lane(project, fixture_bin):
    from recomp.server import RecompServer
    _make_fastbad_plugin(project)
    srv = RecompServer(project.path, host="127.0.0.1", port=0)
    base = srv.start_background()
    try:
        key = enroll_worker(base, srv, "mallory")
        claim, (status, verdict) = do_submission(base, key, fixture_bin, project)
        assert verdict["status"] == "rejected", "untrusted submissions must pass synchronous verify"
        assert not srv.store.is_trusted(key)
    finally:
        srv.stop()


def test_merge_creates_git_commit(project, fixture_bin):
    from recomp.server import RecompServer
    subprocess.run(["git", "init", "-q"], cwd=project.path, check=True)
    subprocess.run(["git", "config", "user.email", "recomp@localhost"], cwd=project.path, check=True)
    subprocess.run(["git", "config", "user.name", "recomp"], cwd=project.path, check=True)
    srv = RecompServer(project.path, host="127.0.0.1", port=0)
    base = srv.start_background()
    try:
        key = enroll_worker(base, srv, "alice")
        claim, (status, verdict) = do_submission(base, key, fixture_bin, project)
        assert verdict["status"] == "merged"
        log = subprocess.run(["git", "log", "--oneline"], cwd=project.path,
                             capture_output=True, text=True).stdout
        assert f"recomp: merge {claim['work_id']} by alice" in log
        status_out = subprocess.run(["git", "status", "--porcelain", "--", "recovery"],
                                    cwd=project.path, capture_output=True, text=True).stdout
        assert status_out.strip() == "", "merged artifacts must be committed, not left dirty"
    finally:
        srv.stop()
