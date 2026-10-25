import json
import urllib.request

import pytest


def call(base, method, path, body=None, key=None):
    req = urllib.request.Request(base + path, method=method)
    if key:
        req.add_header("Authorization", "Bearer " + key)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
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


def test_health_and_project(server):
    srv, base = server
    status, body = call(base, "GET", "/api/health")
    assert status == 200 and body["ok"]
    _, proj = call(base, "GET", "/api/project")
    assert proj["name"] == "demo"
    assert proj["policy_version"] == 1


def test_full_contribution_loop(server, project, fixture_bin):
    srv, base = server
    owner_key = srv.owner_key
    _, tok = call(base, "POST", "/api/admin/keys", {"action": "mint-token"}, key=owner_key)
    status, enrolled = call(base, "POST", "/api/enroll", {"token": tok["token"], "name": "alice"})
    assert status == 200
    wkey = enrolled["key"]

    status, claim = call(base, "POST", "/api/claim", {}, key=wkey)
    assert status == 200 and claim["work_id"]

    # worker executes the task locally through the project plugin
    from recomp.plugin import resolve_plugin, run_plugin
    from recomp.project import load_project
    cfg, _ = load_project(project.path)
    plugin = resolve_plugin(project.path, cfg["project"]["plugin"])
    out = run_plugin(plugin, "run_task", {"binary": str(fixture_bin), "args": claim["task"]["args"]})

    status, verdict = call(base, "POST", "/api/submit", {
        "work_id": claim["work_id"],
        "generation": claim["generation"],
        "policy_version": claim["policy_version"],
        "files": out["files"],
    }, key=wkey)
    assert status == 200
    assert verdict["status"] == "merged"
    assert verdict["attestation"]["pass"] is True
    assert verdict["attestation"]["policy_version"] == 1

    # artifact landed in recovery/
    out_path = project.path / "recovery" / next(iter(out["files"]))
    assert out_path.exists()

    _, prog = call(base, "GET", "/api/progress")
    assert prog["merged"] == 1


def test_wrong_submission_is_rejected_not_merged(server, project, fixture_bin):
    srv, base = server
    _, tok = call(base, "POST", "/api/admin/keys", {"action": "mint-token"}, key=srv.owner_key)
    _, enrolled = call(base, "POST", "/api/enroll", {"token": tok["token"], "name": "mallory"})
    wkey = enrolled["key"]
    _, claim = call(base, "POST", "/api/claim", {}, key=wkey)
    bad_files = {claim["task"]["args"]["out"]: json.dumps({"strings": ["lies"]})}
    status, verdict = call(base, "POST", "/api/submit", {
        "work_id": claim["work_id"],
        "generation": claim["generation"],
        "policy_version": claim["policy_version"],
        "files": bad_files,
    }, key=wkey)
    assert status == 200
    assert verdict["status"] == "rejected"
    _, prog = call(base, "GET", "/api/progress")
    assert prog["merged"] == 0 and prog["rejected"] == 1
    assert not (project.path / "recovery" / "strings").exists() or not list((project.path / "recovery" / "strings").glob("*.json"))


def test_stale_generation_conflicts(server):
    srv, base = server
    _, tok = call(base, "POST", "/api/admin/keys", {"action": "mint-token"}, key=srv.owner_key)
    _, enrolled = call(base, "POST", "/api/enroll", {"token": tok["token"], "name": "sneaky"})
    wkey = enrolled["key"]
    _, claim = call(base, "POST", "/api/claim", {}, key=wkey)
    with pytest.raises(urllib.error.HTTPError) as exc:
        call(base, "POST", "/api/submit", {
            "work_id": claim["work_id"], "generation": claim["generation"] + 5,
            "policy_version": claim["policy_version"], "files": {},
        }, key=wkey)
    assert exc.value.code == 409


def test_policy_reload_rejects_old_policy_submissions(server, project, fixture_bin):
    srv, base = server
    _, tok = call(base, "POST", "/api/admin/keys", {"action": "mint-token"}, key=srv.owner_key)
    _, enrolled = call(base, "POST", "/api/enroll", {"token": tok["token"], "name": "alice"})
    wkey = enrolled["key"]
    _, claim = call(base, "POST", "/api/claim", {}, key=wkey)

    # host agent modifies the workflow, owner relocks + reloads
    runner = project.path / "plugins" / "generic" / "runner.py"
    runner.write_text(runner.read_text() + "\n# workflow change\n")
    from recomp.policy import bump_policy
    bump_policy(project.path)
    status, reloaded = call(base, "POST", "/api/admin/reload", {}, key=srv.owner_key)
    assert status == 200 and reloaded["policy_version"] == 2

    with pytest.raises(urllib.error.HTTPError) as exc:
        call(base, "POST", "/api/submit", {
            "work_id": claim["work_id"], "generation": claim["generation"],
            "policy_version": 1, "files": {},
        }, key=wkey)
    assert exc.value.code == 412

    # re-claim under the new policy and finish the loop
    _, claim2 = call(base, "POST", "/api/claim", {}, key=wkey)
    assert claim2["policy_version"] == 2


def test_worker_role_cannot_call_admin(server):
    srv, base = server
    _, tok = call(base, "POST", "/api/admin/keys", {"action": "mint-token"}, key=srv.owner_key)
    _, enrolled = call(base, "POST", "/api/enroll", {"token": tok["token"], "name": "eve"})
    with pytest.raises(urllib.error.HTTPError) as exc:
        call(base, "POST", "/api/admin/keys", {"action": "mint-token"}, key=enrolled["key"])
    assert exc.value.code == 403


def test_dashboard_served(server):
    srv, base = server
    req = urllib.request.Request(base + "/")
    with urllib.request.urlopen(req) as resp:
        body = resp.read().decode()

    assert "recomp" in body.lower()


def test_server_serves_rendered_prompt(server):
    srv, base = server
    _, payload = call(base, "GET", "/api/prompt")
    assert "demo" in payload["prompt"]
    assert base in payload["prompt"]
