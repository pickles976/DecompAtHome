import json
import tomllib

import pytest

from recomp.plugin import PluginError, builtin_plugins_dir, load_plugin, resolve_plugin, run_plugin


def test_loads_valid_builtin_plugin():
    p = load_plugin(builtin_plugins_dir() / "generic")
    assert p.name == "generic"
    assert "work" in p.capabilities
    assert "verify" in p.capabilities


def test_project_plugins_shadow_builtins(project):
    import shutil
    dest = project.path / "plugins" / "myengine"
    shutil.copytree(builtin_plugins_dir() / "generic", dest)
    manifest = dest / "recomp.plugin.toml"
    manifest.write_text(manifest.read_text().replace('name = "generic"', 'name = "myengine"'))
    assert resolve_plugin(project.path, "myengine").root == dest.resolve()
    assert resolve_plugin(project.path, "generic").root == (project.path / "plugins" / "generic").resolve()


def test_invalid_capability_rejected(tmp_path):
    d = tmp_path / "bad"
    d.mkdir()
    (d / "recomp.plugin.toml").write_text(
        '[plugin]\nname = "bad"\nversion = "0.1.0"\ncapabilities = ["teleport"]\n'
    )
    with pytest.raises(PluginError, match="capability"):
        load_plugin(d)


def test_shell_strings_in_commands_rejected(tmp_path):
    d = tmp_path / "shelly"
    d.mkdir()
    (d / "recomp.plugin.toml").write_text(
        '[plugin]\nname = "shelly"\nversion = "0.1.0"\ncapabilities = ["detect"]\n\n'
        '[commands]\ndetect = "python3 runner.py detect"\n'
    )
    with pytest.raises(PluginError, match="argv"):
        load_plugin(d)


def test_missing_command_for_capability_rejected(tmp_path):
    d = tmp_path / "incomplete"
    d.mkdir()
    (d / "recomp.plugin.toml").write_text(
        '[plugin]\nname = "incomplete"\nversion = "0.1.0"\ncapabilities = ["verify"]\n\n'
        '[commands]\ndetect = ["python3", "runner.py", "detect"]\n'
    )
    with pytest.raises(PluginError, match="verify"):
        load_plugin(d)


def _task_with_strings(p, fixture_bin):
    """Claim-agnostic: find a work item whose chunk actually contains strings."""
    plan = run_plugin(p, "work_plan", {"binary": str(fixture_bin), "size": fixture_bin.stat().st_size})
    assert plan["tasks"], "work plan must produce tasks"
    for task in plan["tasks"]:
        out = run_plugin(
            p, "run_task",
            {"binary": str(fixture_bin), "args": task["args"], "outputs": task["outputs"]},
        )
        doc = json.loads(next(iter(out["files"].values())))
        if doc["strings"]:
            return task, out
    raise AssertionError("fixture produced no string-bearing chunk")


def test_run_plugin_json_roundtrip(project, fixture_bin):
    p = resolve_plugin(project.path, "generic")
    task, out = _task_with_strings(p, fixture_bin)
    assert out["files"]
    verdict = run_plugin(
        p, "verify",
        {"binary": str(fixture_bin), "args": task["args"],
         "outputs": task["outputs"], "files": out["files"]},
    )
    assert verdict["pass"] is True


def test_run_plugin_verify_rejects_tampered_output(project, fixture_bin):
    p = resolve_plugin(project.path, "generic")
    task, out = _task_with_strings(p, fixture_bin)
    path = next(iter(out["files"]))
    doc = json.loads(out["files"][path])
    doc["strings"][0]["text"] = "TAMPERED"
    out["files"][path] = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    verdict = run_plugin(
        p, "verify",
        {"binary": str(fixture_bin), "args": task["args"],
         "outputs": task["outputs"], "files": out["files"]},
    )
    assert verdict["pass"] is False


def test_generic_work_plan_declares_bounded_public_outputs(project, fixture_bin):
    plugin = resolve_plugin(project.path, "generic")
    plan = run_plugin(
        plugin, "work_plan",
        {"binary": str(fixture_bin), "size": fixture_bin.stat().st_size},
    )
    task = plan["tasks"][0]
    assert task["args"] == {"offset": 0, "length": 64}
    assert task["outputs"] == [{
        "path": "recovery/strings/strings-0000.json",
        "media_type": "application/json",
        "max_bytes": 65536,
    }]
    assert task["weight"] == 64


def test_generic_manifest_declares_public_static_verification():
    manifest_path = builtin_plugins_dir() / "generic" / "recomp.plugin.toml"
    verify = tomllib.loads(manifest_path.read_text())["verify"]
    assert verify == {
        "mode": "static",
        "public": True,
        "timeout_seconds": 30,
        "max_artifact_bytes": 1048576,
    }


def test_plugin_new_scaffold_loads_with_complete_private_verify_table(tmp_path):
    from recomp import templates

    d = tmp_path / "scaffold"
    d.mkdir()
    (d / "recomp.plugin.toml").write_text(templates.plugin_manifest("scratchplug", "detect"))
    (d / "runner.py").write_text(templates.plugin_runner())

    plugin = load_plugin(d)
    assert plugin.name == "scratchplug"

    verify = tomllib.loads((d / "recomp.plugin.toml").read_text())["verify"]
    assert set(verify) == {"mode", "public", "timeout_seconds", "max_artifact_bytes"}
    assert verify["public"] is False
    assert verify["mode"] == "static"
    assert verify["timeout_seconds"] == 30
    assert verify["max_artifact_bytes"] == 1048576
    assert plugin.verify.public is False
    assert plugin.verify.timeout_seconds == 30
    assert plugin.verify.max_artifact_bytes == 1048576


def test_plugin_new_scaffold_stubs_name_payload_keys_and_result_shape():
    from recomp import templates

    source = templates.plugin_runner()
    for marker in ("p['binary']", "p['args']", "p['outputs']", "p['files']",
                   "{'files': {<path>: <content string>}}",
                   "{'pass': bool, 'evidence': {...}}"):
        assert marker in source


def test_runner_times_out(project):
    d = project.path / "plugins" / "sleeper"
    d.mkdir(parents=True)
    (d / "recomp.plugin.toml").write_text(
        '[plugin]\nname = "sleeper"\nversion = "0.1.0"\ncapabilities = ["detect"]\n\n'
        '[commands]\ndetect = ["python3", "runner.py", "detect"]\n'
    )
    (d / "runner.py").write_text(
        "import json, sys, time\n"
        "json.load(sys.stdin)\n"
        "time.sleep(30)\n"
    )
    p = load_plugin(d)
    with pytest.raises(PluginError, match="timeout"):
        run_plugin(p, "detect", {"binary": "x"}, timeout=2)
