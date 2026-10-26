import json
import tomllib

import pytest

from recomp.plugin import (PluginError, builtin_plugins_dir, command_timeout, load_plugin,
                           resolve_plugin, run_plugin)


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


PROBE_RUNNER = (
    "import json, os, resource, sys\n"
    "json.load(sys.stdin)\n"
    "print(json.dumps({\n"
    "    'home': os.environ.get('HOME'),\n"
    "    'tmpdir': os.environ.get('TMPDIR'),\n"
    "    'path': os.environ.get('PATH'),\n"
    "    'rustup_home': os.environ.get('RUSTUP_HOME'),\n"
    "    'cargo_home': os.environ.get('CARGO_HOME'),\n"
    "    'rustup_toolchain': os.environ.get('RUSTUP_TOOLCHAIN'),\n"
    "    'nproc': list(resource.getrlimit(resource.RLIMIT_NPROC)),\n"
    "    'as_limit': list(resource.getrlimit(resource.RLIMIT_AS)),\n"
    "}))\n"
)


def _probe_plugin(project, name="probe", verify_lines=""):
    d = project.path / "plugins" / name
    d.mkdir(parents=True)
    (d / "recomp.plugin.toml").write_text(
        f'[plugin]\nname = "{name}"\nversion = "0.1.0"\ncapabilities = ["detect"]\n\n'
        '[commands]\ndetect = ["python3", "runner.py", "detect"]\n'
        + verify_lines
    )
    (d / "runner.py").write_text(PROBE_RUNNER)
    return load_plugin(d)


def _verify_only_plugin(tmp_path, name, verify_lines):
    d = tmp_path / name
    d.mkdir()
    (d / "recomp.plugin.toml").write_text(
        f'[plugin]\nname = "{name}"\nversion = "0.1.0"\ncapabilities = ["detect"]\n\n'
        '[commands]\ndetect = ["python3", "runner.py", "detect"]\n\n'
        + verify_lines
    )
    return load_plugin(d)


def test_verify_sandbox_nproc_parses_into_manifest(tmp_path):
    plugin = _verify_only_plugin(tmp_path, "nprocok", "[verify]\nsandbox_nproc = 128\n")
    assert plugin.verify.sandbox_nproc == 128


@pytest.mark.parametrize("value", ["8", "99999", "true", '"lots"'])
def test_verify_sandbox_nproc_rejects_bad_values(tmp_path, value):
    with pytest.raises(PluginError, match="sandbox_nproc"):
        _verify_only_plugin(tmp_path, "nprocbad", f"[verify]\nsandbox_nproc = {value}\n")


def test_run_plugin_env_sets_home_and_propagates_rust_toolchain_vars(project, monkeypatch):
    monkeypatch.setenv("RUSTUP_HOME", "/opt/rustup")
    monkeypatch.setenv("CARGO_HOME", "/opt/cargo")
    monkeypatch.setenv("RUSTUP_TOOLCHAIN", "1.82.0")
    plugin = _probe_plugin(project)
    observed = run_plugin(plugin, "detect", {"binary": "x"})
    assert observed["home"] == str(plugin.root)
    assert observed["tmpdir"] == "/tmp"
    assert observed["path"]
    assert observed["rustup_home"] == "/opt/rustup"
    assert observed["cargo_home"] == "/opt/cargo"
    assert observed["rustup_toolchain"] == "1.82.0"
    assert observed["nproc"] == [512, 512]


def test_run_plugin_omits_rust_toolchain_vars_when_absent(project, monkeypatch):
    for key in ("RUSTUP_HOME", "CARGO_HOME", "RUSTUP_TOOLCHAIN"):
        monkeypatch.delenv(key, raising=False)
    plugin = _probe_plugin(project, name="scrubbed")
    observed = run_plugin(plugin, "detect", {"binary": "x"})
    assert observed["home"] == str(plugin.root)
    assert observed["rustup_home"] is None
    assert observed["cargo_home"] is None
    assert observed["rustup_toolchain"] is None


def test_run_plugin_applies_manifest_sandbox_nproc_as_rlimit(project):
    plugin = _probe_plugin(project, name="roomy", verify_lines="\n[verify]\nsandbox_nproc = 64\n")
    observed = run_plugin(plugin, "detect", {"binary": "x"})
    assert observed["nproc"] == [64, 64]


def test_verify_sandbox_memory_mib_parses_into_manifest(tmp_path):
    plugin = _verify_only_plugin(
        tmp_path, "memok", "[verify]\nsandbox_memory_mib = 2048\n")
    assert plugin.verify.sandbox_memory_mib == 2048


@pytest.mark.parametrize("value", ["0", "127", "4097", "true", '"big"'])
def test_verify_sandbox_memory_mib_rejects_bad_values(tmp_path, value):
    with pytest.raises(PluginError, match="sandbox_memory_mib"):
        _verify_only_plugin(
            tmp_path, "membad", f"[verify]\nsandbox_memory_mib = {value}\n")


def test_run_plugin_applies_default_and_manifest_sandbox_memory_as_rlimit(project):
    observed = run_plugin(_probe_plugin(project, name="asdefault"), "detect", {"binary": "x"})
    assert observed["as_limit"] == [512 << 20, 512 << 20]
    roomy = _probe_plugin(project, name="asroomy",
                         verify_lines="\n[verify]\nsandbox_memory_mib = 3072\n")
    observed = run_plugin(roomy, "detect", {"binary": "x"})
    assert observed["as_limit"] == [3072 << 20, 3072 << 20]


def test_verify_sandbox_timeout_seconds_parses(tmp_path):
    plugin = _verify_only_plugin(
        tmp_path, "slowverify", "[verify]\ntimeout_seconds = 30\nsandbox_timeout_seconds = 600\n")
    assert plugin.verify.sandbox_timeout_seconds == 600
    assert plugin.verify.timeout_seconds == 30


@pytest.mark.parametrize("value", ["4", "1801", "0", "true"])
def test_verify_sandbox_timeout_seconds_rejects_bad_values(tmp_path, value):
    with pytest.raises(PluginError, match="sandbox_timeout_seconds"):
        _verify_only_plugin(
            tmp_path, "badtimeout", f"[verify]\nsandbox_timeout_seconds = {value}\n")


def test_command_timeout_prefers_sandbox_timeout_seconds(tmp_path):
    plugin = _verify_only_plugin(
        tmp_path, "cli1", "[verify]\ntimeout_seconds = 30\nsandbox_timeout_seconds = 600\n")
    assert command_timeout(plugin) == 600


def test_command_timeout_falls_back_to_verify_timeout_seconds(tmp_path):
    plugin = _verify_only_plugin(tmp_path, "cli2", "[verify]\ntimeout_seconds = 120\n")
    assert command_timeout(plugin) == 120


def test_command_timeout_defaults_to_thirty(tmp_path):
    plugin = _verify_only_plugin(tmp_path, "cli3", '[verify]\nmode = "static"\n')
    assert command_timeout(plugin) == 30
