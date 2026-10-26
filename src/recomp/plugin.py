"""Project-local plugins: manifests, resolution, and a sandboxed JSON-command runner.

Plugins are how a host's agent extends the workflow. They live in the project
(``plugins/<name>/recomp.plugin.toml``) and shadow built-ins by name. Commands
are argv lists executed with rlimits, a scrubbed environment, no shell, and a
JSON stdin/stdout protocol.

Sandbox strength by trust tier:
  solo/invited -> this module's process sandbox (rlimits, clean env, timeout)
  public       -> run inside a disposable microVM instead (roadmap; same protocol)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import subprocess
from dataclasses import dataclass
from pathlib import Path

MANIFEST_NAME = "recomp.plugin.toml"

CAPABILITIES = {"detect", "scan", "extract", "toolchain", "work", "verify", "port"}
REQUIRED_COMMANDS = {
    "detect": ("detect",),
    "work": ("work_plan", "run_task"),
    "verify": ("verify",),
}
ALLOWED_INTERPRETERS = {"python3", "python"}

MAX_OUTPUT_BYTES = 1 << 20
MAX_INPUT_BYTES = 1 << 20


class PluginError(Exception):
    pass


VERIFY_MODES = {"static", "bytematch", "behavioral"}
VERIFY_ARGV_KEYS = ("candidate_build", "candidate_run", "oracle_run")


@dataclass(frozen=True)
class VerifyManifest:
    """The trusted `[verify]` contract: how this plugin can be judged publicly."""

    mode: str
    public: bool
    timeout_seconds: int | None
    sandbox_timeout_seconds: int | None
    max_artifact_bytes: int | None
    sandbox_nproc: int | None
    sandbox_memory_mib: int | None
    commands: dict[str, tuple[str, ...]]
    protocol: dict


@dataclass
class Plugin:
    name: str
    version: str
    capabilities: list[str]
    commands: dict[str, list[str]]
    verify: VerifyManifest
    root: Path
    manifest_path: Path


def _sandbox_limits(timeout: int, nproc: int, as_mib: int):
    def apply():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CPU, (timeout * 2 + 5, timeout * 2 + 5))
        resource.setrlimit(resource.RLIMIT_AS, (as_mib << 20, as_mib << 20))
        resource.setrlimit(resource.RLIMIT_FSIZE, (16 << 20, 16 << 20))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    return apply

def builtin_plugins_dir() -> Path:
    return Path(__file__).resolve().parent / "builtin_plugins"


def load_plugin(plugin_dir: str | Path) -> Plugin:
    import tomllib

    root = Path(plugin_dir).resolve()
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file():
        raise PluginError(f"{root} has no {MANIFEST_NAME}")
    manifest = tomllib.loads(manifest_path.read_text())

    meta = manifest.get("plugin", {})
    name = meta.get("name", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,31}", name):
        raise PluginError(f"plugin name {name!r} must be 2-32 chars of [a-z0-9-]")

    capabilities = meta.get("capabilities", [])
    if not isinstance(capabilities, list):
        raise PluginError("capabilities must be a list")
    for cap in capabilities:
        if cap not in CAPABILITIES:
            raise PluginError(f"unknown capability {cap!r}; allowed: {sorted(CAPABILITIES)}")

    commands = manifest.get("commands", {})
    for cmd_name, argv in commands.items():
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise PluginError(f"command {cmd_name} must be an argv list of strings, never a shell string")
        if argv[0] not in ALLOWED_INTERPRETERS:
            raise PluginError(f"command {cmd_name}: interpreter {argv[0]!r} not allowed "
                              f"(use one of {sorted(ALLOWED_INTERPRETERS)})")

    for cap, required in REQUIRED_COMMANDS.items():
        if cap in capabilities:
            for cmd_name in required:
                if cmd_name not in commands:
                    raise PluginError(f"capability {cap!r} requires command {cmd_name!r}")

    verify = _parse_verify(manifest)
    return Plugin(name=name, version=str(meta.get("version", "0")),
                  capabilities=capabilities, commands=commands,
                  verify=verify,
                  root=root, manifest_path=manifest_path)


def _parse_verify(manifest: dict) -> VerifyManifest:
    table = manifest.get("verify", {})
    if not isinstance(table, dict):
        raise PluginError("[verify] must be a table")
    mode = table.get("mode", "static")
    if mode not in VERIFY_MODES:
        raise PluginError(f"unknown verify mode {mode!r}; allowed: {sorted(VERIFY_MODES)}")
    if "candidate_reads_target" in table and table.get("public"):
        raise PluginError("a public plan may not co-locate the candidate and the target")
    commands = {}
    for key in VERIFY_ARGV_KEYS:
        if key not in table:
            continue
        argv = table[key]
        if (not isinstance(argv, list) or not argv
                or not all(isinstance(item, str) and item for item in argv)):
            raise PluginError(f"[verify] {key} must be an argv list, never a shell string")
        if argv[0] not in ALLOWED_INTERPRETERS:
            raise PluginError(f"[verify] {key}: interpreter {argv[0]!r} not allowed")
        commands[key] = tuple(argv)
    for key in ("timeout_seconds", "max_artifact_bytes"):
        value = table.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0):
            raise PluginError(f"[verify] {key} must be a positive integer")
    sandbox_nproc = table.get("sandbox_nproc")
    if sandbox_nproc is not None and (isinstance(sandbox_nproc, bool)
            or not isinstance(sandbox_nproc, int) or not 32 <= sandbox_nproc <= 4096):
        raise PluginError("[verify] sandbox_nproc must be an integer in [32, 4096]")
    sandbox_timeout = table.get("sandbox_timeout_seconds")
    if sandbox_timeout is not None and (isinstance(sandbox_timeout, bool)
            or not isinstance(sandbox_timeout, int) or not 5 <= sandbox_timeout <= 1800):
        raise PluginError("[verify] sandbox_timeout_seconds must be an integer in [5, 1800]")
    sandbox_memory = table.get("sandbox_memory_mib")
    if sandbox_memory is not None and (isinstance(sandbox_memory, bool)
            or not isinstance(sandbox_memory, int) or not 128 <= sandbox_memory <= 4096):
        raise PluginError("[verify] sandbox_memory_mib must be an integer in [128, 4096]")
    protocol = table.get("protocol", {})
    if not isinstance(protocol, dict):
        raise PluginError("[verify.protocol] must be a table")
    return VerifyManifest(
        mode=mode,
        public=bool(table.get("public", False)),
        timeout_seconds=table.get("timeout_seconds"),
        sandbox_timeout_seconds=sandbox_timeout,
        max_artifact_bytes=table.get("max_artifact_bytes"),
        sandbox_nproc=sandbox_nproc,
        sandbox_memory_mib=sandbox_memory,
        commands=commands,
        protocol=dict(protocol),
    )


def resolve_plugin(project_root: str | Path, name: str) -> Plugin:
    local = Path(project_root) / "plugins" / name
    if (local / MANIFEST_NAME).is_file():
        return load_plugin(local)
    builtin = builtin_plugins_dir() / name
    if (builtin / MANIFEST_NAME).is_file():
        return load_plugin(builtin)
    raise PluginError(f"plugin {name!r} not found in project plugins/ or built-ins")


def plugin_file_hashes(plugin: Plugin) -> dict[str, str]:
    out = {}
    for path in sorted(plugin.root.rglob("*")):
        if path.is_dir() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        out[path.relative_to(plugin.root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def run_plugin(plugin: Plugin, command: str, payload: dict, timeout: int = 30) -> dict:
    if command not in plugin.commands:
        raise PluginError(f"plugin {plugin.name} has no command {command!r}")
    argv = plugin.commands[command]
    stdin_data = json.dumps(payload)
    if len(stdin_data.encode()) > MAX_INPUT_BYTES:
        raise PluginError("plugin payload too large")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C",
           "TMPDIR": "/tmp", "HOME": str(plugin.root)}
    for key in ("RUSTUP_HOME", "CARGO_HOME", "RUSTUP_TOOLCHAIN"):
        if key in os.environ:
            env[key] = os.environ[key]
    try:
        proc = subprocess.run(
            argv, cwd=plugin.root, input=stdin_data, capture_output=True,
            text=True, timeout=timeout, env=env,
            preexec_fn=_sandbox_limits(timeout, plugin.verify.sandbox_nproc or 512,
                                       plugin.verify.sandbox_memory_mib or 512),
        )
    except subprocess.TimeoutExpired:
        raise PluginError(f"plugin command {command!r} timeout after {timeout}s") from None
    except FileNotFoundError as e:
        raise PluginError(f"plugin command failed to start: {e}") from None
    if len(proc.stdout.encode() or b"") > MAX_OUTPUT_BYTES:
        raise PluginError("plugin output too large")
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()[-400:]
        raise PluginError(f"plugin command {command!r} exited {proc.returncode}: {detail}")
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise PluginError(f"plugin command {command!r} did not emit JSON") from None
    if not isinstance(result, dict):
        raise PluginError(f"plugin command {command!r} must emit a JSON object")
    return result


def command_timeout(plugin: Plugin) -> int:
    """Wall-clock budget for a host-run task command: sandbox override first."""
    return plugin.verify.sandbox_timeout_seconds or plugin.verify.timeout_seconds or 30
