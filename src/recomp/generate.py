"""`recomp init`: scaffold a runnable decomp-collaboration project."""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path

from recomp import templates
from recomp.detect import detect_path
from recomp.plugin import builtin_plugins_dir
from recomp.policy import bump_policy


@dataclass
class GeneratedProject:
    path: Path


GOAL_TIERS = {
    "assets": "t0-assets",
    "structure": "t1-structure",
    "recomp": "t2-recomp",
    "bytematch": "t3-bytematch",
}


def generate_project(dest: str | Path, bin_path: str | Path, name: str | None = None,
                     goal: str = "structure", trust: str = "invited",
                     assets: list[str] | None = None, port_target: str | None = None,
                     toolchain: str | None = None, plugin: str = "generic") -> GeneratedProject:
    dest = Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise FileExistsError(f"{dest} is not empty")
    dest.mkdir(parents=True)

    binary = Path(bin_path).resolve()
    if not binary.is_file():
        raise FileNotFoundError(binary)
    name = name or binary.stem.lower().replace(" ", "-")
    if goal not in GOAL_TIERS:
        raise ValueError(f"goal must be one of {sorted(GOAL_TIERS)}")
    tier = GOAL_TIERS[goal]
    if goal == "bytematch" and not toolchain:
        raise ValueError("goal 'bytematch' needs --toolchain (e.g. msvc-7.1); "
                         "byte-match requires a pinned original toolchain")

    detection = detect_path(binary, toolchain=toolchain)
    sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()

    bin_dir = dest / "bin"
    bin_dir.mkdir()
    shutil.copy2(binary, bin_dir / binary.name)

    plugins_dir = dest / "plugins"
    shutil.copytree(builtin_plugins_dir() / plugin, plugins_dir / plugin)

    recovery = dest / "recovery" / "strings"
    recovery.mkdir(parents=True)

    if port_target:
        port_dir = dest / "port"
        port_dir.mkdir()
        (port_dir / "README.md").write_text(
            f"# {name} — {port_target} port\n\n"
            f"This tree consumes snapshots of `../recovery/`. Ports never share a merge\n"
            f"queue with recovery: the port follows pinned recovery commits only.\n")

    (dest / "server").mkdir()
    (dest / ".gitignore").write_text(
        "bin/\nserver/\n.recomp/\n__pycache__/\n*.pyc\n")

    cfg = {
        "project": {"name": name, "goal": goal, "plugin": plugin, "trust": trust},
        "target": {
            "binary": f"bin/{binary.name}",
            "sha256": sha256,
            "platform": detection.format,
            "arch": detection.arch,
            "engine": detection.engine,
            "tier": tier,
            "toolchain": toolchain or "",
        },
        "assets": {"extract": assets or []},
        "collab": {"mode": ["https"]},
    }
    from recomp.project import save_project
    save_project(cfg, dest / "recomp.toml")

    (dest / "AGENTS.md").write_text(templates.project_agents_md(cfg))
    lock = bump_policy(dest)
    (dest / "PROMPT.md").write_text(render_prompt_static(dest, cfg, lock))
    return GeneratedProject(path=dest)


def render_prompt_static(root: Path, cfg: dict, lock: dict | None = None) -> str:
    from recomp.prompt import render_prompt
    return render_prompt(root, cfg=cfg, lock=lock)


