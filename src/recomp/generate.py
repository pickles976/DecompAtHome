"""`recomp init`: scaffold a GitHub-coordinated recovery repository.

The generated repository contains no target bytes and no runtime secrets. The
target is pinned by filename, size, and sha256; every contributor supplies
their own copy. Coordination state lives in GitHub, not in the tree.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from recomp import templates
from recomp.contracts import ImageRef
from recomp.detect import detect_path
from recomp.plugin import builtin_plugins_dir
from recomp.policy import bump_policy
from recomp.progress import ProgressSnapshot, render_progress_json, render_progress_svg

GOAL_TIERS = {
    "assets": "t0-assets",
    "structure": "t1-structure",
    "recomp": "t2-recomp",
    "bytematch": "t3-bytematch",
}
_ACTION_RE = re.compile(r"([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)@([0-9a-f]{40})")
_READ_CHUNK = 1 << 20


@dataclass
class GeneratedProject:
    path: Path


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_READ_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _render(text: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def generate_project(
    dest: str | Path,
    bin_path: str | Path | None = None,
    *,
    toolchain_image: str,
    framework_action: str,
    name: str | None = None,
    owner: str = "OWNER",
    repository: str | None = None,
    goal: str = "structure",
    assets: list[str] | None = None,
    port_target: str | None = None,
    toolchain: str | None = None,
    plugin: str = "generic",
    trusted_actor_id: int = 0,
    protected_paths: list[str] | None = None,
) -> GeneratedProject:
    """Create a repository that coordinates on GitHub.

    A project either pins a target binary by hash or declares none at all; a
    targetless project ports from sources the contributors already hold.
    """

    dest = Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise FileExistsError(f"{dest} is not empty")

    target = Path(bin_path).resolve() if bin_path is not None else None
    if target is not None and not target.is_file():
        raise FileNotFoundError(target)
    try:
        image = ImageRef.parse(toolchain_image)
    except ValueError as exc:
        raise ValueError(
            "--toolchain-image must be digest-pinned, e.g. "
            "ghcr.io/owner/name@sha256:<64hex>") from exc
    action = _ACTION_RE.fullmatch(framework_action or "")
    if action is None:
        raise ValueError(
            "--framework-action must be commit-pinned, e.g. owner/repo@<40hex>")
    if goal not in GOAL_TIERS:
        raise ValueError(f"goal must be one of {sorted(GOAL_TIERS)}")
    if goal == "bytematch" and not toolchain:
        raise ValueError("goal 'bytematch' needs --toolchain (e.g. msvc-7.1); "
                         "byte-match requires a pinned original toolchain")

    name = name or (target.stem.lower().replace(" ", "-") if target is not None
                    else dest.resolve().name.lower().replace(" ", "-"))
    repository = repository or name
    detection = detect_path(target, toolchain=toolchain) if target is not None else None
    sha256 = _file_sha256(target) if target is not None else ""

    dest.mkdir(parents=True, exist_ok=True)
    shutil.copytree(builtin_plugins_dir() / plugin, dest / "plugins" / plugin)
    (dest / "recovery").mkdir()
    (dest / "recovery/.gitkeep").write_text("")
    (dest / "toolchain").mkdir()
    (dest / "toolchain/Containerfile").write_text(templates.toolchain_containerfile())
    (dest / "docs").mkdir()
    (dest / ".github/workflows").mkdir(parents=True)

    values = {
        "PROJECT_NAME": name,
        "OWNER": owner,
        "REPOSITORY": repository,
        "TARGET_FILENAME": target.name if target is not None else "no pinned target",
        "TARGET_SHA256": sha256 or "none",
        "TARGET_SIZE": str(target.stat().st_size) if target is not None else "0",
        "PLATFORM": detection.format if detection is not None else "sources",
        "TIER": GOAL_TIERS[goal],
        "GOAL": goal,
        "PLUGIN": plugin,
        "IMAGE": str(image),
    }

    launcher = dest / "recomp-launcher"
    launcher.write_text(templates.toolchain_launcher(image))
    launcher.chmod(0o755)

    for name_, text in (
        ("recomp-preflight.yml", templates.github_workflow("preflight.yml")),
    ):
        rendered = (text
                    .replace("__RECOMP_ACTION_REPOSITORY__",
                             f"{action.group(1)}/{action.group(2)}")
                    .replace("0000000000000000000000000000000000000000", action.group(3))
                    .replace("__RECOMP_TRUSTED_ACTOR_ID__", str(trusted_actor_id))
                    .replace("__RECOMP_PROTECTED_PATHS__",
                             '"' + ",".join(protected_paths or ()) + '"'))
        (dest / ".github/workflows" / name_).write_text(rendered)

    (dest / ".github/pull_request_template.md").write_text(templates.pull_request_template())
    (dest / ".github/CODEOWNERS").write_text(_render(templates.codeowners(), values))
    (dest / "README.md").write_text(_render(templates.project_readme(), values))
    (dest / "CONTRIBUTING.md").write_text(_render(templates.contributing(), values))

    if port_target:
        (dest / "port").mkdir()
        (dest / "port/README.md").write_text(
            f"# {name} — {port_target} port\n\n"
            "This tree consumes snapshots of `../recovery/`. Ports never share a merge\n"
            "queue with recovery: the port follows pinned recovery commits only.\n")

    (dest / ".gitignore").write_text(
        ".recomp/\n__pycache__/\n*.pyc\n"
        "# never commit target bytes or extracted game data\n"
        "*.exe\n*.bin\n*.iso\n*.dat\n*.pak\n")

    empty = ProgressSnapshot(project=name, generated_at=0, tasks=())
    (dest / "docs/progress.json").write_text(render_progress_json(empty))
    (dest / "docs/progress.svg").write_text(render_progress_svg(empty))

    cfg = {
        "project": {"name": name, "goal": goal, "plugin": plugin},
    }
    if target is not None:
        cfg["target"] = {
            "filename": target.name,
            "sha256": sha256,
            "size": target.stat().st_size,
            "platform": detection.format,
            "arch": detection.arch,
            "engine": detection.engine,
            "tier": GOAL_TIERS[goal],
            "toolchain": toolchain or "",
        }
    cfg["toolchain"] = {"image": str(image)}
    cfg["github"] = {
        "owner": owner,
        "repository": repository,
        "framework_action": framework_action,
        "trusted_actor_id": trusted_actor_id,
    }
    cfg["assets"] = {"extract": assets or []}
    if protected_paths:
        cfg["policy"] = {"protected_paths": list(protected_paths)}
    from recomp.project import save_project

    save_project(cfg, dest / "recomp.toml")
    (dest / "AGENTS.md").write_text(templates.project_agents_md(cfg))
    lock = bump_policy(dest)
    (dest / "PROMPT.md").write_text(render_prompt_static(dest, cfg, lock))
    return GeneratedProject(path=dest)


def render_prompt_static(root: Path, cfg: dict, lock: dict | None = None) -> str:
    from recomp.prompt import render_prompt

    return render_prompt(root, cfg=cfg, lock=lock)
