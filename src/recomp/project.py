"""recomp.toml loading/saving and project root discovery."""

from __future__ import annotations

import tomllib
from pathlib import Path

MANIFEST_NAME = "recomp.toml"
LOCK_NAME = "recomp.lock.toml"


class ProjectError(Exception):
    pass


def find_project(start: str | Path) -> Path | None:
    cur = Path(start).resolve()
    for candidate in (cur, *cur.parents):
        if (candidate / MANIFEST_NAME).is_file():
            return candidate
    return None


def load_project(root: str | Path) -> tuple[dict, Path]:
    path = Path(root) / MANIFEST_NAME
    if not path.is_file():
        raise ProjectError(f"no {MANIFEST_NAME} under {root}")
    cfg = tomllib.loads(path.read_text())
    for key in ("name", "goal", "plugin"):
        if key not in cfg.get("project", {}):
            raise ProjectError(f"recomp.toml [project] is missing {key!r}")
    return cfg, path


def save_project(cfg: dict, path: str | Path) -> Path:
    path = Path(path)

    def fmt(value):
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, (list, tuple)):
            return "[" + ", ".join(fmt(v) for v in value) + "]"
        return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'

    lines = []
    for section, values in cfg.items():
        lines.append(f"[{section}]")
        for key, value in values.items():
            lines.append(f"{key} = {fmt(value)}")
        lines.append("")
    path.write_text("\n".join(lines) + "\n")
    return path


def target_binary_path(root: str | Path, cfg: dict) -> Path:
    rel = cfg.get("target", {}).get("binary", "")
    return (Path(root) / rel).resolve()
