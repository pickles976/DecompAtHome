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


def has_target(cfg: dict) -> bool:
    """True when this project pins a target binary contributors must supply."""

    target = (cfg or {}).get("target") or {}
    return isinstance(target, dict) and bool(target.get("sha256"))


def protected_paths(cfg: dict) -> tuple[str, ...]:
    """Maintainer-owned paths declared in `[policy] protected_paths`."""

    policy = (cfg or {}).get("policy") or {}
    values = policy.get("protected_paths") if isinstance(policy, dict) else None
    if not isinstance(values, (list, tuple)):
        return ()
    return tuple(item for item in values if isinstance(item, str) and item.strip())


def validate_target(path: str | Path, cfg: dict) -> "TargetRef | None":
    """Check a locally supplied target against the repository's pinned reference.

    Projects that pin no target return None: there is nothing to check.
    """

    import hashlib

    from recomp.contracts import Sha256, TargetRef

    target = cfg.get("target", {}) or {}
    if not target.get("sha256"):
        return None
    candidate = Path(path)
    if not candidate.is_file():
        raise ProjectError(f"target file {candidate} does not exist")
    size = candidate.stat().st_size
    digest = hashlib.sha256()
    with candidate.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    if digest.hexdigest() != target.get("sha256"):
        raise ProjectError(
            f"target file hash does not match this project's pinned target "
            f"({size} bytes supplied, {target.get('size')} expected)")
    return TargetRef(filename=target["filename"], sha256=Sha256(target["sha256"]), size=size)
