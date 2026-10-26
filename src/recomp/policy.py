"""Workflow policy: hash every trusted project input, version it in recomp.lock.toml.

The policy covers `recomp.toml`, everything under `plugins/` and `toolchain/`,
and the generated protected launcher. Host agents edit plugins freely; the
lock records what the server pinned. A submission carries the policy_version
it was produced under, and the server refuses submissions from stale policies
(the host must `recomp workflow lock` and reload first). This keeps "the
host's agent changed the workflow" a reviewable, revertable, versioned event.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from recomp.project import LOCK_NAME, MANIFEST_NAME

EXCLUDED_PARTS = {"__pycache__", "server", ".git", ".recomp"}
EXCLUDED_SUFFIXES = {".pyc", ".db"}

# Trusted source directories and the generated protected launcher; the lock
# file itself is never hashed (it would hash into itself).
TRUSTED_DIRS = ("plugins", "toolchain")
LAUNCHER_NAME = "recomp-launcher"


def policy_files(project_root: str | Path) -> list[Path]:
    root = Path(project_root)
    files = [root / MANIFEST_NAME, root / LAUNCHER_NAME]
    for dirname in TRUSTED_DIRS:
        directory = root / dirname
        if directory.is_dir():
            files.extend(sorted(p for p in directory.rglob("*")
                                if p.is_file()
                                and not (EXCLUDED_PARTS & set(p.relative_to(root).parts))
                                and p.suffix not in EXCLUDED_SUFFIXES))
    return [f for f in files
            if f.is_file() and f.name != LOCK_NAME]


def _entry(root: Path, path: Path) -> str:
    rel = path.relative_to(root).as_posix()
    return f"{rel}\0{hashlib.sha256(path.read_bytes()).hexdigest()}\n"


def compute_policy_hash(project_root: str | Path) -> str:
    root = Path(project_root)
    h = hashlib.sha256()
    for path in policy_files(root):
        h.update(_entry(root, path).encode())
    return h.hexdigest()


def load_lock(project_root: str | Path) -> dict | None:
    import tomllib
    path = Path(project_root) / LOCK_NAME
    if not path.is_file():
        return None
    lock = tomllib.loads(path.read_text())
    if "policy_version" not in lock or "hash" not in lock:
        return None
    return lock


def _write_lock(project_root: Path, version: int, hash_: str, files: list[Path]) -> dict:
    lines = [f"policy_version = {version}", f'hash = "{hash_}"', "", "[files]"]
    for path in files:
        rel = path.relative_to(project_root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f'"{rel}" = "{digest}"')
    (project_root / LOCK_NAME).write_text("\n".join(lines) + "\n")
    return {"policy_version": version, "hash": hash_}


def check_policy(project_root: str | Path) -> tuple[str, dict | None]:
    root = Path(project_root)
    lock = load_lock(root)
    if lock is None:
        return "missing", None
    current = compute_policy_hash(root)
    if current == lock["hash"]:
        return "ok", lock
    return "stale", lock


def bump_policy(project_root: str | Path) -> dict:
    root = Path(project_root)
    previous = load_lock(root)
    version = (previous["policy_version"] + 1) if previous else 1
    files = policy_files(root)
    return _write_lock(root, version, compute_policy_hash(root), files)
