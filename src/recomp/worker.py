"""Contributor worker: enroll once, then loop claim -> execute -> submit."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from recomp.plugin import resolve_plugin, run_plugin
from recomp.project import find_project, load_project, target_binary_path

WORKER_FILE = ".recomp/worker.json"


class WorkerError(Exception):
    pass


def _call(base_url: str, method: str, path: str, body: dict | None = None,
          key: str | None = None) -> dict:
    req = urllib.request.Request(base_url.rstrip("/") + path, method=method)
    if key:
        req.add_header("Authorization", "Bearer " + key)
    data = json.dumps(body).encode() if body is not None else None
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()
        raise WorkerError(f"{method} {path} -> {e.code}: {detail}") from None


def enroll(base_url: str, token: str, name: str, project_root: str | Path | None = None) -> Path:
    root = Path(project_root) if project_root else find_project(Path.cwd())
    if root is None:
        raise WorkerError("run inside a recomp project (no recomp.toml found)")
    result = _call(base_url, "POST", "/api/enroll", {"token": token, "name": name})
    cfg_dir = root / ".recomp"
    cfg_dir.mkdir(exist_ok=True)
    path = cfg_dir / WORKER_FILE.split("/", 1)[1]
    path.write_text(json.dumps({"base_url": base_url, "key": result["key"],
                                "name": result["name"]}, indent=2) + "\n")
    path.chmod(0o600)
    print(f"enrolled as {result['name']}; worker config written to {path}")
    return path


def load_worker_config(project_root: str | Path) -> tuple[dict, Path]:
    root = Path(project_root) if Path(project_root, "recomp.toml").is_file() else find_project(project_root)
    path = root / ".recomp" / "worker.json"
    if not path.is_file():
        raise WorkerError(f"no worker config at {path}; run `recomp join <url> --token ...` first")
    return json.loads(path.read_text()), root


def work_once(project_root: str | Path | None = None, cfg: dict | None = None,
              root: Path | None = None) -> dict:
    if cfg is None or root is None:
        cfg, root = load_worker_config(project_root or Path.cwd())
    proj_cfg, _ = load_project(root)
    plugin = resolve_plugin(root, proj_cfg["project"]["plugin"])
    binary = target_binary_path(root, proj_cfg)

    claim = _call(cfg["base_url"], "POST", "/api/claim", {}, key=cfg["key"])
    if not claim.get("work_id"):
        return {"status": "idle"}
    task = claim["task"]
    out = run_plugin(plugin, "run_task", {"binary": str(binary), "args": task["args"]})
    try:
        verdict = _call(cfg["base_url"], "POST", "/api/submit", {
            "work_id": claim["work_id"], "generation": claim["generation"],
            "policy_version": claim["policy_version"], "files": out["files"],
        }, key=cfg["key"])
    except WorkerError as e:
        if "409" in str(e) or "412" in str(e):
            return {"status": "stale", "detail": str(e)}
        raise
    return {"status": verdict["status"], "work_id": claim["work_id"]}


def work_loop(project_root: str | Path | None = None, interval: float = 2.0) -> None:
    cfg, root = load_worker_config(project_root or Path.cwd())
    print(f"worker {cfg['name']} looping against {cfg['base_url']} (ctrl-c to stop)")
    while True:
        try:
            result = work_once(cfg=cfg, root=root)
        except WorkerError as e:
            if "403" in str(e) and "seats" in str(e):
                print(time.strftime("%H:%M:%S"),
                      f"waiting for a vacant seat ({e}); retrying in 30s")
                time.sleep(30)
                continue
            raise
        print(time.strftime("%H:%M:%S"), json.dumps(result))
        if result["status"] == "idle":
            time.sleep(interval)
