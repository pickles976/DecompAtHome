"""recomp serve: the coordination API + dashboard.

Trust boundaries (P0, solo/invited tier):
  - worker keys may: claim, heartbeat, submit. Nothing else.
  - owner key may: mint tokens, reload policy.
  - submissions are quarantined to server/quarantine/, verified by the project
    plugin in a sandboxed subprocess, and only byte-identical artifacts are
    written into recovery/ through a path-checked allowlist.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath

from recomp import policy as policy_mod
from recomp.plugin import PluginError, resolve_plugin, run_plugin
from recomp.project import load_project, target_binary_path
from recomp.state import Store

MAX_FILES_PER_SUBMISSION = 16
MAX_FILE_BYTES = 64 * 1024
ALLOWED_OUTPUT_SUFFIX = ".json"


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class RecompServer:
    def __init__(self, project_root: str | Path, host: str = "127.0.0.1", port: int = 0,
                 store_path: str | Path | None = None):
        self.root = Path(project_root).resolve()
        self.cfg, _ = load_project(self.root)
        self.plugin = resolve_plugin(self.root, self.cfg["project"]["plugin"])
        self.binary = target_binary_path(self.root, self.cfg)
        self.server_dir = self.root / "server"
        self.server_dir.mkdir(exist_ok=True)
        store_path = Path(store_path) if store_path else self.server_dir / "state.db"
        self.store = Store(store_path)
        keyfile = self.server_dir / "keys" / "owner.key"
        if not keyfile.is_file():
            key = self.store.create_owner_key()
            keyfile.parent.mkdir(parents=True, exist_ok=True)
            keyfile.write_text(key + "\n")
            keyfile.chmod(0o600)
        self.owner_key = keyfile.read_text().strip()
        self._sync_policy_and_work(initial=True)
        self._http: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._handler = self._build_handler()

    # ------------------------------------------------------------- setup

    def _sync_policy_and_work(self, initial: bool = False) -> dict:
        status, lock = policy_mod.check_policy(self.root)
        if status != "ok":
            lock = policy_mod.bump_policy(self.root)
            self.store.add_event("policy", f"{'initial' if initial else 'auto'} lock at v{lock['policy_version']}")
        self.store.set_policy(lock["policy_version"], lock["hash"])
        plan = run_plugin(self.plugin, "work_plan",
                          {"binary": str(self.binary), "size": self.binary.stat().st_size})
        self.store.sync_work(plan.get("tasks", []), lock["policy_version"])
        return {"policy_version": lock["policy_version"], "policy_hash": lock["hash"],
                "tasks": len(plan.get("tasks", [])), "lock_status": "ok"}

    def reload_policy(self) -> dict:
        result = self._sync_policy_and_work()
        self.store.add_event("policy", f"reloaded to v{result['policy_version']}")
        return result

    # ------------------------------------------------------------ http

    def _build_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def _send(self, status: int, payload):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _html(self, body: str):
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _body(self) -> dict:
                length = int(self.headers.get("Content-Length") or 0)
                if length > 2 * 1024 * 1024:
                    raise ApiError(413, "request too large")
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    raise ApiError(400, "invalid JSON body") from None
                if not isinstance(data, dict):
                    raise ApiError(400, "body must be a JSON object")
                return data

            def _role(self) -> str:
                auth = self.headers.get("Authorization", "")
                key = auth[7:].strip() if auth.startswith("Bearer ") else ""
                role = outer.store.key_role(key) if key else None
                if role is None:
                    raise ApiError(401, "missing or invalid key")
                return role

            def _owner(self) -> None:
                if self._role() != "owner":
                    raise ApiError(403, "owner key required")

            def _worker(self) -> int:
                if self._role() != "worker":
                    raise ApiError(403, "worker key required")
                auth = self.headers.get("Authorization", "")
                key = auth[7:].strip()
                return outer.store.worker_id(key)

            def do_GET(self):
                try:
                    parsed = urllib.parse.urlparse(self.path)
                    if parsed.path == "/api/health":
                        self._send(200, {"ok": True, "name": outer.cfg["project"]["name"]})
                    elif parsed.path == "/api/project":
                        pol = outer.store.get_policy()
                        self._send(200, {
                            "name": outer.cfg["project"]["name"],
                            "goal": outer.cfg["project"]["goal"],
                            "plugin": outer.cfg["project"]["plugin"],
                            "trust": outer.cfg["project"].get("trust", "solo"),
                            "tier": outer.cfg.get("target", {}).get("tier", "t1-structure"),
                            "policy_version": pol["policy_version"],
                            "policy_hash": pol["policy_hash"],
                        })
                    elif parsed.path == "/api/progress":
                        self._send(200, outer.store.progress())
                    elif parsed.path == "/api/events":
                        qs = urllib.parse.parse_qs(parsed.query)
                        since = int(qs.get("since", ["0"])[0])
                        events = outer.store.events(since=since)
                        self._send(200, {"events": events, "last": events[-1]["id"] if events else since})
                    elif parsed.path == "/api/prompt":
                        from recomp.prompt import render_prompt
                        base = f"http://{self.headers.get('Host', '127.0.0.1')}"
                        self._send(200, {"prompt": render_prompt(outer.root, base_url=base)})
                    elif parsed.path == "/":
                        from recomp.templates import dashboard_html
                        self._html(dashboard_html(outer.cfg["project"]["name"]))
                    else:
                        raise ApiError(404, f"no route {parsed.path}")
                except ApiError as e:
                    self._send(e.status, {"error": e.message})

            def do_POST(self):
                try:
                    parsed = urllib.parse.urlparse(self.path)
                    if parsed.path == "/api/enroll":
                        self._enroll()
                    elif parsed.path == "/api/claim":
                        self._claim()
                    elif parsed.path == "/api/heartbeat":
                        self._heartbeat()
                    elif parsed.path == "/api/submit":
                        self._submit()
                    elif parsed.path == "/api/admin/keys":
                        self._admin_keys()
                    elif parsed.path == "/api/admin/reload":
                        self._owner()
                        self._send(200, outer.reload_policy())
                    else:
                        raise ApiError(404, f"no route {parsed.path}")
                except ApiError as e:
                    self._send(e.status, {"error": e.message})
                except PluginError as e:
                    self._send(500, {"error": f"plugin failure: {e}"})

            def _enroll(self):
                body = self._body()
                token, name = str(body.get("token", "")), str(body.get("name", ""))
                if not token or not name:
                    raise ApiError(400, "token and name required")
                try:
                    key = outer.store.redeem_enroll_token(token, name)
                except PermissionError as e:
                    raise ApiError(403, str(e)) from None
                outer.store.add_event("enroll", f"{name} joined")
                self._send(200, {"key": key, "name": name})

            def _claim(self):
                worker_id = self._worker()
                pol = outer.store.get_policy()
                lease = outer.store.claim(worker_id=worker_id)
                if lease is None:
                    self._send(200, {"work_id": None, "policy_version": pol["policy_version"]})
                    return
                outer.store.heartbeat(worker_id)
                self._send(200, {"work_id": lease["work_id"], "generation": lease["generation"],
                                 "task": {"kind": lease["kind"], "args": lease["args"]},
                                 "policy_version": pol["policy_version"]})

            def _heartbeat(self):
                worker_id = self._worker()
                outer.store.heartbeat(worker_id)
                self._send(200, {"ok": True})

            def _submit(self):
                worker_id = self._worker()
                body = self._body()
                work_id = str(body.get("work_id", ""))
                generation = body.get("generation")
                policy_version = body.get("policy_version")
                files = body.get("files")
                if not work_id or generation is None or not isinstance(files, dict):
                    raise ApiError(400, "work_id, generation and files required")
                if not outer.store.validate_lease(work_id, worker_id, int(generation)):
                    raise ApiError(409, "stale lease: item expired or was reclaimed")
                current = outer.store.get_policy()
                if int(policy_version) != current["policy_version"]:
                    raise ApiError(412, f"policy changed: server at v{current['policy_version']}, "
                                        f"submission from v{policy_version}; re-claim")
                task = outer._task_args(work_id)
                outer._check_files(task, files)
                sub_id = outer.store.record_submission(work_id, worker_id, int(generation),
                                                       int(policy_version))
                quarantine = outer.server_dir / "quarantine" / str(sub_id)
                quarantine.mkdir(parents=True, exist_ok=True)
                for rel, content in files.items():
                    (quarantine / rel.replace("/", "_")).write_text(content)
                verdict = run_plugin(outer.plugin, "verify",
                                     {"binary": str(outer.binary), "args": task, "files": files},
                                     timeout=60)
                attestation = {"pass": bool(verdict.get("pass")),
                               "policy_version": current["policy_version"],
                               "policy_hash": current["policy_hash"],
                               "work_id": work_id, "evidence": verdict.get("evidence", {})}
                if attestation["pass"]:
                    for rel, content in files.items():
                        dest = outer.root / "recovery" / rel
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_text(content)
                    outer.store.complete(work_id, "merged")
                    outer.store.set_submission_status(sub_id, "merged", attestation)
                    outer.store.add_event("merge", f"{work_id} merged at policy v{current['policy_version']}")
                    self._send(200, {"status": "merged", "attestation": attestation})
                else:
                    outer.store.reopen(work_id)
                    outer.store.set_submission_status(sub_id, "rejected", attestation)
                    outer.store.add_event("reject", f"{work_id} rejected by verifier")
                    self._send(200, {"status": "rejected", "attestation": attestation})

            def _admin_keys(self):
                self._owner()
                body = self._body()
                action = body.get("action")
                if action == "mint-token":
                    token = outer.store.mint_enroll_token()
                    self._send(200, {"token": token})
                elif action == "grant":
                    name = str(body.get("name", ""))
                    if not name:
                        raise ApiError(400, "name required")
                    self._send(200, {"key": outer.store.grant_worker_key(name)})
                elif action == "revoke":
                    outer.store.revoke_key(str(body.get("name", "")))
                    self._send(200, {"ok": True})
                else:
                    raise ApiError(400, "action must be mint-token, grant or revoke")

        return Handler

    # -------------------------------------------------------- helpers

    def _task_args(self, work_id: str) -> dict:
        row = self.store._db.execute("SELECT args FROM work WHERE work_id=?", (work_id,)).fetchone()
        if row is None:
            raise ApiError(404, f"unknown work item {work_id}")
        return json.loads(row["args"])

    @staticmethod
    def _check_files(task_args: dict, files: dict) -> None:
        if not files or len(files) > MAX_FILES_PER_SUBMISSION:
            raise ApiError(400, f"1..{MAX_FILES_PER_SUBMISSION} files required")
        allowed_root = PurePosixPath(task_args.get("out", "")).parent.as_posix()
        if allowed_root in (".", ""):
            allowed_root = ""
        for rel, content in files.items():
            path = PurePosixPath(rel)
            if ".." in path.parts or path.is_absolute():
                raise ApiError(400, f"illegal path {rel!r}")
            if allowed_root and path.parent.as_posix() != allowed_root:
                raise ApiError(400, f"file {rel!r} outside the task's declared output dir {allowed_root!r}")
            if path.suffix != ALLOWED_OUTPUT_SUFFIX:
                raise ApiError(400, f"only {ALLOWED_OUTPUT_SUFFIX} outputs are accepted in P0, got {rel!r}")
            if not isinstance(content, str) or len(content.encode()) > MAX_FILE_BYTES:
                raise ApiError(400, f"file {rel!r} too large or not text")

    # -------------------------------------------------------- lifecycle

    def start_background(self) -> str:
        self._http = ThreadingHTTPServer(("127.0.0.1" if self._http is None else "", 0)
                                         if False else (self._bind_host(), 0), self._handler)
        port = self._http.server_address[1]
        base = f"http://127.0.0.1:{port}"
        self._thread = threading.Thread(target=self._http.serve_forever, daemon=True)
        self._thread.start()
        self.store.add_event("serve", f"listening on {base}")
        return base

    def _bind_host(self):
        return "127.0.0.1"

    def serve_forever(self, host: str = "127.0.0.1", port: int = 7331) -> None:
        self._http = ThreadingHTTPServer((host, port), self._handler)
        print(f"recomp serve: http://{host}:{port}  (owner key: server/keys/owner.key)")
        self._http.serve_forever()

    def stop(self) -> None:
        if self._http:
            self._http.shutdown()
            self._http.server_close()
            self._http = None
