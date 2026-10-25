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
        collab = self.cfg.get("collab", {})
        self.store.base_seats = int(collab.get(
            "base_seats", collab.get("max_seats", 1)))
        self.store.seat_ttl = float(collab.get("seat_ttl_seconds", 600))
        self.store.seat_ceiling = int(collab.get("seat_ceiling", 0))
        keyfile = self.server_dir / "keys" / "owner.key"
        if not keyfile.is_file():
            key = self.store.create_owner_key()
            keyfile.parent.mkdir(parents=True, exist_ok=True)
            keyfile.write_text(key + "\n")
            keyfile.chmod(0o600)
        self.owner_key = keyfile.read_text().strip()
        self._reverify_queue: list[dict] = self.store.pending_reverify()
        self._reverify_lock = threading.Lock()
        self._reverify_stop = threading.Event()
        self._reverify_worker: threading.Thread | None = None
        self._http: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._handler = self._build_handler()
        self._sync_policy_and_work(initial=True)

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

            def _worker(self) -> tuple[int, str]:
                if self._role() != "worker":
                    raise ApiError(403, "worker key required")
                auth = self.headers.get("Authorization", "")
                key = auth[7:].strip()
                worker_id = outer.store.worker_id(key)
                try:
                    outer.store.touch_seat(worker_id)
                except PermissionError as e:
                    raise ApiError(403, str(e)) from None
                return worker_id, key

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
                worker_id, _ = self._worker()
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
                worker_id, _ = self._worker()
                outer.store.heartbeat(worker_id)
                self._send(200, {"ok": True})

            def _submit(self):
                worker_id, key = self._worker()
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

                fast = outer.plugin.fast_lane and outer.store.is_trusted(key)
                if fast:
                    attestation = {"pass": None, "deferred": True, "fast_lane": True,
                                   "policy_version": current["policy_version"],
                                   "policy_hash": current["policy_hash"], "work_id": work_id}
                    outer._apply_merge(work_id, files)
                    outer._commit_merge(files, work_id,
                                        outer.store.worker_name(worker_id), fast=True)
                    outer.store.complete(work_id, "merged")
                    outer.store.set_submission_status(sub_id, "merged", attestation)
                    outer.store.add_event("merge",
                                          f"{work_id} fast-lane merged at policy "
                                          f"v{current['policy_version']} (re-verify pending)")
                    outer._queue_reverify(sub_id, work_id, worker_id, task, files)
                    self._send(200, {"status": "merged", "attestation": attestation})
                    return

                try:
                    verdict = run_plugin(outer.plugin, "verify",
                                         {"binary": str(outer.binary), "args": task, "files": files},
                                         timeout=60)
                except PluginError as e:
                    verdict = {"pass": False, "evidence": {"verifier_error": str(e)}}
                attestation = {"pass": bool(verdict.get("pass")),
                               "policy_version": current["policy_version"],
                               "policy_hash": current["policy_hash"],
                               "work_id": work_id, "evidence": verdict.get("evidence", {})}
                if attestation["pass"]:
                    outer._apply_merge(work_id, files)
                    outer._commit_merge(files, work_id,
                                        outer.store.worker_name(worker_id), fast=False)
                    outer.store.complete(work_id, "merged")
                    outer.store.set_submission_status(sub_id, "merged", attestation)
                    if not outer.store.is_trusted(key):
                        outer.store.promote(worker_id)
                        outer.store.add_event("promote",
                                              f"{outer.store.worker_name(worker_id)} promoted to "
                                              f"collaborator (direct-merge lane) after first verified merge")
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

    # -------------------------------------------------------- merge plane

    def _apply_merge(self, work_id: str, files: dict) -> None:
        for rel, content in files.items():
            dest = self.root / "recovery" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)

    def _commit_merge(self, files: dict, work_id: str, worker: str, fast: bool) -> None:
        """One commit per merged submission, explicit paths only (the BFME
        model: ~150 commits/h sustained, 400/h peak, straight to master)."""
        if not (self.root / ".git").exists():
            return
        import subprocess
        paths = [str(self.root / "recovery" / rel) for rel in files]
        tag = "fast" if fast else "verified"
        try:
            subprocess.run(["git", "add", "--", *paths], cwd=self.root,
                           capture_output=True, timeout=30, check=True)
            subprocess.run(
                ["git", "-c", "user.name=recomp", "-c", "user.email=recomp@localhost",
                 "commit", "-q", "-m",
                 f"recomp: merge {work_id} by {worker} ({tag})",
                 "--", *paths],
                cwd=self.root, capture_output=True, timeout=30, check=True)
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            self.store.add_event("git", f"commit failed for {work_id}: {e}")

    def _queue_reverify(self, submission_id: int, work_id: str, worker_id: int,
                        task_args: dict, files: dict) -> None:
        job = {"submission_id": submission_id, "work_id": work_id,
               "worker_id": worker_id, "args": task_args, "files": files}
        self.store.queue_reverify(
            submission_id, work_id, worker_id, task_args, files)
        with self._reverify_lock:
            self._reverify_queue.append(job)

    def drain_reverify(self) -> int:
        """Re-run deferred verifications; revert + untrust on failure."""
        reverted = 0
        while True:
            with self._reverify_lock:
                if not self._reverify_queue:
                    break
                job = self._reverify_queue.pop(0)
            sub_id, work_id = job["submission_id"], job["work_id"]
            try:
                verdict = run_plugin(self.plugin, "verify",
                                     {"binary": str(self.binary), "args": job["args"],
                                      "files": job["files"]}, timeout=120)
                ok = bool(verdict.get("pass"))
            except PluginError as e:
                verdict, ok = {"evidence": {"verifier_error": str(e)}}, False
            if ok:
                self.store.set_submission_status(sub_id, "reverified", {
                    "pass": True, "deferred": True, "work_id": work_id,
                    "evidence": verdict.get("evidence", {})})
                self.store.finish_reverify(sub_id)
                continue
            for rel in job["files"]:
                dest = self.root / "recovery" / rel
                dest.unlink(missing_ok=True)
            if (self.root / ".git").exists():
                import subprocess
                paths = [str(self.root / "recovery" / rel) for rel in job["files"]]
                try:
                    subprocess.run(
                        ["git", "-c", "user.name=recomp", "-c", "user.email=recomp@localhost",
                         "commit", "-q", "-a", "-m", f"recomp: revert {work_id} (re-verify failed)",
                         "--", *paths],
                        cwd=self.root, capture_output=True, timeout=30, check=True)
                except (subprocess.SubprocessError, FileNotFoundError):
                    pass
            self.store.reopen(work_id)
            self.store.demote(job["worker_id"])
            self.store.set_submission_status(sub_id, "reverted", {
                "pass": False, "deferred": True, "work_id": work_id,
                "evidence": verdict.get("evidence", {})})
            name = self.store.worker_name(job["worker_id"])
            self.store.add_event("revert", f"{work_id} reverted after failed re-verify; "
                                           f"{name} demoted to synchronous lane")
            self.store.finish_reverify(sub_id)
            reverted += 1
        return reverted

    def _reverify_loop(self) -> None:
        while not self._reverify_stop.wait(2):
            try:
                self.drain_reverify()
            except Exception:  # noqa: BLE001 - the re-verifier must never die
                pass

    def _start_reverify_worker(self) -> None:
        if self._reverify_worker and self._reverify_worker.is_alive():
            return
        self._reverify_stop.clear()
        self._reverify_worker = threading.Thread(
            target=self._reverify_loop, daemon=True)
        self._reverify_worker.start()

    # -------------------------------------------------------- lifecycle

    def start_background(self) -> str:
        self._http = ThreadingHTTPServer((self._bind_host(), 0), self._handler)
        port = self._http.server_address[1]
        base = f"http://127.0.0.1:{port}"
        self._thread = threading.Thread(target=self._http.serve_forever, daemon=True)
        self._thread.start()
        self._start_reverify_worker()
        self.store.add_event("serve", f"listening on {base}")
        return base

    def _bind_host(self):
        return "127.0.0.1"

    def serve_forever(self, host: str = "127.0.0.1", port: int = 7331) -> None:
        self._http = ThreadingHTTPServer((host, port), self._handler)
        actual_port = self._http.server_address[1]
        print(f"recomp serve: http://{host}:{actual_port}  "
              "(owner key: server/keys/owner.key)")
        self._start_reverify_worker()
        self._http.serve_forever()
    def stop(self) -> None:
        self._reverify_stop.set()
        if self._http:
            self._http.shutdown()
            self._http.server_close()
            self._http = None
        if (self._reverify_worker and self._reverify_worker.is_alive()
                and self._reverify_worker is not threading.current_thread()):
            self._reverify_worker.join(timeout=3)
        self._reverify_worker = None
