"""recomp command line."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from recomp import __version__
from recomp.detect import detect_path
from recomp.plugin import PluginError, load_plugin
from recomp.project import find_project


def _project_root_or_die(start: Path) -> Path:
    root = find_project(start)
    if root is None:
        print("error: not inside a recomp project (no recomp.toml found)", file=sys.stderr)
        raise SystemExit(2)
    return root


def cmd_init(args) -> int:
    from recomp.generate import generate_project
    try:
        project = generate_project(
            args.path, args.bin, name=args.name, goal=args.goal, trust=args.trust,
            assets=args.assets, port_target=args.port_target, toolchain=args.toolchain)
    except (FileExistsError, FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"generated {project.path}")
    print(f"  next: cd {project.path}")
    print("       recomp plugin test generic      # sanity-check the workflow")
    print("       recomp prompt                   # the contributor prompt")
    print("       recomp serve                    # accept submissions")
    print("       recomp admin token              # mint an invite token")
    return 0


def cmd_detect(args) -> int:
    d = detect_path(args.binary, toolchain=args.toolchain)
    print(f"format:    {d.format}")
    print(f"arch:      {d.arch}")
    print(f"engine:    {d.engine}")
    print(f"toolchain: {d.toolchain or 'unknown (pin with --toolchain for byte-match)'}")
    print(f"tier:      {d.tier}")
    for note in d.notes:
        print(f"note:      {note}")
    return 0


def cmd_plugin(args) -> int:
    root = _project_root_or_die(Path.cwd())
    plugins_dir = root / "plugins"
    if args.action == "new":
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,31}", args.name or ""):
            print("error: plugin name must be 2-32 chars of [a-z0-9-]", file=sys.stderr)
            return 1
        from recomp import templates
        dest = plugins_dir / args.name
        if dest.exists():
            print(f"error: {dest} already exists", file=sys.stderr)
            return 1
        dest.mkdir(parents=True)
        (dest / "recomp.plugin.toml").write_text(
            templates.plugin_manifest(args.name, args.capability))
        (dest / "runner.py").write_text(templates.plugin_runner())
        (dest / "prompt.md").write_text(templates._read("prompt_default.md"))
        print(f"created {dest}")
        print(f"implement the command stubs in runner.py, then: recomp plugin test {args.name}")
        return 0
    if args.action == "check":
        if not args.name:
            print("error: plugin name required", file=sys.stderr)
            return 1
        try:
            plugin = load_plugin(plugins_dir / args.name)
        except PluginError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(f"ok: {plugin.name} v{plugin.version} capabilities={plugin.capabilities}")
        return 0
    if args.action == "test":
        from recomp.plugin import resolve_plugin, run_plugin
        try:
            plugin = resolve_plugin(root, args.name or "generic")
            result = run_plugin(plugin, "selftest", {})
        except PluginError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(json.dumps(result))
        return 0
    return 1


def cmd_workflow(args) -> int:
    root = _project_root_or_die(Path.cwd())
    from recomp import policy as policy_mod
    if args.action == "show":
        status, lock = policy_mod.check_policy(root)
        if lock is None:
            print("no lock yet; run `recomp workflow lock`")
            return 1
        print(f"policy_version: {lock['policy_version']}")
        print(f"hash:           {lock['hash']}")
        print(f"status:         {status}")
        print(f"files:          {len(lock.get('files', {}))}")
        return 0
    if args.action == "lock":
        lock = policy_mod.bump_policy(root)
        print(f"locked policy v{lock['policy_version']} ({lock['hash'][:16]}…)")
        print("restart `recomp serve` (or POST /api/admin/reload) to pin it")
        return 0
    return 1


def cmd_prompt(args) -> int:
    root = _project_root_or_die(Path.cwd())
    from recomp.prompt import render_prompt
    sys.stdout.write(render_prompt(root, base_url=args.url))
    if not sys.stdout.isatty():
        sys.stdout.write("\n")
    return 0


def cmd_serve(args) -> int:
    root = _project_root_or_die(Path.cwd())
    from recomp.server import RecompServer
    srv = RecompServer(root)
    srv.serve_forever(host=args.host, port=args.port)
    return 0


def cmd_join(args) -> int:
    from recomp.worker import WorkerError, enroll
    try:
        enroll(args.url, token=args.token, name=args.name)
    except WorkerError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

def cmd_work(args) -> int:
    from recomp.worker import WorkerError, work_loop, work_once
    try:
        if args.loop:
            work_loop()
        else:
            print(json.dumps(work_once()))
    except WorkerError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_admin(args) -> int:
    root = _project_root_or_die(Path.cwd())
    from recomp.state import Store
    store = Store(root / "server" / "state.db")
    if store._db.execute("SELECT COUNT(*) n FROM keys WHERE role='owner'").fetchone()["n"] == 0:
        key = store.create_owner_key()
        keys_dir = root / "server" / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        (keys_dir / "owner.key").write_text(key + "\n")
    if args.action == "token":
        print(store.mint_enroll_token())
    elif args.action == "grant":
        if not args.name:
            print("error: name required", file=sys.stderr)
            return 1
        print(store.grant_worker_key(args.name))
    elif args.action == "revoke":
        store.revoke_key(args.name or "")
        print(f"revoked {args.name}")
    elif args.action == "list":
        for row in store._db.execute(
                "SELECT role, name, revoked FROM keys ORDER BY role, name"):
            print(f"{row['role']:6} {row['name']}{' (revoked)' if row['revoked'] else ''}")
    return 0


def cmd_toolchain(args) -> int:
    from recomp.contracts import ImageRef
    from recomp.toolchain import (
        OciRuntime, ToolchainError, build_and_push_toolchain, inspect_image_digest,
    )

    try:
        if args.action == "inspect":
            image = ImageRef.parse(args.image)
            inspect_image_digest(OciRuntime.discover(preferred=args.runtime), image)
            print(str(image))
            return 0
        base = args.base_image
        image = build_and_push_toolchain(
            OciRuntime.discover(preferred=args.runtime),
            Path(args.source), base, args.destination,
        )
        print(str(image))
        return 0
    except (ToolchainError, ValueError) as exc:
        message = str(exc)
        if isinstance(exc, ValueError) and not isinstance(exc, ToolchainError):
            message = f"{message} (references must be digest-pinned)"
        print(f"error: {message}", file=sys.stderr)
        return 1


def _github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token
    completed = subprocess.run(["gh", "auth", "token"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True, check=False)
    if completed.returncode != 0 or not completed.stdout.strip():
        raise SystemExit("set GITHUB_TOKEN or run `gh auth login` first")
    return completed.stdout.strip()


def cmd_task(args) -> int:
    from recomp.contracts import ImageRef
    from recomp.github_api import GitHubClient
    from recomp.project import load_project
    from recomp.task_cli import Git, TaskCliError, parse_task_url, run_task_command
    from recomp.toolchain import OciRuntime, run_toolchain

    root = _project_root_or_die(Path.cwd())
    cfg, _path = load_project(root)
    github_cfg = cfg.get("github", {})
    image = cfg.get("toolchain", {}).get("image", "")
    try:
        url = parse_task_url(args.url) if getattr(args, "url", None) else None
        owner = url.owner if url is not None else github_cfg.get("owner", "")
        repository = url.repository if url is not None else github_cfg.get("repository", "")
        token = _github_token()
        github = GitHubClient(args.api_url, owner, repository, lambda: token)
        runtime = OciRuntime.discover()

        def launch(arguments, *, target, project):
            return run_toolchain(runtime, ImageRef.parse(image), project, target,
                                 ["task-guest", *arguments])

        status, out, err = run_task_command(
            [args.action, *([args.url] if getattr(args, "url", None) else [])],
            github=github, git=Git(root), project=root, now=int(time.time()),
            run_toolchain=launch, image=image, target=args.target,
            trusted_actor_id=int(github_cfg.get("trusted_actor_id", 0)),
        )
    except TaskCliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(out)
    sys.stderr.write(err)
    return status


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="recomp",
                                description="self-hostable decomp collaboration platform")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="scaffold a new decomp project")
    init.add_argument("path")
    init.add_argument("--bin", required=True, help="executable/image to recover")
    init.add_argument("--name")
    init.add_argument("--goal", default="structure",
                      choices=["assets", "structure", "recomp", "bytematch"])
    init.add_argument("--trust", default="invited", choices=["solo", "invited", "public"])
    init.add_argument("--assets", nargs="*", default=[],
                      help="e.g. model:glb texture:png audio:wav")
    init.add_argument("--port-target", help="engine port template: bevy | godot | unity")
    init.add_argument("--toolchain", help="pin original toolchain for byte-match")
    init.set_defaults(func=cmd_init)

    det = sub.add_parser("detect", help="identify a binary")
    det.add_argument("binary")
    det.add_argument("--toolchain")
    det.set_defaults(func=cmd_detect)

    plug = sub.add_parser("plugin", help="manage project-local workflow plugins")
    plug.add_argument("action", choices=["new", "check", "test"])
    plug.add_argument("name", nargs="?")
    plug.add_argument("--capability", default="scan",
                      choices=["detect", "scan", "extract", "toolchain", "work", "verify", "port"])
    plug.set_defaults(func=cmd_plugin)

    wf = sub.add_parser("workflow", help="inspect/lock the pinned verification policy")
    wf.add_argument("action", choices=["show", "lock"])
    wf.set_defaults(func=cmd_workflow)

    prompt = sub.add_parser("prompt", help="print the generated contributor prompt")
    prompt.add_argument("--url", help="server base URL to embed")
    prompt.set_defaults(func=cmd_prompt)

    serve = sub.add_parser("serve", help="run the coordination API + dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=7331)
    serve.set_defaults(func=cmd_serve)

    join = sub.add_parser("join", help="enroll a worker with an invite URL+token")
    join.add_argument("url")
    join.add_argument("--token", required=True)
    join.add_argument("--name", required=True)
    join.set_defaults(func=cmd_join)

    work = sub.add_parser("work", help="claim and complete one item (or loop)")
    work.add_argument("--once", action="store_true", help="complete a single item (default)")
    work.add_argument("--loop", action="store_true")
    work.set_defaults(func=cmd_work)

    admin = sub.add_parser("admin", help="owner operations (keys, tokens)")
    admin.add_argument("action", choices=["token", "grant", "revoke", "list"])
    admin.add_argument("name", nargs="?")
    admin.set_defaults(func=cmd_admin)

    tool = sub.add_parser("toolchain", help="build and verify the digest-pinned toolchain image")
    tool_sub = tool.add_subparsers(dest="action", required=True)
    tool.add_argument("--runtime", choices=["docker", "podman"],
                      help="force an OCI runtime instead of discovering one")
    tool_build = tool_sub.add_parser("build", help="build, push, and print the immutable image")
    tool_build.add_argument("--source", required=True, help="build context containing Containerfile")
    tool_build.add_argument("--base-image", required=True, help="repository@sha256:<64hex>")
    tool_build.add_argument("--destination", required=True, help="registry repository:tag to push")
    tool_build.set_defaults(func=cmd_toolchain)
    tool_inspect = tool_sub.add_parser("inspect", help="verify a local image matches its digest")
    tool_inspect.add_argument("image", help="repository@sha256:<64hex>")
    tool_inspect.set_defaults(func=cmd_toolchain)

    task = sub.add_parser("task", help="contributor workflow: claim, run, verify, submit")
    task.add_argument("action", choices=["next", "start", "heartbeat", "run", "verify",
                                         "submit", "status"])
    task.add_argument("url", nargs="?", help="repository or Issue link")
    task.add_argument("--target", help="path to your own copy of the target file")
    task.add_argument("--api-url", default="https://api.github.com")
    task.set_defaults(func=cmd_task)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
