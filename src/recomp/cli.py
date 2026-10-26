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
from recomp.project import ProjectError
from recomp.project import find_project


def _project_root_or_die(start: Path) -> Path:
    root = find_project(start)
    if root is None:
        print("error: not inside a recomp project (no recomp.toml found)", file=sys.stderr)
        raise SystemExit(2)
    return root


def cmd_init(args) -> int:
    from recomp.generate import generate_project
    if args.no_target and args.bin:
        print("error: --no-target and --bin are mutually exclusive", file=sys.stderr)
        return 1
    if not args.no_target and not args.bin:
        print("error: pass --bin <your-copy> to pin a target, or --no-target for a "
              "project that ports from sources", file=sys.stderr)
        return 1
    try:
        project = generate_project(
            args.path, None if args.no_target else args.bin,
            name=args.name, owner=args.owner,
            repository=args.repository, goal=args.goal,
            toolchain_image=args.toolchain_image, framework_action=args.framework_action,
            assets=args.assets, port_target=args.port_target, toolchain=args.toolchain,
            trusted_actor_id=args.trusted_actor_id,
            protected_paths=args.protected_path)
    except (FileExistsError, FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"generated {project.path}")
    print(f"  next: cd {project.path}")
    print("       recomp plugin test generic           # sanity-check the workflow")
    print("       git init && git add -A && git commit # publish to GitHub")
    print("       recomp coordinator setup --owner <owner> --repository <repo>")
    print("       recomp github sync-tasks"
          + ("" if args.no_target else " --target <your-copy>"))
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
    if args.action in ("run-task", "verify"):
        from recomp.plugin import command_timeout, resolve_plugin, run_plugin
        from recomp.project import has_target, load_project, validate_target

        cfg, _path = load_project(root)
        target = args.target or os.environ.get("RECOMP_TARGET")
        if has_target(cfg):
            if not target:
                print("error: --target (or RECOMP_TARGET) is required; this command runs "
                      "against your own copy of the target", file=sys.stderr)
                return 1
        else:
            target = None
        try:
            if target is not None:
                validate_target(target, cfg)
            plugin = resolve_plugin(root, cfg["project"]["plugin"])
            binary = str(target) if target is not None else None
            tasks = run_plugin(plugin, "work_plan", {"binary": binary, "args": {}})
            task = next((item for item in tasks.get("tasks", [])
                         if item.get("id") == args.name), None)
            if task is None:
                print(f"error: no task {args.name!r} in the current work plan", file=sys.stderr)
                return 1
            command = "run_task" if args.action == "run-task" else "verify"
            payload = {"binary": binary, "args": task.get("args", {}),
                       "outputs": task.get("outputs", [])}
            if command == "verify":
                payload["files"] = {
                    output["path"]: (root / output["path"]).read_text()
                    for output in task.get("outputs", [])
                    if (root / output["path"]).is_file()
                }
            timeout = command_timeout(plugin)
            result = run_plugin(plugin, command, payload, timeout=timeout)
        except (PluginError, ProjectError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if command == "run_task":
            for relative, content in result.get("files", {}).items():
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(content)
                print(f"wrote {relative}")
            return 0
        print(json.dumps(result))
        return 0 if result.get("pass") else 1
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
        print("commit the lockfile, then restart the coordinator to pin it")
        return 0
    return 1



def cmd_github(args) -> int:
    from recomp.github_api import GitHubClient, GitHubError
    from recomp.github_tasks import GitHubTaskError, bootstrap_labels, sync_tasks
    from recomp.project import load_project

    root = _project_root_or_die(Path.cwd())
    cfg, _path = load_project(root)
    github_cfg = cfg.get("github", {})
    owner = str(github_cfg.get("owner", ""))
    repository = str(github_cfg.get("repository", ""))

    # Task Issues are only trusted from the coordinator App — publication must
    # use its installation token whenever this project has a coordinator
    # config; a personal token would silently publish Issues nobody can claim.
    from recomp.coordinator_run import SetupError, app_token_source
    try:
        sourced = app_token_source(owner, repository, environ=os.environ)
    except SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if sourced is None:
        token = _github_token()
        token_source = lambda: token
        print(f"warning: no coordinator App configured for {owner}/{repository}; "
              "task Issues published with GITHUB_TOKEN are invisible to every "
              "contributor. Run `recomp coordinator setup` for this project first.",
              file=sys.stderr)
    else:
        token_source, installation_id = sourced
        print(f"identity: coordinator App installation {installation_id}")
    viewer = None
    raw_trusted = github_cfg.get("trusted_actor_id")
    if sourced is not None and raw_trusted is not None:
        viewer = (int(raw_trusted), f"coordinator-app:{installation_id}")
    client = GitHubClient(args.api_url, owner, repository, token_source,
                          viewer=viewer)
    try:
        if args.action == "bootstrap":
            created = bootstrap_labels(client)
            print(f"labels ensured: {', '.join(created) if created else 'none missing'}")
            return 0
        result = sync_tasks(client, root, cfg, target=args.target)
        print(f"published {len(result.created)} new task issues "
              f"({len(result.existing)} already present)")
        return 0
    except (GitHubTaskError, GitHubError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


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


    if args.action == "doctor":
        return cmd_task_doctor(args)
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

        plugin_commands = {"plugin-run-task": "run-task", "plugin-verify": "verify"}

        def launch(arguments, *, target, project):
            action = plugin_commands[arguments[0]]
            return run_toolchain(runtime, ImageRef.parse(image), project, target,
                                 ["plugin", action, arguments[1]])

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


def cmd_coordinator(args) -> int:
    from recomp import coordinator_run
    from recomp.coordinator_setup import (
        CoordinatorPaths, SetupError, doctor, install_commands, microvm_pins,
        read_coordinator_config, render_service_unit, setup_coordinator,
    )

    paths = CoordinatorPaths.for_repository(args.owner, args.repository)
    try:
        if args.action == "machine-setup":
            from recomp.templates import coordinator_machine_setup

            script = coordinator_machine_setup()
            if args.output:
                target = Path(args.output)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(script)
                target.chmod(0o755)
                print(f"wrote {target}")
            else:
                print(script, end="")
            return 0

        if args.action == "setup":
            previous: dict = {}
            previous_pins: dict = {}
            if paths.config.is_file():
                try:
                    saved = read_coordinator_config(paths.config)
                    previous = dict(saved["coordinator"])
                    recorded = microvm_pins(saved)
                    previous_pins = dict(recorded.paths)
                    previous_pins["jail_root"] = recorded.jail_root
                except SetupError as exc:
                    print(f"warning: existing config is unusable ({exc}); pass every "
                          "value explicitly", file=sys.stderr)

            def value(flag, key, source: dict = previous):
                """Flag wins; otherwise keep whatever is already pinned."""

                if flag is not None:
                    return flag
                if source.get(key) is not None:
                    return source[key]
                raise SetupError(
                    f"--{key.replace('_', '-')} is required: {paths.config} has no "
                    "previous value to reuse")

            written = setup_coordinator(
                paths, owner=args.owner, repository=args.repository,
                app_id=value(args.app_id, "app_id"),
                installation_id=value(args.installation_id, "installation_id"),
                trusted_actor_id=value(args.trusted_actor_id, "trusted_actor_id"),
                image=value(args.image, "image"),
                project_root=value(args.project_root, "project_root"),
                firecracker=value(args.firecracker, "firecracker", previous_pins),
                jailer=value(args.jailer, "jailer", previous_pins),
                kernel=value(args.kernel, "kernel", previous_pins),
                rootfs=value(args.rootfs, "rootfs", previous_pins),
                jail_root=value(args.jail_root, "jail_root", previous_pins),
                target=args.target if args.target is not None else previous.get("target"),
                kvm_device=args.kvm_device, mke2fs=args.mke2fs, debugfs=args.debugfs,
                branch=args.branch or previous.get("branch") or "main",
                poll_interval_seconds=value(args.poll_interval, "poll_interval_seconds"))
            print(f"config: {written}")
            print(f"app key: {paths.app_key} (put the App's PEM there, mode 0600)")
            print("next: recomp coordinator doctor --owner ... --repository ...")
            return 0

        config_file = coordinator_run.config_path(args.owner, args.repository)
        config = read_coordinator_config(config_file) if config_file.is_file() else None

        if args.action == "doctor":
            report = doctor(paths=paths, config=config)
            print(json.dumps(report.as_mapping(), indent=2, sort_keys=True))
            return 0 if report.ok else 1

        if args.action == "install-service":
            if config is None:
                raise SetupError(
                    f"{config_file} is missing; run `recomp coordinator setup` first")
            pins = microvm_pins(config)
            import getpass
            unit = render_service_unit(
                paths, user=args.user or getpass.getuser(), owner=args.owner,
                repository=args.repository,
                executable=args.executable or str(Path(sys.executable).parent / "recomp"),
                jail_root=pins.jail_root,
                project_root=config["coordinator"]["project_root"],
                protect_home=args.protect_home)
            target = Path(args.output) if args.output else paths.state / "recomp-coordinator.service"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(unit)
            print(f"wrote {target}")
            for command in install_commands(target):
                print(command)
            return 0

        return coordinator_run.run_coordinator(
            owner=args.owner, repository=args.repository, target=args.target,
            max_passes=args.max_passes)
    except (SetupError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_toolchain_rootfs(args) -> int:
    from recomp.project import ProjectError, load_project
    from recomp.rootfs import RootfsError, build_rootfs_from_image

    project = Path(args.project) if args.project else Path.cwd()
    try:
        cfg, _ = load_project(project)
        image = args.image or cfg.get("toolchain", {}).get("image")
        if not image:
            raise RootfsError("no pinned toolchain image: pass --image or set "
                              "[toolchain] image in recomp.toml")
        digest = build_rootfs_from_image(image, args.output, runtime=args.runtime)
    except (ProjectError, RootfsError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"rootfs: {args.output}\nsha256: {digest}")
    print("record it with `recomp coordinator setup --rootfs ...`")
    return 0


def cmd_task_doctor(args) -> int:
    from recomp.contributor_doctor import contributor_doctor, render_text

    report = contributor_doctor(args.project or os.getcwd(), target=args.target)
    print(render_text(report))
    return 0 if report.ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recomp",
        description="GitHub-coordinated binary recovery: one repository, "
                    "Issue-claimed tasks, microVM-verified pull requests")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="scaffold a GitHub-coordinated recovery repository")
    init.add_argument("path")
    init.add_argument("--bin",
                      help="your own copy of the target; hashed, never copied into the repo")
    init.add_argument("--no-target", action="store_true",
                      help="generate a project that pins no target binary")
    init.add_argument("--protected-path", action="append", default=[],
                      metavar="PATH",
                      help="maintainer-owned path or prefix contributors may not touch "
                           "(repeatable; written to [policy] protected_paths)")
    init.add_argument("--toolchain-image", required=True,
                      help="digest-pinned image: ghcr.io/owner/name@sha256:<64hex>")
    init.add_argument("--framework-action", required=True,
                      help="commit-pinned framework action: owner/repo@<40hex>")
    init.add_argument("--name")
    init.add_argument("--owner", default="OWNER", help="GitHub owner of the new repository")
    init.add_argument("--repository", help="GitHub repository name (defaults to project name)")
    init.add_argument("--trusted-actor-id", type=int, default=0,
                      help="numeric actor id of the coordinator GitHub App bot")
    init.add_argument("--goal", default="structure",
                      choices=["assets", "structure", "recomp", "bytematch"])
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
    plug.add_argument("action", choices=["new", "check", "test", "run-task", "verify"])
    plug.add_argument("name", nargs="?")
    plug.add_argument("--target", help="your own copy of the target")
    plug.add_argument("--capability", default="scan",
                      choices=["detect", "scan", "extract", "toolchain", "work", "verify", "port"])
    plug.set_defaults(func=cmd_plugin)

    wf = sub.add_parser("workflow", help="inspect/lock the pinned verification policy")
    wf.add_argument("action", choices=["show", "lock"])
    wf.set_defaults(func=cmd_workflow)

    gh = sub.add_parser("github", help="publish tasks and repository scaffolding")
    gh.add_argument("action", choices=["bootstrap", "sync-tasks"])
    gh.add_argument("--target", help="your own copy of the target, for work planning")
    gh.add_argument("--api-url", default="https://api.github.com")
    gh.set_defaults(func=cmd_github)

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
    tool_rootfs = tool_sub.add_parser(
        "rootfs", help="export the pinned image's guest root filesystem for the microVM")
    tool_rootfs.add_argument("--output", required=True,
                             help="ext4 image to write (record it with coordinator setup)")
    tool_rootfs.add_argument("--image", help="override the project's pinned image")
    tool_rootfs.add_argument("--project", help="project root (default: cwd)")
    tool_rootfs.set_defaults(func=cmd_toolchain_rootfs)

    task = sub.add_parser("task", help="contributor workflow: doctor, claim, run, verify, submit")
    task.add_argument("action", choices=["doctor", "next", "start", "heartbeat", "run",
                                         "verify", "submit", "status"])
    task.add_argument("url", nargs="?", help="repository or Issue link")
    task.add_argument("--target", help="path to your own copy of the target file")
    task.add_argument("--project", help="project checkout root (default: cwd)")
    task.add_argument("--api-url", default="https://api.github.com")
    task.set_defaults(func=cmd_task)

    coord = sub.add_parser("coordinator", help="owner operations: setup, doctor, service")
    coord.add_argument("action", choices=["setup", "doctor", "install-service", "run",
                                          "machine-setup"])
    coord.add_argument("--owner", required=True)
    coord.add_argument("--repository", required=True)
    coord.add_argument("--user", help="account the service runs as "
                                      "(default: you, for an owner-run coordinator)")
    coord.add_argument("--output", help="where to render the systemd unit "
                                        "(machine-setup: where to write the script)")
    coord.add_argument("--executable", help="recomp entry point for ExecStart")
    coord.add_argument("--protect-home", default="read-only",
                       choices=["yes", "no", "read-only", "tmpfs"],
                       help="ProtectHome= for the unit (read-only suits an owner-run "
                            "coordinator that reads your target copy)")
    coord.add_argument("--max-passes", type=int, help="stop after N passes (smoke tests)")
    coord.add_argument("--app-id", type=int)
    coord.add_argument("--installation-id", type=int)
    coord.add_argument("--trusted-actor-id", type=int)
    coord.add_argument("--image", help="digest-pinned toolchain image: repo@sha256:<64hex>")
    coord.add_argument("--project-root", help="local checkout of the project repository")
    coord.add_argument("--firecracker", help="firecracker binary to pin")
    coord.add_argument("--jailer", help="jailer binary to pin")
    coord.add_argument("--kernel", help="pinned kernel image")
    coord.add_argument("--rootfs", help="pinned guest rootfs (recomp toolchain rootfs)")
    coord.add_argument("--jail-root", help="private 0700 directory for microVM jails")
    coord.add_argument("--target", help="pinned target binary (or RECOMP_TARGET)")
    coord.add_argument("--kvm-device", help="KVM device (default: /dev/kvm)")
    coord.add_argument("--mke2fs", help="mke2fs path (default: /sbin/mke2fs)")
    coord.add_argument("--debugfs", help="debugfs path (default: /sbin/debugfs)")
    coord.add_argument("--branch", help="branch progress commits target (default: main)")
    coord.add_argument("--poll-interval", type=int, help="seconds between passes (default: 60)")
    coord.set_defaults(func=cmd_coordinator)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
