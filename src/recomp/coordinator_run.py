"""Production wiring: `config.toml` → App auth → pinned plugin → microVMs → loop.

One process, one outbound HTTPS connection, no inbound port. Every artifact that
verification will later depend on is re-measured here at start-up — the pinned
guest binaries by `doctor`, the target by its recorded hash and size, the plugin
by its file hashes inside `VerificationPlan` — so a host that drifted since
`coordinator setup` refuses to start rather than quietly judging candidates with
the wrong tools.

The trust anchor is `trusted_actor_id`: the numeric user id of the App bot that
published the task records. It is read from the config exactly like the App
identifiers, because a coordinator that guessed it would accept a lookalike
bot's comments as leases.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from recomp.coordinator import Coordinator, CoordinatorConfig, framework_revision
from recomp.coordinator_setup import (
    CoordinatorPaths,
    SetupError,
    doctor,
    read_coordinator_config,
)
from recomp.firecracker import FirecrackerRunner, GuestError, load_pinned_config
from recomp.github_api import (
    GitHubAppCredentials,
    GitHubClient,
    InstallationTokenProvider,
)
from recomp.plugin import PluginError, resolve_plugin
from recomp.progress import collect_progress, commit_progress_update
from recomp.project import (
    ProjectError,
    has_target,
    load_project,
    protected_paths,
    validate_target,
)
from recomp.verification import VerificationPlan

#: Set by `install-service`; overrides the per-repository config location.
ENV_CONFIG = "RECOMP_COORDINATOR_CONFIG"
#: Optional override for the pinned target path (the owner keeps the binary).
ENV_TARGET = "RECOMP_TARGET"
#: systemd `LoadCredential=` directory; the App key arrives there in the service.
ENV_CREDENTIALS = "CREDENTIALS_DIRECTORY"
CREDENTIAL_NAME = "app-key"

DEFAULT_BRANCH = "main"


@dataclass(frozen=True)
class CoordinatorWiring:
    """A fully checked coordinator, ready to run."""

    coordinator: Coordinator
    paths: CoordinatorPaths
    config: Mapping[str, Any]
    project_root: Path
    target: Path | None
    plugin_name: str
    mode: str
    toolchain_image: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SetupError(message)


def config_path(owner: str, repository: str, *, home: str | Path | None = None,
                environ: Mapping[str, str] | None = None) -> Path:
    """Where `coordinator run` reads its config, honouring the service override."""

    environment = os.environ if environ is None else environ
    override = environment.get(ENV_CONFIG)
    if override:
        return Path(override)
    return CoordinatorPaths.for_repository(owner, repository, home=home).config


def app_key_path(paths: CoordinatorPaths, *, environ: Mapping[str, str] | None = None,
                 exists: Callable[[Path], bool] = lambda path: Path(path).is_file(),
                 ) -> tuple[Path, bool]:
    """Return (key path, is_systemd_credential) — the credential form is root-owned."""

    environment = os.environ if environ is None else environ
    directory = environment.get(ENV_CREDENTIALS)
    if directory:
        supplied = Path(directory) / CREDENTIAL_NAME
        if exists(supplied):
            return supplied, True
    return paths.app_key, False


def app_token_source(owner: str, repository: str, *,
                     home: str | Path | None = None,
                     environ: Mapping[str, str] | None = None,
                     api_url: str | None = None,
                     ) -> tuple[Callable[[], str], int] | None:
    """Installation-token callable for the project's coordinator App, or None.

    `recomp github` must publish under the App identity: contributor and
    coordinator trust decisions hang on the author id, so a personal-token
    publish produces Issues that nobody can claim. Returns (token,
    installation_id) with no network access at construction. Raises SetupError
    when a coordinator config exists but its App key is missing — a half-built
    setup must say so instead of silently downgrading identity.
    """

    environment = os.environ if environ is None else environ
    config_file = config_path(owner, repository, home=home, environ=environment)
    if not config_file.is_file():
        return None
    config = read_coordinator_config(config_file)
    recorded = config["coordinator"]
    paths = CoordinatorPaths.for_repository(owner, repository, home=home)
    key, root_owned = app_key_path(paths, environ=environment)
    if not key.is_file():
        raise SetupError(
            f"GitHub App private key is missing: {key}; run "
            "`recomp coordinator setup` and install the App key at that path")
    credentials = GitHubAppCredentials(
        app_id=int(recorded["app_id"]),
        installation_id=int(recorded["installation_id"]),
        private_key=key,
        root_owned_credential=root_owned,
    )
    base_url = str(api_url or recorded.get("api_url") or "https://api.github.com")
    tokens = InstallationTokenProvider(credentials, base_url=base_url)
    return tokens.token, int(recorded["installation_id"])


def load_wiring(
    *,
    owner: str,
    repository: str,
    home: str | Path | None = None,
    target: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
    api_url: str | None = None,
) -> CoordinatorWiring:
    """Build the production coordinator, refusing anything that is not pinned."""

    environment = os.environ if environ is None else environ
    paths = CoordinatorPaths.for_repository(owner, repository, home=home)
    config_file = config_path(owner, repository, home=home, environ=environment)
    config = read_coordinator_config(config_file)
    recorded = config["coordinator"]

    # A unit file and a config directory that name different repositories would
    # otherwise have the coordinator verify one project and merge into another.
    _require(str(recorded["owner"]) == owner and str(recorded["repository"]) == repository,
             f"config at {config_file} describes "
             f"{recorded['owner']}/{recorded['repository']}, not {owner}/{repository}")

    project_root = Path(str(recorded["project_root"]))
    _require(project_root.is_dir(), f"project_root does not exist: {project_root}")
    cfg, _ = load_project(project_root)

    key, root_owned = app_key_path(paths, environ=environment)
    _require(key.is_file(),
             f"GitHub App private key is missing: {key}; run "
             "`recomp coordinator setup` and install the App key at that path")

    plugin_name = str(cfg["project"]["plugin"])
    try:
        plugin = resolve_plugin(project_root, plugin_name)
        plan = VerificationPlan.from_plugin(plugin)
    except (PluginError, ValueError) as exc:
        raise SetupError(f"plugin {plugin_name!r} is not usable for verification: {exc}") from exc
    _require(plan.public,
             f"plugin {plugin_name!r} has no separable public verification plan; "
             "it is maintainer-only and cannot accept public pull requests")

    # The host and the project must agree on the toolchain image: the task records
    # carry a toolchain digest derived from it, and a mismatch silently invalidates
    # every candidate the coordinator is about to build.
    project_image = str(cfg.get("toolchain", {}).get("image", ""))
    _require(project_image,
             f"{project_root / 'recomp.toml'} is missing [toolchain] image")
    _require(str(recorded["image"]) == project_image,
             f"coordinator config pins image {recorded['image']!r} but the project pins "
             f"{project_image!r}; re-run `recomp coordinator setup --image <digest-ref>`")

    target_path: Path | None = None
    if has_target(cfg):
        supplied_target = (target or environment.get(ENV_TARGET)
                           or recorded.get("target") or None)
        _require(supplied_target is not None,
                 "the pinned target binary is not configured; pass --target <path> or set "
                 f"{ENV_TARGET}, and record it with `recomp coordinator setup`")
        target_path = Path(str(supplied_target))
        try:
            validate_target(target_path, cfg)
        except (ProjectError, OSError, ValueError) as exc:
            raise SetupError(
                f"target {target_path} does not match the project's pin "
                f"(expected {cfg['target']['filename']}, sha256 {cfg['target']['sha256']}, "
                f"size {cfg['target']['size']}): {exc}") from exc

    credentials = GitHubAppCredentials(
        app_id=int(recorded["app_id"]),
        installation_id=int(recorded["installation_id"]),
        private_key=key,
        root_owned_credential=root_owned,
    )
    base_url = str(api_url or recorded.get("api_url") or "https://api.github.com")
    tokens = InstallationTokenProvider(credentials, base_url=base_url)
    github = GitHubClient(base_url, owner, repository, tokens.token)

    branch = str(recorded.get("branch") or DEFAULT_BRANCH)

    def publish_progress(now: int) -> Any:
        snapshot = collect_progress(github, project=str(cfg["project"]["name"]),
                                    trusted_actor_id=int(recorded["trusted_actor_id"]),
                                    now=now)
        return commit_progress_update(github, snapshot, branch=branch, now=now)

    state = paths.state
    state.mkdir(parents=True, exist_ok=True)
    coordinator = Coordinator(
        config=CoordinatorConfig(
            repository_url=str(recorded.get("repository_url")
                               or f"https://github.com/{owner}/{repository}.git"),
            repository_full_name=f"{owner}/{repository}",
            trusted_actor_id=int(recorded["trusted_actor_id"]),
            quarantine_root=state / "quarantine",
            state_path=state / "candidates.db",
            health_path=state / "health.json",
            poll_interval_seconds=int(recorded.get("poll_interval_seconds") or 60),
            protected_paths=protected_paths(cfg),
        ),
        github=github,
        plan=plan,
        runner=FirecrackerRunner(load_pinned_config(config_file)),
        target=target_path,
        publish_progress=publish_progress,
    )
    return CoordinatorWiring(
        coordinator=coordinator, paths=paths, config=config, project_root=project_root,
        target=target_path, plugin_name=plugin_name, mode=plan.mode,
        toolchain_image=project_image,
    )


def run_coordinator(
    *,
    owner: str,
    repository: str,
    home: str | Path | None = None,
    target: str | Path | None = None,
    max_passes: int | None = None,
    environ: Mapping[str, str] | None = None,
    api_url: str | None = None,
    report: Callable[[str], None] = lambda line: print(line, file=sys.stderr, flush=True),
) -> int:
    """Verify, merge, and publish until stopped; 0 clean, 1 runtime, 2 refuse to start."""

    log_sink: Any = None

    def emit(line: str) -> None:
        """Report to the operator and to a file the operator can actually read.

        The loop runs under `sudo setpriv`, so its stdout belongs to a privileged
        pty an unprivileged session cannot open: without this file, diagnosing a
        refusal means guessing from `health.json` alone.
        """

        report(line)
        if log_sink is not None:
            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            try:
                log_sink.write(f"{stamp} {line}\n")
                log_sink.flush()
            except OSError:
                pass

    try:
        paths = CoordinatorPaths.for_repository(owner, repository, home=home)
        config_file = config_path(owner, repository, home=home, environ=environ)
        config = read_coordinator_config(config_file)
    except SetupError as exc:
        report(f"error: {exc}")
        return 2

    try:
        paths.state.mkdir(parents=True, exist_ok=True)
        log_sink = open(paths.state / "coordinator.log", "a", encoding="utf-8")
    except OSError:
        log_sink = None

    health = doctor(paths=paths, config=config)
    errors = [finding for finding in health.findings if finding.severity == "error"]
    if errors:
        for finding in errors:
            emit(f"error: {finding.check_id}: {finding.observed} — {finding.remediation}")
        emit("error: the coordinator refuses to start until doctor is green")
        return 2

    try:
        wiring = load_wiring(owner=owner, repository=repository, home=home, target=target,
                             environ=environ, api_url=api_url)
    except (SetupError, ProjectError, GuestError) as exc:
        report(f"error: {exc}")
        return 2

    emit(f"coordinator {owner}/{repository}: plugin {wiring.plugin_name} "
         f"mode {wiring.mode}, image {wiring.toolchain_image}, "
         f"framework {framework_revision()[:12]}")
    try:
        wiring.coordinator.run_loop(max_passes=max_passes)
    except KeyboardInterrupt:
        emit("coordinator stopped on interrupt")
        return 0
    except Exception as exc:
        # The loop already absorbs GitHub and guest failures; reaching here means a
        # host-side bug, and the service restarts under `Restart=on-failure`.
        emit(f"error: coordinator loop failed: {type(exc).__name__}: {exc}")
        return 1
    return 0
