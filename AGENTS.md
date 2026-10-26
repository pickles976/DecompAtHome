# AGENTS.md — recomp (Recomp@Home)

Recomp@Home coordinates binary decompilation on GitHub. Fork Recomp@Home, give
the fork to your coordinator agent, customize the workflow for your target,
then generate a **separate project repository**. Contributors receive only
that project's repository or Issue link.

This file onboards three audiences: **owners** (people and agents running a
coordinator), **contributors** (agents doing recovery work in a generated
project), and **developers of recomp itself**. Read the section that matches
you, in full, before working.

## Mental model

- **Fork** = the framework plus your workflow: `plugins/` (what work exists
  and how it is judged), `toolchain/` (the contributor image recipe).
- **Project repository** = one recovery target: `recomp.toml` (target pinned
  by hash, never its bytes) + `recovery/` (artifacts) + task Issues +
  `docs/progress.{json,svg}` + generated `.github/` workflows.
- **Coordinator** = a process on the owner's Linux machine. It polls GitHub,
  reconstructs candidates, verifies them in Firecracker microVMs, merges with
  `expected_head_sha`, and publishes progress. It never opens an inbound port.
- **Policy** = the content hash of `recomp.toml`, every plugin file, every
  toolchain file, and the generated launcher, versioned in `recomp.lock.toml`.
  Pull requests declaring a stale policy fail preflight.
- **Lease** = a two-hour claim on one task, owned by one identity, recorded by
  the coordinator App as a trusted Issue comment. Only the current claimant's
  pull request is admitted.
- **Tiers** = how far recovery can go: `t0-assets`, `t1-structure`,
  `t2-recomp`, `t3-bytematch` (needs the original toolchain pinned), `t4`
  engine port. `recomp init` never claims a tier it cannot verify.

## Owner quick start

```bash
recomp plugin new my-workflow --capability work   # shape the workflow
recomp plugin check my-workflow && recomp plugin test my-workflow
recomp workflow lock

recomp toolchain build --source toolchain \
  --base-image docker.io/library/python@sha256:<64hex> \
  --destination ghcr.io/<you>/<game>-toolchain:build-1
# pushes land on GHCR because buildx attestations are disabled automatically

recomp init ../mygame --bin /path/to/game.exe \
  --owner <you> --repository mygame \
  --toolchain-image ghcr.io/<you>/<game>-toolchain@sha256:<64hex> \
  --framework-action <you>/RecompAtHome@<40hex> \
  --trusted-actor-id <app-bot-user-id>

recomp coordinator machine-setup --output /tmp/recomp-machine-setup.sh
bash /tmp/recomp-machine-setup.sh   # pins Firecracker guest by digest; uses sudo
recomp coordinator doctor --owner <you> --repository mygame
recomp coordinator install-service --owner <you> --repository mygame
cd ../mygame && recomp github bootstrap && recomp github sync-tasks --target /path/to/game.exe
```

Full procedure, including GitHub App permissions, rulesets, systemd, backup,
rotation, break-glass, and uninstall: [`docs/coordinator-setup.md`](docs/coordinator-setup.md).

## Host lane: extending the workflow (do this BEFORE publishing tasks)

1. **Add tooling**: `recomp plugin new <name> --capability scan|extract|...`
   scaffolds `plugins/<name>/` (manifest, runner stub, prompt). Project
   plugins shadow built-ins; point `recomp.toml`'s `[project] plugin` at the
   new one when it supersedes `generic`.
2. **Modify the workflow**: edit the plugin's `runner.py` (`work-plan` defines
   tasks and each task's declared `outputs`; `run-task` produces them
   deterministically; `verify` independently recomputes and compares — never
   trust submission input) and `prompt.md` (the contributor prompt).
3. **Declare how it can be judged publicly**: `[verify] mode/public/
   timeout_seconds/max_artifact_bytes`, plus `candidate_build`,
   `candidate_run`, `oracle_run`, and `[verify.protocol]` for behavioral mode.
   A plugin without a separable public plan is maintainer-only.
4. **Validate**: `recomp plugin check <name>`, `recomp plugin test <name>`.
5. **Version and pin**: `recomp workflow lock` bumps `policy_version`; commit
   the lockfile and restart the coordinator. In-flight pull requests from the
   old policy fail preflight until workers re-claim — that is intentional.

Hard rules: manifest commands are argv lists (no shell strings; interpreters
limited to python3); runners are sandboxed; `verify` must recompute from the
pinned target, never echo submitted bytes back as truth; and the candidate
must never be given the target. Host-run plugin commands get a scrubbed
environment (`HOME` = plugin root; `RUSTUP_HOME`/`CARGO_HOME`/
`RUSTUP_TOOLCHAIN` propagated): `RLIMIT_NPROC` defaults to 512 and
`RLIMIT_AS` to 512 MiB, settable via `[verify] sandbox_nproc` and
`[verify] sandbox_memory_mib`; host-side command timeouts via
`[verify] sandbox_timeout_seconds`. The container `/tmp` mount carries `exec`
because Docker adds `noexec` unless requested.

## Contributor quick start (agents)

```bash
recomp task next <repository-url>
recomp task start <issue-url> --target /path/to/your/copy
recomp task run && recomp task verify
recomp task submit
```

Claims last two hours; `recomp task heartbeat` renews. Only merged pull
requests count. Contributors never edit `.github/`, `plugins/`, `toolchain/`,
`recomp.toml`, `recomp.lock.toml`, `recomp-launcher`, or `docs/progress.*`.
Details: [`docs/contributor-workflow.md`](docs/contributor-workflow.md).

Report at the end: tasks claimed/merged/rejected, policy version worked under,
your real model name, minutes per task, abandoned tasks and why.

## This repository (developing recomp itself)

- Layout: `src/recomp/` (package) · `src/recomp/builtin_plugins/generic/`
  (reference plugin) · `src/recomp/templates/` (project README/AGENTS,
  workflows, launcher, Containerfile, systemd unit, plugin scaffolds) ·
  `.github/actions/` (the trusted composite actions) · `tests/` (pytest,
  stdlib only).
- Runtime dependencies: none beyond Python ≥3.11 stdlib. Keep it that way.
- Conventions: every behavior change lands test-first (`python3 -m pytest`);
  security invariants (trusted actor id, lease generations, path checks, guest
  isolation, policy versioning, exact-head merge) must keep dedicated tests.
- Key modules: `contracts.py` (immutable public types) · `github_api.py`
  (App auth + bounded REST) · `task_records.py` · `claims.py` (two-hour
  leases) · `preflight.py` · `candidate.py` (Git plumbing) · `toolchain.py` ·
  `firecracker.py` + `guest.py` (microVM) · `verification.py` (candidate/
  oracle split) · `coordinator.py` + `coordinator_state.py` · `merge.py` ·
  `progress.py` · `task_cli.py` (contributor) · `coordinator_setup.py`
  (owner) · `generate.py` (project scaffolding).
- Threat model: [`docs/security-model.md`](docs/security-model.md). Read it
  before changing anything that touches isolation or trust.

## Safety and legal defaults

- Original binaries and extracted game assets never enter git; targets are
  hash-pinned and each contributor supplies their own copy.
- Untrusted code runs only in a disposable microVM with no network, no vsock,
  and no host filesystem passthrough; the original target is never present in
  the guest that runs contributor code.
- Verification publishes stable reason codes and counts only — never raw
  logs, host paths, or target bytes.
- Respect upstream projects' stance on AI contributions; never point this tool
  at a project that has not opted in.
