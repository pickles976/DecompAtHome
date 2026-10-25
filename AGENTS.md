# AGENTS.md — recomp (RecompAtHome)

recomp is a self-hostable decompilation-collaboration platform: `recomp init`
scaffolds a project for any binary, the host's agent extends the workflow with
project-local plugins, `recomp serve` accepts submissions over HTTPS, and
contributors (humans or AI agents) join with one link and loop
claim → produce → submit. Only verifier-confirmed artifacts count.

This file onboards two audiences: **hosts** (people and agents running a
project) and **contributors** (agents doing recovery work in a generated
project). Read the section that matches you, in full, before working.

## Mental model

- **Project** = one recovery target: `recomp.toml` + `recovery/` (artifacts) +
  `plugins/` (the workflow) + `server/` (coordination state) + optional
  `port/` (engine port consuming recovery snapshots).
- **Plugin** = the decompilation workflow: what work exists (`work_plan`), how
  a task executes (`run_task`), and how the verifier judges it (`verify`).
  Plugins are project-local, shadowing built-ins by name.
- **Policy** = the content hash of `recomp.toml` + every plugin file, versioned
  in `recomp.lock.toml`. The server pins one policy version; submissions carry
  the version they were produced under and stale-policy submissions are
  refused (HTTP 412).
- **Tiers** = how far recovery can go: `t0-assets` (extract models/textures/
  audio), `t1-structure` (strings, symbols, layout), `t2-recomp`
  (behavioral reconstruction), `t3-bytematch` (needs the original toolchain
  pinned), `t4` engine port. `recomp init` never claims a tier it cannot
  verify; byte-match requires `--toolchain`.

## Host quick start

```bash
python3 -m recomp init mygame --bin /path/to/game.exe \
  [--goal structure|assets|recomp|bytematch] [--toolchain msvc-7.1] \
  [--assets model:glb texture:png audio:wav] [--port-target bevy] [--trust invited]
cd mygame
python3 -m recomp plugin test generic   # workflow self-test
python3 -m recomp serve                 # dashboard + API on :7331
python3 -m recomp admin token           # one-time invite token
```

Contributors then run: `recomp join http://host:7331 --token <tok> --name seat1`
followed by `recomp work --loop`. The server mints the owner key into
`server/keys/owner.key` on first start (0600, gitignored). Owner API routes:
`POST /api/admin/keys` (`mint-token` / `grant` / `revoke`),
`POST /api/admin/reload` (re-pin policy after workflow edits).

Trust tiers gate hardening: `solo` (local containers, no enrollment),
`invited` (keys + process sandbox, this P0), `public` (disposable microVMs,
egress-denied — not yet implemented; do not expose `public` today).

## Host lane: extending the workflow (do this BEFORE onboarding contributors)

The host's agent modifies tooling and the decompilation workflow itself. All
of it lives in the project, versioned by git and pinned by the policy lock:

1. **Add tooling**: `recomp plugin new <name> --capability scan|extract|...`
   scaffolds `plugins/<name>/` (manifest, runner stub, prompt). Project
   plugins shadow built-ins; point `recomp.toml`'s `[project] plugin` at the
   new one when it supersedes `generic`.
2. **Modify the workflow**: edit the plugin's `runner.py` commands
   (`work-plan` defines tasks and each task's declared output path; `run-task`
   produces it deterministically; `verify` independently recomputes and
   compares — never trust submission input), and `prompt.md` (the contributor
   prompt handed to agents, Open-BFME style).
3. **Validate**: `recomp plugin check <name>` (manifest + capability rules),
   `recomp plugin test <name>` (selftest command).
4. **Version and pin**: `recomp workflow lock` bumps `policy_version`; then
   restart `recomp serve` or POST `/api/admin/reload`. In-flight submissions
   from the old policy are refused with 412 until workers re-claim — that is
   intentional.
5. **Commit** plugin + lockfile changes together in the project repo. Tooling
   changes are maintainer-lane: they never travel through the contributor
   submission pipeline.

Hard rules for the host lane: commands in manifests are argv lists (no shell
strings; interpreters limited to python3); runners are sandboxed (rlimits,
clean env, no network egress by policy, timeouts); `verify` must recompute
from the pinned binary, never echo submitted bytes back as truth.

## Contributor quick start (agents)

1. `recomp join <server-url> --token <your-token> --name <seat>` (token is
   single-use; keep your worker key in `.recomp/worker.json` private).
2. Read the generated project's `AGENTS.md`, then fetch the live contributor
   prompt: `recomp prompt --url <server-url>` (also `GET /api/prompt`).
3. `recomp work --once` (or `--loop`). Each claim returns one task manifest:
   kind, args, and the exact output path you may write. Produce exactly that
   output, deterministically, from `bin/` (hash-pinned).
4. Submission verdicts: `merged` (verifier confirmed), `rejected` (your output
   did not recompute — the item reopens for anyone), `409` (stale claim —
   claim again, never resubmit), `412` (policy changed — re-read the prompt).
5. Report at the end: items claimed/merged/rejected, policy version worked
   under, your real model name, minutes per item, abandoned items and why.

Contributors never edit `plugins/`, `recomp.toml`, `server/`, `bin/`, or
anything outside their claimed task's declared output path.

## This repository (developing recomp itself)

- Layout: `src/recomp/` (package) · `src/recomp/builtin_plugins/generic/`
  (reference plugin) · `src/recomp/templates/` (dashboard, project AGENTS.md,
  plugin scaffolds, default prompt) · `tests/` (pytest, stdlib only).
- Runtime dependencies: none beyond Python ≥3.11 stdlib. Keep it that way.
- Conventions: every behavior change lands test-first (`python3 -m pytest`);
  security invariants (fencing tokens, path checks, sandbox limits, policy
  versioning) must keep dedicated tests; CLI is `python3 -m recomp` until
  installed via pip.
- Key modules: `detect.py` (target identification) · `generate.py` (init) ·
  `plugin.py` (manifests + sandbox) · `policy.py` (lock/hash) · `state.py`
  (keys, leases, submissions) · `server.py` (API + dashboard) · `worker.py`
  (join/claim/submit) · `prompt.py` (contributor prompt rendering).
- Roadmap order: Discord front-end → `win32-msvc`/Unity/Godot adapters →
  Firecracker verify sandbox for the `public` trust tier → asset extraction
  (glb/png/wav) lanes → port templates.

## Safety and legal defaults

- Original binaries and extracted game assets never enter git; they are
  hash-pinned in `recomp.toml` and each contributor supplies their own copy.
- Submissions are quarantined, size/path/type-checked, then verified in a
  sandbox with no secrets. Nothing a contributor submits executes on the host
  outside that sandbox in `invited` mode.
- Projects default unlisted. Respect upstream projects' stance on AI
  contributions; never point this tool at a project that has not opted in.
