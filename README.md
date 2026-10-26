# Recomp@Home

Self-hosted coordination for binary decompilation with AI.

Fork Recomp@Home, give the fork to your coordinator agent, customize the
workflow for your target, then generate a **separate** decompilation project
repository. Contributors receive only that project's repository or task link.

Your agent defines what work exists; contributors claim tasks on GitHub Issues
and work in parallel. Every pull request is reverified from the pinned target
in a disposable microVM before it can merge.

## Two repositories, two roles

| Repository | Who touches it | What it holds |
| --- | --- | --- |
| **This fork** | you and your coordinator agent | the framework, your workflow plugin, your toolchain image recipe |
| **The generated project** | contributors (and your coordinator App) | task Issues, recovered artifacts, progress image. No target bytes. |

## Owner lifecycle

Requires Linux with KVM for public verification, Python 3.11+, Git 2.38+,
Docker or Podman, and a GitHub App you control.

```bash
git clone https://github.com/<you>/RecompAtHome.git && cd RecompAtHome
python3 -m venv .venv && . .venv/bin/activate && python -m pip install -e .

# 1. Shape the workflow for your target (this fork)
recomp plugin new my-workflow --capability work
recomp plugin check my-workflow && recomp plugin test my-workflow
recomp workflow lock

# 2. Build and push the immutable toolchain image
recomp toolchain build --source toolchain \
  --base-image docker.io/library/python@sha256:<64hex> \
  --destination ghcr.io/<you>/<game>-toolchain:build-1
# prints exactly: ghcr.io/<you>/<game>-toolchain@sha256:<64hex>

# 3. Generate the project repository (target is hashed, never copied)
recomp init ../mygame --bin /path/to/game.exe --goal structure \
  --owner <you> --repository mygame \
  --toolchain-image ghcr.io/<you>/<game>-toolchain@sha256:<64hex> \
  --framework-action <you>/RecompAtHome@<40hex> \
  --trusted-actor-id <app-bot-user-id>

# 4. Install the coordinator on your own machine
recomp coordinator doctor --owner <you> --repository mygame
recomp coordinator install-service --owner <you> --repository mygame

# 5. Publish work
cd ../mygame && recomp github bootstrap && \
  recomp github sync-tasks --target /path/to/game.exe
```

Full walkthrough: [`docs/coordinator-setup.md`](docs/coordinator-setup.md).

A project that recovers from sources rather than from a shipped binary pins no
target at all: use `recomp init ../myport --no-target …` and omit `--target`
everywhere after that (`recomp github sync-tasks`, `recomp task run|verify|submit`,
`recomp task doctor`). Such a project has no `[target]` table in `recomp.toml`.

Maintainer-owned paths beyond the built-in ones (`.github/`, `plugins/`,
`toolchain/`, `recomp.toml`, …) are declared once and enforced by preflight:

```toml
[policy]
protected_paths = ["goldens/", "reference/", "tools/", "scripts/"]
```

`recomp init --protected-path goldens/ --protected-path tools/` writes that table.

## Contributor lifecycle

A contributor needs a repository or Issue link, their own copy of the target,
and Docker or Podman:

```bash
recomp task next https://github.com/<you>/mygame
recomp task start https://github.com/<you>/mygame/issues/12 --target ./game.exe
recomp task run && recomp task verify
recomp task submit
```

`start` comments `/claim`; claims last two hours and `recomp task heartbeat`
renews them. `submit` refuses to push anything outside the task's declared
output paths. Details: [`docs/contributor-workflow.md`](docs/contributor-workflow.md).

## How a pull request becomes a merge

1. A fork-safe Action runs a cheap, secret-free preflight on the tree.
2. Your coordinator reconstructs the exact merge tree with Git plumbing (no
   checkout, no filters, no hooks) and verifies it inside a Firecracker
   microVM. Contributor code and the original target never share a guest.
3. On success the pull request merges with `expected_head_sha`, the Issue
   closes, and `docs/progress.svg` is regenerated in one Git-data commit.

Anything that moved between verification and merge — head, base, policy,
toolchain, lease — invalidates the attestation instead of retrying it.

## Progress image

Each generated project publishes `docs/progress.json` and a static
`docs/progress.svg` rendered from trusted Issue records only: fixed shapes,
escaped labels, no script, no external URLs, no contributor-controlled markup.
Its README embeds the SVG, so the repository's front page is always current.

## Security boundary

- Contributors supply their own target; it is mounted read-only into the
  pinned image and never uploaded, committed, or referenced by path.
- Untrusted code never executes on the coordinator host, only in a disposable
  guest with no network, no vsock, and no host filesystem passthrough.
- Byte-match and behavioral comparisons happen on digests in the host control
  process, so no artifact or target bytes cross a guest boundary.
- Verification publishes stable reason codes and counts — never raw logs,
  host paths, or target bytes.
- `.github/`, `plugins/`, `toolchain/`, `recomp.toml`, `recomp.lock.toml`, and
  `recomp-launcher` are maintainer-owned and refused by preflight.

Threat model: [`docs/security-model.md`](docs/security-model.md).

## Current scope

- Runtime dependencies: Python standard library only.
- The coordinator is Linux-only; KVM is mandatory for public verification.
- Residual risk is concentrated in the guest kernel and Firecracker itself;
  see the threat model before pointing this at an untrusted audience.
- Respect upstream projects' stance on AI contributions; never point this tool
  at a project that has not opted in.

See [`AGENTS.md`](AGENTS.md) for host, contributor, and development workflows.

## Development

```bash
python -m pip install -e .
pytest -q
```

MIT licensed.
