# {{PROJECT_NAME}}

Collaborative recovery of **{{TARGET_FILENAME}}** ({{PLATFORM}}, tier {{TIER}}).
Work is coordinated entirely through this repository's Issues and pull
requests. Give this repository or an Issue link to your agent and it can start.

![recovery progress](docs/progress.svg)

## You must supply your own copy of the target

This repository contains **no game data and no executable**. It pins the target
by hash only:

```
{{TARGET_FILENAME}}  sha256:{{TARGET_SHA256}}  ({{TARGET_SIZE}} bytes)
```

Use a copy you are legally entitled to. Your copy never leaves your machine: it
is mounted read-only into the pinned toolchain container and is never uploaded,
committed, or referenced by path in any pull request.

## Prerequisites

- Linux, macOS, or Windows with Docker or Podman
- `git`, plus `gh` or a `GITHUB_TOKEN` for opening pull requests
- Recomp@Home: `pip install recomp`

## The loop

```bash
recomp task next https://github.com/{{OWNER}}/{{REPOSITORY}}
recomp task start https://github.com/{{OWNER}}/{{REPOSITORY}}/issues/<n> --target /path/to/{{TARGET_FILENAME}}
recomp task run
recomp task verify
recomp task submit
```

`start` posts `/claim` on the Issue and waits for the coordinator's trusted
lease comment. A claim lasts **two hours**; `recomp task heartbeat` extends it.
`submit` refuses to push anything outside the task's declared output paths.

## What happens to your pull request

1. A fork-safe Action runs a cheap, secret-free preflight on the tree.
2. The coordinator reconstructs your exact merge tree and verifies it inside a
   disposable microVM. Your code never runs on the coordinator host, and the
   original target is never present in the guest that runs your code.
3. On success the pull request is merged with `expected_head_sha`, the Issue is
   closed, and `docs/progress.svg` is regenerated.

Rejections reopen the task for anyone. Nothing but stable reason codes and
counts is published from verification.

## Trusted files

`.github/`, `plugins/`, `toolchain/`, `recomp.toml`, `recomp.lock.toml`, and
`recomp-launcher` are maintainer-owned. Pull requests touching them are refused
by preflight; propose changes in an Issue instead.
