# Contributing to {{PROJECT_NAME}}

Humans and agents follow the same loop. Everything is coordinated in Issues.

## Before your first task

1. Install Docker or Podman and `pip install recomp`.
2. Obtain your own copy of `{{TARGET_FILENAME}}` (sha256 `{{TARGET_SHA256}}`).
   Never commit it, never upload it, never put its path in a pull request.
3. Fork this repository. `recomp task submit` pushes to your fork.

## Claiming work

- `recomp task next https://github.com/{{OWNER}}/{{REPOSITORY}}` lists open tasks.
- `recomp task start <issue-url> --target <your-copy>` comments `/claim` and
  creates the branch `recomp/<task-id>-<issue>`.
- A claim lasts two hours. `recomp task heartbeat` renews it. If you stop, the
  claim lapses and the task returns to the pool: that is normal, not a failure.
- Only the Issue's current claimant can have a pull request admitted.

## Producing work

- `recomp task run` and `recomp task verify` execute inside the pinned
  toolchain image with your target mounted read-only. Do not hand-edit outputs
  so they pass verification; the coordinator recomputes everything independently.
- Change only the files listed in the Issue's task record. One task per pull
  request, one `Closes #<issue>` reference.

## Submitting

`recomp task submit` verifies locally, pushes your branch to your fork, and
opens a pull request with the required `Recomp-*` fields. Then watch the checks:

- `preflight` failing means the tree itself is wrong (paths, size, type, or a
  stale policy). Fix and push; the lease stays yours.
- `recomp verification` failing means your output did not reproduce. The task
  reopens for everyone after repeated failures.

## What is off limits

`.github/`, `plugins/`, `toolchain/`, `recomp.toml`, `recomp.lock.toml`, and
`recomp-launcher` are maintainer-owned. Workflow changes happen in the
maintainer lane, not through contributor pull requests.

## Legal

Only contribute recovery work you produced from a copy of the target you are
entitled to use. No original game assets or executable bytes may enter this
repository.
