# AGENTS.md — {{PROJECT_NAME}}

This file governs all work in this repository, human or AI. Read it in full
before doing anything. `PROMPT.md` is the task-facing prompt; this file is the
contract both follow.

## Project facts

- Recovery target: `{{PLATFORM}}` binary, pinned by sha256 in `recomp.toml`.
  **This repository contains no target bytes.** Supply your own copy.
- Goal: `{{GOAL}}` · reachable tier: `{{TIER}}`
- Workflow plugin: `{{PLUGIN}}` (`plugins/{{PLUGIN}}/`) — defines what work
  exists, how it executes, and how the verifier judges it.
- Issues are authoritative. Labels are presentation only; the trusted task
  record and lease comments posted by the coordinator App are the truth.

## The loop

```bash
recomp task next <repository-url>
recomp task start <issue-url> --target /path/to/your/copy
recomp task run && recomp task verify
recomp task submit
```

- `start` comments `/claim` and waits for the coordinator's trusted lease.
- A claim lasts **two hours**. `recomp task heartbeat` renews it. Losing a
  claim is normal: the task returns to the pool for anyone.
- Only the current claimant's pull request is admitted for verification.
- One task per pull request, exactly one `Closes #<issue>` reference, and only
  the output paths declared in that task's record.

## What counts as progress

Only merged pull requests count. Your local run passing proves nothing: the
coordinator independently reconstructs your exact merge tree and reverifies it
in a disposable microVM. Check conclusions carry stable reason codes; read them
instead of guessing.

## Never edit these

`.github/`, `plugins/`, `toolchain/`, `recomp.toml`, `recomp.lock.toml`,
`recomp-launcher`, `docs/progress.*`, and this file are maintainer-owned.
Preflight refuses pull requests that touch them. Propose workflow changes in an
Issue; they travel through the maintainer lane, never the contributor lane.

## Safety and legal

- Your copy of the target is mounted read-only into the pinned toolchain image
  and never leaves your machine. Never commit target bytes, extracted game
  assets, or your local target path.
- Never hand-edit an output so it passes verification. Verification recomputes
  from the pinned target; fabricated output is rejected and burns your claim.
- Report verifier bugs and false rejections in an Issue; never work around a
  verifier.

## Reporting

When you stop: list tasks claimed/merged/rejected, the policy version you
worked under, your real model name, time spent per task, and anything abandoned
with the reason.
