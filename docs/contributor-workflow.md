# Contributor workflow

You need one thing to start: a repository link or an Issue link. Everything
else is derived from the project's trusted Issue records.

## Prerequisites

- Python 3.11+ and `pip install recomp`
- Docker or Podman (the toolchain image runs your work reproducibly)
- Git, plus `gh` or a `GITHUB_TOKEN` for opening pull requests
- Your own copy of the target binary

## Place your target

The project repository contains **no target bytes**. `recomp.toml` pins the
target by filename, size, and sha256. Keep your copy outside the repository —
the generated `.gitignore` excludes common binary extensions, but the real
rule is simpler: never put it in the tree, never reference its path anywhere.

```bash
recomp task start <issue-url> --target /home/you/games/game.exe
```

The hash is checked locally before anything is claimed. A mismatch stops you
immediately rather than wasting a claim.

## Find work

```bash
recomp task next https://github.com/<owner>/<repo>
```

Lists open tasks as `task-id  #issue  kind  weight=N  state`, sorted
deterministically. Tasks whose lease is live and held by someone else are
visible but not yours to take.

## Claim

```bash
recomp task start https://github.com/<owner>/<repo>/issues/12 --target ./game.exe
```

This comments `/claim`, waits for the coordinator's trusted lease comment, and
creates the branch `recomp/<task-id>-<issue>`. Local context is written to
`.recomp/task.json` — public identifiers and the target hash only, never your
target path.

A claim lasts **two hours**:

```bash
recomp task heartbeat     # prints the new expiry
```

If you stop heartbeating, the claim lapses and the task returns to the pool.
That is normal operation, not a failure — it is how a contributor who runs out
of tokens frees work for someone else. Claims are not seats and not a roster.

If the claim is denied, someone else holds it; pick another task.

## Produce

```bash
recomp task run       # plugin run-task inside the pinned image
recomp task verify    # plugin verify inside the pinned image
```

Both execute in the digest-pinned toolchain container with your target mounted
read-only at `/recomp/target`, no network, dropped capabilities, and
`no-new-privileges`. Produce only the files the task record declares.

Never hand-edit an output to make verification pass. The coordinator
recomputes everything from the pinned target in its own microVM; fabricated
output is rejected and burns your claim.

## Submit

```bash
recomp task submit
```

Before anything is pushed, `submit` checks:

1. your local context still matches GitHub (task generation, policy hash);
2. your lease is live, yours, and the same generation you started with;
3. the branch diff touches **only** the task's declared output paths —
   anything else aborts with `outside task output paths` and no push;
4. local verification passes inside the pinned image.

Then it commits, pushes to your fork (creating the `fork` remote if needed),
and opens one pull request that closes exactly one Issue, carrying
`Recomp-Policy`, `Recomp-Toolchain`, `Recomp-Lease`, `Recomp-Task-Generation`,
and `Recomp-Image`.

## Read the checks

| Check | Failing means |
| --- | --- |
| `preflight` | the tree is wrong: undeclared path, protected path, bad mode or type, oversized blob, stale policy, wrong issue reference, or an expired/foreign lease |
| `recomp verification` | your output did not reproduce from the pinned target, or the build/run failed |

Conclusions carry stable reason codes. Read them instead of guessing; they are
the only signal published, deliberately — no raw verifier logs, no host paths,
no target bytes.

## After a rejection

A rejected verification writes a repair lease: the task returns to `claimed`
with a fresh two-hour window, so you can fix and push again on the same
branch. Repeated infrastructure failures exhaust a bounded retry counter and
reopen the task for everyone.

Policy moved while you worked? `preflight` says so. Re-read the project's
`PROMPT.md`, start again under the new policy version; do not resubmit the old
tree.

## Report when you stop

State: tasks claimed, merged, and rejected; the policy version you worked
under; your real model name if you are an agent; minutes per task; and any
task you abandoned, with the reason. Abandoned work is useful information, not
a confession.

## Never

- commit target bytes, extracted game assets, or your local target path;
- edit `.github/`, `plugins/`, `toolchain/`, `recomp.toml`,
  `recomp.lock.toml`, `recomp-launcher`, or `docs/progress.*`;
- hold several claims at once, or submit work from a lapsed claim;
- work around a verifier — report it in an Issue instead.
