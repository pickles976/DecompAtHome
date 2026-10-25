# AGENTS.md — {{PROJECT_NAME}}

This file governs all work in this repository, human or AI. Read it in full
before doing anything. The contributor prompt for agents is `PROMPT.md`
(served live at `/api/prompt`); this file is the contract both follow.

## Project facts

- Recovery target: `{{PLATFORM}}` binary at `bin/` (sha256 pinned in `recomp.toml`)
- Goal: `{{GOAL}}` · reachable tier: `{{TIER}}`
- Workflow plugin: `{{PLUGIN}}` (`plugins/{{PLUGIN}}/`) — defines what work
  exists, how it executes, and how the verifier judges it
- Original binaries and extracted game assets never enter git. Artifacts are
  hash-pinned; contributors place their own copies.

## What counts as progress

Only artifacts the server's verifier confirmed by independent recomputation
and merged into `recovery/`. Local results, match scores and claims are steps,
never the score.

## The two lanes

1. **Contributor lane** (everyone): claim → produce the declared output →
   submit. One item at a time, exactly the declared output path, nothing else.
2. **Host lane** (owner + host agent, before onboarding anyone): extend and
   modify the workflow itself — plugins, toolchains, verification. See
   `recomp --help` (`plugin`, `workflow`) and the root recomp AGENTS.md.

Contributors never edit `plugins/`, `recomp.toml`, `server/`, or `bin/`.

## Claims

Claims are leases with fencing tokens. A submission from an expired or
reclaimed lease is refused (409) — claim again instead of retrying. If the
policy version changed (412), re-read the prompt before continuing.

## Safety

- Everything you submit is quarantined, then verified in a sandbox with no
  network and no secrets. Path traversal, undeclared files and non-declared
  output types are rejected before anything runs.
- Never attempt to edit files outside your claimed item's output path.
- Report bugs and false rejections to the owner; never work around a verifier.

## Reporting

When you stop: list items claimed/merged/rejected, the policy version you
worked under, your real model name, time spent per item, and anything
abandoned with the reason.
