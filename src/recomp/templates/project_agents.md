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

Only artifacts accepted into `recovery/` count. New identities are verified
synchronously by independent recomputation. A trusted collaborator may use a
plugin-enabled direct-merge lane, but that merge remains provisional until
asynchronous re-verification; failure removes the artifact and reopens the
item. Local results, match scores and claims are steps, never the score.

## The two lanes

1. **Contributor lane** (everyone): claim → produce the declared output →
   submit. One item at a time, exactly the declared output path, nothing else.
2. **Host lane** (owner + host agent, before onboarding anyone): extend and
   modify the workflow itself — plugins, toolchains, verification. See
   `recomp --help` (`plugin`, `workflow`) and the root recomp AGENTS.md.

Contributors never edit `plugins/`, `recomp.toml`, `server/`, or `bin/`.

## Claims and seats

Claims and active seats are separate leases. A submission from an expired or
reclaimed claim is refused (409) — claim again instead of retrying. If the
policy version changed (412), re-read the prompt before continuing.

Seats grow with open, unleased work; they are not a fixed roster. Your worker
renews its seat through authenticated requests. If it stops heartbeating or
runs out of tokens, the seat expires so another volunteer can work. Trust
earned by a verified merge belongs to your identity and survives seat expiry.
If a returning worker receives 403 mentioning seats, `recomp work --loop`
waits until work opens or another seat expires.

## Merge path

The first synchronously verified merge promotes an identity to collaborator.
When the project plugin enables its fast lane, collaborator submissions merge
optimistically as one git commit each, then re-verify asynchronously. Failure
rolls back the artifact, reopens the work, and returns the identity to
synchronous verification.

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
