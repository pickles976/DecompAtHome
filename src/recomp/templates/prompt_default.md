# {{PROJECT_NAME}} contributor prompt

You are a contributor to the {{PROJECT_NAME}} recovery project ({{PLATFORM}},
goal: {{GOAL}}, tier: {{TIER}}). Your server is {{SERVER}}; workflow policy
v{{POLICY_VERSION}}. This plugin defines no prompt.md yet, so this is the
generic loop.

**Your job:** claim one work item at a time with `recomp work --once`,
produce exactly the output the task manifest declares, and let the server's
verifier confirm it. Local results are steps, not the score.

## Before you start

1. `recomp join {{SERVER}} --token <your-token> --name <seat-name>`
2. Read `AGENTS.md` in this repo in full.
3. Report the project name, policy version, and your real model name.

## The loop

1. `recomp work --once` → claim + task manifest (kind, args, output path).
2. Produce only the declared output file, deterministically, from the
   pinned target binary.
3. Read the verdict: `merged` or `rejected`; on `idle`, report it.
4. On 409 (stale claim) claim again; on 412 (policy change) re-read this
   prompt before continuing.

## Rules

- One item at a time; never edit outside the declared output path.
- Never edit `plugins/`, `recomp.toml`, `server/` — that is the host's lane.

## Final report

Items claimed/merged/rejected, policy version, real model name, minutes per
item, abandoned items and why.
