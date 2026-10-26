# Security model

Recomp@Home runs untrusted code from strangers against a proprietary binary on
a machine you own. This document states what an attacker can do, what stops
them, and what remains genuinely risky.

## Attacker capabilities

A contributor can:

- open pull requests with arbitrary file content, paths, sizes, and modes;
- comment arbitrary text on Issues, including text imitating coordinator
  comments;
- force-push, retarget, or close their pull request at any moment, including
  between verification and merge;
- submit output designed to exploit the verifier, the plugin, the guest
  kernel, or the host toolchain;
- claim many tasks, or many identities, to exhaust compute.

A contributor cannot authenticate as the coordinator App, write to protected
paths, or cause the coordinator to execute their code outside a guest.

## Trust anchors

1. **The App's bot actor id.** Task records and lease transitions are only
   believed when the comment author id equals the configured trusted actor id.
   Lookalike comments from anyone else are ignored, not merely out-ranked.
2. **The pinned policy.** `recomp.toml`, `plugins/`, `toolchain/`, and
   `recomp-launcher` are hashed into `recomp.lock.toml`. A pull request
   declaring a different policy hash fails preflight.
3. **The immutable candidate key.** `task_id`, lease generation, policy hash,
   base SHA, head SHA, merge tree SHA, and toolchain digest. An attestation is
   valid for exactly that tuple and nothing else.

## GitHub's role and its limits

GitHub provides identity, the pull-request mechanism, and `expected_head_sha`
on merge — the last of which closes the race between our final recheck and the
merge itself. GitHub does **not** provide isolation for your target or your
host. The fork-safe Action is a cheap filter running with a read-only token on
`pull_request` (never `pull_request_target`), with no secrets and no checkout
of contributor code into a privileged context. Treat its verdict as advisory;
the coordinator repeats the same preflight from trusted data before spending
compute. See GitHub's guidance on securing workflows and the
`pull_request_target` footgun: <https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/>.

## Protected paths

`.github/`, `plugins/`, `toolchain/`, `recomp.toml`, `recomp.lock.toml`,
`recomp-launcher`, `docs/progress.json`, `docs/progress.svg`, and `AGENTS.md`
are maintainer-owned. Preflight refuses any pull request touching them, so a
contributor cannot rewrite the verifier that judges them, the workflow that
gates them, or the progress image the project publishes.

## Candidate/oracle split

The central rule: **untrusted code and the original target never occupy the
same guest.**

| Mode | Candidate guest | Oracle guest | Host |
| --- | --- | --- | --- |
| `static` | — | trusted verifier reads the target; submitted files are inert, non-executable data | compares nothing |
| `bytematch` | builds from the candidate tree, no target present | trusted extraction from the target | compares two sha256 digests |
| `behavioral` | builds and runs the candidate over declared cases, no target present | runs the original over the same cases, no candidate executable present | compares per-case digests |

Each guest is a fresh Firecracker microVM with no network interface, no vsock,
no host filesystem passthrough, read-only job/input drives, and exactly one
writable channel: a small ext4 drive holding `verdict.json`.

## Exfiltration controls

- **Target bytes** never enter a candidate guest and never enter any verdict:
  the only values crossing a guest boundary are sha256 digests, an enum
  status, an integer diagnostic code, and a stderr byte count.
- **Logs** are not propagated. The guest captures a bounded private diagnostic
  code, not arbitrary stdout/stderr. Check conclusions publish sorted stable
  reason codes and integer counts.
- **Host paths** never appear in attestations, check output, or the progress
  files. Guest result reading is capped before JSON parsing and schema-checked
  after.
- **Contributor text** never reaches the SVG unescaped; the renderer emits
  fixed shapes plus escaped, length-bounded labels, with no script, no
  foreignObject, no fonts, and no external URLs.

## Credentials

- The GitHub App private key lives at 0600 in the owner's config directory and
  reaches the service only through systemd `LoadCredential=`.
- JWT signing shells out to OpenSSL without placing key bytes on argv.
- Installation tokens are cached in memory until one minute before expiry.
- The runtime App has no Administration permission, so it cannot relax the
  rulesets that constrain it.
- No token or key is ever written into a project repository, a pull request,
  a check output, or the local task context.

## Denial of service

- Per-author and global concurrency caps bound how much compute one identity
  can occupy; a bounded attempt counter stops endless retries of a failing
  candidate.
- Guests have wall-clock, memory, vCPU, pid, and file-descriptor limits, plus
  a capped result drive; the jail is removed in a `finally` block on every
  path, including timeout.
- Tree inspection enforces per-blob and aggregate size limits and refuses
  truncated trees before any materialization.
- GitHub rate-limit resets are honored; other failures back off exponentially
  with jitter.

## Residual risk

- **Guest kernel and Firecracker.** Isolation is only as strong as the VMM and
  the guest kernel you pinned. Keep both updated and record their checksums.
- **Your plugin.** A plugin whose `verify` does not independently recompute
  from the pinned target can be fooled; `verify` must never echo submitted
  bytes back as truth.
- **Supply chain.** Digest-pinned images and SHA-pinned actions remove tag
  mutation, but a compromised upstream base image is still a compromise.
- **Side channels.** The platform does not attempt to defend against
  cross-VM microarchitectural side channels.

## Response to a bad merge

1. Open a revert pull request. Never rewrite published history.
2. After it merges, the coordinator appends a new task generation and reopens
   the Issue, returning the work to the pool.
3. Audit neighboring merges: every merge commit carries `Recomp-Task`,
   `Recomp-Lease`, `Recomp-Policy`, `Recomp-Toolchain`, `Recomp-Tree`,
   `Recomp-Verifier`, and `Recomp-Mode` trailers. A commit whose trailers do
   not correspond to a verification you ran is the first thing to investigate.
