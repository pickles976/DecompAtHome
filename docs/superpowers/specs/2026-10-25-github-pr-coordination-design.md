# GitHub Pull-Request Coordination Design

**Status:** Approved in chat on 2026-10-25; awaiting written-spec review

## Objective

Replace Recomp@Home's public HTTP coordination service with a GitHub-native collaboration workflow.

The intended lifecycle is:

1. A human owner forks Recomp@Home and gives that fork to a coordinator agent.
2. The owner and coordinator agent customize the decompilation workflow for one target.
3. `recomp init` creates a separate, clean project repository that pins the workflow and shared toolchain.
4. The coordinator publishes work as GitHub Issues.
5. Contributors receive the project repository URL or a task-Issue URL, clone the project, claim work, run the pinned toolchain locally, and open pull requests from forks.
6. A coordinator process admits eligible pull requests, verifies their exact candidate trees in disposable microVMs, merges accepted work, closes the task, and updates the README progress image.

GitHub is the identity, review, and state control plane. It is not the execution sandbox. All public pull-request content remains hostile until independently verified.

## Terminology

- **Framework fork:** the owner's fork of Recomp@Home. It contains the reusable framework and the owner's workflow customizations.
- **Project repository:** the separate generated GitHub repository for one recovery target. Contributors clone this repository.
- **Owner:** the human who controls the project repository and performs initial privileged setup.
- **Coordinator:** the local agent/process that holds the repository GitHub App identity, schedules verification, and serializes merges.
- **Contributor:** any GitHub user who claims a task and opens a fork pull request.
- **Task record:** the coordinator-authored machine-readable record attached to a GitHub Issue.
- **Candidate:** an immutable tuple of task ID, lease generation, policy hash, base SHA, head SHA, merge-tree hash, and toolchain digest.
- **Public lane:** recovery work submitted by arbitrary GitHub users under a task's output allowlist.
- **Maintainer lane:** changes to workflow, verifier, toolchain, policy, GitHub automation, or other trusted infrastructure.

GitHub calls merge requests **pull requests**; this design uses that term.

## Goals

- Let the owner send a repository or Issue link to a contributor agent without operating a public Recomp@Home server.
- Keep GitHub Issues authoritative for task and claim state.
- Give coordinator and contributors the same digest-pinned toolchain.
- Keep original binaries, licensed toolchains, Ghidra projects, credentials, and coordinator runtime state out of Git.
- Treat public pull requests as malicious without exposing the coordinator host, repository credential, or original target.
- Preserve project-local work planning, execution, independent verification, and policy pinning.
- Make owner setup comprehensive, checkable, and recoverable.
- Generate a deterministic README progress image after every accepted pull request.

## Non-goals

- Running full private-target verification on GitHub-hosted infrastructure.
- Treating GitHub branches or pull requests as a sandbox.
- Running public pull-request code on persistent self-hosted GitHub Actions runners.
- Supporting a container-only fallback for public verification when KVM is unavailable.
- Uploading or committing the original binary, extracted licensed assets, Ghidra state, private toolchains, or raw verifier logs.
- Optimistic merging or a trusted-contributor fast lane in the initial GitHub workflow.
- Allowing public contributors to modify workflow, verifier, dependency, toolchain, policy, or GitHub automation files.
- Preserving compatibility aliases for the old `serve`, `join`, and remote `work` protocol.
- Maintaining two authoritative task stores.

## Selected architecture

The selected architecture combines GitHub-native coordination with a local hardened verifier.

```text
Contributor host
  project clone + local target
  pinned OCI toolchain
          |
          | fork pull request
          v
GitHub
  Issues + lease commands
  pull requests + protected main
  secret-free API/diff preflight
          |
          | polling through GitHub App
          v
Coordinator control process (Linux/KVM)
  no untrusted execution
  immutable candidate queue
  single main-branch writer
          |
          +--> Candidate Firecracker VM
          |      candidate tree + toolchain
          |      no target, token, network, or host files
          |
          +--> Trusted verifier/oracle
                 protected verifier + read-only target
                 bounded candidate artifacts only
```

Alternatives rejected:

- **GitHub Actions only:** would require uploading or reconstructing the original target and large/private analysis inputs on GitHub.
- **Local coordinator only:** would spend private compute on cheap validation, provide poor offline feedback, and make the coordinator an avoidable bottleneck.

## Repository boundaries

### Framework fork

The framework README must lead with the fork-and-customize model:

> Fork Recomp@Home, give the fork to your coordinator agent, customize the workflow for your target, then generate a separate decompilation project repository. Contributors receive only that project's repository or task link.

The framework fork contains reusable CLI, generator, plugins, templates, GitHub integration, coordinator, and microVM support. It is not the target's collaboration repository.

### Generated project repository

The generated project contains:

- `recomp.toml` and `recomp.lock.toml`;
- project-local plugin and verifier definitions;
- recovery/decompilation outputs;
- generated `README.md`, `AGENTS.md`, and owner/contributor instructions;
- `.github/` issue forms, PR template, CODEOWNERS, and secret-free workflows;
- reproducible OCI image source plus immutable toolchain digest and dependency checksums;
- `docs/progress.svg` and a generated machine-readable Issue snapshot;
- no original binary, coordinator key, Ghidra project, VM image state, or authoritative runtime database.

The project pins the Recomp@Home release/commit used to generate it. The owner keeps the target outside the repository; project configuration records its hash and identifying metadata, not a host-specific secret path. Contributors supply their own matching copy.

### Existing implementation reuse and cutover

Retain and adapt:

- `generate.py`: project generation, without copying the target into the project tree;
- `detect.py`: target identification and hashing;
- `plugin.py`: project-local manifests and command contracts;
- `policy.py`: content hashing and policy versioning;
- `prompt.py` and templates: generated agent instructions.

The current `plugin.py` subprocess limits remain defense in depth for trusted/local execution. They are not the public security boundary.

Retire from the default workflow:

- the public `RecompServer` HTTP API;
- SQLite as authoritative worker/task/submission state;
- enrollment tokens and worker keys;
- `serve`, `join`, remote `work`, and server-owner administration commands;
- direct submission uploads and server-side optimistic merge/reverify behavior.

A local SQLite database may cache coordinator queue state, but it must be disposable and reconstructable from GitHub.

## Toolchain reproducibility

Coordinator and contributors use one OCI image published to GHCR and pinned by digest. The image source is committed and auditable. Every base image is digest-pinned; downloaded components have checksums; Python/Rust/compiler/Ghidra versions and project dependencies are locked.

The policy lock binds:

- Recomp@Home version;
- plugin/verifier files;
- OCI image digest;
- toolchain component locks;
- target hash;
- task-plan version.

Contributors invoke the image through a protected repository launcher. They do not assemble Python, Rust, Ghidra, compilers, or plugins individually.

The coordinator derives or verifies the Firecracker guest root filesystem from the same OCI content and records the derivation manifest. A digest mismatch fails closed. Public mode never falls back to executing the image directly against the coordinator host kernel.

## GitHub task model

### Task publication

`recomp github bootstrap` executes the pinned plugin's `work-plan` and creates one GitHub Issue per task. Publication is idempotent by stable task ID.

Each Issue contains a human-readable description. A trusted App/bot-authored machine record contains:

- schema version;
- stable task ID and kind;
- normalized arguments;
- allowed output paths and file/type/size limits;
- policy version/hash;
- toolchain digest;
- target hash;
- optional progress weight;
- publication generation and supersession state.

Only machine records authored by the configured trusted identity are accepted. Contributor-authored lookalike comments are ignored.

Labels expose state:

- `recomp:open`;
- `recomp:claimed`;
- `recomp:verifying`;
- `recomp:blocked`;
- `recomp:done`;
- task-kind and module labels.

GitHub assignment is presentation only. The trusted machine record is authoritative because GitHub may restrict assignment of outside contributors.

### Two-hour claims

A contributor comments `/claim`. Trusted default-branch automation reconciles the complete Issue command history and current trusted state; it does not trust a single webhook delivery. It never checks out pull-request content.

A successful claim writes a trusted lease transition containing:

- task ID;
- claimant GitHub login and immutable user ID;
- monotone lease generation;
- issuance time;
- expiry exactly two hours later.

Only the claimant may issue `/heartbeat`. Every valid heartbeat sets expiry to two hours from that heartbeat. Timestamp comparison is authoritative even when labels or scheduled cleanup lag.

The reconciliation workflow is idempotent. Reprocessing comments produces the same state. Concurrent commands are resolved deterministically by GitHub event ordering, command timestamp, comment ID, and the latest trusted generation. Scheduled reconciliation clears stale presentation labels and reopens expired tasks.

An expired claim does not make an already-open pull request disappear. It does prevent new full-verification admission unless the author acquires the current lease and the task remains unmerged.

### Verification lease

When an eligible pull request is admitted, the coordinator records a separate bounded verification lease and marks the task `recomp:verifying`. Contributor heartbeats are no longer required for that candidate. A head-SHA change supersedes the candidate and requires admission again.

After a rejected candidate, the task returns to the same claimant with a fresh two-hour repair lease unless the task was superseded or completed.

## Contributor workflow

The owner may send either the repository URL or a specific Issue URL.

The generated `AGENTS.md` is the machine-first entry point. A protected launcher provides a flow equivalent to:

1. clone the generated project;
2. validate Git, GitHub authentication, and an OCI runtime;
3. select an open Issue or resolve the supplied Issue URL;
4. locate the contributor's local target and verify its hash;
5. claim the task and observe the trusted lease generation;
6. create a task branch;
7. execute the task in the pinned image;
8. run the local verifier;
9. validate the diff against the task allowlist;
10. push a fork branch and open a populated pull request.

The only unavoidable contributor prerequisites are:

- Git;
- GitHub authentication and fork/push access;
- an OCI-capable runtime;
- a legally obtained target matching the pinned hash.

A local pass is useful evidence, not merge authority.

Each pull request must:

- reference exactly one task Issue;
- be authored by the current claimant;
- bind the observed task ID, lease generation, policy hash, and toolchain digest;
- modify only declared task outputs;
- include structured evidence in the PR body;
- contain no trusted-infrastructure changes.

## Secret-free GitHub preflight

Every pull request receives cheap structural validation on a GitHub-hosted ephemeral runner.

The workflow:

- uses `pull_request`, not privileged checkout triggers;
- has a read-only `GITHUB_TOKEN` and no repository secrets;
- never runs on a self-hosted runner;
- pins actions by immutable full commit SHA or workflow dependency lock;
- checks out only the protected base when trusted repository scripts are needed, with credentials disabled;
- queries the pull-request tree/diff through GitHub APIs instead of executing contributor content;
- does not publish artifacts or caches that privileged jobs consume.

The preflight checks task reference, claimant/lease, policy/toolchain values, file tree, declared paths, and input bounds. Passing preflight does not establish correctness.

GitHub's secure-use guidance explicitly warns that privileged `pull_request_target` or `workflow_run` jobs that check out untrusted content can compromise the repository, and that persistent self-hosted runners can be compromised by public pull requests. This design follows that guidance: <https://docs.github.com/en/actions/reference/security/secure-use>.

## Coordinator identity and permissions

The coordinator authenticates as a repository-installed GitHub App. The owner creates and installs it during setup.

Runtime permissions are limited to those required for:

- Metadata: read;
- Issues: read/write;
- Pull requests: read/write;
- Checks: read/write;
- Contents: read/write for serialized merges and trusted progress commits;
- Actions/check status: read where required for admission.

The runtime App does not receive repository administration permission. A temporary owner-authenticated setup session configures rulesets and is removed afterward.

The App private key lives outside the repository with owner-only permissions, preferably delivered to the systemd service through systemd credentials. Short-lived installation tokens exist only in the host control process. Tokens and keys never enter a checkout, OCI container, guest, log, verdict, or generated file.

Repository rules:

- protect `main` from force-push and deletion;
- require current coordinator and preflight checks;
- require public work to use pull requests;
- prevent GitHub Actions from approving pull requests;
- allow only the coordinator App to perform normal `main` writes;
- retain a logged owner break-glass recovery path;
- use CODEOWNERS for `.github/`, plugins, toolchain definitions, policy files, and verifier code.

Maintainer-lane changes are reviewed separately and repin policy before public tasks resume.

## Admission and immutable candidate construction

The coordinator spends private resources only when all admission conditions hold:

- exactly one open task is referenced;
- the PR author owns its live two-hour lease;
- secret-free preflight passed for the current head;
- the task and policy are current;
- the diff is inside the declared public output allowlist;
- no newer candidate for the Issue is queued or running;
- per-author and global queue limits permit admission.

The coordinator fetches immutable Git objects into an unprivileged quarantine without executing hooks, filters, submodules, attributes, or repository commands. Trusted code validates tree entries before materialization.

It rejects:

- undeclared paths or generated files;
- changes to `.github/`, plugins, verifier, toolchain, lock/configuration, README, progress, or task snapshot files;
- symlinks, submodules, special files, unexpected mode changes, and undeclared LFS pointers;
- path traversal, case/Unicode collisions, malformed trees, and disallowed encodings;
- files, aggregate trees, archive expansion, or claimed output exceeding task limits;
- stale policy/toolchain/task data.

Asset tasks may explicitly allow bounded binary types. There is no universal text-only rule.

The coordinator constructs the exact conflict-free merge candidate from protected base plus PR head with hooks and filters disabled. The attestation binds base SHA, head SHA, resulting tree hash, task ID, lease generation, policy hash, and toolchain digest.

## Malicious-code isolation

### Core invariant

No environment that executes contributor-controlled code may receive the original target, GitHub credentials, host files, network access, prior-job state, or an output channel capable of leaking arbitrary target bytes.

### Candidate VM

The candidate Firecracker VM receives:

- the validated candidate tree as a read-only input;
- the pinned toolchain root filesystem;
- an ephemeral bounded scratch disk;
- declared test inputs that contain no private target material.

It receives no target binary, network device, GitHub token, host socket, Docker socket, reusable cache, or host mount. Firecracker runs through the jailer with pinned kernel/rootfs, least host privileges, and CPU, memory, process, time, disk, and output limits. Each candidate gets a fresh guest and overlay, destroyed after use.

The candidate VM builds contributor inputs. Where behavioral testing is needed, it may run the candidate only against coordinator-mediated declared inputs.

### Trusted verifier/oracle

Trusted verifier code comes from the protected base/policy, never the pull request.

Static or byte-match verification treats candidate output as bounded data and compares it with the read-only target through trusted code. For behavioral verification, original and candidate execution occur in separate guests. The coordinator supplies predefined inputs to each and compares schema-bounded outputs. The candidate cannot see the original binary, original process, oracle filesystem, or private raw output beyond what the test contract explicitly exposes.

A task that cannot be verified under this separation is ineligible for the public lane until its plugin provides a mediated verifier.

### Result channel

Only a small versioned, schema-validated verdict crosses from verification into the control process. Public feedback uses trusted error codes and sanitized metadata.

Raw guest stdout/stderr is size-bounded, retained locally only as required for owner diagnosis, and never copied verbatim into GitHub comments or checks. This prevents private-target or host data from being encoded into public logs.

MicroVM isolation reduces risk; it does not make hostile execution harmless. The owner must keep the host kernel, KVM, Firecracker, and toolchain patched.

## Merge protocol

The coordinator is the single normal writer to `main`. It serializes contributor merges, maintainer merges, and progress commits.

Before merging a passed candidate it rechecks:

- the task is current and incomplete;
- the verified lease generation is still valid for the admitted candidate;
- the protected base has not moved;
- the PR head equals the verified head;
- required checks are current;
- policy and toolchain digests match;
- no conflicting writer is active.

Any mismatch invalidates the result and requeues against a new candidate.

Accepted work is squash-merged so one task produces one recovery commit while preserving PR attribution and discussion. GitHub's merge operation must supply `expected_head_sha`; GitHub returns 422 if the PR head moved. The API behavior is documented at <https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request>.

The task Issue is closed and linked to the merged PR/verdict. Public work is always verified before merge; there is no optimistic collaborator lane.

A wrong merge is corrected by a coordinator-created revert pull request. The task is reopened with a new generation and progress is regenerated. Published history is not rewritten.

## Progress snapshot and README image

GitHub Issues remain authoritative. After each accepted pull request, the coordinator refetches every trusted task record and current state, then deterministically generates:

- a machine-readable Issue snapshot for offline display/audit;
- `docs/progress.svg`;
- no contributor-editable task authority.

The generated project `README.md` references the stable SVG path. The SVG is static, contains no script or external resource, and reports at least total, open, claimed, verifying, blocked, and completed work. When plugins supply stable weights, it also reports weighted completion; otherwise count-based completion is explicit.

The update is a trusted follow-up commit serialized with merges. A generation or commit failure does not undo accepted work: the Issue and merge remain authoritative, the prior image remains visible, the coordinator reports degraded health, and it retries from a fresh Issue read. Contributors never modify the snapshot or SVG.

Rejected or inconclusive pull requests do not change completion progress.

## Owner setup and operations

### Required owner documentation

The framework provides one authoritative, comprehensive coordinator guide with:

- the fork/customize/generate mental model;
- supported Linux/KVM and hardware prerequisites;
- target and licensing constraints;
- OCI/Firecracker installation and pinning;
- GitHub App creation, exact permissions, installation, rotation, and revocation;
- fresh repository creation and initial push;
- ruleset, Actions, labels, Issue, PR-template, and CODEOWNERS setup;
- coordinator systemd installation;
- start, stop, upgrade, policy-repin, backup/rebuild, and uninstall procedures;
- logs and sanitized diagnostics;
- break-glass owner recovery;
- threat model and incident response;
- exact verification commands and expected success states.

### Guided setup

`recomp coordinator setup` guides the owner through:

1. Linux/KVM capability checks;
2. project generation and target hashing;
3. pinned toolchain build/pull and digest validation;
4. GitHub App manifest/permission generation and installation;
5. setup-time owner authentication;
6. labels, forms, templates, workflows, CODEOWNERS, and ruleset configuration;
7. idempotent task publication;
8. local key/config placement outside the repository;
9. systemd service installation;
10. removal of the setup-time owner credential;
11. a benign end-to-end verification and merge simulation.

Setup operations are idempotent or explicitly report the conflicting existing state. They do not print secrets.

### Doctor

`recomp coordinator doctor` is rerunnable and checks:

- Linux and usable KVM;
- Firecracker/jailer/kernel/rootfs versions and checksums;
- guest network and mount isolation;
- OCI/toolchain digest and derivation manifest;
- target hash and read-only placement;
- GitHub App identity, installation, permissions, and token minting;
- branch rules, required checks, force-push/deletion protection, and single-writer invariant;
- Actions token policy and pinned workflow dependencies;
- labels, task schema, and progress paths;
- local directory/key ownership and modes;
- coordinator service health and queue reconstruction;
- a safe fixture candidate through the production verification path.

Every failure names the exact remediation. Public mode fails closed when KVM or any security invariant is absent.

## Failure and recovery behavior

- **Coordinator offline:** claim reconciliation and expiry remain available on GitHub; PRs wait unmerged.
- **GitHub unavailable or rate-limited:** back off without inventing local authoritative state; reconstruct after recovery.
- **App authentication failure:** stop coordination and expose a local health error; do not partially update GitHub.
- **Preflight failure:** do not admit full verification.
- **Guest crash, timeout, malformed result, or resource breach:** fail/inconclusive, destroy guest state, and do not merge.
- **Head/base/policy/task/toolchain movement:** invalidate the attestation and build a new candidate.
- **Coordinator crash:** recover pending work from GitHub; local queue/cache loss is harmless.
- **Progress update failure:** retain accepted Issue/merge state, show degraded health, and retry deterministically.
- **Dirty or divergent local quarantine:** discard and reconstruct; never reset a user's working repository.
- **Policy change:** pause admission, bump and publish the new policy, supersede affected task records, expire incompatible claims, and invalidate outstanding checks before resuming.

Per-author/global queues, one current candidate per Issue, bounded retries per head, and guest quotas limit denial-of-service. Standard GitHub moderation blocks abusive accounts without creating another identity database.

## Security-specific constraints

- Never use `pull_request_target` or a privileged `workflow_run` to check out fork content.
- Never run public PR jobs on persistent self-hosted Actions runners.
- Never expose App credentials or the target to candidate execution.
- Never publish raw candidate/oracle logs.
- Never trust PR bodies, titles, branch names, Issue comments, filenames, or GitHub context values as shell syntax.
- Never consume untrusted caches or artifacts in privileged jobs.
- Never let public PRs alter the verifier or toolchain they are judged by.
- Never merge a result verified for a different head, base, policy, task generation, or toolchain.
- Never silently weaken public mode to process/container isolation.

## Verification and acceptance

The implementation is complete only when the following observable contracts pass.

### Unit and contract coverage

- task publication is idempotent by task ID;
- only trusted machine records are authoritative;
- two-hour claim, heartbeat, expiry, generation, and concurrent-command transitions are deterministic;
- dropped/replayed Issue events reconcile from complete history;
- PR author/task/lease binding and verification-lease transitions are enforced;
- exact allowed-path/type/size policy is enforced;
- symlink, submodule, special-file, LFS, mode, workflow/config, malformed-tree, path-collision, stale-digest, and oversized-input attacks are rejected;
- immutable candidate and attestation fields are complete;
- head/base/policy/toolchain/task movement invalidates results;
- expected-head merge refusal is handled safely;
- Issue snapshot and SVG output are deterministic and script-free;
- local queue deletion followed by restart reconstructs state from GitHub;
- progress failure/retry and revert/reopen behavior preserve authority.

### KVM integration coverage

Real Firecracker tests prove:

- candidate guests cannot reach a network;
- candidate guests cannot see target, host files, credentials, host sockets, or prior-job state;
- read-only inputs and bounded scratch are enforced;
- CPU, memory, process, time, disk, and output limits terminate abuse;
- fork bombs, oversized output, malformed verdicts, and guest crashes are cleaned up;
- candidate and original execution remain separated;
- only schema-bounded verdict data reaches the host;
- raw output is not published to GitHub-facing diagnostics.

### End-to-end acceptance

A disposable GitHub repository and non-proprietary fixture must demonstrate:

1. project publication;
2. task Issue creation;
3. `/claim` and `/heartbeat` with a two-hour lease;
4. contributor launcher setup from a repository/Issue link;
5. benign and malicious fork pull requests;
6. secret-free preflight;
7. admission only for the live claimant;
8. real microVM verification of the benign candidate and rejection of the malicious candidate;
9. exact-head/base-safe merge;
10. Issue closure;
11. deterministic README progress-image update;
12. coordinator restart and state reconstruction;
13. `recomp coordinator doctor --self-test` through the installed production path.

The fixture contains no proprietary binary or asset.

## Documentation deliverables

- Update the framework `README.md` to explain that Recomp@Home is forked, customized by the coordinator agent, and used to generate a separate project repository.
- Update the framework `AGENTS.md` host lane to the GitHub workflow.
- Add the comprehensive owner/coordinator setup and operations guide.
- Generate project `README.md`, `AGENTS.md`, and contributor instructions that make a repository or Issue link sufficient context for an agent.
- Document the malicious-PR threat model, target confidentiality boundary, and incident response.
- Remove public-service deployment instructions and obsolete server enrollment/submit guidance from active documentation and templates.
