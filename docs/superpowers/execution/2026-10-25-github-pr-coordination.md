# Execution ledger — plan: docs/superpowers/plans/2026-10-25-github-pr-coordination.md

Baseline: `python3 -m pytest -q` passed, 57 tests, 0 failures on `a47a3d7`.

## Pre-flight scan

### Per-task internal consistency

| Task | Files/tests/interfaces checked | Finding |
|---|---|---|
| 1 | contracts, policy hash, contract/policy tests | Clean. |
| 2 | GitHub App auth, REST transport, fake opener | Clean; OpenSSL remains an explicit host prerequisite. |
| 3 | task records, generic plugin output schema, publication | Clean. |
| 4 | two-hour leases, deterministic replay, verification leases | Clean; TTL is consistently 7,200 seconds. |
| 5 | tree/path/media/claim preflight | Clean. |
| 6 | remote composite actions and rendered workflows | Clean after plan correction: fork preflight uses native job conclusion and no writable Checks token. |
| 7 | Git plumbing, materialization, CandidateKey | Clean; Git >=2.38 is global. |
| 8 | OCI runtime, image build, launcher, CLI | Conflict: plan text mentions copying the Task 9 guest runner before it exists. Ruling below. |
| 9 | ext4 drives, guest PID 1, jailer lifecycle | Clean; must also finish guest installation in the Task 8 Containerfile. |
| 10 | plugin verify modes and candidate/oracle separation | Clean. |
| 11 | disposable queue, admission, checks, polling | Clean. |
| 12 | invariant recheck, merge, progress Git-data commit | Clean. |
| 13 | contributor task CLI and local state | Clean. |
| 14 | owner setup, doctor, systemd | Clean; tests may use generated fixtures before Task 15 wires real generation. |
| 15 | generated repo and destructive old-server cutover | Clean; intentionally owns final caller/test migration. |
| 16 | README/AGENTS/owner/security/contributor docs | Clean. |
| 17 | fake/live GitHub and real-KVM acceptance | Clean; live tests remain explicit opt-in. |

### Shared files and interfaces

| Producer | Consumer | Shared boundary | Finding |
|---|---|---|---|
| 1 | 3, 5, 7, 8, 10-12 | `Sha256`, `ImageRef`, `TargetRef`, `PolicyRef`, `CandidateKey` | Names and fields agree. |
| 1 | 15 | policy inputs and external target contract | Task 15 performs final generator/caller cutover. |
| 2 | 3, 6, 11, 12, 14 | `GitHubClient` and App token provider | Thin REST helpers support fake transports. |
| 3 | 4, 5, 11-13, 15 | `TaskRecord` and `OutputRule` | Exact output rules remain authoritative. |
| 3 | 10 | plugin `[verify]` metadata | Task 3 introduces generic static metadata; Task 10 generalizes parsing. |
| 4 | 6, 11, 12, 13 | lease/verification transitions | Generation and 7,200-second TTL agree. |
| 5 | 6, 7, 11, 13 | `PreflightReport` and tree rules | Coordinator repeats trusted preflight; GitHub action is only cheap gate. |
| 6 | 15 | workflow/action templates | Task 15 renders them with immutable framework action SHA. |
| 7 | 10, 11 | `CandidateTree` and immutable candidate key | Tree hash is computed before verification. |
| 8 | 9, 10, 13-15 | OCI image/launcher and guest rootfs | Guest entry point is completed in Task 9 per ruling. |
| 9 | 10, 14, 17 | `FirecrackerRunner` and doctor fixtures | Public mode has no container fallback. |
| 10 | 11, 12 | `VerificationAttestation` | Merge consumes exact candidate tuple. |
| 11 | 12, 14 | coordinator queue/health and serialized writer | GitHub stays authoritative. |
| 12 | 15-17 | `docs/progress.json` and `docs/progress.svg` | Generated project reserves both paths. |
| 13 | 15-17 | `recomp task` CLI | Generated instructions consume exact commands. |
| 14 | 15-17 | `recomp coordinator` CLI, local paths, doctor | Task 15 exposes final CLI; docs/acceptance follow. |
| 15 | 16, 17 | final generated layout and CLI cutover | Obsolete server modules/tests removed before final docs/e2e. |

Ruling: Task 8 installs the Recomp wheel and defines the toolchain build/launcher, but does not copy or validate `recomp-guest` before `src/recomp/guest.py` exists. Task 9 adds the `recomp-guest` entry point and updates `src/recomp/templates/toolchain/Containerfile` plus its tests in the same commit. This preserves green commits and costs one additional Task 9 file touch.

User constraint: the coordinator itself is Linux-only. Setup and `doctor` must reject non-Linux hosts before GitHub mutation; KVM is additionally mandatory for public verification.

Task 1: complete (`a47a3d7..bf9cf0c`; 14 focused tests passed; inline diff review found no blocking issue).
Task 2: complete (`bf9cf0c..13fdcea`; 12 focused tests passed; inline review found no blocking issue).
Task 3: complete (`13fdcea..943041b`; 38 focused integration tests passed; inline review added immutable-author validation for Issue markers).
Task 4: complete (`943041b..7c8fee7`; 13 focused state-machine tests passed; inline review found no blocking issue).
Task 5: complete (`7c8fee7..1c1e45d`; 28 adversarial preflight tests passed; inline review added positive lease-generation validation).
Task 6: complete (`1c1e45d..9be8ded`; 47 focused action/claims/preflight tests passed; inline review found no blocking issue).
Task 7: complete (`9be8ded..c0e5664`; 41 Git-plumbing/preflight tests passed; sanitized env, merge-tree only, no checkout/filters).
Task 8: complete (`c0e5664..8399127`; 29 toolchain/CLI/contract tests passed; argv-only OCI invocation, digest-pinned launcher).
Task 9: complete (`8399127..0485b31`; 16 guest tests passed, real-KVM test skipped without `RECOMP_FIRECRACKER_TEST=1`). Deviation from plan step 5: the guest boots through `jailer --config-file` with `--no-api` instead of driving the Firecracker API socket. One-shot boot needs no API; this removes a Unix-socket HTTP client from the trusted path.
Task 10: complete (24 verification/plugin tests plus 17 guest tests passed). `[verify]` parsing lives in `plugin.py` (`VerifyManifest`); `verification.py` owns mode orchestration. Candidate guests never receive `target_path`; oracle guests never receive `input_dir`. Byte-match and behavioral comparisons happen on digests in the host control process, so no artifact or target bytes cross a guest boundary. Plugin-level `[verify]` rejection rules are asserted from `tests/test_verification.py` rather than duplicated in `tests/test_plugin.py`.

Known mid-cutover red set (deleted by Task 15 per plan): `tests/test_server_e2e.py` (2) and `tests/test_fastlane_e2e.py` (5) fail because the generic plugin moved to trusted `outputs` records in Task 3; the legacy HTTP serve lane still passes `args.out`. Verified green at plan base `7370fff`. This set must not grow.
