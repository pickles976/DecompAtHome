# GitHub Pull-Request Coordination Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Recomp@Home's HTTP submission service with a GitHub Issues and pull-request workflow whose public contributions are verified in disposable Firecracker guests before a serialized merge.

**Architecture:** GitHub is the authoritative control plane for tasks, two-hour claims, pull requests, checks, and merged history. A local Linux/KVM coordinator authenticates as a repository GitHub App, validates immutable Git trees, separates candidate execution from the private target, and writes progress through one serialized `main` queue. Contributors use the same digest-pinned OCI toolchain through a generated repository launcher.

**Tech Stack:** Python 3.11+ standard library, pytest, GitHub REST API, Git CLI 2.38+, OCI runtime (Docker or Podman), GHCR, Firecracker+jailer, KVM, e2fsprogs, OpenSSL, systemd.

**Spec:** `docs/superpowers/specs/2026-10-25-github-pr-coordination-design.md`

## Global Constraints

- Keep the Python package dependency-free beyond the Python 3.11+ standard library.
- Public coordinator mode requires Linux with usable KVM; it must never fall back to host-process or container-only execution.
- Every public task claim expires exactly 7,200 seconds after `/claim` or the claimant's latest valid `/heartbeat`.
- GitHub Issues are authoritative for task/lease state; any local SQLite coordinator state is disposable cache only.
- Original binaries, licensed assets, Ghidra projects, App keys, guest state, and raw verifier logs never enter Git.
- Candidate execution never receives the original target, network access, GitHub credentials, host files, or prior-job state.
- Trusted verifier code always comes from the protected base/policy, never from the pull request.
- Public PRs may change only task-declared outputs. Tooling, workflow, policy, dependency, verifier, and progress files use the maintainer lane.
- GitHub-hosted preflight uses `pull_request`, a read-only token, no secrets, no persistent self-hosted runner, and no privileged checkout of fork content.
- Merge attestations bind task ID, lease generation, policy hash, base SHA, head SHA, merge-tree hash, and OCI digest.
- Only the coordinator App normally writes `main`; every merge uses the verified head and a stable protected base.
- Tests follow existing pytest conventions and run with `python3 -m pytest`.
- Each task starts with a failing behavioral test, implements only that task's contract, runs its focused tests, then runs the affected existing tests before committing.
- Final cutover removes `serve`, `join`, remote `work`, `admin`, enrollment keys, optimistic fast lane, and obsolete HTTP/server documentation. No compatibility aliases remain.

## File Structure

### Core package

- `src/recomp/contracts.py` — immutable hashes, image references, project/task/candidate value objects.
- `src/recomp/github_api.py` — dependency-free REST transport and GitHub App installation-token authentication.
- `src/recomp/task_records.py` — task/output schema, trusted Issue records, publication and supersession.
- `src/recomp/claims.py` — deterministic `/claim` and `/heartbeat` reconciliation with 7,200-second leases.
- `src/recomp/preflight.py` — PR/tree policy, protected paths, size/type/mode validation, report codes.
- `src/recomp/candidate.py` — credential-free Git fetch, tree inspection, merge-tree construction, safe materialization.
- `src/recomp/toolchain.py` — digest-pinned image parsing, OCI execution/build inspection, launcher rendering.
- `src/recomp/firecracker.py` — jailer lifecycle, ext4 input/result drives, networkless guest execution.
- `src/recomp/guest.py` — minimal PID 1/job runner used inside the toolchain guest rootfs.
- `src/recomp/verification.py` — static, byte-match, and separated behavioral verification plans/attestations.
- `src/recomp/coordinator_state.py` — disposable candidate queue/cache with reconstruction markers.
- `src/recomp/coordinator.py` — polling, admission, check runs, queue scheduling, and loop health.
- `src/recomp/merge.py` — final invariant recheck, exact-head squash merge, issue completion, atomic progress commit.
- `src/recomp/progress.py` — canonical Issue snapshot and deterministic static SVG.
- `src/recomp/task_cli.py` — contributor clone/claim/run/verify/diff/submit workflow.
- `src/recomp/coordinator_setup.py` — guided owner setup, local paths, ruleset checks, systemd installation, doctor.

### GitHub Actions and generated templates

- `.github/actions/recomp-claims/action.yml`, `action.py` — trusted default-branch claim reconciliation action.
- `.github/actions/recomp-preflight/action.yml`, `action.py` — secret-free PR preflight action.
- `src/recomp/templates/github/issue_commands.yml` — generated Issue command/reconciliation workflow.
- `src/recomp/templates/github/preflight.yml` — generated pull-request workflow.
- `src/recomp/templates/github/pull_request_template.md` — required task/evidence fields.
- `src/recomp/templates/github/CODEOWNERS` — trusted-infrastructure ownership.
- `src/recomp/templates/project_readme.md` — generated project overview and stable progress image.
- `src/recomp/templates/contributing.md` — human contributor prerequisites and launcher flow.
- `src/recomp/templates/recomp-launcher` — POSIX launcher for the pinned OCI image.
- `src/recomp/templates/toolchain/Containerfile` — project toolchain image source.
- `src/recomp/templates/systemd/recomp-coordinator.service` — generated coordinator service.

### Tests

- `tests/test_contracts.py`
- `tests/test_github_api.py`
- `tests/test_task_records.py`
- `tests/test_claims.py`
- `tests/test_preflight.py`
- `tests/test_github_actions.py`
- `tests/test_candidate.py`
- `tests/test_toolchain.py`
- `tests/test_firecracker.py`
- `tests/test_verification.py`
- `tests/test_coordinator.py`
- `tests/test_merge_progress.py`
- `tests/test_task_cli.py`
- `tests/test_coordinator_setup.py`
- `tests/test_generate_github.py`
- `tests/test_public_workflow_e2e.py`

---

### Task 1: Immutable Public-Workflow Contracts

**Files:**
- Create: `src/recomp/contracts.py`
- Create: `tests/test_contracts.py`
- Modify: `src/recomp/policy.py:17-43`
- Modify: `tests/test_policy.py`

**Interfaces:**
- Produces: `Sha256`, `ImageRef`, `TargetRef`, `PolicyRef`, `CandidateKey`, `parse_sha256()`, `parse_image_ref()`.
- Consumes: existing `recomp.toml` dictionaries and `policy.compute_policy_hash()`.

- [ ] **Step 1: Write failing value-object tests**

```python
from pathlib import PurePosixPath

import pytest

from recomp.contracts import CandidateKey, ImageRef, Sha256, TargetRef


def test_image_ref_requires_registry_name_and_digest():
    digest = "a" * 64
    ref = ImageRef.parse(f"ghcr.io/acme/recomp-toolchain@sha256:{digest}")
    assert ref.repository == "ghcr.io/acme/recomp-toolchain"
    assert ref.digest == Sha256(digest)
    with pytest.raises(ValueError, match="digest-pinned"):
        ImageRef.parse("ghcr.io/acme/recomp-toolchain:latest")


def test_candidate_key_serialization_is_canonical():
    key = CandidateKey(
        task_id="strings-0001", lease_generation=4,
        policy_hash=Sha256("1" * 64), base_sha="2" * 40,
        head_sha="3" * 40, tree_sha="4" * 40,
        toolchain_digest=Sha256("5" * 64),
    )
    assert key.canonical()["task_id"] == "strings-0001"
    assert list(key.canonical()) == [
        "task_id", "lease_generation", "policy_hash", "base_sha",
        "head_sha", "tree_sha", "toolchain_digest",
    ]
```

- [ ] **Step 2: Run the tests and verify the missing module failure**

Run: `python3 -m pytest tests/test_contracts.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'recomp.contracts'`.

- [ ] **Step 3: Implement strict immutable contracts**

```python
@dataclass(frozen=True, order=True)
class Sha256:
    hex: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.hex):
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")


@dataclass(frozen=True)
class ImageRef:
    repository: str
    digest: Sha256

    @classmethod
    def parse(cls, value: str) -> "ImageRef":
        match = re.fullmatch(r"([^\s@]+)@sha256:([0-9a-f]{64})", value)
        if match is None or "/" not in match.group(1):
            raise ValueError("OCI image must be registry-qualified and digest-pinned")
        return cls(match.group(1), Sha256(match.group(2)))

    def __str__(self) -> str:
        return f"{self.repository}@sha256:{self.digest.hex}"
```

Add frozen `TargetRef(filename: str, sha256: Sha256, size: int)`, `PolicyRef(version: int, hash: Sha256)`, and `CandidateKey` with the exact fields/order asserted above. Validate task IDs with `[a-z0-9][a-z0-9._-]{0,127}` and Git SHAs with 40 lowercase hex characters.

- [ ] **Step 4: Bind trusted project inputs into policy hashing**

Change `policy_files()` to hash `recomp.toml`, every regular file under `plugins/` and `toolchain/`, and the generated protected launcher. Continue excluding `.git`, caches, runtime state, and `recomp.lock.toml` to avoid hashing the lock into itself. Add a policy test proving a `toolchain/Containerfile` change changes the policy hash.

- [ ] **Step 5: Run focused and policy tests**

Run: `python3 -m pytest tests/test_contracts.py tests/test_policy.py -q`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/recomp/contracts.py src/recomp/policy.py tests/test_contracts.py tests/test_policy.py
git commit -m "feat: define immutable public workflow contracts"
```

---

### Task 2: Dependency-Free GitHub App REST Client

**Files:**
- Create: `src/recomp/github_api.py`
- Create: `tests/test_github_api.py`

**Interfaces:**
- Consumes: OpenSSL executable, GitHub REST responses, `Path` to App private key.
- Produces: `GitHubAppCredentials`, `InstallationToken`, `GitHubClient.request()`, `GitHubClient.paginate()`, and typed helpers used by later tasks.

- [ ] **Step 1: Write failing authentication and pagination tests**

```python
def test_installation_tokens_are_cached_until_one_minute_before_expiry(fake_opener, tmp_path):
    creds = GitHubAppCredentials(12, 34, tmp_path / "app.pem")
    provider = InstallationTokenProvider(creds, opener=fake_opener, signer=lambda _: "jwt", clock=lambda: 1000)
    first = provider.token()
    second = provider.token()
    assert first == second == "installation-token"
    assert fake_opener.installation_requests == 1


def test_paginate_follows_only_same_origin_next_links(fake_opener):
    client = GitHubClient("https://api.github.test", "acme", "game", lambda: "token", opener=fake_opener)
    assert [row["id"] for row in client.paginate("GET", "/repos/acme/game/issues")] == [1, 2]
    assert fake_opener.requested_urls == [
        "https://api.github.test/repos/acme/game/issues",
        "https://api.github.test/repos/acme/game/issues?page=2",
    ]
```

Include tests for 401/403/422 error bodies, JSON size caps, rate-limit headers, no cross-origin pagination, header redaction, and token refresh.

- [ ] **Step 2: Run the tests and verify failure**

Run: `python3 -m pytest tests/test_github_api.py -q`

Expected: FAIL because `recomp.github_api` does not exist.

- [ ] **Step 3: Implement App JWT signing through OpenSSL**

Construct JWT header/payload with canonical compact JSON, `iat = now - 30`, `exp = now + 540`, and `iss = app_id`. Sign the ASCII `header.payload` bytes by invoking:

```python
subprocess.run(
    ["openssl", "dgst", "-sha256", "-sign", os.fspath(private_key)],
    input=signing_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    check=True, env={"PATH": os.environ.get("PATH", "")},
)
```

Never pass key bytes or tokens on argv. Convert the signature to unpadded base64url. Reject key paths not owned by the current user or having group/other permission bits.

- [ ] **Step 4: Implement bounded REST transport**

`GitHubClient.request(method, path, *, body=None, expected=(200,), max_bytes=1 << 20)` must set `Accept`, `Authorization`, `X-GitHub-Api-Version`, and a fixed User-Agent; JSON-encode bodies; cap response reads; redact authorization from exceptions; and expose status/rate-limit metadata through `GitHubError`. `paginate()` accepts only `rel="next"` links on the configured API origin and enforces a page ceiling.

Add helpers for Issues, comments, labels, pulls, pull files/trees/blobs, checks, refs, blobs, trees, commits, and merge. Helpers remain thin wrappers over `request()` so tests can use one fake transport.

- [ ] **Step 5: Run tests**

Run: `python3 -m pytest tests/test_github_api.py -q`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/recomp/github_api.py tests/test_github_api.py
git commit -m "feat: add GitHub App REST client"
```

---

### Task 3: Trusted Task Records and Issue Publication

**Files:**
- Create: `src/recomp/task_records.py`
- Create: `tests/test_task_records.py`
- Modify: `src/recomp/builtin_plugins/generic/runner.py:53-64`
- Modify: `src/recomp/builtin_plugins/generic/recomp.plugin.toml`
- Modify: `tests/test_plugin.py`

**Interfaces:**
- Consumes: plugin `work-plan` results, `PolicyRef`, `TargetRef`, `ImageRef`, `GitHubClient`.
- Produces: `OutputRule`, `TaskRecord`, `render_task_record()`, `parse_trusted_task_record()`, `publish_task_records()`.

- [ ] **Step 1: Write failing task-schema tests**

```python
def test_task_record_round_trips_canonical_bot_comment():
    record = TaskRecord.from_mapping({
        "schema": 1, "task_id": "strings-0000", "kind": "t1-strings",
        "args": {"offset": 0, "length": 64},
        "outputs": [{"path": "recovery/strings/strings-0000.json",
                     "media_type": "application/json", "max_bytes": 65536}],
        "policy_version": 2, "policy_hash": "1" * 64,
        "toolchain_digest": "2" * 64, "target_sha256": "3" * 64,
        "weight": 64, "generation": 1,
    })
    body = render_task_record(record)
    assert parse_task_record_body(body) == record
    assert body.startswith("<!-- recomp-task-v1\n")


def test_publication_is_idempotent_by_task_id(fake_github, record):
    publish_task_records(fake_github, [record])
    publish_task_records(fake_github, [record])
    assert fake_github.created_issue_count == 1
```

Add rejection tests for absolute/traversing paths, duplicate outputs, non-positive bounds, unknown keys, wrong target/policy, contributor-authored lookalikes, and a changed record that must create a trusted supersession transition rather than edit history silently.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest tests/test_task_records.py -q`

Expected: FAIL because the module is absent.

- [ ] **Step 3: Implement canonical records**

Use frozen dataclasses. `OutputRule.path` is a normalized `PurePosixPath`, must begin with `recovery/` or another plugin-declared public output root, and stores `media_type`, `max_bytes`, and `allow_binary`. Serialize with `json.dumps(..., sort_keys=True, separators=(",", ":"))` inside the versioned HTML comment marker.

`parse_trusted_task_record(comments, trusted_actor_id)` accepts only comments whose immutable GitHub author ID equals the configured trusted actor and chooses the highest non-superseded generation.

- [ ] **Step 4: Make plugin output declarations explicit**

Change the generic `work-plan` task from an `args.out` convention to:

```python
{
    "id": f"strings-{i:04d}",
    "kind": "t1-strings",
    "args": {"offset": off, "length": length},
    "outputs": [{
        "path": f"recovery/strings/strings-{i:04d}.json",
        "media_type": "application/json",
        "max_bytes": 65536,
    }],
    "weight": length,
}
```

Update `run-task` and `verify` payload handling to receive the normalized output path from the trusted task record. Add `[verify] mode = "static"` and `public = true` to the generic manifest.

- [ ] **Step 5: Implement idempotent Issue publication**

Use a stable `recomp-task:<task_id>` marker. Create missing Issues with human-readable title/body, machine record, and labels. If the current machine record differs, append a trusted supersession record, update labels, and leave prior comments intact. Never infer authority from editable user text.

- [ ] **Step 6: Run tests**

Run: `python3 -m pytest tests/test_task_records.py tests/test_plugin.py -q`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/recomp/task_records.py src/recomp/builtin_plugins/generic/runner.py src/recomp/builtin_plugins/generic/recomp.plugin.toml tests/test_task_records.py tests/test_plugin.py
git commit -m "feat: publish trusted task issue records"
```

---

### Task 4: Two-Hour Claim Reconciliation

**Files:**
- Create: `src/recomp/claims.py`
- Create: `tests/test_claims.py`

**Interfaces:**
- Consumes: ordered GitHub Issue comments and trusted task record.
- Produces: `LeaseState`, `LeaseTransition`, `ClaimCommand`, `reconcile_claims()` with `CLAIM_TTL_SECONDS = 7200`.

- [ ] **Step 1: Write failing state-machine tests**

```python
def test_claim_and_heartbeat_each_set_two_hour_expiry():
    state = reconcile_claims(task, [], [command(10, "alice", 101, "/claim", at=1000)], now=1000)
    assert state.lease.generation == 1
    assert state.lease.expires_at == 8200
    renewed = reconcile_claims(task, [state.transition], [command(11, "alice", 101, "/heartbeat", at=2000)], now=2000)
    assert renewed.lease.expires_at == 9200


def test_expired_claim_can_be_reclaimed_with_new_generation():
    prior = trusted_lease("alice", user_id=101, generation=7, expires_at=500)
    state = reconcile_claims(task, [prior], [command(12, "bob", 202, "/claim", at=501)], now=501)
    assert (state.lease.claimant_id, state.lease.generation) == (202, 8)
```

Cover exact command parsing, author ID rather than mutable login, non-claimant heartbeat refusal, duplicate/replayed comments, commands arriving in the same second ordered by comment ID, dropped event reconciliation, blocked/done tasks, clock skew bounds, and presentation-label drift.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest tests/test_claims.py -q`

Expected: FAIL because `recomp.claims` does not exist.

- [ ] **Step 3: Implement deterministic event reconciliation**

```python
CLAIM_TTL_SECONDS = 2 * 60 * 60


def parse_command(body: str) -> str | None:
    command = body.strip()
    return command if command in {"/claim", "/heartbeat"} else None
```

Sort command comments by `(created_at, id)`. Start from the latest trusted lease transition, ignore commands at or before its `last_command_id`, and produce at most one new transition per reconciliation call. A claim succeeds when no live lease exists; heartbeat succeeds only for the live claimant. Store issue/task ID, immutable user ID, display login, generation, issued/expiry timestamps, and last consumed command ID.

- [ ] **Step 4: Add verification-lease transitions**

Add `begin_verification(lease, candidate_key, now, ttl_seconds)` and explicit accepted/rejected/inconclusive transitions. Rejection grants the same claimant a new claim lease expiring `now + 7200`; acceptance closes the task; a new head supersedes only the verification candidate, not task history.

- [ ] **Step 5: Run tests**

Run: `python3 -m pytest tests/test_claims.py -q`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/recomp/claims.py tests/test_claims.py
git commit -m "feat: reconcile two-hour GitHub issue claims"
```

---

### Task 5: Pull-Request Tree Preflight

**Files:**
- Create: `src/recomp/preflight.py`
- Create: `tests/test_preflight.py`

**Interfaces:**
- Consumes: `TaskRecord`, PR author/head/base facts, Git tree entries, bounded blob prefixes.
- Produces: `TreeEntry`, `PullRequestFacts`, `PreflightFinding`, `PreflightReport`, `check_preflight()`.

- [ ] **Step 1: Write adversarial failing tests**

```python
@pytest.mark.parametrize(("mode", "code"), [
    ("120000", "symlink"), ("160000", "submodule"), ("100755", "mode-change"),
])
def test_special_or_executable_entries_are_rejected(record, mode, code):
    report = check_preflight(record, facts(author_id=7), [entry("recovery/out.json", mode=mode)])
    assert code in report.codes


def test_casefold_and_unicode_normalization_collisions_are_rejected(record):
    entries = [entry("recovery/A.json"), entry("recovery/a.json")]
    assert "path-collision" in check_preflight(record, facts(), entries).codes
```

Cover protected prefixes, exact output allowlist, extra files, deleted files, tree truncation, path traversal, NUL/control characters, NFC collisions, file/aggregate limits, wrong media type, undeclared binary data, LFS pointer prefixes, stale policy/toolchain, wrong claimant, multiple Issue references, and missing evidence fields.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest tests/test_preflight.py -q`

Expected: FAIL because `recomp.preflight` is absent.

- [ ] **Step 3: Implement data-only validation**

Define protected roots including `.github/`, `plugins/`, `toolchain/`, `recomp.toml`, `recomp.lock.toml`, `README.md`, `AGENTS.md`, `CONTRIBUTING.md`, `docs/progress.svg`, and the generated Issue snapshot. Accept only regular `100644` blobs in the public lane. Match normalized paths exactly against `TaskRecord.outputs`; do not use shell globs.

Detect LFS with the bounded prefix `b"version https://git-lfs.github.com/spec/v1\n"`. Determine binary permission from the task rule, not from file extension alone. Return stable machine codes and sanitized messages without echoing arbitrary PR content.

- [ ] **Step 4: Enforce immutable PR/task binding**

Require exactly one `Closes #N`/structured task field, matching PR author immutable ID, live lease generation, current task generation, base repository, policy hash, and image digest. A report is pass only when `findings == ()`.

- [ ] **Step 5: Run tests**

Run: `python3 -m pytest tests/test_preflight.py -q`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/recomp/preflight.py tests/test_preflight.py
git commit -m "feat: validate public pull request trees"
```

---

### Task 6: Trusted GitHub Actions for Claims and Preflight

**Files:**
- Create: `.github/actions/recomp-claims/action.yml`
- Create: `.github/actions/recomp-claims/action.py`
- Create: `.github/actions/recomp-preflight/action.yml`
- Create: `.github/actions/recomp-preflight/action.py`
- Create: `src/recomp/templates/github/issue_commands.yml`
- Create: `src/recomp/templates/github/preflight.yml`
- Create: `tests/test_github_actions.py`
- Modify: `pyproject.toml:19-20`

**Interfaces:**
- Consumes: `github.event_path`, scoped `github.token`, trusted action repository SHA, `claims`, `task_records`, `preflight`.
- Produces: generated workflows that never execute fork content.

- [ ] **Step 1: Write failing static workflow tests**

```python
def test_preflight_workflow_is_secret_free_and_not_privileged(rendered_preflight):
    assert "pull_request:" in rendered_preflight
    assert "pull_request_target" not in rendered_preflight
    assert "self-hosted" not in rendered_preflight
    assert "contents: read" in rendered_preflight
    assert "persist-credentials: true" not in rendered_preflight


def test_issue_workflow_never_checks_out_repository(rendered_issue_commands):
    assert "issue_comment:" in rendered_issue_commands
    assert "schedule:" in rendered_issue_commands
    assert "actions/checkout" not in rendered_issue_commands
```

Add tests that every `uses:` reference has a 40-character SHA, permissions are explicit, no `${{ github.event.* }}` value is interpolated into a `run:` script, and action outputs contain only stable report codes.

- [ ] **Step 2: Run tests and confirm missing templates**

Run: `python3 -m pytest tests/test_github_actions.py -q`

Expected: FAIL because action/workflow files do not exist.

- [ ] **Step 3: Implement composite actions**

Each `action.yml` runs `python3 "$GITHUB_ACTION_PATH/action.py"`. The entrypoint adds the checked-out action repository's `src/` to `sys.path`, loads the event JSON as data, and calls the package API. It receives the token through an input environment variable and never prints it.

The claims action fetches complete Issue comments and trusted transitions, calls `reconcile_claims()`, appends one transition if needed, and reconciles labels. The preflight action fetches PR/Issue/tree/blob metadata through REST without checking out PR content, calls `check_preflight()`, writes only stable codes to the step summary/output, and exits nonzero on rejection. The GitHub Actions job conclusion is the required preflight check; a fork PR's read-only token is never used to create a Check Run.

- [ ] **Step 4: Render locked workflows**

`issue_commands.yml` handles `issue_comment.created` plus a 15-minute schedule. Event-driven and scheduled runs both reconcile complete history, making dropped/coalesced events harmless. Grant only `issues: write` and `contents: read`.

`preflight.yml` handles `pull_request` open/synchronize/reopen/edited, grants only `contents: read`, `pull-requests: read`, and `issues: read`, and calls the pinned remote action. It has no secrets, cache, artifacts, writable token scope, or self-hosted labels.

Update package data to include nested `templates/**/*`.

- [ ] **Step 5: Exercise action entrypoints against a fake API**

Tests set `GITHUB_EVENT_PATH`, an in-process fake API URL, and a fake token. Assert lease comments/labels are idempotent, preflight success/failure maps to the action exit status, only sanitized summary codes are emitted, no subprocess runs, and no checkout path is read.

- [ ] **Step 6: Run tests**

Run: `python3 -m pytest tests/test_github_actions.py tests/test_claims.py tests/test_preflight.py -q`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add .github/actions src/recomp/templates/github pyproject.toml tests/test_github_actions.py
git commit -m "feat: add trusted GitHub coordination actions"
```

---

### Task 7: Immutable Git Candidate Construction

**Files:**
- Create: `src/recomp/candidate.py`
- Create: `tests/test_candidate.py`

**Interfaces:**
- Consumes: public repository URL, exact base/head SHAs, passed `PreflightReport`, quarantine root.
- Produces: `CandidateTree(key: CandidateKey, path: Path)`, `inspect_tree()`, `construct_candidate()`, `materialize_tree()`.

- [ ] **Step 1: Write failing Git-plumbing tests**

```python
def test_candidate_tree_binds_base_head_and_merge_tree(git_fixture, tmp_path):
    result = construct_candidate(git_fixture.url, git_fixture.base, git_fixture.head, tmp_path)
    assert result.key.base_sha == git_fixture.base
    assert result.key.head_sha == git_fixture.head
    assert result.key.tree_sha == git_fixture.expected_merge_tree
    assert (result.path / "recovery/out.json").read_text() == "{}"


def test_materialization_does_not_run_filters_or_hooks(malicious_git_fixture, tmp_path):
    construct_candidate(malicious_git_fixture.url, malicious_git_fixture.base,
                        malicious_git_fixture.head, tmp_path)
    assert not malicious_git_fixture.side_effect.exists()
```

Cover merge conflicts, unexpected tree object types, symlinks/gitlinks, oversized blobs, `.gitattributes` filters, malicious global Git config, alternate objects, weird filenames, and cleanup after failure.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest tests/test_candidate.py -q`

Expected: FAIL because `recomp.candidate` is absent.

- [ ] **Step 3: Implement a sanitized Git runner**

Invoke Git with argv lists only and an environment containing `PATH`, `GIT_CONFIG_NOSYSTEM=1`, an empty private `HOME`, `GIT_TERMINAL_PROMPT=0`, and no inherited `GIT_*` variables. Initialize a fresh bare quarantine, fetch only exact public SHAs without credentials/tags/submodules, and verify fetched object IDs.

Require Git 2.38+ and use `git merge-tree --write-tree <base> <head>` to obtain a conflict-free result tree without checkout or hooks.

- [ ] **Step 4: Inspect and materialize with plumbing, not checkout**

Parse `git ls-tree -rz -l <tree>`. Re-run the same entry validation as preflight. Read regular blob bytes through `git cat-file --batch`; write them under a newly created destination using `os.open(..., O_CREAT|O_EXCL|O_NOFOLLOW, 0o600)`. Create directories with mode 0o700. Never invoke checkout, archive extraction, smudge filters, or submodule commands.

- [ ] **Step 5: Produce the immutable candidate key**

Take task, lease, policy, and toolchain fields as explicit inputs and return a `CandidateKey` containing the computed merge tree. Atomically rename a completed materialization into its final quarantine directory; remove partial directories on every exception.

- [ ] **Step 6: Run tests**

Run: `python3 -m pytest tests/test_candidate.py tests/test_preflight.py -q`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/recomp/candidate.py tests/test_candidate.py
git commit -m "feat: construct immutable Git candidates safely"
```

---

### Task 8: Digest-Pinned OCI Toolchain and Contributor Launcher

**Files:**
- Create: `src/recomp/toolchain.py`
- Create: `src/recomp/templates/recomp-launcher`
- Create: `src/recomp/templates/toolchain/Containerfile`
- Create: `tests/test_toolchain.py`
- Modify: `src/recomp/cli.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: `ImageRef`, a digest-pinned base image, Docker/Podman argv, project/target paths.
- Produces: `OciRuntime`, `build_and_push_toolchain()`, `render_launcher()`, `inspect_image_digest()`, `run_toolchain()`, and `recomp toolchain build|inspect`.

- [ ] **Step 1: Write failing runtime/launcher tests**

```python
def test_launcher_contains_only_digest_pinned_image(tmp_path):
    image = ImageRef.parse("ghcr.io/acme/game-toolchain@sha256:" + "a" * 64)
    text = render_launcher(image)
    assert str(image) in text
    assert ":latest" not in text
    assert "eval " not in text


def test_toolchain_mounts_target_read_only(fake_runtime, project, target):
    run_toolchain(fake_runtime, image_ref, project, target, ["task", "run", "#12"])
    argv = fake_runtime.argv
    assert f"{target}:/recomp/target:ro" in argv
    assert "--network=none" in argv

def test_build_returns_registry_digest_not_transient_tag(fake_runtime, tmp_path):
    result = build_and_push_toolchain(
        fake_runtime, tmp_path, "python@sha256:" + "b" * 64,
        "ghcr.io/acme/game-toolchain:build-7",
    )
    assert str(result) == "ghcr.io/acme/game-toolchain@sha256:" + "c" * 64
```

Cover Docker/Podman discovery, digest mismatch, missing target, non-matching target hash, spaces/newlines in paths, no shell invocation, read-only target mount, project mount scope, and nonzero exit propagation.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest tests/test_toolchain.py -q`

Expected: FAIL because `recomp.toolchain` is absent.

- [ ] **Step 3: Implement OCI argv construction**

`OciRuntime` accepts only absolute discovered `docker` or `podman` executables. `run_toolchain()` constructs a fixed argv with `--rm`, `--network=none`, dropped capabilities, `no-new-privileges`, bounded pids/memory/cpu, project mounted at `/workspace`, and target mounted read-only at `/recomp/target`. Contributor execution may write only the task workspace; coordinator public verification never uses this container as its isolation boundary.

Inspect the local image through the runtime's JSON output and require the exact configured repo digest. Refuse tags and ambiguous multiple digest results. `build_and_push_toolchain()` requires a digest-pinned base image, builds with `--build-arg BASE_IMAGE=<digest-ref>`, pushes the temporary destination tag, resolves exactly one matching registry `RepoDigest`, and returns that immutable `ImageRef`; a failed push or missing digest produces no project configuration.

- [ ] **Step 4: Add the CLI, protected launcher, and image source**

Add `recomp toolchain build --source PATH --base-image DIGEST_REF --destination REGISTRY_TAG` and `recomp toolchain inspect DIGEST_REF`. `build` prints only the resulting digest-pinned reference on stdout so it can be passed directly to `recomp init`; detailed build output stays on stderr.

The POSIX launcher selects `RECOMP_OCI_RUNTIME` only when it equals `docker` or `podman`, otherwise discovers one. It passes all user arguments as `"$@"`, never uses `eval`, and embeds the exact image reference generated by `render_launcher()`.

The Containerfile takes a required digest-pinned `BASE_IMAGE` build argument, installs a prebuilt local Recomp@Home wheel, copies the guest runner, and sets `ENTRYPOINT ["recomp"]`. No network fetch occurs after the base image and build context are supplied.


- [ ] **Step 5: Run tests**

Run: `python3 -m pytest tests/test_toolchain.py tests/test_contracts.py -q`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/recomp/toolchain.py src/recomp/templates/recomp-launcher src/recomp/templates/toolchain/Containerfile src/recomp/cli.py tests/test_toolchain.py tests/test_cli.py
git commit -m "feat: pin and launch shared OCI toolchains"
```

---

### Task 9: Firecracker Guest Runtime

**Files:**
- Create: `src/recomp/firecracker.py`
- Create: `src/recomp/guest.py`
- Create: `tests/test_firecracker.py`
- Modify: `pyproject.toml:13-20`

**Interfaces:**
- Consumes: pinned kernel/rootfs manifest, `GuestSpec`, Firecracker+jailer, KVM, `mke2fs`, `debugfs`.
- Produces: `GuestLimits`, `GuestDrive`, `GuestSpec`, `GuestResult`, `FirecrackerRunner.run()`, and the `recomp-guest` console entry point.

- [ ] **Step 1: Write failing configuration and lifecycle tests**

```python
def test_public_guest_has_no_network_vsock_or_host_mounts(fake_firecracker, guest_spec):
    runner = FirecrackerRunner(fake_firecracker.config)
    runner.run(guest_spec)
    machine = fake_firecracker.machine_config
    assert "network-interfaces" not in machine
    assert "vsock" not in machine
    assert all(d["path_on_host"].startswith(str(fake_firecracker.jail)) for d in machine["drives"])


def test_result_is_bounded_and_schema_validated(fake_firecracker, guest_spec):
    fake_firecracker.result_bytes = b"x" * 70000
    with pytest.raises(GuestError, match="result exceeds"):
        FirecrackerRunner(fake_firecracker.config).run(guest_spec)
    assert fake_firecracker.jail_removed
```

Cover KVM absence, checksum mismatch, jail ownership, no network device/vsock, read-only input flags, fresh rootfs overlay, timeout kill, result-disk cap, malformed JSON, unexpected files, child cleanup, concurrent guest IDs, and signal interruption.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest tests/test_firecracker.py -q`

Expected: FAIL because the runtime modules are absent.

- [ ] **Step 3: Implement ext4 job/input/result drives**

Create sparse images with fixed maximum sizes, populate input images using `mke2fs -d <source> -F <image>`, and never mount guest-controlled filesystems on the host. Extract only `/verdict.json` from the result image using `debugfs -R "cat /verdict.json"`, cap stdout before JSON parsing, and reject any verdict outside the versioned schema.

Job JSON contains only an enum operation, fixed command identifier from the trusted manifest, resource limits, and drive mount names. It never contains a shell string.

- [ ] **Step 4: Implement and register the minimal guest runner**

`recomp-guest` runs as PID 1, mounts `/proc`, the read-only job/input drives, and the bounded writable result drive; applies rlimits; invokes the trusted argv from the image manifest with `shell=False`; writes a compact atomic `/result/verdict.json`; syncs; and powers off. It captures a bounded private diagnostic code but does not copy arbitrary stdout/stderr into the verdict. Add `recomp-guest = "recomp.guest:main"` to `[project.scripts]` in `pyproject.toml` in the same change so the entry point never references a missing module.

- [ ] **Step 5: Implement jailer/Firecracker lifecycle**

Validate `/dev/kvm`, executable versions/checksums, kernel/rootfs manifest, jail root ownership, and dedicated uid/gid. Copy a fresh writable rootfs overlay into the jail; attach job/input drives read-only and result read-write; omit network and vsock configuration; start through `jailer`; configure the API socket with bounded Unix HTTP requests; enforce wall timeout; terminate the complete process group; and remove the jail in `finally`.

- [ ] **Step 6: Add opt-in real-KVM integration test**

When `RECOMP_FIRECRACKER_TEST=1`, boot the pinned fixture guest, prove `/dev/vdb` is read-only, prove no network interfaces beyond loopback, attempt and fail to read a host canary, write a valid verdict, and confirm a second run cannot see the first run's canary. Skip with an exact prerequisite message otherwise.

- [ ] **Step 7: Run tests**

Run: `python3 -m pytest tests/test_firecracker.py -q`

Expected: PASS for unit tests; real-KVM test is skipped unless explicitly enabled.

- [ ] **Step 8: Commit**

```bash
git add src/recomp/firecracker.py src/recomp/guest.py pyproject.toml tests/test_firecracker.py
git commit -m "feat: run verification jobs in disposable microvms"
```

---

### Task 10: Separated Candidate and Oracle Verification

**Files:**
- Create: `src/recomp/verification.py`
- Create: `tests/test_verification.py`
- Modify: `src/recomp/plugin.py:24-153`
- Modify: `tests/test_plugin.py`

**Interfaces:**
- Consumes: trusted `Plugin`, `TaskRecord`, `CandidateTree`, target path, `FirecrackerRunner`.
- Produces: `VerificationMode`, `VerificationPlan`, `VerificationAttestation`, `verify_candidate()`.

- [ ] **Step 1: Write failing separation tests**

```python
def test_candidate_build_guest_never_receives_target(fake_runner, behavioral_plan):
    verify_candidate(fake_runner, behavioral_plan, candidate, target, key)
    candidate_spec, oracle_spec = fake_runner.specs
    assert all(d.role != "target" for d in candidate_spec.drives)
    assert any(d.role == "target" and d.read_only for d in oracle_spec.drives)


def test_static_verifier_treats_submission_as_data(fake_runner, static_plan):
    attestation = verify_candidate(fake_runner, static_plan, candidate, target, key)
    assert len(fake_runner.specs) == 1
    assert fake_runner.specs[0].operation == "trusted-static-verify"
    assert attestation.passed
```

Cover static, byte-match, and behavioral modes; untrusted build failure; target absent from candidate spec; candidate executable absent from oracle filesystem; bounded mediated inputs/outputs; malformed verdict; changed candidate key; and no raw logs in attestation.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest tests/test_verification.py -q`

Expected: FAIL because `recomp.verification` is absent.

- [ ] **Step 3: Extend trusted plugin manifest parsing**

Parse `[verify]` with:

```toml
[verify]
mode = "static"
public = true
timeout_seconds = 30
max_artifact_bytes = 1048576
```

For behavioral mode, require trusted `candidate_build`, `candidate_run`, and `oracle_run` argv lists plus a declared versioned JSON input/output protocol. Reject shell strings, unknown modes, missing limits, and `public = true` plans that request candidate/target co-location.

- [ ] **Step 4: Implement mode-specific orchestration**

- Static: run only trusted verifier code in an oracle guest with target read-only and submitted files mounted as non-executable data.
- Byte-match: build in a target-free candidate guest, then compare the bounded artifact to the target as data in trusted oracle code.
- Behavioral: build/run candidate in one target-free guest; run the original in a separate oracle guest; feed both the same declared input cases; compare only schema-bounded outputs in the host control process.

A plugin without a separable public plan is maintainer-only.

- [ ] **Step 5: Emit a complete attestation**

`VerificationAttestation` contains `CandidateKey`, verifier policy hash, mode, pass/fail, stable evidence digests, started/completed UTC timestamps, and sanitized reason codes. It never contains target bytes, arbitrary guest output, host paths, or secrets.

- [ ] **Step 6: Run tests**

Run: `python3 -m pytest tests/test_verification.py tests/test_plugin.py -q`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/recomp/verification.py src/recomp/plugin.py tests/test_verification.py tests/test_plugin.py
git commit -m "feat: separate candidate and target verification"
```

---

### Task 11: Coordinator Admission, Queue, and Check Runs

**Files:**
- Create: `src/recomp/coordinator_state.py`
- Create: `src/recomp/coordinator.py`
- Create: `tests/test_coordinator.py`

**Interfaces:**
- Consumes: `GitHubClient`, task/lease records, `PreflightReport`, `construct_candidate()`, `verify_candidate()`.
- Produces: `CoordinatorConfig`, `AdmissionDecision`, `Coordinator.reconcile_once()`, `Coordinator.run_loop()`.

- [ ] **Step 1: Write failing admission/reconstruction tests**

```python
def test_only_live_claimant_is_admitted(coordinator, github):
    github.add_pr(author_id=9, issue=12, head="a" * 40)
    github.set_lease(issue=12, claimant_id=8, expires_at=9999)
    result = coordinator.reconcile_once(now=1000)
    assert result.admitted == ()
    assert result.rejected[0].code == "not-current-claimant"


def test_empty_local_cache_reconstructs_queue_from_github(coordinator_factory, github, tmp_path):
    github.add_eligible_pr(issue=12, head="b" * 40)
    first = coordinator_factory(tmp_path / "state.db").reconcile_once(now=1000)
    (tmp_path / "state.db").unlink()
    second = coordinator_factory(tmp_path / "state.db").reconcile_once(now=1001)
    assert second.pending_keys == first.pending_keys
```

Cover one current candidate per Issue, newest-head supersession, per-author/global limits, retry caps, expired leases, stale preflight, policy mismatch, base movement, API rate limit, restart, and cancellation cleanup.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest tests/test_coordinator.py -q`

Expected: FAIL because coordinator modules are absent.

- [ ] **Step 3: Implement disposable queue state**

Use SQLite WAL for local scheduling only. Store candidate key, PR/Issue numbers, attempt count, status, timestamps, and local quarantine path. No row is authoritative: `reconcile_once()` compares every cached row with current GitHub state, deletes stale rows, and recreates missing eligible rows.

- [ ] **Step 4: Implement admission gates**

For each open PR, require one current task, current author lease, successful current-head preflight, public-eligible verifier, current policy/toolchain, declared-path diff, and available author/global capacity. Append a trusted verification-lease transition before spending private compute. Create/update a neutral queued Check Run bound to the head SHA.

- [ ] **Step 5: Execute and report without leaking raw data**

Construct the immutable candidate, verify it, and create a GitHub Check conclusion using stable reason codes and sanitized counts/digests. On a head change, cancel/supersede old local work. On rejection, write the trusted repair lease transition. On infrastructure failure, mark neutral/inconclusive and retain bounded retry state.

- [ ] **Step 6: Implement polling/backoff/health**

`run_loop()` uses monotonic time, honors GitHub rate-limit reset, applies capped exponential backoff with jitter, handles SIGTERM/SIGINT, and writes a local schema-versioned health JSON atomically. It never opens an inbound network listener.

- [ ] **Step 7: Run tests**

Run: `python3 -m pytest tests/test_coordinator.py tests/test_claims.py tests/test_preflight.py -q`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/recomp/coordinator_state.py src/recomp/coordinator.py tests/test_coordinator.py
git commit -m "feat: coordinate admitted pull request verification"
```

---

### Task 12: Exact-Head Merge and Deterministic Progress Commit

**Files:**
- Create: `src/recomp/progress.py`
- Create: `src/recomp/merge.py`
- Create: `tests/test_merge_progress.py`

**Interfaces:**
- Consumes: passed `VerificationAttestation`, current GitHub task/lease/pull/base state.
- Produces: `ProgressSnapshot`, `render_progress_svg()`, `merge_verified_pull()`, `commit_progress_update()`.

- [ ] **Step 1: Write failing TOCTOU and rendering tests**

```python
@pytest.mark.parametrize("moved", ["head", "base", "policy", "lease"])
def test_any_verified_input_movement_refuses_merge(fake_github, attestation, moved):
    fake_github.move(moved)
    with pytest.raises(MergeRefused, match=moved):
        merge_verified_pull(fake_github, attestation)
    assert fake_github.merge_calls == []


def test_progress_svg_is_deterministic_and_script_free(snapshot):
    first = render_progress_svg(snapshot)
    second = render_progress_svg(snapshot)
    assert first == second
    assert b"<script" not in first.lower()
    assert b"http:" not in first.lower() and b"https:" not in first.lower()
```

Cover `expected_head_sha`, 422 head movement, stable base, failed checks, issue already closed, concurrent progress ref update, escaping task labels, weighted/count metrics, progress retry, and revert/reopen.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest tests/test_merge_progress.py -q`

Expected: FAIL because merge/progress modules are absent.

- [ ] **Step 3: Implement final invariant recheck and merge**

Hold the coordinator's repository-wide async/file lock. Refetch PR, base ref, task, lease transition, required checks, policy, and toolchain. Compare every field to the attestation. Call the GitHub merge endpoint with:

```python
{
    "merge_method": "squash",
    "expected_head_sha": attestation.candidate.head_sha,
    "commit_title": f"{task.task_id}: {task.kind} (#{pr_number})",
}
```

Treat HTTP 409/422 as invalidation, not a retry of the old attestation. Close/label the Issue only after GitHub confirms merge.

- [ ] **Step 4: Implement canonical snapshot and static SVG**

Sort trusted task states by task ID. Serialize JSON with canonical separators and newline. Render an SVG using only fixed shapes/text, escaped project name, integer counts, and explicit count/weight labels. Do not embed script, foreign objects, external URLs, fonts, or contributor text beyond escaped bounded labels.

- [ ] **Step 5: Commit both progress files atomically through Git data APIs**

Create blobs for `docs/progress.json` and `docs/progress.svg`, create a tree based on the current `main` tree, create one commit whose parent is the refetched current `main`, then update `refs/heads/main` with `force=false`. A concurrent ref movement makes the update fail; refetch Issues and retry from the new base. Serialize this operation in the same merge lock.

- [ ] **Step 6: Add revert/reopen behavior**

Given a merged PR/commit, open a coordinator-authored revert PR rather than rewriting history. After the revert merges, append a trusted task-generation transition, reopen the Issue, and regenerate progress.

- [ ] **Step 7: Run tests**

Run: `python3 -m pytest tests/test_merge_progress.py tests/test_coordinator.py -q`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/recomp/progress.py src/recomp/merge.py tests/test_merge_progress.py
git commit -m "feat: merge verified heads and publish progress"
```

---

### Task 13: Link-Driven Contributor Task CLI

**Files:**
- Create: `src/recomp/task_cli.py`
- Create: `tests/test_task_cli.py`
- Modify: `src/recomp/cli.py`

**Interfaces:**
- Consumes: repository or Issue URL, local Git/GitHub auth, local matching target, generated launcher/toolchain.
- Produces: `recomp task next|start|heartbeat|run|verify|submit|status`.

- [ ] **Step 1: Write failing link-to-PR workflow tests**

```python
def test_issue_link_start_claims_and_creates_branch(task_cli, target):
    result = task_cli("start", "https://github.com/acme/game/issues/12", "--target", str(target))
    assert result.returncode == 0
    assert task_cli.github.comments[-1].body == "/claim"
    assert task_cli.git.current_branch == "recomp/strings-0000-12"


def test_submit_refuses_diff_outside_task_outputs(task_cli):
    task_cli.write("plugins/generic/runner.py", "malicious")
    result = task_cli("submit")
    assert result.returncode != 0
    assert "outside task output paths" in result.stderr
    assert task_cli.github.created_pulls == []
```

Cover repository URL task selection, Issue URL parsing, target hash mismatch, missing OCI runtime, claim timeout/denial, heartbeat, policy movement, dirty unrelated files, local verifier failure, fork remote creation, PR body fields, and idempotent resume after process restart.

- [ ] **Step 2: Run tests and confirm missing commands**

Run: `python3 -m pytest tests/test_task_cli.py -q`

Expected: FAIL because the `task` command is absent.

- [ ] **Step 3: Persist non-secret local task context**

Store current Issue number, task ID/generation, branch, policy/image digests, and target hash under `.recomp/task.json`; keep the actual target path in the user's config directory, not the repository. Ensure `.recomp/` remains ignored. Validate context against GitHub before every mutating command.

- [ ] **Step 4: Implement start/run/verify**

`next` lists trusted open tasks and deterministic selection metadata. `start` comments `/claim`, waits for the trusted lease transition, creates `recomp/<task-id>-<issue>`, and records context. `heartbeat` posts the exact command and confirms the new expiry. `run` and `verify` invoke the protected OCI launcher with fixed subcommands and the read-only target mount.

- [ ] **Step 5: Implement submit**

Inspect the branch diff through local Git plumbing and `check_preflight()` before push. Push to the authenticated user's fork using `gh` when available or an already configured fork remote. Create a PR with one closing Issue reference and structured task/lease/policy/image/evidence fields. Never embed the target path or raw verifier log.

- [ ] **Step 6: Run tests**

Run: `python3 -m pytest tests/test_task_cli.py tests/test_cli.py -q`

Expected: PASS with the new `task` command present.

- [ ] **Step 7: Commit**

```bash
git add src/recomp/task_cli.py src/recomp/cli.py tests/test_task_cli.py tests/test_cli.py
git commit -m "feat: add link-driven contributor workflow"
```

---

### Task 14: Owner Setup, Doctor, and systemd Service

**Files:**
- Create: `src/recomp/coordinator_setup.py`
- Create: `src/recomp/templates/systemd/recomp-coordinator.service`
- Create: `tests/test_coordinator_setup.py`
- Modify: `src/recomp/cli.py`

**Interfaces:**
- Consumes: owner setup token/session, GitHub repository, App metadata/key path, Linux/KVM/toolchain paths.
- Produces: `recomp coordinator setup|doctor|install-service|run`, local coordinator config, exact diagnostics.

- [ ] **Step 1: Write failing setup/doctor tests**

```python
def test_public_doctor_fails_closed_without_kvm(doctor_fixture):
    doctor_fixture.remove("/dev/kvm")
    report = doctor_fixture.run()
    assert not report.ok
    assert report.finding("kvm").remediation == "Enable KVM and grant the coordinator account read/write access to /dev/kvm."


def test_setup_never_writes_app_key_into_project(setup_fixture):
    setup_fixture.run()
    assert not any(setup_fixture.project.rglob("*.pem"))
    assert setup_fixture.key_path.stat().st_mode & 0o077 == 0
```

Cover Linux-only enforcement, KVM permissions, Firecracker/jailer/kernel/rootfs checksums, OpenSSL/Git/e2fsprogs/OCI versions, target hash, App permissions, ruleset invariants, Actions policy, trusted labels/records, key ownership/mode, systemd credential path, idempotent rerun, and setup-token deletion.

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest tests/test_coordinator_setup.py -q`

Expected: FAIL because coordinator setup is absent.

- [ ] **Step 3: Define local paths and secret handling**

Use:

```text
~/.config/recomp/coordinators/<owner>__<repo>/config.toml
~/.config/recomp/coordinators/<owner>__<repo>/app-private-key.pem
~/.local/state/recomp/coordinators/<owner>__<repo>/
~/.cache/recomp/coordinators/<owner>__<repo>/
```

Create directories 0700 and key/config files 0600 with `O_NOFOLLOW|O_EXCL` for first creation. Config stores paths and public IDs, never token/key bytes. Accept the temporary owner token through a 0600 file or `gh auth token` subprocess stdout; do not accept it on argv or write it to disk.

- [ ] **Step 4: Implement guided setup stages**

Stages are idempotent and recorded only after verification: host prerequisites; App manifest and installation validation; labels; ruleset/Actions/CODEOWNERS checks; task publication; image digest; target; guest fixture; service installation. Repository administration uses the temporary owner session; runtime configuration validates that the App lacks administration permission.

After repository setup, discard the owner token in memory and verify that runtime operations use only a minted installation token.

- [ ] **Step 5: Implement doctor with exact remediation**

Return a structured `DoctorReport` with stable check IDs, severity, observed sanitized value, and exact remediation. `--self-test` runs a benign fixture through candidate and oracle guests, creates no real task/PR, proves target absence from candidate, and deletes all guest state.

- [ ] **Step 6: Render/install the service**

The systemd unit uses a dedicated user, `LoadCredential=` for the App key, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, explicit writable state/cache paths, restart-on-failure, and only required device access to KVM. Installation prints the exact `systemctl` commands; `--apply` performs them only after explicit CLI selection.

- [ ] **Step 7: Run tests**

Run: `python3 -m pytest tests/test_coordinator_setup.py tests/test_coordinator.py tests/test_firecracker.py -q`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/recomp/coordinator_setup.py src/recomp/templates/systemd src/recomp/cli.py tests/test_coordinator_setup.py
git commit -m "feat: guide and verify coordinator installation"
```

---

### Task 15: Generated GitHub Project and Clean CLI Cutover

**Files:**
- Create: `src/recomp/templates/project_readme.md`
- Create: `src/recomp/templates/contributing.md`
- Create: `src/recomp/templates/github/pull_request_template.md`
- Create: `src/recomp/templates/github/CODEOWNERS`
- Create: `tests/test_generate_github.py`
- Modify: `src/recomp/generate.py:29-104`
- Modify: `src/recomp/templates.py`
- Modify: `src/recomp/templates/project_agents.md`
- Modify: `src/recomp/project.py:24-59`
- Modify: `src/recomp/cli.py:24-249`
- Modify: `tests/conftest.py`
- Modify: `tests/test_cli.py`
- Modify: `pyproject.toml:5-20`
- Remove: `src/recomp/server.py`
- Remove: `src/recomp/state.py`
- Remove: `src/recomp/worker.py`
- Remove: `src/recomp/templates/dashboard.html`
- Remove: `tests/test_server_e2e.py`
- Remove: `tests/test_fastlane_e2e.py`
- Remove: `tests/test_seats.py`
- Remove: `tests/test_state.py`

**Interfaces:**
- Consumes: all preceding GitHub/toolchain/coordinator components.
- Produces: final generated repository layout and final CLI surface: `init`, `detect`, `plugin`, `workflow`, `toolchain`, `github`, `task`, `coordinator`.

- [ ] **Step 1: Write failing generated-layout tests**

```python
def test_generated_project_is_github_ready_without_target_copy(github_project, fixture_bin):
    root = github_project.path
    assert not (root / "bin").exists()
    assert not any(root.rglob(fixture_bin.name))
    assert (root / ".github/workflows/recomp-preflight.yml").is_file()
    assert (root / ".github/workflows/recomp-issue-commands.yml").is_file()
    assert (root / "docs/progress.svg").is_file()
    assert "Fork Recomp@Home" not in (root / "README.md").read_text()
    assert "Give this repository or an Issue link" in (root / "README.md").read_text()


def test_cli_has_no_http_collaboration_commands():
    help_text = run_cli("--help").stdout
    for removed in ("serve", "join", "admin"):
        assert removed not in help_text
    for current in ("toolchain", "github", "task", "coordinator"):
        assert current in help_text
```

Also assert target filename/hash/size but no local path in `recomp.toml`, exact digest-pinned image/framework action ref, nested templates, protected launcher mode, `.gitignore`, initial progress, no `server/`, and no references to seats/worker keys/fast lane.

- [ ] **Step 2: Run tests and confirm old layout fails**

Run: `python3 -m pytest tests/test_generate_github.py tests/test_cli.py -q`

Expected: FAIL because the generator still creates `bin/`/`server/` and old commands.

- [ ] **Step 3: Change generation contract**

Require `--toolchain-image ghcr.io/...@sha256:<64hex>` and `--framework-action owner/repo@<40hexsha>`. Read/hash the supplied target but do not copy it. Store target filename/hash/size/platform/tier and toolchain/framework references in `recomp.toml`, copy plugin/toolchain/template files, generate GitHub files, initialize empty progress, and write no runtime secrets/state.

Update `project.py` to provide `validate_target(path, cfg) -> TargetRef`; remove `target_binary_path()` because a repository-relative target is forbidden.

- [ ] **Step 4: Render contributor/owner boundaries**

Generated `README.md` explains the target-specific project, prerequisites, link-driven launcher, current progress image, and legal requirement to supply one's own target. Generated `AGENTS.md` makes Issues authoritative, documents two-hour claims, forbids trusted-file edits, and gives exact launcher commands. `CONTRIBUTING.md` provides the human equivalent. PR template contains one Issue reference and structured evidence fields. CODEOWNERS protects all trusted roots.

- [ ] **Step 5: Replace CLI commands and remove obsolete implementation**

Add `github bootstrap|sync-tasks`, `task ...`, and `coordinator ...` parsers. Remove `serve`, `join`, remote `work`, and `admin`; delete server/state/worker modules, dashboard, and their tests in the same commit. Keep plugin local `run-task` behavior accessible only through `task run`.

Update package description from “self-hostable ... serve HTTPS submissions” to the GitHub PR coordination model.

- [ ] **Step 6: Run focused and full tests**

Run: `python3 -m pytest tests/test_generate_github.py tests/test_cli.py tests/test_prompt.py tests/test_policy.py -q`

Expected: PASS.

Run: `python3 -m pytest -q`

Expected: PASS with no imports or help text referencing deleted modules/commands.

- [ ] **Step 7: Commit**

```bash
git add src/recomp tests pyproject.toml
git commit -m "feat: generate GitHub-coordinated recovery projects"
```

---

### Task 16: Framework and Owner Documentation Cutover

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`
- Create: `docs/coordinator-setup.md`
- Create: `docs/security-model.md`
- Create: `docs/contributor-workflow.md`
- Modify: `src/recomp/templates/prompt_default.md`
- Modify: `tests/test_prompt.py`

**Interfaces:**
- Consumes: final CLI/output from Tasks 1-15.
- Produces: one authoritative fork/customize guide, comprehensive owner setup/operations guide, threat model, and link-only contributor instructions.

- [ ] **Step 1: Write failing documentation-contract tests**

```python
def test_generated_prompt_uses_github_workflow(project):
    text = render_prompt_static(project.path)
    assert "/claim" in text
    assert "two hours" in text
    assert "pull request" in text.lower()
    assert "recomp join" not in text
    assert "/api/submit" not in text
```

Add a test reading framework README/guide text to require the phrases `Fork Recomp@Home`, `separate project repository`, `Linux`, `KVM`, `GitHub App`, `coordinator doctor`, and `repository or Issue link`; reject old `recomp serve`, invite-token, seat, and public-API quick starts.

- [ ] **Step 2: Run documentation-contract tests and confirm failure**

Run: `python3 -m pytest tests/test_prompt.py -q`

Expected: FAIL on the old server workflow text.

- [ ] **Step 3: Rewrite the framework README and AGENTS host lane**

Lead with:

```text
Fork Recomp@Home, give the fork to your coordinator agent, customize the
workflow for your target, then generate a separate decompilation project
repository. Contributors receive only that project's repository or task link.
```

Show the owner lifecycle, contributor lifecycle, progress image behavior, and security boundary. Remove public-server deployment, enrollment, seat, and optimistic-fast-lane instructions.

- [ ] **Step 4: Write the comprehensive owner guide**

Document supported Linux/KVM prerequisites; fork customization; image build/push/digest; fresh repo creation; GitHub App manifest and exact permissions; App installation/key storage; setup-time owner token; ruleset/Actions/CODEOWNERS settings; task publication; systemd; `doctor --self-test`; start/stop/logs; upgrades and policy repinning; backup/rebuild; key rotation/revocation; break-glass; incident response; uninstall; and exact expected outputs. Commands must match the implemented CLI exactly.

- [ ] **Step 5: Write security and contributor guides**

`security-model.md` documents attacker capabilities, GitHub's role, protected paths, candidate/oracle split, target/log exfiltration controls, credentials, DoS limits, residual microVM/kernel risk, and response to a bad merge. Link GitHub's secure-use reference.

`contributor-workflow.md` starts from a repository/Issue link and covers prerequisites, target placement, claim/heartbeat, OCI execution, diff validation, submission, rejection repair lease, and reporting.

- [ ] **Step 6: Run tests and validate commands**

Run: `python3 -m pytest tests/test_prompt.py tests/test_cli.py tests/test_generate_github.py -q`

Expected: PASS.

Run each documented `--help` command: `python3 -m recomp init --help`, `python3 -m recomp github --help`, `python3 -m recomp task --help`, and `python3 -m recomp coordinator --help`.

Expected: every command exits 0 and every documented option is present.

- [ ] **Step 7: Commit**

```bash
git add README.md AGENTS.md docs/coordinator-setup.md docs/security-model.md docs/contributor-workflow.md src/recomp/templates/prompt_default.md tests/test_prompt.py
git commit -m "docs: explain GitHub coordinator deployment"
```

---

### Task 17: Public Workflow End-to-End Acceptance

**Files:**
- Create: `tests/test_public_workflow_e2e.py`
- Create: `tests/fixtures/public_plugin/recomp.plugin.toml`
- Create: `tests/fixtures/public_plugin/runner.py`
- Create: `tests/fixtures/guest/README.txt`
- Modify: `tests/conftest.py`

**Interfaces:**
- Consumes: completed generated project, fake and optional live GitHub repository, optional real Firecracker fixture.
- Produces: executable proof of the full accepted/rejected/restart/progress lifecycle.

- [ ] **Step 1: Write the fake-GitHub end-to-end test**

```python
def test_public_pull_request_lifecycle(public_harness):
    issue = public_harness.publish_fixture_task()
    lease = public_harness.comment(issue, actor="alice", body="/claim", now=1000)
    assert lease.expires_at == 8200

    good = public_harness.open_pr(issue, actor="alice", content='{"value": 7}')
    bad = public_harness.open_pr(issue, actor="mallory", extra={".github/workflows/pwn.yml": "x"})
    public_harness.reconcile()

    assert public_harness.check(bad).code == "not-current-claimant"
    assert public_harness.check(good).conclusion == "success"
    assert public_harness.pull(good).merged
    assert public_harness.issue(issue).state == "closed"
    assert public_harness.progress.completed == 1
```

Add restart/cache deletion, head push invalidation, base movement, rejected verifier repair lease, progress ref race/retry, and revert/reopen scenarios.

- [ ] **Step 2: Run the fake end-to-end test and fix only integration defects**

Run: `python3 -m pytest tests/test_public_workflow_e2e.py -q`

Expected: PASS using only local fake GitHub transport and the non-proprietary fixture target.

- [ ] **Step 3: Add opt-in live GitHub acceptance**

When `RECOMP_GITHUB_E2E_REPO=owner/repo` and setup credential-file variables are present, create uniquely prefixed fixture Issues/branches/PRs, run claim/preflight/coordinator/merge/progress, and clean up branches/Issues in `finally`. Refuse to run against a repository without the fixture marker topic/config. Never print credentials.

- [ ] **Step 4: Add real Firecracker acceptance**

When both live-GitHub and `RECOMP_FIRECRACKER_TEST=1` are enabled, run the benign candidate through the actual guest path and submit a malicious candidate that attempts network, host-canary, target, oversized-output, and prior-job-state access. Assert all attempts fail and only the benign candidate merges.

- [ ] **Step 5: Run the complete local suite**

Run: `python3 -m pytest -q`

Expected: PASS; live GitHub/KVM tests skip with exact prerequisite messages when not enabled.

- [ ] **Step 6: Run installed CLI smoke tests**

Build/install in a clean virtual environment, then run:

```bash
python3 -m venv /tmp/recomp-plan-smoke
/tmp/recomp-plan-smoke/bin/pip install .
/tmp/recomp-plan-smoke/bin/recomp --help
/tmp/recomp-plan-smoke/bin/recomp coordinator doctor --help
/tmp/recomp-plan-smoke/bin/recomp task --help
```

Expected: installation succeeds without third-party Python runtime packages; all help commands exit 0.

- [ ] **Step 7: Run production-path verification on a prepared Linux/KVM host**

Run: `recomp coordinator doctor --self-test`.

Expected: every required check passes, a benign fixture traverses real candidate/oracle guests, no target is visible to the candidate guest, and all guest/quarantine state is removed.

- [ ] **Step 8: Commit**

```bash
git add tests/test_public_workflow_e2e.py tests/fixtures tests/conftest.py
git commit -m "test: prove public GitHub coordination end to end"
```

---

## Final Verification

- [ ] Run `python3 -m pytest -q` and record the complete passing summary.
- [ ] Run `python3 -m build` only if the repository already provides the build frontend; otherwise build with `python3 -m pip wheel . --no-deps` in a clean virtual environment and install the wheel.
- [ ] Run every generated workflow/action test and inspect GitHub permissions from rendered files.
- [ ] Run `recomp coordinator doctor --self-test` on Linux/KVM with the pinned guest artifacts.
- [ ] Run the opt-in disposable-repository GitHub acceptance test.
- [ ] Generate a project from a fixture target, confirm no target/key/runtime state entered its Git tree, and hand only its repository URL to a fresh agent session.
- [ ] Confirm that agent can discover a task, acquire a 7,200-second lease, run the pinned toolchain, and open a valid PR without installing project language/toolchain dependencies directly.
- [ ] Confirm an adversarial PR cannot modify trusted infrastructure, read the target, access network/credentials/host state, leak raw logs, consume unbounded resources, or merge after any candidate field changes.
- [ ] Confirm the accepted PR closes its Issue and the trusted follow-up commit changes `docs/progress.svg` and `docs/progress.json` deterministically.
