"""Data-only, fail-closed preflight for public pull-request trees."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable

from recomp.contracts import Sha256
from recomp.task_records import TaskRecord

LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1\n"
BLOB_PREFIX_LIMIT = 4096
DEFAULT_MAX_TOTAL_BYTES = 16 << 20
_PROTECTED_PREFIXES = (".github/", "plugins/", "toolchain/")
_PROTECTED_FILES = {
    "recomp.toml",
    "recomp.lock.toml",
    "recomp-launcher",
    "README.md",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "docs/progress.svg",
    "docs/progress.json",
    "docs/tasks.json",
}
_GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")
_MESSAGES = {
    "missing-evidence": "Required pull-request evidence is missing or malformed.",
    "tree-truncated": "The pull-request tree response is truncated.",
    "protected-path": "The pull request modifies a protected project path.",
    "unsafe-path": "The pull request contains an unsafe path.",
    "path-collision": "Pull-request paths collide after portable normalization.",
    "symlink": "Symbolic links are not allowed in public submissions.",
    "submodule": "Git submodules are not allowed in public submissions.",
    "mode-change": "Only regular non-executable files are allowed.",
    "extra-file": "The pull request changes an undeclared output path.",
    "missing-output": "The pull request omits a declared output path.",
    "deleted-file": "Public submissions may not delete files.",
    "file-too-large": "A declared output exceeds its byte limit.",
    "aggregate-too-large": "The submitted output set exceeds its aggregate byte limit.",
    "media-type": "A declared output does not match its required media type.",
    "binary-not-allowed": "Binary data is not allowed for this output.",
    "lfs-pointer": "Git LFS pointers are not allowed for this output.",
    "stale-policy": "The pull request does not use the current policy.",
    "stale-toolchain": "The pull request does not use the current toolchain.",
    "wrong-claimant": "The pull-request author does not own the live claim.",
    "expired-lease": "The task claim is no longer live.",
    "stale-task": "The pull request references an obsolete task generation.",
    "wrong-repository": "The pull request targets an unexpected base repository.",
    "task-reference": "The pull request must reference exactly its assigned Issue.",
}


@dataclass(frozen=True)
class TreeEntry:
    path: str
    mode: str
    kind: str
    sha: str | None
    size: int | None
    status: str
    prefix: bytes | None
    media_type: str | None


@dataclass(frozen=True)
class PullRequestFacts:
    author_id: int | None
    head_sha: str | None
    base_sha: str | None
    base_repository: str | None
    expected_repository: str | None
    referenced_issue_numbers: tuple[int, ...] | None
    task_issue_number: int | None
    lease_claimant_id: int | None
    lease_generation: int | None
    lease_expires_at: int | None
    now: int | None
    task_generation: int | None
    policy_hash: Sha256 | None
    toolchain_digest: Sha256 | None
    tree_truncated: bool | None


@dataclass(frozen=True)
class PreflightFinding:
    code: str
    message: str


@dataclass(frozen=True)
class PreflightReport:
    findings: tuple[PreflightFinding, ...]

    @property
    def passed(self) -> bool:
        return not self.findings

    @property
    def codes(self) -> tuple[str, ...]:
        return tuple(finding.code for finding in self.findings)


class _Findings:
    def __init__(self) -> None:
        self.items: list[PreflightFinding] = []
        self._seen: set[str] = set()

    def add(self, code: str) -> None:
        if code not in self._seen:
            self._seen.add(code)
            self.items.append(PreflightFinding(code, _MESSAGES[code]))


def _safe_path(path: str) -> bool:
    if not isinstance(path, str) or not path or "\\" in path:
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return False
    parsed = PurePosixPath(path)
    return (
        not parsed.is_absolute()
        and parsed.as_posix() == path
        and "." not in parsed.parts
        and ".." not in parsed.parts
    )


def _portable_path(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _protected(path: str) -> bool:
    return path in _PROTECTED_FILES or any(path.startswith(prefix) for prefix in _PROTECTED_PREFIXES)


def _valid_sha(value: str | None) -> bool:
    return isinstance(value, str) and _GIT_SHA_RE.fullmatch(value) is not None


def _check_binding(record: TaskRecord, facts: PullRequestFacts, findings: _Findings) -> None:
    required = (
        facts.author_id,
        facts.head_sha,
        facts.base_sha,
        facts.base_repository,
        facts.expected_repository,
        facts.referenced_issue_numbers,
        facts.task_issue_number,
        facts.lease_claimant_id,
        facts.lease_generation,
        facts.lease_expires_at,
        facts.now,
        facts.task_generation,
        facts.policy_hash,
        facts.toolchain_digest,
        facts.tree_truncated,
    )
    identifiers = (
        facts.author_id, facts.task_issue_number, facts.lease_claimant_id,
        facts.lease_generation, facts.lease_expires_at, facts.task_generation,
    )
    invalid_identifier = any(
        isinstance(value, bool) or not isinstance(value, int) or value < 1
        for value in identifiers if value is not None
    )
    if (any(value is None for value in required) or invalid_identifier
            or not _valid_sha(facts.head_sha) or not _valid_sha(facts.base_sha)):
        findings.add("missing-evidence")
    if (facts.base_repository is not None and facts.expected_repository is not None
            and facts.base_repository != facts.expected_repository):
        findings.add("wrong-repository")
    if (facts.referenced_issue_numbers is None or facts.task_issue_number is None
            or len(facts.referenced_issue_numbers) != 1
            or facts.referenced_issue_numbers[0] != facts.task_issue_number):
        findings.add("task-reference")
    if (facts.author_id is not None and facts.lease_claimant_id is not None
            and facts.author_id != facts.lease_claimant_id):
        findings.add("wrong-claimant")
    if (facts.lease_expires_at is not None and facts.now is not None
            and facts.lease_expires_at <= facts.now):
        findings.add("expired-lease")
    if facts.task_generation is not None and facts.task_generation != record.generation:
        findings.add("stale-task")
    if facts.policy_hash is not None and facts.policy_hash != record.policy_hash:
        findings.add("stale-policy")
    if facts.toolchain_digest is not None and facts.toolchain_digest != record.toolchain_digest:
        findings.add("stale-toolchain")
    if facts.tree_truncated:
        findings.add("tree-truncated")


def check_preflight(
    record: TaskRecord,
    facts: PullRequestFacts,
    entries: Iterable[TreeEntry],
    *,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> PreflightReport:
    """Validate immutable PR facts and a bounded Git tree without checkout."""

    findings = _Findings()
    _check_binding(record, facts, findings)
    rules = {rule.path.as_posix(): rule for rule in record.outputs}
    seen_paths: set[str] = set()
    portable_paths: set[str] = set()
    total_bytes = 0

    for entry in entries:
        path = entry.path
        if not _safe_path(path):
            findings.add("unsafe-path")
            continue
        portable = _portable_path(path)
        if path in seen_paths or portable in portable_paths:
            findings.add("path-collision")
        seen_paths.add(path)
        portable_paths.add(portable)
        if _protected(path):
            findings.add("protected-path")
        if entry.status == "deleted":
            findings.add("deleted-file")
        if entry.mode == "120000":
            findings.add("symlink")
        elif entry.mode == "160000" or entry.kind == "commit":
            findings.add("submodule")
        elif entry.mode != "100644" or entry.kind != "blob":
            findings.add("mode-change")

        rule = rules.get(path)
        if rule is None:
            findings.add("extra-file")
            continue
        if (not _valid_sha(entry.sha) or isinstance(entry.size, bool)
                or not isinstance(entry.size, int) or entry.size < 0
                or not isinstance(entry.prefix, bytes)
                or len(entry.prefix) > BLOB_PREFIX_LIMIT
                or not isinstance(entry.media_type, str)):
            findings.add("missing-evidence")
            continue
        total_bytes += entry.size
        if entry.size > rule.max_bytes:
            findings.add("file-too-large")
        if entry.prefix.startswith(LFS_POINTER_PREFIX):
            findings.add("lfs-pointer")
        if entry.media_type != rule.media_type:
            findings.add("media-type")
        if not rule.allow_binary:
            try:
                entry.prefix.decode("utf-8")
            except UnicodeDecodeError:
                findings.add("binary-not-allowed")
            if b"\x00" in entry.prefix:
                findings.add("binary-not-allowed")
            if rule.media_type == "application/json":
                leading = entry.prefix.lstrip()[:1]
                if leading not in {b"{", b"["}:
                    findings.add("media-type")

    for path in rules:
        if path not in seen_paths:
            findings.add("missing-output")
    if total_bytes > max_total_bytes:
        findings.add("aggregate-too-large")
    return PreflightReport(tuple(findings.items))
