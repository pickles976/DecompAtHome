"""Immutable candidate construction with sanitized Git plumbing only."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping
from urllib.parse import urlsplit

from recomp.contracts import CandidateKey, Sha256
from recomp.preflight import PreflightReport

_MIN_GIT_VERSION = (2, 38)
_DEFAULT_MAX_BLOB_BYTES = 16 << 20
_DEFAULT_MAX_TOTAL_BYTES = 64 << 20
# Regular files only. Symlinks (120000), gitlinks (160000), and trees are refused:
# the guest mounts the input drive noexec, so the executable bit is inert there.
_REGULAR_MODES = {"100644", "100755"}
_GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")


class CandidateError(RuntimeError):
    pass


@dataclass(frozen=True)
class InspectedEntry:
    path: str
    mode: str
    kind: str
    sha: str
    size: int


@dataclass(frozen=True)
class CandidateTree:
    key: CandidateKey
    path: Path


def _git_environment(home: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.fspath(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }


def _run_git(
    args: Iterable[str],
    *,
    env: Mapping[str, str],
    cwd: Path | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", "-c", "credential.helper=", *args],
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=text,
        )
    except FileNotFoundError as exc:
        raise CandidateError("Git executable is unavailable") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode("utf-8", "replace")
        if "conflict" in detail.lower():
            raise CandidateError("Git merge-tree reported a merge conflict") from None
        raise CandidateError("sanitized Git plumbing command failed") from None


def _require_git_version(env: Mapping[str, str]) -> None:
    output = _run_git(["--version"], env=env).stdout.strip()
    match = re.fullmatch(r"git version (\d+)\.(\d+)(?:\..*)?", output)
    if match is None or tuple(map(int, match.groups())) < _MIN_GIT_VERSION:
        raise CandidateError("Git 2.38 or newer is required")


def _validate_source(repository_url: str) -> None:
    if (not isinstance(repository_url, str) or not repository_url
            or "\x00" in repository_url or "\n" in repository_url):
        raise CandidateError("repository URL is invalid")
    parsed = urlsplit(repository_url)
    if parsed.username is not None or parsed.password is not None:
        raise CandidateError("repository URL must not contain credentials")
    if parsed.scheme:
        if parsed.scheme not in {"https", "file"}:
            raise CandidateError("repository URL uses an unsupported scheme")
    elif not Path(repository_url).is_absolute() or not Path(repository_url).exists():
        raise CandidateError("repository URL must be HTTPS or an existing absolute local path")


def _verify_commit(repo: Path, ref: str, expected: str, env: Mapping[str, str]) -> None:
    actual = _run_git(["-C", os.fspath(repo), "rev-parse", f"{ref}^{{commit}}"], env=env).stdout.strip()
    if actual != expected:
        raise CandidateError("fetched Git object does not match requested commit")


def _fetch_exact(repo: Path, repository_url: str, base_sha: str, head_sha: str,
                 env: Mapping[str, str]) -> None:
    for value in (base_sha, head_sha):
        if _GIT_SHA_RE.fullmatch(value) is None:
            raise CandidateError("base and head must be exact lowercase Git commit IDs")
    _run_git(["init", "--bare", os.fspath(repo)], env=env)
    _run_git([
        "-C", os.fspath(repo),
        "fetch", "--no-tags", "--no-write-fetch-head", "--no-recurse-submodules",
        "--", repository_url,
        f"+{base_sha}:refs/recomp/base",
        f"+{head_sha}:refs/recomp/head",
    ], env=env)
    _verify_commit(repo, "refs/recomp/base", base_sha, env)
    _verify_commit(repo, "refs/recomp/head", head_sha, env)


def _safe_tree_path(raw: bytes) -> str:
    try:
        path = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CandidateError("Git tree contains an unsafe filename") from exc
    if (not path or "\\" in path or any(ord(character) < 32 or ord(character) == 127 for character in path)):
        raise CandidateError("Git tree contains an unsafe filename")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or parsed.as_posix() != path or "." in parsed.parts or ".." in parsed.parts:
        raise CandidateError("Git tree contains an unsafe filename")
    return path


def inspect_tree(
    repo: str | Path,
    tree_sha: str,
    *,
    max_blob_bytes: int = _DEFAULT_MAX_BLOB_BYTES,
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES,
    env: Mapping[str, str] | None = None,
) -> tuple[InspectedEntry, ...]:
    """Inspect a tree with NUL-delimited plumbing and reject non-regular objects."""

    repo_path = Path(repo)
    if env is None:
        home = repo_path.parent / ".inspect-home"
        home.mkdir(mode=0o700, exist_ok=True)
        env = _git_environment(home)
    raw = _run_git(
        ["-C", os.fspath(repo_path), "ls-tree", "-rz", "-l", tree_sha],
        env=env,
        text=False,
    ).stdout
    entries = []
    total = 0
    seen: set[str] = set()
    for record in raw.split(b"\x00"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, raw_sha, raw_size = metadata.split(b" ", 3)
            path = _safe_tree_path(raw_path)
            mode_text = mode.decode("ascii")
            kind_text = kind.decode("ascii")
            sha = raw_sha.decode("ascii")
            size = int(raw_size)
        except (ValueError, UnicodeDecodeError) as exc:
            raise CandidateError("Git tree contains a malformed entry") from exc
        if path in seen:
            raise CandidateError("Git tree contains duplicate paths")
        seen.add(path)
        if (mode_text not in _REGULAR_MODES or kind_text != "blob"
                or _GIT_SHA_RE.fullmatch(sha) is None):
            raise CandidateError("Git tree contains an unsupported tree object")
        if size < 0 or size > max_blob_bytes:
            raise CandidateError("Git tree contains an oversized blob")
        total += size
        if total > max_total_bytes:
            raise CandidateError("Git tree exceeds the aggregate blob limit")
        entries.append(InspectedEntry(path, mode_text, kind_text, sha, size))
    return tuple(entries)


def _read_blobs(
    repo: Path,
    entries: tuple[InspectedEntry, ...],
    env: Mapping[str, str],
) -> dict[str, bytes]:
    try:
        process = subprocess.Popen(
            ["git", "-c", "credential.helper=", "-C", os.fspath(repo), "cat-file", "--batch"],
            env=dict(env),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise CandidateError("Git executable is unavailable") from exc
    assert process.stdin is not None and process.stdout is not None
    blobs: dict[str, bytes] = {}
    try:
        for entry in entries:
            process.stdin.write(entry.sha.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().rstrip(b"\n").split(b" ")
            if len(header) != 3:
                raise CandidateError("Git cat-file returned a malformed header")
            actual_sha, kind, raw_size = header
            try:
                size = int(raw_size)
            except ValueError as exc:
                raise CandidateError("Git cat-file returned a malformed size") from exc
            if actual_sha.decode("ascii") != entry.sha or kind != b"blob" or size != entry.size:
                raise CandidateError("Git blob changed after tree inspection")
            content = process.stdout.read(size)
            delimiter = process.stdout.read(1)
            if len(content) != size or delimiter != b"\n":
                raise CandidateError("Git cat-file returned a truncated blob")
            blobs[entry.sha] = content
        process.stdin.close()
        if process.wait(timeout=30) != 0:
            raise CandidateError("Git cat-file failed")
    except Exception:
        process.kill()
        process.wait()
        raise
    return blobs


def _secure_parent(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for component in relative.parts[:-1]:
        current = current / component
        if not current.exists():
            current.mkdir(mode=0o700)
        elif not current.is_dir() or current.is_symlink():
            raise CandidateError("candidate path parent is not a directory")
    return current


def materialize_tree(
    repo: str | Path,
    entries: tuple[InspectedEntry, ...],
    destination: str | Path,
    *,
    env: Mapping[str, str] | None = None,
) -> Path:
    """Write inspected blobs without checkout, filters, hooks, or archive extraction."""

    repo_path = Path(repo)
    destination_path = Path(destination)
    if destination_path.exists():
        raise CandidateError("candidate destination already exists")
    destination_path.mkdir(mode=0o700)
    if env is None:
        home = destination_path.parent / ".materialize-home"
        home.mkdir(mode=0o700, exist_ok=True)
        env = _git_environment(home)
    blobs = _read_blobs(repo_path, entries, env)
    try:
        for entry in entries:
            relative = PurePosixPath(entry.path)
            parent = _secure_parent(destination_path, relative)
            target = parent / relative.name
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o600)
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    stream.write(blobs[entry.sha])
                    stream.flush()
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return destination_path
    except Exception:
        shutil.rmtree(destination_path, ignore_errors=True)
        raise


def construct_candidate(
    repository_url: str,
    base_sha: str,
    head_sha: str,
    quarantine_root: str | Path,
    *,
    task_id: str,
    lease_generation: int,
    policy_hash: Sha256,
    toolchain_digest: Sha256,
    preflight_report: PreflightReport,
    max_blob_bytes: int = _DEFAULT_MAX_BLOB_BYTES,
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES,
) -> CandidateTree:
    """Fetch exact commits, compute a merge tree, and atomically materialize it."""

    if not isinstance(preflight_report, PreflightReport) or not preflight_report.passed:
        raise CandidateError("candidate construction requires a passed preflight report")
    _validate_source(repository_url)
    root = Path(quarantine_root)
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".candidate-", dir=root))
    os.chmod(work, 0o700)
    home = work / "home"
    home.mkdir(mode=0o700)
    repo = work / "objects.git"
    tree_path = work / "tree"
    env = _git_environment(home)
    final_path: Path | None = None
    try:
        _require_git_version(env)
        _fetch_exact(repo, repository_url, base_sha, head_sha, env)
        try:
            merge_output = _run_git([
                "-C", os.fspath(repo), "merge-tree", "--write-tree",
                "refs/recomp/base", "refs/recomp/head",
            ], env=env).stdout.splitlines()
        except CandidateError as exc:
            raise CandidateError("Git merge-tree failed or reported a conflict") from exc
        if not merge_output or _GIT_SHA_RE.fullmatch(merge_output[0]) is None:
            raise CandidateError("Git merge-tree did not produce a tree")
        tree_sha = merge_output[0]
        entries = inspect_tree(
            repo, tree_sha,
            max_blob_bytes=max_blob_bytes,
            max_total_bytes=max_total_bytes,
            env=env,
        )
        materialize_tree(repo, entries, tree_path, env=env)
        key = CandidateKey(
            task_id=task_id,
            lease_generation=lease_generation,
            policy_hash=policy_hash,
            base_sha=base_sha,
            head_sha=head_sha,
            tree_sha=tree_sha,
            toolchain_digest=toolchain_digest,
        )
        candidate_path = root / f"{task_id}-{head_sha[:12]}-{tree_sha[:12]}"
        if candidate_path.exists():
            raise CandidateError("immutable candidate destination already exists")
        os.rename(tree_path, candidate_path)
        final_path = candidate_path
        return CandidateTree(key, candidate_path)
    except CandidateError:
        if final_path is not None and final_path.exists():
            shutil.rmtree(final_path, ignore_errors=True)
        raise
    except Exception as exc:
        if final_path is not None and final_path.exists():
            shutil.rmtree(final_path, ignore_errors=True)
        raise CandidateError("candidate construction failed") from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)
