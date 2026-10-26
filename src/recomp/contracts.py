"""Immutable public-workflow contracts shared by every trusted party.

Value objects that cross process and trust boundaries (task candidates,
policy pins, toolchain images, target binaries) are frozen and validated at
construction, so the coordinator, server, plugins, and contributor hosts all
recompute the same canonical identifiers. Standard library only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")
_TASK_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")


def _require_non_negative_int(value: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{what} must be a non-negative integer")
    return value


def _git_sha(value: str, what: str) -> str:
    if not isinstance(value, str) or _GIT_SHA_RE.fullmatch(value) is None:
        raise ValueError(f"{what} must be 40 lowercase hexadecimal characters")
    return value


@dataclass(frozen=True, order=True)
class Sha256:
    hex: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.hex):
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")


def parse_sha256(value: str) -> Sha256:
    return Sha256(value)


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


def parse_image_ref(value: str) -> ImageRef:
    return ImageRef.parse(value)


@dataclass(frozen=True)
class TargetRef:
    filename: str
    sha256: Sha256
    size: int

    def __post_init__(self) -> None:
        if (not isinstance(self.filename, str)
                or self.filename in ("", ".", "..")
                or PurePosixPath(self.filename).name != self.filename):
            raise ValueError("target filename must be a single path component")
        _require_non_negative_int(self.size, "target size")


@dataclass(frozen=True)
class PolicyRef:
    version: int
    hash: Sha256

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise ValueError("policy version must be a positive integer")


@dataclass(frozen=True)
class CandidateKey:
    task_id: str
    lease_generation: int
    policy_hash: Sha256
    base_sha: str
    head_sha: str
    tree_sha: str
    toolchain_digest: Sha256

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or _TASK_ID_RE.fullmatch(self.task_id) is None:
            raise ValueError("task_id must match [a-z0-9][a-z0-9._-]{0,127}")
        _require_non_negative_int(self.lease_generation, "lease_generation")
        _git_sha(self.base_sha, "base_sha")
        _git_sha(self.head_sha, "head_sha")
        _git_sha(self.tree_sha, "tree_sha")

    def canonical(self) -> dict:
        """Plain JSON-serializable form in the exact trusted field order."""
        return {
            "task_id": self.task_id,
            "lease_generation": self.lease_generation,
            "policy_hash": self.policy_hash.hex,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "tree_sha": self.tree_sha,
            "toolchain_digest": self.toolchain_digest.hex,
        }
