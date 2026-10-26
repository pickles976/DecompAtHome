import dataclasses
from pathlib import PurePosixPath

import pytest

from recomp.contracts import (
    CandidateKey,
    ImageRef,
    PolicyRef,
    Sha256,
    TargetRef,
    parse_image_ref,
    parse_sha256,
)


def test_image_ref_requires_registry_name_and_digest():
    digest = "a" * 64
    ref = ImageRef.parse(f"ghcr.io/acme/recomp-toolchain@sha256:{digest}")
    assert ref.repository == "ghcr.io/acme/recomp-toolchain"
    assert ref.digest == Sha256(digest)
    assert str(ref) == f"ghcr.io/acme/recomp-toolchain@sha256:{digest}"
    with pytest.raises(ValueError, match="digest-pinned"):
        ImageRef.parse("ghcr.io/acme/recomp-toolchain:latest")
    with pytest.raises(ValueError, match="digest-pinned"):
        ImageRef.parse("recomp-toolchain@sha256:" + digest)


def test_parse_helpers_validate_their_input():
    assert parse_sha256("a" * 64) == Sha256("a" * 64)
    with pytest.raises(ValueError, match="64 lowercase"):
        parse_sha256("A" * 64)
    with pytest.raises(ValueError, match="64 lowercase"):
        parse_sha256("z" * 64)
    parsed = parse_image_ref("ghcr.io/acme/game-toolchain@sha256:" + "b" * 64)
    assert parsed == ImageRef("ghcr.io/acme/game-toolchain", Sha256("b" * 64))


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
    assert key.canonical()["policy_hash"] == "1" * 64
    assert key.canonical()["toolchain_digest"] == "5" * 64


def _candidate_kwargs():
    return dict(
        task_id="strings-0001", lease_generation=4,
        policy_hash=Sha256("1" * 64), base_sha="2" * 40,
        head_sha="3" * 40, tree_sha="4" * 40,
        toolchain_digest=Sha256("5" * 64),
    )


def test_candidate_key_rejects_unsanitary_identifiers():
    for field, bad in (
        ("task_id", "Strings-0001"),
        ("task_id", "x" * 129),
        ("task_id", "-leading-dash"),
        ("base_sha", "2" * 39),
        ("head_sha", "A" * 40),
        ("tree_sha", "4" * 40 + "z"),
        ("lease_generation", "4"),
    ):
        with pytest.raises(ValueError):
            CandidateKey(**{**_candidate_kwargs(), field: bad})


def test_value_objects_are_frozen():
    key = CandidateKey(**_candidate_kwargs())
    with pytest.raises(dataclasses.FrozenInstanceError):
        key.task_id = "strings-0002"
    with pytest.raises(dataclasses.FrozenInstanceError):
        Sha256("a" * 64).hex = "b" * 64


def test_target_ref_is_a_bare_filename_bound_to_hash_and_size():
    ref = TargetRef("game.exe", Sha256("a" * 64), 4096)
    assert ref.filename == "game.exe"
    assert ref.size == 4096
    with pytest.raises(ValueError):
        TargetRef(str(PurePosixPath("bin", "game.exe")), Sha256("a" * 64), 4096)
    with pytest.raises(ValueError):
        TargetRef("game.exe", Sha256("a" * 64), -1)


def test_policy_ref_binds_a_positive_version_to_a_hash():
    ref = PolicyRef(2, Sha256("1" * 64))
    assert ref.version == 2
    assert ref.hash == Sha256("1" * 64)
    with pytest.raises(ValueError):
        PolicyRef(0, Sha256("1" * 64))
