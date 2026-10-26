from __future__ import annotations

import base64
from dataclasses import replace

import pytest

from recomp.contracts import Sha256
from recomp.preflight import (
    PullRequestFacts,
    TreeEntry,
    check_preflight,
    collect_tree_entries,
)
from recomp.task_records import TaskRecord


def record(*, outputs=None, generation=3):
    return TaskRecord.from_mapping({
        "schema": 1,
        "task_id": "strings-0000",
        "kind": "t1-strings",
        "args": {"offset": 0, "length": 64},
        "outputs": outputs or [{
            "path": "recovery/out.json",
            "media_type": "application/json",
            "max_bytes": 100,
        }],
        "policy_version": 2,
        "policy_hash": "1" * 64,
        "toolchain_digest": "2" * 64,
        "target_sha256": "3" * 64,
        "weight": 64,
        "generation": generation,
    })


def facts(**overrides):
    values = {
        "author_id": 7,
        "head_sha": "a" * 40,
        "base_sha": "b" * 40,
        "base_repository": "acme/game",
        "expected_repository": "acme/game",
        "referenced_issue_numbers": (42,),
        "task_issue_number": 42,
        "lease_claimant_id": 7,
        "lease_generation": 4,
        "lease_expires_at": 9000,
        "now": 1000,
        "task_generation": 3,
        "policy_hash": Sha256("1" * 64),
        "toolchain_digest": Sha256("2" * 64),
        "tree_truncated": False,
    }
    values.update(overrides)
    return PullRequestFacts(**values)


def entry(path="recovery/out.json", **overrides):
    values = {
        "path": path,
        "mode": "100644",
        "kind": "blob",
        "sha": "c" * 40,
        "size": 12,
        "status": "modified",
        "prefix": b'{"ok":true}',
        "media_type": "application/json",
    }
    values.update(overrides)
    return TreeEntry(**values)


def test_valid_exact_tree_passes():
    report = check_preflight(record(), facts(), [entry()])
    assert report.passed
    assert report.findings == ()
    assert report.codes == ()


@pytest.mark.parametrize(("mode", "code"), [
    ("120000", "symlink"), ("160000", "submodule"), ("100755", "mode-change"),
])
def test_special_or_executable_entries_are_rejected(mode, code):
    report = check_preflight(record(), facts(), [entry(mode=mode)])
    assert code in report.codes


@pytest.mark.parametrize("path", [
    ".github/workflows/pwn.yml", "plugins/generic/runner.py", "toolchain/Containerfile",
    "recomp.toml", "recomp.lock.toml", "README.md", "AGENTS.md", "CONTRIBUTING.md",
    "docs/progress.svg", "docs/tasks.json",
])
def test_protected_paths_are_rejected(path):
    assert "protected-path" in check_preflight(record(), facts(), [entry(path)]).codes


def test_casefold_and_unicode_normalization_collisions_are_rejected():
    two_outputs = [
        {"path": "recovery/A.json", "media_type": "application/json", "max_bytes": 100},
        {"path": "recovery/a.json", "media_type": "application/json", "max_bytes": 100},
    ]
    entries = [entry("recovery/A.json"), entry("recovery/a.json", sha="d" * 40)]
    assert "path-collision" in check_preflight(record(outputs=two_outputs), facts(), entries).codes

    composed = "recovery/caf\u00e9.json"
    decomposed = "recovery/cafe\u0301.json"
    unicode_outputs = [
        {"path": composed, "media_type": "application/json", "max_bytes": 100},
        {"path": decomposed, "media_type": "application/json", "max_bytes": 100},
    ]
    entries = [entry(composed), entry(decomposed, sha="d" * 40)]
    assert "path-collision" in check_preflight(record(outputs=unicode_outputs), facts(), entries).codes


@pytest.mark.parametrize("path", [
    "/recovery/out.json", "recovery/../out.json", "recovery//out.json",
    "recovery\\out.json", "recovery/evil\x00.json", "recovery/evil\x1f.json",
])
def test_unsafe_paths_are_rejected(path):
    assert "unsafe-path" in check_preflight(record(), facts(), [entry(path)]).codes


def test_exact_allowlist_rejects_extra_missing_and_deleted_files():
    assert "extra-file" in check_preflight(record(), facts(), [entry("recovery/extra.json")]).codes
    assert "missing-output" in check_preflight(record(), facts(), []).codes
    report = check_preflight(record(), facts(), [entry(status="deleted")])
    assert "deleted-file" in report.codes


def test_truncated_tree_and_missing_entry_evidence_fail_closed():
    assert "tree-truncated" in check_preflight(record(), facts(tree_truncated=True), [entry()]).codes
    assert "missing-evidence" in check_preflight(record(), facts(), [entry(sha=None)]).codes
    assert "missing-evidence" in check_preflight(record(), facts(), [entry(size=None)]).codes
    assert "missing-evidence" in check_preflight(record(), facts(), [entry(prefix=None)]).codes


def test_file_and_aggregate_limits_are_enforced():
    assert "file-too-large" in check_preflight(record(), facts(), [entry(size=101)]).codes
    outputs = [
        {"path": "recovery/a.bin", "media_type": "application/octet-stream", "max_bytes": 10,
         "allow_binary": True},
        {"path": "recovery/b.bin", "media_type": "application/octet-stream", "max_bytes": 10,
         "allow_binary": True},
    ]
    entries = [
        entry("recovery/a.bin", size=10, prefix=b"a", media_type="application/octet-stream"),
        entry("recovery/b.bin", size=10, prefix=b"b", media_type="application/octet-stream", sha="d" * 40),
    ]
    assert "aggregate-too-large" in check_preflight(
        record(outputs=outputs), facts(), entries, max_total_bytes=19).codes


def test_media_binary_and_lfs_rules_come_from_output_declaration():
    assert "media-type" in check_preflight(
        record(), facts(), [entry(media_type="text/plain")]).codes
    assert "binary-not-allowed" in check_preflight(
        record(), facts(), [entry(prefix=b"{\x00}")]).codes
    lfs = b"version https://git-lfs.github.com/spec/v1\n" + b"oid sha256:" + b"0" * 64
    assert "lfs-pointer" in check_preflight(record(), facts(), [entry(prefix=lfs)]).codes


def test_stale_binding_wrong_claimant_repo_and_issue_references_fail():
    cases = [
        (facts(policy_hash=Sha256("9" * 64)), "stale-policy"),
        (facts(toolchain_digest=Sha256("9" * 64)), "stale-toolchain"),
        (facts(author_id=8), "wrong-claimant"),
        (facts(lease_expires_at=1000), "expired-lease"),
        (facts(task_generation=2), "stale-task"),
        (facts(base_repository="attacker/game"), "wrong-repository"),
        (facts(referenced_issue_numbers=()), "task-reference"),
        (facts(referenced_issue_numbers=(42, 43)), "task-reference"),
        (facts(referenced_issue_numbers=(43,)), "task-reference"),
        (facts(lease_generation=0), "missing-evidence"),
    ]
    for pr_facts, code in cases:
        assert code in check_preflight(record(), pr_facts, [entry()]).codes


def test_missing_pr_evidence_fields_fail_closed_without_echoing_content():
    report = check_preflight(
        record(),
        facts(head_sha=None, policy_hash=None, referenced_issue_numbers=None),
        [entry()],
    )
    assert "missing-evidence" in report.codes
    assert all("secret" not in finding.message for finding in report.findings)


def test_duplicate_tree_path_is_rejected():
    assert "path-collision" in check_preflight(
        record(), facts(), [entry(), entry(sha="d" * 40)]).codes


@pytest.mark.parametrize("path", [
    "SUMMARY.md", ".mulch/expertise/merges.jsonl", ".mulch/mulch.config.yaml",
])
def test_contributor_context_is_admissible_beside_the_declared_output(path):
    report = check_preflight(record(), facts(), [
        entry(), entry(path=path, media_type="text/markdown", prefix=b"# notes", size=7),
    ])
    assert report.passed, report.codes
    assert "extra-file" not in report.codes


def test_context_does_not_count_against_the_aggregate_output_budget():
    context = entry(path="SUMMARY.md", media_type="text/markdown",
                    prefix=b"# notes", size=100 * 1024)
    report = check_preflight(record(), facts(), [entry(), context], max_total_bytes=1024)
    assert report.passed, report.codes


def test_oversized_context_is_refused_with_its_own_code():
    report = check_preflight(record(), facts(), [
        entry(), entry(path="SUMMARY.md", media_type="text/markdown",
                       prefix=b"# notes", size=512 * 1024),
    ])
    assert not report.passed
    assert "context-too-large" in report.codes


def test_undeclared_non_context_file_is_still_an_extra_file():
    report = check_preflight(record(), facts(), [entry(), entry(path="src/sneaky.rs")])
    assert not report.passed
    assert "extra-file" in report.codes


def test_context_rules_cannot_smuggle_a_protected_file():
    report = check_preflight(record(), facts(), [
        entry(), entry(path="AGENTS.md", media_type="text/markdown", prefix=b"# x"),
    ])
    assert not report.passed
    assert "protected-path" in report.codes


def test_unfolded_blob_base64_is_accepted():
    import base64
    payload = base64.b64encode(b'{"wrapped": true}').decode()
    folded = "\n".join(payload[i:i + 60] for i in range(0, len(payload), 60))
    client = _ClientWithBlob(folded)
    collected, truncated = collect_tree_entries(client, 5, "a" * 40, {
        "recovery/out.json": _rule(),
    })
    assert truncated is False
    assert collected[0].prefix == b'{"wrapped": true}'


def test_non_boolean_truncation_fails_closed():
    client = _ClientWithBlob(base64.b64encode(b'{"ok":true}').decode(),
                             truncated="maybe")
    collected, truncated = collect_tree_entries(client, 5, "a" * 40, {
        "recovery/out.json": _rule(),
    })
    assert truncated is True, "a garbage truncation flag must read as truncated"


class _ClientWithBlob:
    """Minimal collect_tree_entries client: one tree, one blob, one changed file."""

    def __init__(self, content: str, *, truncated=False):
        self.tree = {"truncated": truncated, "tree": [{
            "path": "recovery/out.json", "mode": "100644", "type": "blob",
            "sha": "d" * 40, "size": 16,
        }]}
        self.blob = {"encoding": "base64", "content": content, "size": 16}

    def get_tree(self, sha, recursive=False):
        return self.tree

    def list_pull_files(self, number):
        return [{"filename": "recovery/out.json", "status": "modified",
                 "sha": "d" * 40}]

    def get_blob(self, sha):
        return self.blob


def _rule():
    from recomp.task_records import TaskRecord
    return TaskRecord.from_mapping({
        "schema": 1, "task_id": "strings-0000", "kind": "t1-strings",
        "args": {"offset": 0, "length": 64},
        "outputs": [{"path": "recovery/out.json", "media_type": "application/json",
                     "max_bytes": 4096}],
        "policy_version": 2, "policy_hash": "1" * 64,
        "toolchain_digest": "2" * 64, "target_sha256": "3" * 64,
        "weight": 64, "generation": 3,
    }).outputs[0]
