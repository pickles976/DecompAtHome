"""Canonical task records published by the trusted GitHub App identity."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence

from recomp.contracts import PolicyRef, Sha256

_RECORD_PREFIX = "<!-- recomp-task-v1\n"
_RECORD_SUFFIX = "\n-->"
TASK_MARKER_PREFIX = "<!-- recomp-task:"
_TASK_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_KIND_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_RECORD_KEYS = {
    "schema", "task_id", "kind", "args", "outputs", "policy_version",
    "policy_hash", "toolchain_digest", "target_sha256", "weight", "generation",
}
_OUTPUT_KEYS = {"path", "media_type", "max_bytes", "allow_binary"}


class TaskRecordError(ValueError):
    pass


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TaskRecordError(f"{name} must be a positive integer")
    return value


def _freeze_json(value: Any, path: str = "args") -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        raise TaskRecordError(f"{path} must not contain floating-point values")
    if isinstance(value, list):
        return tuple(_freeze_json(item, f"{path}[]") for item in value)
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TaskRecordError(f"{path} keys must be strings")
        return tuple((key, _freeze_json(value[key], f"{path}.{key}")) for key in sorted(value))
    raise TaskRecordError(f"{path} contains unsupported JSON value {type(value).__name__}")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, tuple):
        if all(isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str)
               for item in value):
            return {key: _thaw_json(item) for key, item in value}
        return [_thaw_json(item) for item in value]
    return value


def _strict_keys(mapping: Mapping[str, Any], allowed: set[str], name: str) -> None:
    unknown = set(mapping) - allowed
    if unknown:
        raise TaskRecordError(f"{name} has unknown keys: {sorted(unknown)}")


@dataclass(frozen=True)
class OutputRule:
    path: PurePosixPath
    media_type: str
    max_bytes: int
    allow_binary: bool = False

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        output_roots: Sequence[str] = ("recovery",),
    ) -> "OutputRule":
        if not isinstance(value, dict):
            raise TaskRecordError("output rule must be an object")
        _strict_keys(value, _OUTPUT_KEYS, "output rule")
        raw_path = value.get("path")
        if not isinstance(raw_path, str) or not raw_path or "\\" in raw_path:
            raise TaskRecordError("output path must be a normalized public relative path")
        path = PurePosixPath(raw_path)
        allowed_roots = set(output_roots)
        if (path.is_absolute() or path.as_posix() != raw_path or ".." in path.parts
                or "." in path.parts or len(path.parts) < 2 or path.parts[0] not in allowed_roots):
            raise TaskRecordError("output path must be a normalized public relative path")
        media_type = value.get("media_type")
        if (not isinstance(media_type, str) or not media_type or "/" not in media_type
                or any(char.isspace() for char in media_type)):
            raise TaskRecordError("output media_type must be a non-empty MIME type")
        max_bytes = _positive_int(value.get("max_bytes"), "output max_bytes")
        allow_binary = value.get("allow_binary", False)
        if not isinstance(allow_binary, bool):
            raise TaskRecordError("output allow_binary must be boolean")
        return cls(path, media_type, max_bytes, allow_binary)

    def to_mapping(self) -> dict[str, Any]:
        result = {
            "path": self.path.as_posix(),
            "media_type": self.media_type,
            "max_bytes": self.max_bytes,
        }
        if self.allow_binary:
            result["allow_binary"] = True
        return result


@dataclass(frozen=True)
class TaskRecord:
    schema: int
    task_id: str
    kind: str
    _args: Any
    outputs: tuple[OutputRule, ...]
    policy_version: int
    policy_hash: Sha256
    toolchain_digest: Sha256
    target_sha256: Sha256 | None
    weight: int
    generation: int

    @property
    def args(self) -> dict[str, Any]:
        return _thaw_json(self._args)

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        output_roots: Sequence[str] = ("recovery",),
    ) -> "TaskRecord":
        if not isinstance(value, dict):
            raise TaskRecordError("task record must be an object")
        _strict_keys(value, _RECORD_KEYS, "task record")
        if value.get("schema") != 1:
            raise TaskRecordError("task record schema must be 1")
        task_id = value.get("task_id")
        if not isinstance(task_id, str) or _TASK_ID_RE.fullmatch(task_id) is None:
            raise TaskRecordError("task_id has invalid syntax")
        kind = value.get("kind")
        if not isinstance(kind, str) or _KIND_RE.fullmatch(kind) is None:
            raise TaskRecordError("task kind has invalid syntax")
        args = value.get("args")
        if not isinstance(args, dict):
            raise TaskRecordError("task args must be an object")
        outputs_value = value.get("outputs")
        if not isinstance(outputs_value, list) or not outputs_value:
            raise TaskRecordError("task outputs must be a non-empty array")
        outputs = tuple(OutputRule.from_mapping(item, output_roots=output_roots)
                        for item in outputs_value)
        paths = [output.path for output in outputs]
        if len(paths) != len(set(paths)):
            raise TaskRecordError("task record has duplicate output paths")
        try:
            policy_hash = Sha256(value.get("policy_hash"))
            toolchain_digest = Sha256(value.get("toolchain_digest"))
            raw_target = value.get("target_sha256")
            target_sha256 = None if raw_target is None else Sha256(raw_target)
        except (TypeError, ValueError) as exc:
            raise TaskRecordError(str(exc)) from exc
        return cls(
            schema=1,
            task_id=task_id,
            kind=kind,
            _args=_freeze_json(args),
            outputs=outputs,
            policy_version=_positive_int(value.get("policy_version"), "policy_version"),
            policy_hash=policy_hash,
            toolchain_digest=toolchain_digest,
            target_sha256=target_sha256,
            weight=_positive_int(value.get("weight"), "weight"),
            generation=_positive_int(value.get("generation"), "generation"),
        )

    def to_mapping(self) -> dict[str, Any]:
        result = {
            "schema": self.schema,
            "task_id": self.task_id,
            "kind": self.kind,
            "args": self.args,
            "outputs": [output.to_mapping() for output in self.outputs],
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash.hex,
            "toolchain_digest": self.toolchain_digest.hex,
            "weight": self.weight,
            "generation": self.generation,
        }
        if self.target_sha256 is not None:
            result["target_sha256"] = self.target_sha256.hex
        return result

    def semantic_mapping(self) -> dict[str, Any]:
        result = self.to_mapping()
        result.pop("generation")
        return result


def render_task_record(record: TaskRecord) -> str:
    payload = json.dumps(record.to_mapping(), sort_keys=True, separators=(",", ":"))
    return f"{_RECORD_PREFIX}{payload}{_RECORD_SUFFIX}"


def parse_task_record_body(body: str, *, output_roots: Sequence[str] = ("recovery",)) -> TaskRecord:
    if not isinstance(body, str) or not body.startswith(_RECORD_PREFIX) or not body.endswith(_RECORD_SUFFIX):
        raise TaskRecordError("comment is not a recomp task record")
    payload = body[len(_RECORD_PREFIX):-len(_RECORD_SUFFIX)]
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise TaskRecordError("task record contains invalid JSON") from exc
    return TaskRecord.from_mapping(value, output_roots=output_roots)


def parse_trusted_task_record(
    comments: Iterable[Mapping[str, Any]],
    trusted_actor_id: int,
    *,
    expected_policy: PolicyRef | None = None,
    expected_target_sha256: Sha256 | None = None,
    output_roots: Sequence[str] = ("recovery",),
) -> TaskRecord:
    by_generation: dict[int, TaskRecord] = {}
    for comment in comments:
        user = comment.get("user") if isinstance(comment, Mapping) else None
        if not isinstance(user, Mapping) or user.get("id") != trusted_actor_id:
            continue
        body = comment.get("body")
        if not isinstance(body, str) or not body.startswith(_RECORD_PREFIX):
            continue
        record = parse_task_record_body(body, output_roots=output_roots)
        existing = by_generation.get(record.generation)
        if existing is not None and existing != record:
            raise TaskRecordError(f"ambiguous trusted task generation {record.generation}")
        by_generation[record.generation] = record
    if not by_generation:
        raise TaskRecordError("no trusted task record found")
    record = by_generation[max(by_generation)]
    if expected_policy is not None:
        if (record.policy_version != expected_policy.version
                or record.policy_hash != expected_policy.hash):
            raise TaskRecordError("trusted task record does not match pinned policy")
    if expected_target_sha256 is not None and record.target_sha256 != expected_target_sha256:
        raise TaskRecordError("trusted task record does not match pinned target")
    return record


def _task_marker(task_id: str) -> str:
    return f"{TASK_MARKER_PREFIX}{task_id} -->"


def publish_task_records(
    github: Any,
    records: Iterable[TaskRecord],
    *,
    trusted_actor_id: int | None = None,
    issue_body: Callable[[TaskRecord], str] | None = None,
) -> tuple[tuple[str, str, Mapping[str, Any]], ...]:
    """Create or supersede task Issues without rewriting trusted history.

    Returns `(action, task_id, issue)` per record, where action is `created`,
    `superseded`, or `unchanged`, so a caller can report what it changed.
    """
    records = tuple(records)
    actor_id = trusted_actor_id if trusted_actor_id is not None else getattr(github, "trusted_actor_id", None)
    if not isinstance(actor_id, int):
        raise TaskRecordError("trusted GitHub actor id is required for publication")
    existing_by_task: dict[str, Mapping[str, Any]] = {}
    for issue in github.list_issues():
        body = issue.get("body", "") if isinstance(issue, Mapping) else ""
        user = issue.get("user") if isinstance(issue, Mapping) else None
        if (not isinstance(body, str) or not isinstance(user, Mapping)
                or user.get("id") != actor_id):
            continue
        for record in records:
            marker = _task_marker(record.task_id)
            if marker in body:
                if record.task_id in existing_by_task:
                    raise TaskRecordError(f"multiple Issues claim marker for task {record.task_id}")
                existing_by_task[record.task_id] = issue

    published = []
    for requested in records:
        issue = existing_by_task.get(requested.task_id)
        if issue is None:
            issue = github.create_issue({
                "title": f"[{requested.kind}] {requested.task_id}",
                "body": (issue_body(requested) if issue_body is not None else
                         "Recovery task `{}`. Machine authority is in trusted App "
                         "comments.\n\n{}".format(
                             requested.task_id, _task_marker(requested.task_id))),
                "labels": ["recomp-task", "open"],
            })
            github.create_comment(issue["number"], render_task_record(requested))
            published.append(("created", requested.task_id, issue))
            continue

        comments = list(github.list_comments(issue["number"]))
        try:
            current = parse_trusted_task_record(comments, actor_id)
        except TaskRecordError as exc:
            if "no trusted task record" not in str(exc):
                raise
            current = None
        if current is None:
            next_record = requested
        elif current.semantic_mapping() == requested.semantic_mapping():
            published.append(("unchanged", requested.task_id, issue))
            continue
        else:
            next_record = replace(requested, generation=current.generation + 1)
        github.create_comment(issue["number"], render_task_record(next_record))
        github.set_issue_labels(issue["number"], ["recomp-task", "open"])
        published.append(("superseded", requested.task_id, issue))
    return published
