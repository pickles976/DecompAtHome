#!/usr/bin/env python3
"""Acceptance fixture plugin: deterministic, independently recomputable."""

from __future__ import annotations

import hashlib
import json
import sys

CHUNK = 64


def scan(binary: str, args: dict) -> str:
    with open(binary, "rb") as stream:
        stream.seek(int(args["offset"]))
        data = stream.read(int(args["length"]))
    return json.dumps({
        "offset": int(args["offset"]),
        "length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "printable": sum(1 for byte in data if 32 <= byte < 127),
    }, sort_keys=True, separators=(",", ":")) + "\n"


def output_path(payload: dict) -> str:
    outputs = payload.get("outputs")
    if not isinstance(outputs, list) or len(outputs) != 1:
        raise ValueError("fixture task requires exactly one trusted output")
    return outputs[0]["path"]


def cmd_work_plan(payload: dict) -> dict:
    import os

    size = os.path.getsize(payload["binary"])
    tasks, offset, index = [], 0, 0
    while offset < size:
        length = min(CHUNK, size - offset)
        tasks.append({
            "id": f"chunk-{index:04d}",
            "kind": "t1-chunk",
            "args": {"offset": offset, "length": length},
            "outputs": [{"path": f"recovery/chunks/chunk-{index:04d}.json",
                         "media_type": "application/json", "max_bytes": 4096}],
            "weight": length,
        })
        offset += length
        index += 1
    return {"tasks": tasks}


def cmd_run_task(payload: dict) -> dict:
    return {"files": {output_path(payload): scan(payload["binary"], payload["args"])}}


def cmd_verify(payload: dict) -> dict:
    expected = scan(payload["binary"], payload["args"])
    submitted = (payload.get("files") or {}).get(output_path(payload))
    return {
        "pass": submitted is not None and submitted == expected,
        "evidence": {
            "expected_sha256": hashlib.sha256(expected.encode()).hexdigest(),
            "submitted_sha256": hashlib.sha256((submitted or "").encode()).hexdigest(),
        },
    }


def cmd_selftest(_payload: dict) -> dict:
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as directory:
        sample = Path(directory) / "sample.bin"
        sample.write_bytes(bytes(range(256)))
        args = {"offset": 0, "length": 64}
        produced = cmd_run_task({"binary": str(sample), "args": args,
                                 "outputs": [{"path": "recovery/chunks/chunk-0000.json"}]})
        verdict = cmd_verify({"binary": str(sample), "args": args,
                              "outputs": [{"path": "recovery/chunks/chunk-0000.json"}],
                              "files": produced["files"]})
        tampered = cmd_verify({"binary": str(sample), "args": args,
                               "outputs": [{"path": "recovery/chunks/chunk-0000.json"}],
                               "files": {"recovery/chunks/chunk-0000.json": "{}"}})
    return {"ok": verdict["pass"] and not tampered["pass"], "tests": 2}


COMMANDS = {
    "work-plan": cmd_work_plan,
    "run-task": cmd_run_task,
    "verify": cmd_verify,
    "selftest": cmd_selftest,
}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        print(json.dumps({"error": f"usage: runner.py {{{'|'.join(COMMANDS)}}}"}))
        return 2
    raw = sys.stdin.read() or "{}"
    try:
        print(json.dumps(COMMANDS[sys.argv[1]](json.loads(raw))))
    except Exception as exc:  # surfaced to the host as a plugin error
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
