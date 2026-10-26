#!/usr/bin/env python3
"""Fixture plugin whose work plan needs no target binary at all."""

from __future__ import annotations

import json
import sys

PORTS = ("md5", "crc32")


def _output_path(payload: dict) -> str:
    outputs = payload.get("outputs")
    if not isinstance(outputs, list) or len(outputs) != 1:
        raise ValueError("fixture task requires exactly one trusted output")
    return outputs[0]["path"]


def _answer(args: dict) -> str:
    return json.dumps({"unit": args["unit"], "cases": args["cases"]},
                      sort_keys=True, separators=(",", ":")) + "\n"


def cmd_work_plan(payload: dict) -> dict:
    # A targetless project passes `binary: null`; a plugin that reached for the
    # file here would be the bug this fixture guards against.
    if payload.get("binary") is not None:
        raise ValueError("targetless work plan must not receive a binary")
    return {"tasks": [{
        "id": f"port-{index:04d}",
        "kind": "cpp-port",
        "args": {"unit": unit, "cases": 8},
        "outputs": [{"path": f"recovery/ports/{unit}.json",
                     "media_type": "application/json", "max_bytes": 4096}],
        "weight": 1,
    } for index, unit in enumerate(PORTS, start=1)]}


def cmd_run_task(payload: dict) -> dict:
    return {"files": {_output_path(payload): _answer(payload["args"])}}


def cmd_verify(payload: dict) -> dict:
    expected = _answer(payload["args"])
    submitted = (payload.get("files") or {}).get(_output_path(payload))
    return {"pass": submitted == expected, "evidence": {"expected": expected}}


def cmd_selftest(_payload: dict) -> dict:
    return {"ok": True, "tests": 1}


CMDS = {"work-plan": cmd_work_plan, "run-task": cmd_run_task,
        "verify": cmd_verify, "selftest": cmd_selftest}


def main() -> int:
    payload = json.load(sys.stdin)
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    handler = CMDS.get(command)
    if handler is None:
        print(json.dumps({"error": f"unknown command {command!r}"}))
        return 3
    try:
        print(json.dumps(handler(payload)))
        return 0
    except Exception as exc:  # noqa: BLE001 - protocol reports errors as JSON
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
