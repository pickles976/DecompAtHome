#!/usr/bin/env python3
"""Workflow plugin scaffold. JSON on stdin, JSON on stdout, one command per argv[1]."""
import json
import sys


def cmd_detect(p):
    return {"format": "unknown", "engine": "unknown", "toolchain": None, "tier": "t1-structure"}


def cmd_work_plan(p):
    # Return the project's work items: [{"id": ..., "kind": ..., "args": {...}}].
    # args must include "out": the relative path under recovery/ this task may write.
    return {"tasks": []}


def cmd_run_task(p):
    # Produce the declared output deterministically from p["binary"] and p["args"].
    # Return {"files": {"<out>": "<content>"}}.
    raise NotImplementedError(
        "run-task is not implemented: read p['binary'] (path to the target), "
        "p['args'] (task arguments, including 'out': the relative path under "
        "recovery/ this task may write) and p['outputs'] (the declared output "
        "paths), then return {'files': {<path>: <content string>}}")


def cmd_verify(p):
    # Independently recompute the expected output and compare with p["files"].
    # Return {"pass": bool, "evidence": {...}}. Never trust the submission.
    raise NotImplementedError(
        "verify is not implemented: read p['binary'], p['args'], p['outputs'] "
        "and p['files'] (the submitted {<path>: <content string>} mapping), "
        "recompute the expected content yourself instead of trusting the "
        "submission, then return {'pass': bool, 'evidence': {...}}")


def cmd_selftest(p):
    return {"ok": True, "tests": 0}


CMDS = {"detect": cmd_detect, "work-plan": cmd_work_plan, "run-task": cmd_run_task,
        "verify": cmd_verify, "selftest": cmd_selftest}


def main():
    payload = json.load(sys.stdin)
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    fn = CMDS.get(cmd)
    if fn is None:
        print(json.dumps({"error": f"unknown command {cmd!r}"}))
        return 3
    try:
        print(json.dumps(fn(payload)))
        return 0
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
