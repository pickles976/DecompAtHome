#!/usr/bin/env python3
"""Generic T1 plugin: deterministic printable-string recovery.

Protocol: one JSON object on stdin, one JSON object on stdout. The server and
workers call the same commands, so `verify` is an independent recomputation,
never a trust of the worker's own output.
"""
import hashlib
import json
import sys

CHUNK = 64
MIN_RUN = 4


def printable_strings(data: bytes, offset: int, length: int) -> list[dict]:
    out, start = [], None
    view = data[offset:offset + length]
    for i, b in enumerate(view):
        if 32 <= b < 127:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= MIN_RUN:
                out.append({"offset": offset + start, "text": view[start:i].decode("ascii")})
            start = None
    if start is not None and len(view) - start >= MIN_RUN:
        out.append({"offset": offset + start, "text": view[start:].decode("ascii")})
    return out


def scan(binary: str, args: dict) -> str:
    with open(binary, "rb") as fh:
        data = fh.read()
    doc = {"offset": args["offset"], "length": args["length"],
           "strings": printable_strings(data, args["offset"], args["length"])}
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))


def cmd_detect(p):
    with open(p["binary"], "rb") as fh:
        head = fh.read(4096)
    fmt = "unknown"
    if head[:2] == b"MZ":
        fmt = "pe"
    elif head[:4] == b"\x7fELF":
        fmt = "elf"
    elif head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        fmt = "macho"
    return {"format": fmt, "engine": "unknown", "toolchain": None, "tier": "t1-structure"}


def cmd_work_plan(p):
    import os
    size = p.get("size") or os.path.getsize(p["binary"])
    tasks, off, i = [], 0, 0
    while off < size:
        length = min(CHUNK, size - off)
        tasks.append({
            "id": f"strings-{i:04d}",
            "kind": "t1-strings",
            "args": {"offset": off, "length": length},
            "outputs": [{
                "path": f"recovery/strings/strings-{i:04d}.json",
                "media_type": "application/json",
                "max_bytes": 65536,
            }],
            "weight": length,
        })
        off += length
        i += 1
    return {"tasks": tasks}


def output_path(payload):
    outputs = payload.get("outputs")
    if not isinstance(outputs, list) or len(outputs) != 1:
        raise ValueError("generic task requires exactly one trusted output")
    path = outputs[0].get("path")
    if not isinstance(path, str):
        raise ValueError("trusted output path is required")
    return path


def cmd_run_task(p):
    blob = scan(p["binary"], p["args"])
    return {"files": {output_path(p): blob}}


def cmd_verify(p):
    expected = scan(p["binary"], p["args"])
    got = (p.get("files") or {}).get(output_path(p))
    ok = got is not None and got == expected
    return {"pass": ok,
            "evidence": {"expected_sha256": hashlib.sha256(expected.encode()).hexdigest(),
                         "submitted_sha256": (hashlib.sha256(got.encode()).hexdigest()
                                              if got is not None else None)}}


def cmd_selftest(p):
    sample = b"\x00abcdefgh\x00\x01ijklmnop\x00\xfe"
    found = printable_strings(sample, 0, len(sample))
    assert [s["text"] for s in found] == ["abcdefgh", "ijklmnop"], found
    return {"ok": True, "tests": 2}


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
    except Exception as e:  # noqa: BLE001 - protocol reports errors as JSON
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
