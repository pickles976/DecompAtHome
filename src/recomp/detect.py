"""Target detection: what is this binary, what recovery tiers are reachable."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

MACHO_MAGICS = {0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE}
ELF_MACHINES = {0x03: "i386", 0x28: "arm", 0x3E: "x86-64", 0xB7: "aarch64", 0xF3: "riscv64"}
PE_MACHINES = {0x014C: "i386", 0x8664: "x86-64", 0x01C0: "arm", 0xAA64: "aarch64"}


@dataclass
class Detection:
    format: str
    arch: str
    engine: str
    toolchain: str | None
    tier: str
    notes: list[str] = field(default_factory=list)


def _pe_info(data: bytes) -> tuple[str, str | None]:
    if len(data) < 0x40:
        return "pe", None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 6 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return "pe", None
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    return "pe", PE_MACHINES.get(machine, "unknown")


def _elf_info(data: bytes) -> tuple[str, str | None]:
    if len(data) < 20:
        return "elf", None
    machine = struct.unpack_from("<H", data, 18)[0]
    return "elf", ELF_MACHINES.get(machine, "unknown")


def _engine_hint(data: bytes) -> tuple[str, list[str]]:
    window = data[:1 << 20]
    if b"UnityFS" in window:
        return "unity", ["unity: asset extraction available via unity plugins"]
    if window[:4] == b"GDPC" or b"GDPC" in window[:64]:
        return "godot", ["godot: asset extraction available via godot plugins"]
    for magic in (b"\xe1\x12\x6f\x5a", b"\x5a\x6f\x12\xe1"):
        if window[:4] == magic or magic in window[:64]:
            return "unreal", ["unreal: asset extraction available via unreal plugins"]
    return "unknown", []


def detect_bytes(data: bytes, toolchain: str | None = None) -> Detection:
    fmt, arch, notes = "unknown", "unknown", []
    if data[:2] == b"MZ":
        fmt, arch = _pe_info(data)
    elif data[:4] == b"\x7fELF":
        fmt, arch = _elf_info(data)
    elif len(data) >= 4 and struct.unpack(">I", data[:4])[0] in MACHO_MAGICS:
        fmt, arch = "macho", "unknown"
        notes.append("macho: arch detection needs a fuller header parser")

    engine, engine_notes = _engine_hint(data)
    notes.extend(engine_notes)

    if toolchain:
        tier = "t3-bytematch"
        notes.append(f"toolchain pinned ({toolchain}): byte-match tier reachable")
    elif engine != "unknown":
        tier = "t0-assets"
    else:
        tier = "t1-structure"

    return Detection(format=fmt, arch=arch or "unknown", engine=engine,
                     toolchain=toolchain, tier=tier, notes=notes)


def detect_path(path: str | Path, toolchain: str | None = None) -> Detection:
    data = Path(path).read_bytes()
    return detect_bytes(data, toolchain=toolchain)
