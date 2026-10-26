import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))


def make_fixture_binary(path: Path) -> Path:
    """A tiny fake PE with embedded ASCII strings, enough for detection + T1 scans."""
    strings = b"Hello, target!\x00unity_player_init\x00another_string_here\x00"
    pe_offset = 0x80
    data = bytearray(b"\x00" * (pe_offset + 4 + 20 + len(strings)))
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)  # e_lfanew
    data[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    machine = 0x014C  # i386
    struct.pack_into("<H", data, pe_offset + 4, machine)
    data[pe_offset + 24:pe_offset + 24 + len(strings)] = strings
    path.write_bytes(bytes(data))
    return path


@pytest.fixture
def fixture_bin(tmp_path):
    return make_fixture_binary(tmp_path / "game.exe")


@pytest.fixture
def project(tmp_path, fixture_bin):
    """A generated project via the public generator API."""
    from recomp.generate import generate_project
    return generate_project(
        tmp_path / "proj", bin_path=fixture_bin, name="demo",
        toolchain_image="ghcr.io/acme/demo-toolchain@sha256:" + "a" * 64,
        framework_action="acme/recomp@" + "b" * 40,
    )
