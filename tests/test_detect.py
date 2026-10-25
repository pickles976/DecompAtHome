from recomp.detect import detect_bytes, detect_path


def test_detects_pe_binary(fixture_bin):
    d = detect_path(fixture_bin)
    assert d.format == "pe"
    assert d.arch == "i386"
    assert d.engine == "unknown"
    assert d.tier == "t1-structure"


def test_detects_elf_binary():
    elf = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00" + b"\x3e\x00" + b"\x00" * 200
    d = detect_bytes(elf)
    assert d.format == "elf"
    assert d.arch == "x86-64"


def test_detects_unity_bundle():
    blob = b"UnityFS\x00\x00\x01\x02" + b"\x00" * 64
    d = detect_bytes(blob)
    assert d.engine == "unity"
    assert d.tier == "t0-assets"
    assert "asset extraction available via unity plugins" in " ".join(d.notes).lower()


def test_detects_godot_pck():
    blob = b"GDPC" + b"\x00" * 60
    d = detect_bytes(blob)
    assert d.engine == "godot"
    assert d.tier == "t0-assets"


def test_detects_unreal_pak():
    blob = b"\xe1\x12\x6f\x5a" + b"\x00" * 60
    d = detect_bytes(blob)
    assert d.engine == "unreal"
    assert d.tier == "t0-assets"


def test_unknown_format_falls_back_to_generic_tier():
    d = detect_bytes(b"\x01\x02\x03\x04random junk")
    assert d.format == "unknown"
    assert d.tier == "t1-structure"


def test_pe_with_msvc_toolchain_reaches_bytematch_tier():
    pe = bytearray(b"\x00" * 256)
    pe[0:2] = b"MZ"
    struct_offset = 0x80
    import struct
    struct.pack_into("<I", pe, 0x3C, struct_offset)
    pe[struct_offset:struct_offset + 4] = b"PE\x00\x00"
    d = detect_bytes(bytes(pe), toolchain="msvc-7.1")
    assert d.tier == "t3-bytematch"
    assert d.toolchain == "msvc-7.1"
