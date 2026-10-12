#!/usr/bin/env python3
"""Generate harmless synthetic test samples (no real malware).

* build_min_pe() -- a minimal valid PE32 assembled with struct, with
  planted IOC strings in its .data section.
* EICAR -- the standard anti-malware test string (a text file).
* notes.txt -- plain text with benign IOC-looking strings.
"""

from __future__ import annotations

import struct
from pathlib import Path

EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-"
         b"FILE!$H+H*")

_PLANTED_STRINGS = (
    b"http://evil.example.com/payload.bin\x00",
    b"185.220.101.4\x00",
    b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\x00",
    b"C:\\Users\\victim\\AppData\\Roaming\\upd.exe\x00",
    b"VMwareVirtualBoxSbieDll\x00",
)


def build_min_pe() -> bytes:
    file_alignment = 0x200
    header_size = 0x200  # DOS + PE headers + section table, padded

    text_raw = bytearray(0x200)
    text_raw[0:8] = bytes.fromhex("558bec83ec10c3909090")[:8]
    data_raw = bytearray(0x200)
    blob = b"".join(_PLANTED_STRINGS)
    data_raw[:len(blob)] = blob

    # Optional header (PE32, 0xE0 bytes)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)          # Magic PE32
    struct.pack_into("<I", opt, 16, 0x1000)        # AddressOfEntryPoint
    struct.pack_into("<I", opt, 28, 0x400000)      # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)        # SectionAlignment
    struct.pack_into("<I", opt, 36, file_alignment)
    struct.pack_into("<I", opt, 56, 0x3000)        # SizeOfImage
    struct.pack_into("<I", opt, 60, header_size)   # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)             # Subsystem: console
    struct.pack_into("<I", opt, 92, 16)            # NumberOfRvaAndSizes

    def section(name: bytes, vsize: int, va: int, raw: bytes, chars: int) -> bytes:
        hdr = bytearray(40)
        hdr[:len(name)] = name
        struct.pack_into("<I", hdr, 8, vsize)
        struct.pack_into("<I", hdr, 12, va)
        struct.pack_into("<I", hdr, 16, len(raw))
        struct.pack_into("<I", hdr, 20, header_size + (0x200 if va == 0x2000 else 0))
        struct.pack_into("<I", hdr, 36, chars)
        return bytes(hdr)

    coff = struct.pack("<HHIIIHH", 0x014C, 2, 0x63F00000, 0, 0, 0xE0, 0x0102)

    headers = bytearray()
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    headers += dos
    headers += b"PE\x00\x00" + coff + bytes(opt)
    headers += section(b".text", 0x180, 0x1000, bytes(text_raw), 0x60000020)
    headers += section(b".data", 0x200, 0x2000, bytes(data_raw), 0xC0000040)
    headers += b"\x00" * (header_size - len(headers))
    return bytes(headers) + bytes(text_raw) + bytes(data_raw)


def build_samples(directory: str | Path) -> dict[str, Path]:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    paths = {}
    pe = out / "sample_pe.exe"
    pe.write_bytes(build_min_pe())
    paths["pe"] = pe
    eicar = out / "eicar.txt"
    eicar.write_bytes(EICAR)
    paths["eicar"] = eicar
    notes = out / "notes.txt"
    notes.write_text("contact admin@example.org, mirror at 10.0.0.8, "
                     "docs on example.org\n", encoding="utf-8")
    paths["notes"] = notes
    return paths


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "samples_out"
    for kind, path in build_samples(target).items():
        print(kind, path)
