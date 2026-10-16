"""Unpacking helpers: pe-sieve integration and pure-Python PE carving.

Nothing in this module returns sample/dump bytes to the caller: carved
PEs and memory dumps are written to the artifacts directory on the
analysis host and only metadata (path, offsets, sizes, hashes) is
returned.
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from debugger.base import MAX_READ_MEMORY, DebuggerBackend, parse_address

_KNOWN_MACHINES = {0x014C, 0x8664, 0x01C0, 0x01C4, 0xAA64, 0x0200}


# ---------------------------------------------------------------------------
# PE carving (pure Python; unit-tested)
# ---------------------------------------------------------------------------

def _parse_pe_at(data: bytes, offset: int) -> dict | None:
    """If a plausible PE starts at `offset`, return {offset, size,
    sections} describing its on-disk image; else None."""
    if offset + 0x40 > len(data) or data[offset:offset + 2] != b"MZ":
        return None
    (e_lfanew,) = struct.unpack_from("<I", data, offset + 0x3C)
    if e_lfanew < 0x40 or e_lfanew > 0x1000:
        return None
    pe_off = offset + e_lfanew
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return None
    machine, num_sections, _ts, _symtab, _nsyms, opt_size, _chars = \
        struct.unpack_from("<HHIIIHH", data, pe_off + 4)
    if machine not in _KNOWN_MACHINES or not (1 <= num_sections <= 96):
        return None
    sections_off = pe_off + 24 + opt_size
    if sections_off + num_sections * 40 > len(data):
        return None
    end = sections_off + num_sections * 40 - offset  # headers end (file-relative)
    for i in range(num_sections):
        raw_size, raw_ptr = struct.unpack_from("<II", data,
                                               sections_off + i * 40 + 16)
        end = max(end, raw_ptr + raw_size)
    if end <= 0 or offset + end > len(data):
        return None  # truncated image -- do not carve partial PEs silently
    return {"offset": offset, "size": end, "sections": num_sections,
            "machine": machine}


def carve_pe(data: bytes, artifacts_dir: Path) -> list[dict]:
    """Scan `data` for embedded PEs, write each unique one to
    artifacts_dir/'carved'/ and return metadata only."""
    out_dir = Path(artifacts_dir) / "carved"
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    seen_hashes: set[str] = set()
    pos = 0
    while True:
        idx = data.find(b"MZ", pos)
        if idx < 0:
            break
        pos = idx + 2
        info = _parse_pe_at(data, idx)
        if info is None:
            continue
        blob = data[idx:idx + info["size"]]
        digest = hashlib.sha256(blob).hexdigest()
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        path = out_dir / f"{digest}.bin"
        if not path.is_file():
            path.write_bytes(blob)
        results.append({
            "offset": idx,
            "size": info["size"],
            "sections": info["sections"],
            "machine": f"0x{info['machine']:04X}",
            "sha256": digest,
            "path": str(path),
        })
        pos = idx + info["size"]  # do not re-scan inside a carved image
    return results


def carve_pe_from_file(file_path: str, artifacts_dir: Path) -> dict:
    """Tool-facing wrapper: carve PEs from a file that already lives in
    the artifacts directory (e.g. a memory dump produced by this server).
    The path is jailed to the artifacts directory."""
    artifacts_root = Path(artifacts_dir).resolve()
    target = Path(file_path).resolve()
    if target != artifacts_root and artifacts_root not in target.parents:
        raise ValueError("carve_pe source must live inside the artifacts directory")
    if not target.is_file():
        raise ValueError(f"file not found in artifacts: {file_path}")
    carved = carve_pe(target.read_bytes(), artifacts_root)
    return {"ok": True, "source": str(target), "carved_count": len(carved),
            "carved": carved}


# ---------------------------------------------------------------------------
# Memory dumps via the debugger backend
# ---------------------------------------------------------------------------

def dump_memory_region(backend: DebuggerBackend, address, size: int,
                       artifacts_dir: Path) -> dict:
    """Read a region through the debugger backend (64 KiB chunks) and
    write it to artifacts/dumps/. Returns metadata, never the bytes."""
    addr = parse_address(address)
    size = int(size)
    if size <= 0:
        raise ValueError("size must be positive")
    out_dir = Path(artifacts_dir) / "dumps"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out_dir / f"dump_{addr:X}_{size}_{stamp}.bin"
    digest = hashlib.sha256()
    written = 0
    with open(path, "wb") as fh:
        remaining = size
        cursor = addr
        while remaining > 0:
            chunk = min(remaining, MAX_READ_MEMORY)
            blob = backend.read_memory_bytes(cursor, chunk)
            if not blob:
                break
            fh.write(blob)
            digest.update(blob)
            written += len(blob)
            cursor += len(blob)
            remaining -= len(blob)
            if len(blob) < chunk:
                break
    return {"ok": True, "path": str(path), "address": f"0x{addr:X}",
            "requested_size": size, "written_size": written,
            "sha256": digest.hexdigest()}


# ---------------------------------------------------------------------------
# pe-sieve integration
# ---------------------------------------------------------------------------

def pe_sieve_scan(pesieve_path: str | None, pid: int,
                  artifacts_dir: Path, timeout: int = 180) -> dict:
    if not pesieve_path:
        return {"ok": False, "configured": False,
                "error": "pe-sieve is not configured on the analysis host; "
                         "set RELAB_PESIEVE_PATH to the pe-sieve executable"}
    exe = Path(pesieve_path)
    if not exe.is_file():
        return {"ok": False, "configured": True,
                "error": f"pe-sieve executable not found at configured path: {pesieve_path}"}
    out_dir = Path(artifacts_dir) / "pe_sieve" / (
        f"pid{pid}_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            [str(exe), "/pid", str(int(pid)), "/json"],
            capture_output=True, text=True, timeout=timeout, cwd=str(out_dir),
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "configured": True,
                "error": f"pe-sieve timed out after {timeout}s"}
    except OSError as exc:
        return {"ok": False, "configured": True, "error": f"failed to run pe-sieve: {exc}"}

    result: dict = {"ok": proc.returncode == 0, "configured": True, "pid": int(pid),
                    "output_dir": str(out_dir), "returncode": proc.returncode}
    stdout = proc.stdout or ""
    parsed = None
    start = stdout.find("{")
    if start >= 0:
        try:
            parsed = json.loads(stdout[start:])
        except json.JSONDecodeError:
            parsed = None
    if parsed is not None:
        result["scan"] = parsed
    else:
        result["raw_output"] = stdout[:8000]
    if proc.stderr:
        result["stderr"] = proc.stderr[:2000]
    return result
