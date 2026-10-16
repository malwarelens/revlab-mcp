"""Unit tests for the unpacking helpers (unpack.py).

carve_pe itself is covered in test_units.py, but the tool-facing
wrappers were previously only exercised indirectly through the
end-to-end test's single happy path. These tests pin their contracts
directly:

* carve_pe_from_file jails its source to the artifacts directory --
  a dump path must never become a read-anywhere primitive;
* dump_memory_region chunks backend reads at MAX_READ_MEMORY, stops
  on a short or empty read, and returns metadata only (never bytes);
* pe_sieve_scan degrades to a structured result when pe-sieve is not
  configured / not found / times out, and parses the JSON document
  out of pe-sieve's noisy stdout (falling back to raw output).
"""

from __future__ import annotations

import hashlib
import json
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import make_samples  # noqa: E402
from debugger.base import MAX_READ_MEMORY  # noqa: E402
from unpack import carve_pe, carve_pe_from_file, dump_memory_region, pe_sieve_scan  # noqa: E402


# ---------------------------------------------------------------------------
# carve_pe: de-duplication
# ---------------------------------------------------------------------------

def test_carve_pe_deduplicates_identical_images(tmp_path):
    pe = make_samples.build_min_pe()
    blob = pe + b"\xCC" * 16 + pe  # the same image twice
    carved = carve_pe(blob, tmp_path)
    assert len(carved) == 1
    assert carved[0]["offset"] == 0
    assert carved[0]["sha256"] == hashlib.sha256(pe).hexdigest()


# ---------------------------------------------------------------------------
# carve_pe_from_file: the artifacts jail
# ---------------------------------------------------------------------------

def test_carve_from_file_inside_artifacts(tmp_path):
    artifacts = tmp_path / "artifacts"
    dumps = artifacts / "dumps"
    dumps.mkdir(parents=True)
    pe = make_samples.build_min_pe()
    dump = dumps / "dump.bin"
    dump.write_bytes(b"\xAA" * 32 + pe)
    result = carve_pe_from_file(str(dump), artifacts)
    assert result["ok"] is True
    assert result["source"] == str(dump.resolve())
    assert result["carved_count"] == 1
    assert result["carved"][0]["offset"] == 32


def test_carve_from_file_rejects_outside_artifacts(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(make_samples.build_min_pe())
    with pytest.raises(ValueError, match="inside the artifacts"):
        carve_pe_from_file(str(outside), artifacts)
    # A ".." path that resolves outside the jail is rejected as well:
    # the check runs on the resolved path, not the literal string.
    with pytest.raises(ValueError, match="inside the artifacts"):
        carve_pe_from_file(str(artifacts / ".." / "outside.bin"), artifacts)


def test_carve_from_file_missing_inside_artifacts(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    with pytest.raises(ValueError, match="file not found"):
        carve_pe_from_file(str(artifacts / "nope.bin"), artifacts)


# ---------------------------------------------------------------------------
# dump_memory_region: chunking through a fake backend
# ---------------------------------------------------------------------------

class _FakeBackend:
    """Serves `data` as the memory image starting at `base`.

    `serve_limit` caps the total bytes the backend will ever return,
    simulating a region that ends early (short / empty reads).
    """

    def __init__(self, base: int, data: bytes, serve_limit: int | None = None):
        self.base = base
        self.data = data
        self.serve_limit = len(data) if serve_limit is None else serve_limit
        self.calls: list[tuple[int, int]] = []
        self._served = 0

    def read_memory_bytes(self, address, size: int) -> bytes:
        self.calls.append((address, size))
        budget = self.serve_limit - self._served
        if budget <= 0:
            return b""
        start = address - self.base
        blob = self.data[start:start + min(size, budget)]
        self._served += len(blob)
        return blob


def test_dump_rejects_non_positive_size(tmp_path):
    backend = _FakeBackend(0x1000, b"\x00" * 16)
    for bad in (0, -5):
        with pytest.raises(ValueError, match="size must be positive"):
            dump_memory_region(backend, "0x1000", bad, tmp_path)
    assert backend.calls == []  # rejected before any backend read


def test_dump_chunks_at_max_read_and_returns_metadata_only(tmp_path):
    size = MAX_READ_MEMORY + 100
    data = bytes(i % 251 for i in range(size))
    backend = _FakeBackend(0x1000, data)
    result = dump_memory_region(backend, "0x1000", size, tmp_path)
    # Reads never exceed the 64 KiB cap and walk forward contiguously.
    assert [c[1] for c in backend.calls] == [MAX_READ_MEMORY, 100]
    assert [c[0] for c in backend.calls] == [0x1000, 0x1000 + MAX_READ_MEMORY]
    assert result["ok"] is True
    assert result["address"] == "0x1000"
    assert result["requested_size"] == size
    assert result["written_size"] == size
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    # Metadata only: exactly the documented keys, no byte payload.
    assert set(result) == {"ok", "path", "address", "requested_size",
                           "written_size", "sha256"}
    assert Path(result["path"]).read_bytes() == data
    assert Path(result["path"]).parent.name == "dumps"


def test_dump_stops_on_short_read(tmp_path):
    size = MAX_READ_MEMORY + 100
    data = bytes(i % 251 for i in range(size))
    # The region ends 10 bytes into the second chunk.
    backend = _FakeBackend(0x1000, data, serve_limit=MAX_READ_MEMORY + 10)
    result = dump_memory_region(backend, "0x1000", size, tmp_path)
    assert result["written_size"] == MAX_READ_MEMORY + 10
    assert result["sha256"] == hashlib.sha256(data[:MAX_READ_MEMORY + 10]).hexdigest()
    assert Path(result["path"]).read_bytes() == data[:MAX_READ_MEMORY + 10]


def test_dump_stops_on_empty_read(tmp_path):
    backend = _FakeBackend(0x1000, b"\x00" * 16, serve_limit=0)
    result = dump_memory_region(backend, "0x1000", 16, tmp_path)
    assert result["written_size"] == 0
    assert result["sha256"] == hashlib.sha256(b"").hexdigest()
    assert Path(result["path"]).read_bytes() == b""


# ---------------------------------------------------------------------------
# pe_sieve_scan: degradation + stdout parsing against a fake executable
# ---------------------------------------------------------------------------

_FAKE_PESIEVE = '''#!/usr/bin/env python3
"""Fake pe-sieve: behaviour selected by FAKE_PESIEVE_MODE."""
import json
import os
import sys
import time

mode = os.environ.get("FAKE_PESIEVE_MODE", "json")
if mode == "json":
    print("pe-sieve fake banner")
    print(json.dumps({"scanned": {"total": 1}, "suspicious": []}))
    print("fake warning", file=sys.stderr)
elif mode == "raw":
    print("scan failed: no such process")
    sys.exit(1)
elif mode == "sleep":
    time.sleep(30)
'''


@pytest.fixture()
def fake_pesieve(tmp_path):
    """Executable *copy* pattern (as in test_ghidra.py): the tests must
    not depend on the executable bit of a file in the source tree."""
    exe = tmp_path / "fake_pe_sieve.py"
    exe.write_text(_FAKE_PESIEVE, encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return exe


def test_pe_sieve_not_configured(tmp_path):
    result = pe_sieve_scan(None, 4242, tmp_path)
    assert result == {"ok": False, "configured": False,
                      "error": "pe-sieve is not configured on the analysis host; "
                               "set RELAB_PESIEVE_PATH to the pe-sieve executable"}


def test_pe_sieve_configured_but_missing(tmp_path):
    missing = str(tmp_path / "no-such-pe-sieve.exe")
    result = pe_sieve_scan(missing, 4242, tmp_path)
    assert result["ok"] is False and result["configured"] is True
    assert missing in result["error"]


def test_pe_sieve_parses_json_after_noise(fake_pesieve, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_PESIEVE_MODE", "json")
    result = pe_sieve_scan(str(fake_pesieve), 4242, tmp_path)
    assert result["ok"] is True and result["configured"] is True
    assert result["pid"] == 4242 and result["returncode"] == 0
    assert result["scan"] == {"scanned": {"total": 1}, "suspicious": []}
    assert "raw_output" not in result
    assert result["stderr"] == "fake warning\n"
    assert Path(result["output_dir"]).is_dir()


def test_pe_sieve_non_json_falls_back_to_raw_output(fake_pesieve, tmp_path,
                                                    monkeypatch):
    monkeypatch.setenv("FAKE_PESIEVE_MODE", "raw")
    result = pe_sieve_scan(str(fake_pesieve), 4242, tmp_path)
    assert result["ok"] is False  # the fake exits 1 in raw mode
    assert result["returncode"] == 1
    assert "scan" not in result
    assert result["raw_output"] == "scan failed: no such process\n"


def test_pe_sieve_timeout(fake_pesieve, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_PESIEVE_MODE", "sleep")
    result = pe_sieve_scan(str(fake_pesieve), 4242, tmp_path, timeout=1)
    assert result["ok"] is False and result["configured"] is True
    assert result["error"] == "pe-sieve timed out after 1s"
