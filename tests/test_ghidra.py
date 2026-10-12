"""Tests for the Ghidra headless integration (ghidra_tools.py).

Runs against tests/fake_ghidra.py -- a small executable that mimics
analyzeHeadless' invocation shape and writes a fixed export document.
No real Ghidra required.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import ghidra_tools  # noqa: E402

FAKE_GHIDRA = Path(__file__).resolve().parent / "fake_ghidra.py"


@pytest.fixture()
def sample(tmp_path):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ" + b"\x00" * 64)
    return target


@pytest.fixture()
def with_fake_ghidra(monkeypatch):
    monkeypatch.setenv("RELAB_GHIDRA_PATH", str(FAKE_GHIDRA))
    monkeypatch.delenv("FAKE_GHIDRA_MODE", raising=False)


def test_find_ghidra_env_executable(monkeypatch):
    monkeypatch.setenv("RELAB_GHIDRA_PATH", str(FAKE_GHIDRA))
    assert ghidra_tools.find_ghidra() == str(FAKE_GHIDRA)


def test_find_ghidra_install_directory(tmp_path, monkeypatch):
    """RELAB_GHIDRA_PATH may point at a Ghidra install root; the
    support/analyzeHeadless inside it is resolved."""
    support = tmp_path / "ghidra" / "support"
    support.mkdir(parents=True)
    headless = support / "analyzeHeadless"
    headless.write_text("#!/bin/sh\n")
    monkeypatch.setenv("RELAB_GHIDRA_PATH", str(tmp_path / "ghidra"))
    assert ghidra_tools.find_ghidra() == str(headless)


def test_find_ghidra_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("RELAB_GHIDRA_PATH", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))  # nothing on PATH
    assert ghidra_tools.find_ghidra() is None


def test_run_ghidra_degrades_when_not_configured(monkeypatch, tmp_path,
                                                 sample):
    monkeypatch.delenv("RELAB_GHIDRA_PATH", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))
    result = ghidra_tools.run_ghidra(sample, sample_id="abc")
    assert result["ok"] is False
    assert result["configured"] is False
    assert "RELAB_GHIDRA_PATH" in result["error"]


def test_run_ghidra_end_to_end(with_fake_ghidra, sample):
    result = ghidra_tools.run_ghidra(sample, sample_id="deadbeef")
    assert result["ok"] is True
    assert result["configured"] is True
    assert result["sample_id"] == "deadbeef"
    assert result["function_count"] == 3
    names = {f["name"] for f in result["functions"]}
    assert {"entry", "inject_payload"} <= names
    assert result["import_count"] == 2
    libraries = {i["library"] for i in result["imports"]}
    assert libraries == {"KERNEL32"}
    assert result["suspicious_count"] == 1
    suspicious = result["suspicious_functions"][0]
    assert suspicious["function"] == "inject_payload"
    assert "VirtualAllocEx" in suspicious["apis"]
    assert "VirtualAllocEx" in suspicious["decompiled"]
    hotspots = result["string_hotspots"]
    assert hotspots[0]["value"].startswith("http://")
    assert hotspots[0]["references"] == 4


def test_run_ghidra_garbage_output(monkeypatch, with_fake_ghidra, sample):
    monkeypatch.setenv("FAKE_GHIDRA_MODE", "garbage")
    result = ghidra_tools.run_ghidra(sample)
    assert result["ok"] is False
    assert result["configured"] is True
    assert "unreadable" in result["error"]


def test_run_ghidra_no_output(monkeypatch, with_fake_ghidra, sample):
    monkeypatch.setenv("FAKE_GHIDRA_MODE", "nooutput")
    result = ghidra_tools.run_ghidra(sample)
    assert result["ok"] is False
    assert "no export JSON" in result["error"]


def test_parse_ghidra_output_truncation():
    many = [{"name": f"f{i}", "address": "0x1", "size": 1,
             "signature": "s"} for i in range(500)]
    summary = ghidra_tools.parse_ghidra_output({
        "functions": many, "imports": [], "suspicious_calls": [],
        "string_hotspots": []})
    assert summary["function_count"] == 500
    assert len(summary["functions"]) == ghidra_tools.MAX_FUNCTIONS_RETURNED
    assert summary["functions_truncated"] is True
