"""Tests for Frida event persistence + digest (frida_tools.py) and
the bundled script library.

Frida itself is not installed in the test environment, so the
manager-level tests monkeypatch FRIDA_AVAILABLE and inject session
entries directly; the persistence and digest code paths under test
do not touch real Frida objects.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections import deque
from pathlib import Path

import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import frida_tools  # noqa: E402
from frida_tools import FridaManager, summarize_events  # noqa: E402

SCRIPTS_DIR = BASE_DIR / "frida_scripts"


def _event(api, args=None):
    return {"ts": "2026-10-12T00:00:00+00:00", "type": "send",
            "payload": {"api": api, "args": args or {}, "tid": 1}}


def _fake_entry():
    return {"pid": 1234, "session": None, "scripts": [],
            "events": deque(maxlen=frida_tools.MAX_EVENTS)}


def test_bundled_scripts_present():
    for name in ("api_monitor.js", "crypto_monitor.js",
                 "process_network.js"):
        assert (SCRIPTS_DIR / name).is_file()


def test_crypto_monitor_hooks_expected_apis():
    source = (SCRIPTS_DIR / "crypto_monitor.js").read_text(encoding="utf-8")
    for api in ("CryptEncrypt", "CryptDecrypt", "BCryptEncrypt"):
        assert api in source
    assert "PREVIEW_BYTES = 64" in source


def test_process_network_hooks_expected_apis():
    source = (SCRIPTS_DIR / "process_network.js").read_text(encoding="utf-8")
    for api in ("CreateProcessW", "InternetOpenW", "HttpOpenRequestW",
                "WinHttpConnect", "WinHttpOpenRequest",
                "getaddrinfo", "DnsQuery_W"):
        assert api in source


@pytest.mark.skipif(shutil.which("node") is None,
                    reason="node not available for syntax check")
@pytest.mark.parametrize("script", ["crypto_monitor.js", "process_network.js"])
def test_bundled_scripts_pass_node_check(script):
    proc = subprocess.run(["node", "--check", str(SCRIPTS_DIR / script)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_summarize_events_groups_by_api():
    events = [_event("CreateFileW"), _event("CreateFileW"),
              _event("CryptEncrypt"),
              {"ts": "t", "type": "detached", "payload": {"reason": "x"}}]
    digest = summarize_events(events, recent=2)
    assert digest["total"] == 4
    assert digest["by_api"] == {"CreateFileW": 2, "CryptEncrypt": 1,
                                 "detached": 1}
    assert digest["recent"] == events[-2:]


def test_events_persist_to_jsonl_and_digest(tmp_path, monkeypatch):
    monkeypatch.setattr(frida_tools, "FRIDA_AVAILABLE", True)
    mgr = FridaManager(tmp_path / "frida")
    mgr._sessions["frida-1"] = _fake_entry()

    mgr._record_event("frida-1", _event("CreateFileW", {"path": "a"}))
    mgr._record_event("frida-1", _event("CryptEncrypt",
                                        {"data_len": 16,
                                         "preview": "ab" * 16}))
    mgr._record_event("frida-1", _event("CreateFileW", {"path": "b"}))

    jsonl = tmp_path / "frida" / "frida-1.jsonl"
    assert jsonl.is_file()
    lines = jsonl.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3
    decoded = [json.loads(line) for line in lines]
    assert decoded[1]["payload"]["api"] == "CryptEncrypt"
    assert decoded[1]["payload"]["args"]["preview"] == "ab" * 16

    digest = mgr.events_digest("frida-1", recent=1)
    assert digest["ok"] is True
    assert digest["total"] == 3
    assert digest["by_api"] == {"CreateFileW": 2, "CryptEncrypt": 1}
    assert digest["recent"][-1]["payload"]["args"]["path"] == "b"
    assert digest["events_file"] == str(jsonl)


def test_events_digest_degrades_without_frida(monkeypatch, tmp_path):
    monkeypatch.setattr(frida_tools, "FRIDA_AVAILABLE", False)
    mgr = FridaManager(tmp_path / "frida")
    result = mgr.events_digest("frida-1")
    assert result["ok"] is False
    assert result["configured"] is False


def test_record_event_survives_missing_session(tmp_path):
    """A detached event racing stop() still lands on disk."""
    mgr = FridaManager(tmp_path / "frida")
    mgr._record_event("frida-9", _event("__gone__"))
    lines = (tmp_path / "frida" / "frida-9.jsonl").read_text(
        encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
