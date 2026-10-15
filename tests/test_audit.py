"""Unit tests for the audit log (tests/test_audit.py).

The audit log is a security boundary: it records that a tool ran, never
what a sample or a memory read contained. These tests pin that contract
directly -- previously audit.py was only exercised indirectly through
the end-to-end test's check that *some* audit lines exist.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit import AuditLog, audited, summarise_args, summarise_result  # noqa: E402


# ---------------------------------------------------------------------------
# summarise_args: truncation keeps payloads out of the log
# ---------------------------------------------------------------------------

def test_summarise_args_truncates_long_strings():
    text = summarise_args(("x" * 500,), {})
    assert "x" * 200 in text
    assert "x" * 201 not in text
    assert "<truncated>" in text


def test_summarise_args_caps_list_and_dict():
    payload = json.loads(summarise_args((), {"items": list(range(25)),
                                             "meta": {str(i): i for i in range(25)}}))
    assert payload["kwargs"]["items"] == list(range(10))
    assert len(payload["kwargs"]["meta"]) == 20


def test_summarise_args_overall_cap_and_unknown_types():
    # Each value is first truncated to 200 chars; many such values still
    # exceed the 800-char overall cap, which then truncates the JSON.
    many = {f"k{i}": "y" * 500 for i in range(10)}
    text = summarise_args((), many)
    assert len(text) == 800 + len("...<truncated>")
    assert text.endswith("...<truncated>")
    # Non-JSON-native values are summarised by type, never stringified.
    small = summarise_args((object(),), {})
    assert "<object>" in small


def test_summarise_args_keeps_scalars():
    payload = json.loads(summarise_args((1, 2.5, True, None, "ok"), {}))
    assert payload["args"] == [1, 2.5, True, None, "ok"]


# ---------------------------------------------------------------------------
# summarise_result: shape only, never values
# ---------------------------------------------------------------------------

def test_summarise_result_never_leaks_values():
    secret = "deadbeef-secret-payload"
    assert summarise_result({"sha256": secret, "size": 3}) == "dict keys=sha256,size"
    assert secret not in summarise_result({"k": secret})
    assert summarise_result([secret, secret]) == "list len=2"
    assert summarise_result("plain") == "str"
    assert summarise_result(None) == "NoneType"


# ---------------------------------------------------------------------------
# AuditLog.write: JSONL shape
# ---------------------------------------------------------------------------

def _read_entries(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_audit_log_writes_jsonl_and_creates_parent(tmp_path):
    log = AuditLog(tmp_path / "nested" / "audit.jsonl")
    log.write("static_triage", '{"args": []}', "ok", 12.3456,
              result_summary="dict keys=sha256")
    log.write("debug_run", '{"args": []}', "error", 1.0, error="Boom: " + "e" * 600)
    entries = _read_entries(tmp_path / "nested" / "audit.jsonl")
    assert len(entries) == 2
    ok, err = entries
    assert ok["tool"] == "static_triage" and ok["status"] == "ok"
    assert ok["duration_ms"] == 12.35 and ok["result"] == "dict keys=sha256"
    assert "error" not in ok and ok["ts"]
    assert err["status"] == "error" and len(err["error"]) == 500
    assert "result" not in err


# ---------------------------------------------------------------------------
# audited decorator: ok + error paths
# ---------------------------------------------------------------------------

def test_audited_logs_ok_without_payload(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")

    @audited(log)
    def tool(sample_id: str) -> dict:
        return {"sample_id": sample_id, "hex": "aa" * 100}

    assert tool("abc")["sample_id"] == "abc"
    assert tool.__name__ == "tool"
    (entry,) = _read_entries(tmp_path / "audit.jsonl")
    assert entry["tool"] == "tool" and entry["status"] == "ok"
    assert entry["result"] == "dict keys=hex,sample_id"
    # The returned hex payload itself must not appear in the log line.
    assert "aa" * 100 not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


def test_audited_logs_error_and_reraises(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")

    @audited(log)
    def boom() -> None:
        raise ValueError("no such sample")

    with pytest.raises(ValueError, match="no such sample"):
        boom()
    (entry,) = _read_entries(tmp_path / "audit.jsonl")
    assert entry["status"] == "error"
    assert entry["error"] == "ValueError: no such sample"
