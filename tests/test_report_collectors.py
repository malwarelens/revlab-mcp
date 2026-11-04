"""Direct tests for report.py's two collectors and its triage renderer.

test_report.py exercises compose_session_report end to end; these
tests pin the collectors' own contracts:

* collect_debug_activity windows the audit log by [since, until],
  keeps only debug_* calls, skips malformed lines and keeps entries
  whose timestamp cannot be parsed (they cannot be windowed out);
* collect_artifacts buckets pe-sieve runs / dumps / carved PEs,
  ignores stray files and subdirectories where they do not belong,
  and labels a carved file's stem as its SHA-256 only when the stem
  really is 64 lowercase hex characters;
* _render_triage renders well-shaped fields and drops malformed ones
  instead of crashing: a cached triage dict is served verbatim once
  its top level is a dict, so a wrong-shaped nested field (a list
  where an object is expected, a scalar where a list is expected)
  must not break report composition.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from report import (  # noqa: E402
    _render_debug,
    _render_frida,
    _render_triage,
    collect_artifacts,
    collect_debug_activity,
    compose_session_report,
)

SINCE = "2026-10-12T10:00:00+00:00"
UNTIL = "2026-10-12T11:00:00+00:00"


def _write_log(tmp_path: Path, lines: list[str]) -> Path:
    path = tmp_path / "audit.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _entry(ts, tool="debug_run", **extra):
    return json.dumps({"ts": ts, "tool": tool, "status": "ok",
                       "args": "{}", **extra})


# ---------------------------------------------------------------------------
# collect_debug_activity
# ---------------------------------------------------------------------------

def test_collect_debug_activity_windows_and_filters(tmp_path):
    log = _write_log(tmp_path, [
        _entry("2026-10-12T09:59:59+00:00"),                    # before window
        _entry(SINCE),                                          # at start: kept
        _entry("2026-10-12T10:30:00+00:00", tool="debug_step"),  # inside
        _entry(UNTIL),                                          # at end: kept
        _entry("2026-10-12T11:00:01+00:00"),                    # after window
        _entry("2026-10-12T10:15:00+00:00", tool="static_triage"),  # not debug_*
        "this is not json",
        "",
        _entry("not-a-timestamp", tool="debug_attach"),         # unparseable: kept
        json.dumps({"tool": "debug_run", "status": "ok"}),      # no ts: kept
    ])
    events = collect_debug_activity(log, SINCE, UNTIL)
    assert [e["tool"] for e in events] == [
        "debug_run", "debug_step", "debug_run", "debug_attach", "debug_run"]
    assert all(e["status"] == "ok" for e in events)


def test_collect_debug_activity_skips_non_object_json_lines(tmp_path):
    log = _write_log(tmp_path, [
        _entry("2026-10-12T10:30:00+00:00"),
        "[1, 2]",
        '"just a string"',
        "123",
        "null",
        "true",
        _entry("2026-10-12T10:45:00+00:00", tool="debug_step"),
    ])
    events = collect_debug_activity(log, SINCE, UNTIL)
    assert [e["tool"] for e in events] == ["debug_run", "debug_step"]


def test_collect_debug_activity_keeps_non_string_timestamps(tmp_path):
    # A timestamp that is not a string cannot be windowed out, so the
    # entry is kept, like the unparseable-string case above -- and it
    # must not crash _parse_ts (fromisoformat raises TypeError, not
    # ValueError, on a non-str argument).
    log = _write_log(tmp_path, [
        json.dumps({"ts": 12345, "tool": "debug_run", "status": "ok"}),
        json.dumps({"ts": ["2026-10-12T10:30:00+00:00"], "tool": "debug_step",
                    "status": "ok"}),
    ])
    events = collect_debug_activity(log, SINCE, UNTIL)
    assert [e["tool"] for e in events] == ["debug_run", "debug_step"]


def test_collect_debug_activity_open_ended_window(tmp_path):
    log = _write_log(tmp_path, [
        _entry("2026-10-12T09:00:00+00:00"),
        _entry("2026-10-12T12:00:00+00:00"),
    ])
    assert len(collect_debug_activity(log, SINCE)) == 1
    assert len(collect_debug_activity(log, None, UNTIL)) == 1
    assert len(collect_debug_activity(log, None)) == 2


# ---------------------------------------------------------------------------
# collect_artifacts
# ---------------------------------------------------------------------------

def test_collect_artifacts_missing_root(tmp_path):
    out = collect_artifacts(tmp_path / "does-not-exist")
    assert out == {"pe_sieve_runs": [], "dumps": [], "carved": []}


def test_collect_artifacts_buckets_and_strays(tmp_path):
    root = tmp_path / "artifacts"
    run = root / "pe_sieve" / "pid4242_20261012T000000Z"
    run.mkdir(parents=True)
    (run / "scan_report.json").write_text("{}", encoding="utf-8")
    (run / "dump.bin").write_bytes(b"MZ")
    (root / "pe_sieve" / "stray.txt").write_text("x", encoding="utf-8")

    (root / "dumps").mkdir()
    (root / "dumps" / "dump_1000_16.bin").write_bytes(b"\x00" * 16)
    (root / "dumps" / "nested").mkdir()  # directories are not dumps

    (root / "carved").mkdir()
    digest = "a" * 64
    (root / "carved" / f"{digest}.bin").write_bytes(b"MZ")
    (root / "carved" / "not-a-hash.bin").write_bytes(b"MZ")

    out = collect_artifacts(root)
    assert len(out["pe_sieve_runs"]) == 1
    assert out["pe_sieve_runs"][0]["files"] == ["dump.bin", "scan_report.json"]
    assert [d["name"] for d in out["dumps"]] == ["dump_1000_16.bin"]
    assert out["dumps"][0]["size"] == 16
    carved = {c["name"]: c for c in out["carved"]}
    assert carved[f"{digest}.bin"]["sha256"] == digest
    assert carved["not-a-hash.bin"]["sha256"] is None


def test_collect_artifacts_carved_stem_must_be_hex(tmp_path):
    carved_dir = tmp_path / "artifacts" / "carved"
    carved_dir.mkdir(parents=True)
    (carved_dir / ("g" * 64 + ".bin")).write_bytes(b"MZ")  # 64 chars, not hex
    (carved_dir / ("A" * 64 + ".bin")).write_bytes(b"MZ")  # uppercase hex
    out = collect_artifacts(tmp_path / "artifacts")
    assert [c["sha256"] for c in out["carved"]] == [None, None]


# ---------------------------------------------------------------------------
# _render_triage with wrong-shaped fields
# ---------------------------------------------------------------------------

def test_render_triage_drops_wrong_shaped_fields():
    """Every field the renderer used to .get() / len() blindly, given a
    wrong-shaped value, must render without crashing (previously
    AttributeError / TypeError) and must not render a bare string IOC
    or indicator character by character."""
    malformed = {
        "hashes": ["not", "a", "dict"],
        "pe": "not-a-dict",
        "iocs": {"urls": "http://example.com", "ipv4": 42},
        "indicators": "packed",
        "yara": ["rule1"],
    }
    lines, counts = _render_triage(malformed, None)
    text = "\n".join(lines)
    assert "## Static triage" in text
    assert counts == {"iocs": 0, "indicators": 0}
    # The string IOC must not have been split into single characters.
    assert "http://example.com" not in text
    assert "No IOCs extracted from strings." in text

    # A non-dict section inside an otherwise valid PE block is skipped
    # while the valid section still renders.
    lines, _ = _render_triage({
        "pe": {"is_pe": True,
               "sections": ["MZ",
                            {"name": ".text", "virtual_size": 1,
                             "raw_size": 2, "entropy": 3.0,
                             "flags": "r-x"}],
               "imported_functions": "CreateFileW"},
    }, None)
    text = "\n".join(lines)
    assert ".text" in text
    assert "Imported functions" not in text  # scalar imports are dropped


def test_render_triage_non_dict_result():
    lines, counts = _render_triage(["not", "a", "dict"], None)
    assert "malformed" in "\n".join(lines)
    assert counts == {"iocs": 0, "indicators": 0}


# ---------------------------------------------------------------------------
# _render_frida and analyst notes with wrong-shaped session fields
# ---------------------------------------------------------------------------

def test_render_frida_drops_wrong_shaped_fields():
    """A string frida_sessions used to render one bogus section per
    character; a non-dict result or a non-list events field crashed
    on .get(); a non-dict event inside the list crashed the same way.
    All of these must render without crashing, dropping only the
    malformed part, while a well-shaped session still renders."""
    lines, total = _render_frida(
        {"frida_sessions": "frida-1"},
        {"frida-1": {"ok": True, "events": [], "total_buffered": 0}})
    text = "\n".join(lines)
    assert "### `f`" not in text
    assert "No Frida session was attached" in text
    assert total == 0

    lines, total = _render_frida(
        {"frida_sessions": ["frida-1"]}, "not-a-dict")
    assert "could not be retrieved" in "\n".join(lines)
    assert total == 0

    lines, total = _render_frida(
        {"frida_sessions": ["frida-1"]},
        {"frida-1": "not-a-dict"})
    assert "could not be retrieved" in "\n".join(lines)
    assert total == 0

    lines, total = _render_frida(
        {"frida_sessions": ["frida-1"]},
        {"frida-1": {"ok": True, "events": "abc", "total_buffered": 3}})
    assert total == 0

    lines, total = _render_frida(
        {"frida_sessions": ["frida-1"]},
        {"frida-1": {"ok": True, "events": [
            "not-an-event", 42,
            {"ts": "2026-10-12T00:00:01+00:00", "type": "send",
             "payload": {"api": "CreateFileW"}}],
         "total_buffered": 3}})
    text = "\n".join(lines)
    assert total == 1
    assert "CreateFileW" in text


class _StubSessions:
    def __init__(self, session):
        self._session = session

    def get(self, session_id):
        assert session_id == self._session["session_id"]
        return dict(self._session)


def test_compose_report_drops_wrong_shaped_notes(tmp_path):
    """A string notes field used to crash compose on str.get(), and a
    non-dict entry in the list crashed it the same way; the valid
    note must still render and be counted."""
    session = {"session_id": "s1", "status": "open",
               "created_at": "2026-10-12T10:00:00+00:00",
               "closed_at": None, "notes": "packed"}
    result = compose_session_report(
        "s1", sessions=_StubSessions(session),
        artifacts_dir=tmp_path / "artifacts")
    text = (tmp_path / "artifacts" / "reports" / "s1.md").read_text(
        encoding="utf-8")
    assert "No notes were recorded" in text
    assert result["summary"]["notes"] == 0

    session["notes"] = [{"ts": "2026-10-12T10:01:00+00:00",
                         "note": "real note"}, "oops", 42]
    result = compose_session_report(
        "s1", sessions=_StubSessions(session),
        artifacts_dir=tmp_path / "artifacts")
    text = (tmp_path / "artifacts" / "reports" / "s1.md").read_text(
        encoding="utf-8")
    assert "real note" in text
    assert result["summary"]["notes"] == 1


# ---------------------------------------------------------------------------
# _render_debug with wrong-shaped events / args
# ---------------------------------------------------------------------------

def test_render_debug_drops_wrong_shaped_events_and_coerces_args(tmp_path):
    """A non-dict event used to crash _render_debug on .get(), and a
    hand-edited audit-log line can carry a non-string args field
    (a dict, an int) that crashed on .replace(). Malformed events are
    dropped and non-string args are rendered as JSON / text, while a
    well-shaped event still renders."""
    lines = _render_debug(
        {"debugger_bridge_session": "bridge-1"},
        ["not-an-event", 42,
         {"ts": "2026-10-12T10:30:00+00:00", "tool": "debug_run",
          "status": "ok", "args": {"address": "0x1000"}},
         {"ts": "2026-10-12T10:31:00+00:00", "tool": "debug_step",
          "status": "ok", "args": 42},
         {"ts": "2026-10-12T10:32:00+00:00", "tool": "debug_read",
          "status": "ok", "args": None}])
    text = "\n".join(lines)
    assert "bridge-1" in text
    assert "debug_run" in text and "debug_step" in text and "debug_read" in text
    assert "0x1000" in text
    assert "| 42 |" in text


def test_compose_report_renders_non_string_audit_args(tmp_path):
    """End to end: an audit-log line whose args is a dict (not the
    string the AuditLog writer produces) must not break report
    composition."""
    log = _write_log(tmp_path, [
        json.dumps({"ts": "2026-10-12T10:30:00+00:00", "tool": "debug_run",
                    "status": "ok", "args": {"address": "0x1000"}}),
    ])
    session = {"session_id": "s2", "status": "open",
               "created_at": "2026-10-12T10:00:00+00:00",
               "closed_at": "2026-10-12T11:00:00+00:00",
               "notes": []}
    result = compose_session_report(
        "s2", sessions=_StubSessions(session),
        artifacts_dir=tmp_path / "artifacts", audit_log_path=log)
    text = (tmp_path / "artifacts" / "reports" / "s2.md").read_text(
        encoding="utf-8")
    assert "debug_run" in text
    assert "0x1000" in text
    assert result["summary"]["debug_events"] == 1
