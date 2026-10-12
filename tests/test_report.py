"""Tests for session report composition (report.py).

Runs against the real vendored triage output for the synthetic PE
sample plus planted audit-log lines and artifact files -- the same
"existing test data" the server itself produces.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import make_samples  # noqa: E402
import report as report_mod  # noqa: E402
from samples import SampleStore  # noqa: E402
from sessions import SessionManager  # noqa: E402


def _real_triage(pe_path: Path, tmp_path: Path) -> dict:
    out = tmp_path / "triage.json"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "vendor" / "triage.py"), str(pe_path),
         "--json", str(out)],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.fixture()
def lab(tmp_path):
    """A miniature lab: store + sessions + artifacts + audit log."""
    paths = make_samples.build_samples(tmp_path / "inbox")
    store = SampleStore(tmp_path / "samples")
    meta = store.register(str(paths["pe"]))
    artifacts = tmp_path / "artifacts"
    sessions = SessionManager(artifacts / "sessions.json")
    session = sessions.create(sample_id=meta["sample_id"])
    sessions.attach_debugger(session["session_id"], "mock-session-1")
    sessions.attach_frida(session["session_id"], "frida-1")
    sessions.add_note(session["session_id"], "entry point looks like a loader stub")
    sessions.add_note(session["session_id"], "check the Run key target next")

    # audit log: two in-window debug calls, one non-debug call, one
    # debug call from *before* the session existed (must be excluded)
    created = datetime.fromisoformat(session["created_at"])
    before = (created - timedelta(hours=1)).isoformat()
    audit_path = artifacts / "audit.jsonl"
    entries = [
        {"ts": before, "tool": "debug_run", "status": "ok", "args": "{}"},
        {"ts": session["created_at"], "tool": "debug_launch",
         "status": "ok", "args": '{"kwargs": {"sample_id": "…"}}'},
        {"ts": session["created_at"], "tool": "debug_registers",
         "status": "error", "args": "{}", "error": "bridge went away"},
        {"ts": session["created_at"], "tool": "static_triage",
         "status": "ok", "args": "{}"},
    ]
    audit_path.write_text(
        "\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")

    # artifacts: one dump, one carved PE (named by its sha256), one
    # pe-sieve run directory
    (artifacts / "dumps").mkdir(parents=True)
    (artifacts / "dumps" / "dump_140000000_4096_20261012T000000Z.bin") \
        .write_bytes(b"MZ" + b"\x00" * 4094)
    (artifacts / "carved").mkdir(parents=True)
    (artifacts / "carved" / f"{meta['sha256']}.bin") \
        .write_bytes(paths["pe"].read_bytes())
    run_dir = artifacts / "pe_sieve" / "pid4242_20261012T000000Z"
    run_dir.mkdir(parents=True)
    (run_dir / "scan_report.json").write_text("{}", encoding="utf-8")

    return {"paths": paths, "store": store, "sessions": sessions,
            "session": session, "meta": meta, "artifacts": artifacts,
            "audit_path": audit_path, "tmp": tmp_path}


FRIDA_EVENTS = {
    "frida-1": {
        "ok": True, "frida_session": "frida-1", "count": 2,
        "total_buffered": 2,
        "events": [
            {"ts": "2026-10-12T00:00:01+00:00", "type": "send",
             "payload": {"api": "CreateFileW", "path": "C:\\tmp\\x"}},
            {"ts": "2026-10-12T00:00:02+00:00", "type": "send",
             "payload": {"api": "RegSetValueExW"}},
        ],
    },
}


def test_compose_session_report(lab):
    triage = _real_triage(lab["paths"]["pe"], lab["tmp"])
    result = report_mod.compose_session_report(
        lab["session"]["session_id"], sessions=lab["sessions"],
        store=lab["store"], triage=triage, frida_events=FRIDA_EVENTS,
        artifacts_dir=lab["artifacts"], audit_log_path=lab["audit_path"])

    path = Path(result["path"])
    assert path.is_file()
    assert path.parent == lab["artifacts"] / "reports"
    text = path.read_text(encoding="utf-8")

    # header + sample
    assert "# Analysis session report" in text
    assert lab["meta"]["sha256"] in text
    assert "sample_pe.exe" in text
    # static triage content from the real triage run
    assert "## Static triage" in text
    assert "185.220.101.4" in text
    assert "### Triage indicators" in text
    # debug activity: in-window debug calls only
    assert "## Debug activity" in text
    assert "mock-session-1" in text
    assert "debug_launch" in text and "debug_registers" in text
    debug_section = text.split("## Debug activity")[1].split("## ")[0]
    assert "debug_run" not in debug_section  # pre-session call excluded
    # frida events
    assert "CreateFileW" in text and "RegSetValueExW" in text
    # artifacts metadata
    assert "dump_140000000_4096" in text
    assert lab["meta"]["sha256"] in text.split("### Carved PEs")[1]
    assert "pid4242_20261012T000000Z" in text
    # notes
    assert "entry point looks like a loader stub" in text
    assert "check the Run key target next" in text

    summary = result["summary"]
    assert summary["iocs"] >= 5
    assert summary["indicators"] >= 1
    assert summary["debug_events"] == 2
    assert summary["frida_events"] == 2
    assert summary["notes"] == 2
    assert summary["dumps"] == 1
    assert summary["carved"] == 1
    assert summary["pe_sieve_runs"] == 1


def test_compose_report_without_sample_or_triage(tmp_path):
    sessions = SessionManager(tmp_path / "sessions.json")
    session = sessions.create()
    result = report_mod.compose_session_report(
        session["session_id"], sessions=sessions,
        artifacts_dir=tmp_path / "artifacts")
    text = Path(result["path"]).read_text(encoding="utf-8")
    assert "No sample was bound to this session." in text
    assert "Static triage has not been run" in text
    assert "No Frida session was attached" in text
    assert "No notes were recorded" in text
    assert result["summary"]["debug_events"] == 0


def test_compose_report_unknown_session(tmp_path):
    sessions = SessionManager(tmp_path / "sessions.json")
    with pytest.raises(ValueError):
        report_mod.compose_session_report(
            "nope", sessions=sessions, artifacts_dir=tmp_path / "artifacts")


def test_collect_debug_activity_missing_log(tmp_path):
    assert report_mod.collect_debug_activity(
        tmp_path / "absent.jsonl",
        datetime.now(timezone.utc).isoformat()) == []
