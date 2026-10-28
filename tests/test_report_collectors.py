"""Direct tests for report.py's two collectors.

test_report.py exercises compose_session_report end to end; these
tests pin the collectors' own contracts:

* collect_debug_activity windows the audit log by [since, until],
  keeps only debug_* calls, skips malformed lines and keeps entries
  whose timestamp cannot be parsed (they cannot be windowed out);
* collect_artifacts buckets pe-sieve runs / dumps / carved PEs,
  ignores stray files and subdirectories where they do not belong,
  and labels a carved file's stem as its SHA-256 only when the stem
  really is 64 lowercase hex characters.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from report import collect_artifacts, collect_debug_activity  # noqa: E402

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
