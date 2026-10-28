"""Session report composition.

compose_session_report() gathers everything an analysis session has
produced -- the static triage result, debugger activity (recovered from
the audit log), Frida events, pe-sieve / dump / carve artifact metadata
and the analyst notes -- and renders one Markdown report under
artifacts/reports/. Only metadata and analysis results are rendered:
no sample bytes, no raw memory content.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

_MAX_EVENTS_RENDERED = 50
_MAX_DEBUG_RENDERED = 100

# Carved files are named by their SHA-256 (see unpack.py); a stem is
# only labelled as a hash when it really is 64 lowercase hex chars.
_SHA256_STEM_RE = re.compile(r"^[0-9a-f]{64}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

def collect_debug_activity(audit_log_path, since: str | None,
                           until: str | None = None) -> list[dict]:
    """Debugger tool calls recorded in the audit log within a window.

    The audit log is the platform's record of what the agent actually
    did; filtering it to debug_* calls inside the session's lifetime
    gives the report its debug-activity summary.
    """
    path = Path(audit_log_path) if audit_log_path else None
    if path is None or not path.is_file():
        return []
    start = _parse_ts(since)
    end = _parse_ts(until)
    events: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        if not str(entry.get("tool", "")).startswith("debug_"):
            continue
        ts = _parse_ts(entry.get("ts"))
        if start and ts and ts < start:
            continue
        if end and ts and ts > end:
            continue
        events.append({
            "ts": entry.get("ts"),
            "tool": entry.get("tool"),
            "status": entry.get("status"),
            "args": entry.get("args"),
            "error": entry.get("error"),
        })
    return events


def _file_meta(path: Path) -> dict:
    stat = path.stat()
    return {
        "name": path.name,
        "path": str(path),
        "size": stat.st_size,
        "modified_utc": datetime.fromtimestamp(
            stat.st_mtime, timezone.utc).isoformat(),
    }


def collect_artifacts(artifacts_dir) -> dict:
    """Metadata for pe-sieve runs, memory dumps and carved PEs."""
    root = Path(artifacts_dir)
    out: dict = {"pe_sieve_runs": [], "dumps": [], "carved": []}

    sieve_dir = root / "pe_sieve"
    if sieve_dir.is_dir():
        for run in sorted(sieve_dir.iterdir()):
            if run.is_dir():
                meta = _file_meta(run)
                meta["files"] = sorted(p.name for p in run.iterdir())
                out["pe_sieve_runs"].append(meta)

    dumps_dir = root / "dumps"
    if dumps_dir.is_dir():
        for dump in sorted(dumps_dir.iterdir()):
            if dump.is_file():
                out["dumps"].append(_file_meta(dump))

    carved_dir = root / "carved"
    if carved_dir.is_dir():
        for carved in sorted(carved_dir.iterdir()):
            if carved.is_file():
                meta = _file_meta(carved)
                # carved files are named by their SHA-256 (see unpack.py)
                meta["sha256"] = carved.stem \
                    if _SHA256_STEM_RE.match(carved.stem) else None
                out["carved"].append(meta)
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _fmt_iocs(iocs: dict) -> tuple[list[str], int]:
    lines: list[str] = []
    total = 0
    labels = {"urls": "URLs", "ipv4": "IPv4 addresses", "domains": "Domains",
              "emails": "Emails", "run_keys": "Registry Run keys",
              "file_paths": "File paths"}
    for key, label in labels.items():
        values = iocs.get(key) or []
        if not values:
            continue
        total += len(values)
        lines.append(f"- **{label}** ({len(values)}):")
        lines.extend(f"  - `{v}`" for v in values)
    return lines, total


def _render_triage(triage: dict | None, triage_error: str | None) -> tuple[list[str], dict]:
    counts = {"iocs": 0, "indicators": 0}
    if triage is None:
        note = f"Static triage failed for this sample: {triage_error}" if triage_error \
            else "Static triage has not been run for this session's sample."
        return ["## Static triage", "", note, ""], counts

    lines = ["## Static triage", ""]
    lines.append(f"- File type: {triage.get('file_type')}")
    lines.append(f"- Size: {triage.get('size')} bytes; "
                 f"overall entropy: {triage.get('entropy')}")
    hashes = triage.get("hashes") or {}
    if hashes:
        lines.append(f"- MD5: `{hashes.get('md5')}`")
        lines.append(f"- SHA-1: `{hashes.get('sha1')}`")
        lines.append(f"- SHA-256: `{hashes.get('sha256')}`")

    pe = triage.get("pe") or {}
    if pe.get("is_pe"):
        lines += ["", "### PE structure", "",
                  f"- Machine: {pe.get('machine')}; subsystem: {pe.get('subsystem')}; "
                  f"image base: {pe.get('image_base')}; entry point RVA: "
                  f"{pe.get('entry_point_rva')}; imphash: `{pe.get('imphash')}`; "
                  f"overlay: {pe.get('overlay_size')} bytes",
                  "", "| Section | VirtSize | RawSize | Entropy | Flags |",
                  "|---|---|---|---|---|"]
        for section in pe.get("sections") or []:
            lines.append(f"| {section.get('name')} | {section.get('virtual_size')} "
                         f"| {section.get('raw_size')} | {section.get('entropy')} "
                         f"| {section.get('flags')} |")
        imports = pe.get("imported_functions") or []
        if imports:
            lines += ["", f"Imported functions ({len(imports)}): "
                      + ", ".join(f"`{fn}`" for fn in imports[:40])]

    ioc_lines, ioc_total = _fmt_iocs(triage.get("iocs") or {})
    counts["iocs"] = ioc_total
    lines += ["", "### IOCs", ""]
    lines += ioc_lines if ioc_lines else ["No IOCs extracted from strings."]

    apis = triage.get("suspicious_apis")
    if apis:
        lines += ["", "### Suspicious APIs", ""]
        if isinstance(apis, dict):
            for group, names in apis.items():
                rendered = ", ".join(f"`{n}`" for n in names) if isinstance(names, list) else f"`{names}`"
                lines.append(f"- **{group}**: {rendered}")
        elif isinstance(apis, list):
            lines.extend(f"- `{name}`" for name in apis)

    indicators = triage.get("indicators") or []
    counts["indicators"] = len(indicators)
    if indicators:
        lines += ["", "### Triage indicators", ""]
        lines.extend(f"- {note}" for note in indicators)

    yara = triage.get("yara") or {}
    matches = yara.get("matches") or []
    if matches:
        lines += ["", "### YARA matches", ""]
        lines.extend(f"- `{m}`" for m in matches)
    elif yara.get("note"):
        lines += ["", f"YARA: {yara['note']}"]
    lines.append("")
    return lines, counts


def _render_debug(session: dict, events: list[dict]) -> list[str]:
    lines = ["## Debug activity", ""]
    bridge = session.get("debugger_bridge_session")
    lines.append(f"- Debugger bridge session: `{bridge}`" if bridge
                 else "- No debugger session was attached to this session.")
    if not events:
        lines += ["", "No `debug_*` tool calls were recorded in the audit "
                      "log during this session's lifetime.", ""]
        return lines
    lines += ["", "| Time (UTC) | Tool | Status | Arguments |",
              "|---|---|---|---|"]
    for event in events[:_MAX_DEBUG_RENDERED]:
        args = (event.get("args") or "").replace("|", "\\|")
        if len(args) > 120:
            args = args[:120] + "…"
        lines.append(f"| {event.get('ts')} | `{event.get('tool')}` "
                     f"| {event.get('status')} | {args} |")
    if len(events) > _MAX_DEBUG_RENDERED:
        lines.append(f"| … | {len(events) - _MAX_DEBUG_RENDERED} more calls "
                     "in the audit log | | |")
    lines.append("")
    return lines


def _render_frida(session: dict, frida_events: dict | None) -> tuple[list[str], int]:
    lines = ["## Frida events", ""]
    attached = session.get("frida_sessions") or []
    if not attached:
        lines += ["No Frida session was attached to this analysis session.", ""]
        return lines, 0
    total = 0
    for frida_id in attached:
        result = (frida_events or {}).get(frida_id)
        lines.append(f"### `{frida_id}`")
        lines.append("")
        if result is None:
            lines += ["Events could not be retrieved (server restarted?).", ""]
            continue
        if not result.get("ok"):
            lines += [f"No events available: {result.get('error', 'unavailable')}", ""]
            continue
        events = result.get("events") or []
        total += len(events)
        lines.append(f"{len(events)} event(s) buffered"
                     f" (total buffered: {result.get('total_buffered')}).")
        lines.append("")
        for event in events[:_MAX_EVENTS_RENDERED]:
            payload = event.get("payload")
            rendered = json.dumps(payload, ensure_ascii=False, default=str) \
                if not isinstance(payload, str) else payload
            if len(rendered) > 200:
                rendered = rendered[:200] + "…"
            lines.append(f"- `{event.get('ts')}` **{event.get('type')}**: {rendered}")
        if len(events) > _MAX_EVENTS_RENDERED:
            lines.append(f"- … and {len(events) - _MAX_EVENTS_RENDERED} more")
        lines.append("")
    return lines, total


def _render_artifacts(artifacts: dict) -> list[str]:
    lines = ["## Unpacking / scan artifacts", ""]
    empty = True
    if artifacts["pe_sieve_runs"]:
        empty = False
        lines.append("### pe-sieve runs")
        lines.append("")
        for run in artifacts["pe_sieve_runs"]:
            lines.append(f"- `{run['path']}` — {len(run['files'])} file(s): "
                         + ", ".join(run["files"][:10]))
        lines.append("")
    if artifacts["dumps"]:
        empty = False
        lines.append("### Memory dumps")
        lines.append("")
        for dump in artifacts["dumps"]:
            lines.append(f"- `{dump['path']}` — {dump['size']} bytes "
                         f"({dump['modified_utc']})")
        lines.append("")
    if artifacts["carved"]:
        empty = False
        lines.append("### Carved PEs")
        lines.append("")
        for carved in artifacts["carved"]:
            sha = f", sha256 `{carved['sha256']}`" if carved.get("sha256") else ""
            lines.append(f"- `{carved['path']}` — {carved['size']} bytes{sha}")
        lines.append("")
    if empty:
        lines += ["No pe-sieve runs, memory dumps or carved PEs were "
                  "produced.", ""]
    return lines


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def compose_session_report(session_id: str, *, sessions, store=None,
                           triage: dict | None = None,
                           triage_error: str | None = None,
                           frida_events: dict | None = None,
                           artifacts_dir, audit_log_path=None) -> dict:
    """Render the report for one analysis session and write it to
    artifacts/reports/<session_id>.md. Returns path + summary counts."""
    session = sessions.get(session_id)
    artifacts_root = Path(artifacts_dir)

    sample_meta = None
    if store is not None and session.get("sample_id"):
        try:
            sample_meta = store.get_info(session["sample_id"])
        except ValueError:
            sample_meta = None

    debug_events = collect_debug_activity(
        audit_log_path, session.get("created_at"), session.get("closed_at"))
    artifacts = collect_artifacts(artifacts_root)

    lines = ["# Analysis session report", ""]
    lines.append(f"- Session: `{session['session_id']}` "
                 f"(status: {session['status']}, "
                 f"created: {session['created_at']}, "
                 f"closed: {session.get('closed_at') or '—'})")
    lines.append(f"- Report generated: {_now()}")
    lines.append("")

    lines += ["## Sample", ""]
    if sample_meta:
        lines.append(f"- Original name: `{sample_meta.get('original_name')}`")
        lines.append(f"- SHA-256: `{sample_meta.get('sha256')}`")
        lines.append(f"- MD5: `{sample_meta.get('md5')}`")
        lines.append(f"- Size: {sample_meta.get('size')} bytes")
        lines.append(f"- Registered: {sample_meta.get('registered_at')}")
    elif session.get("sample_id"):
        lines.append(f"- Sample id: `{session['sample_id']}` "
                     "(metadata unavailable)")
    else:
        lines.append("No sample was bound to this session.")
    lines.append("")

    triage_lines, triage_counts = _render_triage(triage, triage_error)
    lines += triage_lines
    lines += _render_debug(session, debug_events)
    frida_lines, frida_total = _render_frida(session, frida_events)
    lines += frida_lines
    lines += _render_artifacts(artifacts)

    lines += ["## Analyst notes", ""]
    notes = session.get("notes") or []
    if notes:
        lines.extend(f"- `{n.get('ts')}` {n.get('note')}" for n in notes)
    else:
        lines.append("No notes were recorded for this session.")
    lines.append("")

    reports_dir = artifacts_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"{session['session_id']}.md"
    text = "\n".join(lines)
    path.write_text(text, encoding="utf-8")

    summary = {
        "iocs": triage_counts["iocs"],
        "indicators": triage_counts["indicators"],
        "debug_events": len(debug_events),
        "frida_events": frida_total,
        "notes": len(notes),
        "pe_sieve_runs": len(artifacts["pe_sieve_runs"]),
        "dumps": len(artifacts["dumps"]),
        "carved": len(artifacts["carved"]),
    }
    return {"session_id": session["session_id"],
            "sample_id": session.get("sample_id"),
            "path": str(path), "bytes": len(text.encode("utf-8")),
            "summary": summary}
