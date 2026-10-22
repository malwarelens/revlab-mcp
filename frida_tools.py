"""Frida session management.

Frida is an *optional* dependency on the analysis host. If the `frida`
Python package is not installed, every entry point here reports a
structured "not available" result instead of raising, so the rest of
the platform keeps working.

Events produced by scripts via send() are collected into a bounded
ring buffer per session and read back with get_events(). If the
manager is given an events directory, every event is also appended
to artifacts/frida/<session>.jsonl as it arrives, so the record
survives the ring buffer (and the session) for reporting.
"""

from __future__ import annotations

import itertools
import json
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

try:
    import frida  # type: ignore
    FRIDA_AVAILABLE = True
    FRIDA_VERSION = getattr(frida, "__version__", "unknown")
except Exception:  # noqa: BLE001 - any import failure means unavailable
    frida = None
    FRIDA_AVAILABLE = False
    FRIDA_VERSION = None

SCRIPTS_DIR = Path(__file__).resolve().parent / "frida_scripts"
MAX_EVENTS = 5000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def summarize_events(events: list[dict], recent: int = 10) -> dict:
    """Group an event list by API name with counts + the latest events.

    The API name comes from the event payload's "api" field (the
    bundled scripts send() {api: ..., args: ...}); portal events like
    script-load markers live there too. Anything without one falls
    back to the event's "type".
    """
    by_api: dict[str, int] = {}
    for event in events:
        payload = event.get("payload")
        api = payload.get("api") if isinstance(payload, dict) else None
        key = api or event.get("type") or "unknown"
        by_api[key] = by_api.get(key, 0) + 1
    recent = max(0, int(recent))
    return {
        "total": len(events),
        "by_api": {k: by_api[k] for k in sorted(by_api)},
        "recent": events[-recent:] if recent else [],
    }


class FridaManager:
    def __init__(self, events_dir: Path | None = None):
        self._lock = threading.Lock()
        self._counter = itertools.count(1)
        self._sessions: dict[str, dict] = {}
        self.events_dir = Path(events_dir) if events_dir else None
        if self.events_dir is not None:
            self.events_dir.mkdir(parents=True, exist_ok=True)

    # -- status -------------------------------------------------------------
    def status(self) -> dict:
        return {
            "ok": True,
            "available": FRIDA_AVAILABLE,
            "version": FRIDA_VERSION,
            "active_sessions": sorted(self._sessions.keys()),
            "note": None if FRIDA_AVAILABLE else
                    "frida python package is not installed on the analysis host; "
                    "Frida tools are unavailable (pip install frida frida-tools).",
        }

    def _unavailable(self) -> dict:
        return {"ok": False, "configured": False, "available": False,
                "error": "frida is not installed on the analysis host; "
                         "install it with: pip install frida frida-tools"}

    # -- session lifecycle --------------------------------------------------
    def spawn(self, program: str, argv: list[str] | None = None) -> dict:
        if not FRIDA_AVAILABLE:
            return self._unavailable()
        device = frida.get_local_device()
        pid = device.spawn([program] + list(argv or []))
        session = device.attach(pid)
        key = self._register(session, pid=pid, target=program, spawned=True)
        return {"ok": True, "frida_session": key, "pid": pid, "resumed": False,
                "note": "process spawned suspended; load scripts, then frida_resume"}

    def resume(self, frida_session: str) -> dict:
        if not FRIDA_AVAILABLE:
            return self._unavailable()
        entry = self._get(frida_session)
        frida.get_local_device().resume(entry["pid"])
        return {"ok": True, "frida_session": frida_session, "pid": entry["pid"]}

    def attach(self, pid: int) -> dict:
        if not FRIDA_AVAILABLE:
            return self._unavailable()
        session = frida.get_local_device().attach(int(pid))
        key = self._register(session, pid=int(pid), target=f"pid:{pid}", spawned=False)
        return {"ok": True, "frida_session": key, "pid": int(pid)}

    def _register(self, session, pid: int, target: str, spawned: bool) -> str:
        key = f"frida-{next(self._counter)}"
        entry = {
            "session": session, "pid": pid, "target": target, "spawned": spawned,
            "scripts": {}, "events": deque(maxlen=MAX_EVENTS),
        }
        session.on("detached", lambda reason, _k=key: self._on_detached(_k, reason))
        with self._lock:
            self._sessions[key] = entry
        return key

    def _on_detached(self, key: str, reason) -> None:
        self._record_event(key, {"ts": _now(), "type": "detached",
                                 "payload": {"reason": str(reason)}})

    def _record_event(self, key: str, event: dict) -> None:
        """Append an event to the session ring buffer and, if an
        events directory is configured, to artifacts/frida/<key>.jsonl.

        The file write happens even if the in-memory session is already
        gone (e.g. a detached notification racing stop()): the JSONL
        record is the durable copy used by reports.
        """
        with self._lock:
            entry = self._sessions.get(key)
            if entry is not None:
                entry["events"].append(event)
            if self.events_dir is not None:
                try:
                    with open(self.events_dir / f"{key}.jsonl", "a",
                              encoding="utf-8") as fh:
                        fh.write(json.dumps(event, default=str) + "\n")
                except OSError:
                    pass  # persistence is best-effort; never break a hook

    def _get(self, key: str) -> dict:
        entry = self._sessions.get(key)
        if entry is None:
            raise ValueError(f"unknown frida session: {key}")
        return entry

    # -- scripts ------------------------------------------------------------
    def load_script(self, frida_session: str, source: str, name: str = "script") -> dict:
        if not FRIDA_AVAILABLE:
            return self._unavailable()
        entry = self._get(frida_session)
        script = entry["session"].create_script(source)

        def on_message(message, _data):
            payload = message.get("payload") if isinstance(message, dict) else None
            self._record_event(frida_session, {
                "ts": _now(),
                "type": message.get("type", "message") if isinstance(message, dict) else "message",
                "payload": payload if payload is not None else str(message),
            })

        script.on("message", on_message)
        script.load()
        entry["scripts"][name] = script
        return {"ok": True, "frida_session": frida_session, "script": name}

    def load_bundled_script(self, frida_session: str, name: str) -> dict:
        path = SCRIPTS_DIR / name
        if not path.is_file():
            return {"ok": False, "error": f"bundled script not found: {name}"}
        return self.load_script(frida_session, path.read_text(encoding="utf-8"),
                                name=name)

    def get_events(self, frida_session: str, limit: int = 200,
                   clear: bool = False) -> dict:
        if not FRIDA_AVAILABLE:
            return self._unavailable()
        entry = self._get(frida_session)
        events = list(entry["events"])
        if clear:
            entry["events"].clear()
        # Clamp like summarize_events does for `recent`: a bare
        # events[-limit:] slice would return *everything* for
        # limit == 0 and a shifted window for negative limits.
        limit = max(0, int(limit))
        selected = events[-limit:] if limit else []
        return {"ok": True, "frida_session": frida_session,
                "count": len(selected), "total_buffered": len(events),
                "events": selected}

    def events_digest(self, frida_session: str, recent: int = 10) -> dict:
        """Per-API event counts for a session plus the latest events.

        Counts come from the in-memory buffer; the same events are on
        disk under artifacts/frida/<session>.jsonl when persistence is
        configured (see the events_file field).
        """
        if not FRIDA_AVAILABLE:
            return self._unavailable()
        entry = self._get(frida_session)
        digest = summarize_events(list(entry["events"]), recent=recent)
        events_file = None
        if self.events_dir is not None:
            candidate = self.events_dir / f"{frida_session}.jsonl"
            events_file = str(candidate) if candidate.is_file() else None
        return {"ok": True, "frida_session": frida_session,
                "events_file": events_file, **digest}

    def stop(self, frida_session: str) -> dict:
        if not FRIDA_AVAILABLE:
            return self._unavailable()
        with self._lock:
            entry = self._sessions.pop(frida_session, None)
        if entry is None:
            raise ValueError(f"unknown frida session: {frida_session}")
        for script in entry["scripts"].values():
            try:
                script.unload()
            except Exception:  # noqa: BLE001
                pass
        try:
            entry["session"].detach()
        except Exception:  # noqa: BLE001
            pass
        return {"ok": True, "frida_session": frida_session, "stopped": True}
