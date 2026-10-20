"""Analysis sessions.

A session ties together one sample, at most one debugger bridge session,
any number of Frida sessions and a running list of analyst notes, so an
agent can keep state across many tool calls. State is persisted as JSON
under the artifacts directory so it survives server restarts.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SessionManager:
    def __init__(self, state_file: Path):
        self.state_file = Path(state_file)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._sessions: dict[str, dict] = self._load()

    def _load(self) -> dict:
        if self.state_file.is_file():
            try:
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}
            # Valid JSON with the wrong top-level shape (a list, a
            # number, null, ...) is just as corrupt as unparseable
            # JSON: recover empty instead of crashing on .values().
            return data if isinstance(data, dict) else {}
        return {}

    def _save(self) -> None:
        tmp = self.state_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._sessions, indent=2), encoding="utf-8")
        tmp.replace(self.state_file)

    def create(self, sample_id: str | None = None) -> dict:
        session = {
            "session_id": uuid.uuid4().hex,
            "sample_id": sample_id,
            "status": "open",
            "created_at": _now(),
            "closed_at": None,
            "debugger_bridge_session": None,
            "frida_sessions": [],
            "notes": [],
        }
        with self._lock:
            self._sessions[session["session_id"]] = session
            self._save()
        return dict(session)

    def get(self, session_id: str) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"unknown analysis session: {session_id}")
        return dict(session)

    def list_sessions(self) -> list[dict]:
        with self._lock:
            return [dict(s) for s in self._sessions.values()]

    def _update(self, session_id: str, mutate) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise ValueError(f"unknown analysis session: {session_id}")
            mutate(session)
            self._save()
            return dict(session)

    def attach_debugger(self, session_id: str, bridge_session_id: str) -> dict:
        return self._update(session_id, lambda s: s.update(
            debugger_bridge_session=bridge_session_id))

    def attach_frida(self, session_id: str, frida_session_id: str) -> dict:
        def _add(s):
            if frida_session_id not in s["frida_sessions"]:
                s["frida_sessions"].append(frida_session_id)
        return self._update(session_id, _add)

    def add_note(self, session_id: str, note: str) -> dict:
        def _append(s):
            s["notes"].append({"ts": _now(), "note": note})
        return self._update(session_id, _append)

    def close(self, session_id: str) -> dict:
        def _close(s):
            s["status"] = "closed"
            s["closed_at"] = _now()
        return self._update(session_id, _close)
