"""Audit logging for revlab-mcp tool calls.

Every tool invocation appends one JSON line to the audit log:
{ts, tool, args_summary, status, duration_ms, error?}

Argument values are summarised (truncated) and result payloads are never
written -- only a shape summary -- so the audit log can never become a
side channel for sample bytes or memory dumps.
"""

from __future__ import annotations

import functools
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

_MAX_VALUE = 200
_MAX_SUMMARY = 800


def _summarise_value(value: Any) -> Any:
    if isinstance(value, str):
        return value if len(value) <= _MAX_VALUE else value[:_MAX_VALUE] + "...<truncated>"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_summarise_value(v) for v in value[:10]]
    if isinstance(value, dict):
        return {str(k): _summarise_value(v) for k, v in list(value.items())[:20]}
    return f"<{type(value).__name__}>"


def summarise_args(args: tuple, kwargs: dict) -> str:
    payload = {"args": _summarise_value(list(args)), "kwargs": _summarise_value(kwargs)}
    text = json.dumps(payload, ensure_ascii=False, default=str)
    return text if len(text) <= _MAX_SUMMARY else text[:_MAX_SUMMARY] + "...<truncated>"


def summarise_result(result: Any) -> str:
    if isinstance(result, dict):
        return "dict keys=" + ",".join(sorted(str(k) for k in result.keys())[:20])
    if isinstance(result, list):
        return f"list len={len(result)}"
    return type(result).__name__


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, tool: str, args_summary: str, status: str,
              duration_ms: float, error: str | None = None,
              result_summary: str | None = None) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "args": args_summary,
            "status": status,
            "duration_ms": round(duration_ms, 2),
        }
        if error:
            entry["error"] = error[:500]
        if result_summary:
            entry["result"] = result_summary
        line = json.dumps(entry, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")


def audited(audit_log: AuditLog) -> Callable:
    """Decorator: wrap a tool function so every call is audit-logged."""
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            started = time.perf_counter()
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - log then re-raise
                audit_log.write(fn.__name__, summarise_args(args, kwargs),
                                "error", (time.perf_counter() - started) * 1000,
                                error=f"{type(exc).__name__}: {exc}")
                raise
            audit_log.write(fn.__name__, summarise_args(args, kwargs),
                            "ok", (time.perf_counter() - started) * 1000,
                            result_summary=summarise_result(result))
            return result
        return wrapper
    return decorator
