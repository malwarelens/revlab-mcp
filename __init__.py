"""Debugger backend factory."""

from __future__ import annotations

from .base import DebuggerBackend, DebuggerError, DebuggerNotConfigured
from .x64dbg import X64dbgBackend

__all__ = ["DebuggerBackend", "DebuggerError", "DebuggerNotConfigured",
           "X64dbgBackend", "make_backend"]


def make_backend(bridge_url: str | None) -> DebuggerBackend | None:
    """Return a backend instance, or None if no bridge is configured.

    Tools translate None into a structured {"configured": false} result
    instead of crashing.
    """
    if not bridge_url:
        return None
    return X64dbgBackend(bridge_url)
