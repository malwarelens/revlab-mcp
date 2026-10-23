"""Debugger backend abstraction.

The MCP server never talks to a debugger directly; it talks to a
*backend*. The only backend in v1 is `x64dbg` (debugger/x64dbg.py),
which speaks the HTTP bridge contract documented in docs/BRIDGE.md.

All methods return plain dicts (addresses as hex strings, memory as
hex). read_memory is capped at MAX_READ_MEMORY bytes per call: enough
for real debugging work, small enough that a runaway agent cannot pull
a whole process image through the tool surface.
"""

from __future__ import annotations

import abc

MAX_READ_MEMORY = 64 * 1024  # 64 KiB per read_memory call, by design


class DebuggerError(Exception):
    """An operational debugger/bridge error."""


class DebuggerNotConfigured(DebuggerError):
    """No debugger bridge is configured (RELAB_X64DBG_BRIDGE_URL unset)."""


def parse_address(value) -> int:
    """Accept int, '0x...' hex, bare hex with a-f letters, or decimal.

    Raises DebuggerError (not ValueError) on unparseable input so the
    server's guard() and the dump_memory_region wrapper turn a malformed
    address into a structured {"ok": False, ...} result instead of an
    unhandled exception.
    """
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if text.isdigit():
            return int(text, 10)
        return int(text, 16)
    except ValueError:
        raise DebuggerError(f"invalid address: {value!r}")


def fmt_address(value: int) -> str:
    return f"0x{value:X}"


class DebuggerBackend(abc.ABC):
    """One backend instance manages at most one live debug session."""

    name = "abstract"

    def __init__(self):
        self.bridge_session_id: str | None = None
        self.pid: int | None = None

    @property
    def active(self) -> bool:
        return self.bridge_session_id is not None

    @abc.abstractmethod
    def launch(self, sample_path: str, arguments: str = "") -> dict: ...

    @abc.abstractmethod
    def attach(self, pid: int) -> dict: ...

    @abc.abstractmethod
    def terminate(self) -> dict: ...

    @abc.abstractmethod
    def command(self, command: str) -> dict:
        """Raw debugger command passthrough (bridge /cmd)."""

    @abc.abstractmethod
    def set_breakpoint(self, location: str) -> dict:
        """`location` is an address ('0x401000') or 'module!symbol'."""

    @abc.abstractmethod
    def list_breakpoints(self) -> dict: ...

    @abc.abstractmethod
    def delete_breakpoint(self, location: str) -> dict: ...

    @abc.abstractmethod
    def run(self) -> dict: ...

    @abc.abstractmethod
    def pause(self) -> dict: ...

    @abc.abstractmethod
    def step_into(self) -> dict: ...

    @abc.abstractmethod
    def step_over(self) -> dict: ...

    @abc.abstractmethod
    def get_registers(self) -> dict: ...

    @abc.abstractmethod
    def read_memory(self, address, size: int) -> dict:
        """Return {"address", "size", "hex"} -- hex capped at 64 KiB."""

    @abc.abstractmethod
    def read_memory_bytes(self, address, size: int) -> bytes:
        """Same read as read_memory but raw bytes, for internal use
        (memory dumps to artifacts). Subject to the same 64 KiB cap per
        call; callers chunk larger regions."""

    @abc.abstractmethod
    def disassemble(self, address, count: int = 16) -> dict: ...

    @abc.abstractmethod
    def get_callstack(self) -> dict: ...

    @abc.abstractmethod
    def list_modules(self) -> dict: ...
