"""Injectable client layer over x64dbg-automate.

The adapter (adapter.py) never imports ``x64dbg_automate`` directly. It
talks to an object satisfying the :class:`AutomateClient` protocol below,
which is a deliberate subset of the real ``X64DbgClient`` API (verified
against the upstream source, see README.md for references):

* ``X64DbgClient`` construction / ``connect_remote`` / session lifecycle
  and the high-level mixin methods live in ``x64dbg_automate/__init__.py``
  and ``x64dbg_automate/hla_xauto.py``.
* ``cmd_sync`` / ``eval_sync`` / ``memmap`` / ``read_memory`` /
  ``get_regs`` / ``disassemble_at`` / ``get_breakpoints`` / ``get_log``
  live in ``x64dbg_automate/commands_xauto.py``.
* Return models (``MemPage``, ``Instruction``, ``Breakpoint``,
  ``RegDump64/32``) live in ``x64dbg_automate/models.py``.

Production code builds the real client through the factories at the
bottom of this module; tests inject a fake implementing the same
protocol, so the adapter's HTTP layer is fully testable on Linux.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

# Breakpoint type values, mirroring x64dbg_automate.models.BreakpointType.
BP_NORMAL = 1
BP_HARDWARE = 2
BP_MEMORY = 4

# MemPage.type value for image (module) pages, from x64dbg_automate.models.
MEM_IMAGE = 0x1000000


@runtime_checkable
class AutomateClient(Protocol):
    """Subset of ``X64DbgClient`` used by the adapter.

    All attribute access on returned objects is duck-typed (the real
    client returns pydantic models; the test fake returns namespaces
    with the same attribute names).
    """

    # -- session lifecycle -------------------------------------------------
    def start_session(self, target_exe: str = "", cmdline: str = "",
                      current_dir: str = "") -> int:
        """Spawn-mode: launch x64dbg and load target_exe. Returns the
        *debugger* PID (not the debuggee PID)."""
        ...

    def start_session_attach(self, pid: int) -> int:
        """Spawn-mode: launch x64dbg and attach to pid."""
        ...

    def terminate_session(self) -> None:
        """End the session and terminate the debugger process."""
        ...

    def detach_session(self) -> None:
        """Disconnect from the debugger, leaving it running."""
        ...

    def load_executable(self, target_exe: str, cmdline: str = "",
                        current_dir: str = "") -> bool:
        """Remote-mode: load an executable into the connected debugger."""
        ...

    def attach(self, pid: int) -> bool:
        """Remote-mode: attach the connected debugger to pid."""
        ...

    def unload_executable(self) -> bool:
        """Stop debugging (kills the debuggee) but keep the debugger."""
        ...

    # -- execution control ---------------------------------------------------
    def go(self) -> bool: ...
    def pause(self) -> bool: ...
    def stepi(self) -> bool: ...
    def stepo(self) -> bool: ...
    def is_running(self) -> bool: ...
    def is_debugging(self) -> bool: ...
    def wait_until_stopped(self, timeout: int = 10) -> bool: ...

    # -- commands / eval / log ------------------------------------------------
    def cmd_sync(self, cmd_str: str) -> bool: ...
    def eval_sync(self, eval_str: str) -> tuple[int, bool]: ...
    def get_log(self, since_index: int = 0, limit: int = 0,
                filter: str = "") -> tuple[int, list[str], int, int]: ...

    # -- state inspection ------------------------------------------------------
    def get_reg(self, reg: str) -> int: ...
    def get_regs(self): ...  # RegDump64 | RegDump32 (has .context)
    def read_memory(self, addr: int, size: int) -> bytes: ...
    def memmap(self) -> list: ...  # list[MemPage]
    def disassemble_at(self, addr: int): ...  # Instruction | None
    def check_valid_read_ptr(self, addr: int) -> bool: ...

    # -- breakpoints -------------------------------------------------------------
    def set_breakpoint(self, address_or_symbol) -> bool: ...
    def clear_breakpoint(self, target=None) -> bool: ...
    def get_breakpoints(self, bp_type: int) -> list: ...  # list[Breakpoint]

    # -- misc ---------------------------------------------------------------------
    def debugee_pid(self) -> int | None: ...
    def get_symbol_at(self, addr: int): ...  # Symbol | None
    def get_label_at(self, addr: int) -> str: ...
    def get_latest_debug_event(self): ...  # DbgEvent | None


class RealAutomateClient:
    """Thin wrapper around a real ``X64DbgClient``.

    Exists so the one type conversion the protocol needs (breakpoint
    type int -> ``BreakpointType`` enum) happens here, keeping the
    protocol itself free of pydantic/enum types so fakes stay trivial.
    """

    def __init__(self, client):
        self._client = client

    def __getattr__(self, name):
        # Everything not explicitly converted delegates 1:1.
        return getattr(self._client, name)

    def get_breakpoints(self, bp_type: int) -> list:
        from x64dbg_automate.models import BreakpointType

        return self._client.get_breakpoints(BreakpointType(bp_type))


# ---------------------------------------------------------------------------
# x64dbg path resolution (mirrors upstream mcp_server._resolve_debugger_path)
# ---------------------------------------------------------------------------

def pe_bitness(exe_path: str) -> int:
    """Read the PE Machine field: 64 for 0x8664, 32 for 0x14C."""
    with open(exe_path, "rb") as f:
        if f.read(2) != b"MZ":
            raise ValueError(f"Not a valid PE file: {exe_path}")
        f.seek(0x3C)
        pe_offset = struct.unpack("<I", f.read(4))[0]
        f.seek(pe_offset + 4)
        machine = struct.unpack("<H", f.read(2))[0]
    if machine == 0x8664:
        return 64
    if machine == 0x14C:
        return 32
    raise ValueError(f"Unknown PE machine type 0x{machine:04X}: {exe_path}")


def resolve_x64dbg_path(x64dbg_path: str, target_exe: str = "") -> str:
    """Resolve an x96dbg.exe launcher path to x64dbg.exe / x32dbg.exe
    based on the target's bitness. Any other path is returned as-is."""
    p = Path(x64dbg_path)
    if p.name.lower() not in ("x96dbg.exe", "x96dbg"):
        return x64dbg_path
    bitness = pe_bitness(target_exe) if target_exe.strip() else 64
    arch_dir = "x64" if bitness == 64 else "x32"
    dbg_name = "x64dbg.exe" if bitness == 64 else "x32dbg.exe"
    candidates = [
        p.parent / arch_dir / dbg_name,            # release/x64/x64dbg.exe
        p.parent / dbg_name,                       # flat layout
        p.parent / "release" / dbg_name,
        p.parent / "release" / arch_dir / dbg_name,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError(
        f"Cannot find {dbg_name} relative to {x64dbg_path}. "
        f"Pass the path to {dbg_name} directly instead of x96dbg.exe.")


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

ClientFactory = Callable[["str | None"], AutomateClient]


def make_spawn_client_factory(x64dbg_path: str) -> ClientFactory:
    """Factory for 'spawn' mode: each call builds a fresh client whose
    start_session() will launch its own x64dbg process.

    ``target_exe`` is used only to resolve x96dbg.exe -> x64/x32dbg.exe.
    The x64dbg_automate import is deferred so this module (and the test
    suite) never requires the package to be installed.
    """

    def factory(target_exe: str | None) -> AutomateClient:
        from x64dbg_automate import X64DbgClient

        resolved = resolve_x64dbg_path(x64dbg_path, target_exe or "")
        return RealAutomateClient(X64DbgClient(x64dbg_path=resolved))

    return factory


def make_remote_client(host: str, req_rep_port: int,
                       pub_sub_port: int) -> AutomateClient:
    """Build a client connected to an already-running x64dbg whose
    Automate plugin is in 'remote' mode. Connects (and PING/PONGs)
    immediately, so misconfiguration fails at adapter startup."""
    from x64dbg_automate import X64DbgClient

    raw = X64DbgClient.connect_remote(host, req_rep_port, pub_sub_port)
    return RealAutomateClient(raw)


def default_factory_from_env() -> tuple[str, ClientFactory | AutomateClient]:
    """Decide spawn vs remote mode from XAUTO_* environment variables.

    Returns ("spawn", factory) or ("remote", connected_client).
    """
    remote_host = os.environ.get("XAUTO_REMOTE_HOST", "").strip()
    if remote_host:
        req = int(os.environ.get("XAUTO_REMOTE_REQ_PORT", "0"))
        pub = int(os.environ.get("XAUTO_REMOTE_PUB_PORT", "0"))
        if not req or not pub:
            raise ValueError(
                "XAUTO_REMOTE_HOST is set but XAUTO_REMOTE_REQ_PORT / "
                "XAUTO_REMOTE_PUB_PORT are missing or zero")
        return "remote", make_remote_client(remote_host, req, pub)
    x64dbg_path = os.environ.get("XAUTO_X64DBG_PATH", "x64dbg")
    return "spawn", make_spawn_client_factory(x64dbg_path)
