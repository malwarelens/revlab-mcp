"""Fake AutomateClient for the adapter test-suite.

Implements the automate_client.AutomateClient protocol with in-memory
state that mimics the real client's observable behavior:

* start_session() returns the *debugger* PID (like the real client);
  debugee_pid() returns the different debuggee PID.
* get_regs() returns a RegDump-shaped object (.context namespace).
* memmap() returns MemPage-shaped namespaces (type MEM_IMAGE for
  module pages).
* disassemble_at() returns Instruction-shaped objects (no raw bytes —
  just like the real model — so the adapter must read_memory() for
  the "bytes" field).
* get_log() implements the same cursor semantics as the plugin
  (since_index / next_index).
* debug events are queued LOAD_DLL records the fake "publishes" when a
  session starts, like the real pub/sub channel.
"""

from __future__ import annotations

import itertools
from types import SimpleNamespace

MEM_IMAGE = 0x1000000
MEM_PRIVATE = 0x20000
MEM_COMMIT = 0x1000
PAGE_EXECUTE_READ = 0x20
PAGE_READWRITE = 0x04

MAIN_BASE = 0x140000000
MAIN_SIZE = 0x2F000
NTDLL_BASE = 0x7FFC10000000
NTDLL_SIZE = 0x1F4000
K32_BASE = 0x7FFC0E000000
K32_SIZE = 0xC3000

CREATEFILEW_ADDR = 0x7FFC0E012340
DEBUGGER_PID = 7777
DEBUGGEE_PID = 4242


class FakeContext:
    def __init__(self):
        self.rax = 0x1111
        self.rbx = 0x2222
        self.rcx = 0x3333
        self.rdx = 0x4444
        self.rbp = MAIN_BASE + 0x5000
        self.rsp = 0x7FF000
        self.rsi = 0
        self.rdi = 0
        for i in range(8, 16):
            setattr(self, f"r{i}", 0)
        self.rip = MAIN_BASE + 0x1000
        self.eflags = 0x202
        self.cs = 0x33
        self.ds = 0x2B
        self.es = 0x2B
        self.fs = 0x53
        self.gs = 0x2B
        self.ss = 0x2B
        self.dr0 = self.dr1 = self.dr2 = self.dr3 = 0
        self.dr6 = 0
        self.dr7 = 0


class FakeAutomateClient:
    def __init__(self):
        self.ctx = FakeContext()
        self.debugging = False
        self.running = False
        self.breakpoints: dict[int, SimpleNamespace] = {}
        self.log_lines: list[str] = []
        self.events: list[SimpleNamespace] = []
        self.cmd_history: list[str] = []
        # call counters for assertions
        self.terminate_calls = 0
        self.detach_calls = 0
        self.unload_calls = 0
        self.load_calls: list[tuple] = []
        self.attach_calls: list[int] = []
        self.memory = self._build_memory()
        self._disasm_cycle = itertools.cycle([
            ("sub rsp, 0x28", 4),
            ("mov rcx, qword ptr ds:[0x0000000140003040]", 7),
            ("call 0x00000001400011A0", 5),
            ("nop", 1),
        ])

    # -- synthetic address space -----------------------------------------
    @staticmethod
    def _build_memory() -> dict[int, int]:
        mem: dict[int, int] = {}
        # MZ header at main base, PE-ish pattern elsewhere.
        for off, b in enumerate(b"\x4D\x5A\x90\x00"):
            mem[MAIN_BASE + off] = b
        for addr in range(MAIN_BASE + 0x1000, MAIN_BASE + 0x1100):
            mem[addr] = 0x90
        return mem

    def _read(self, addr: int, size: int) -> bytes:
        return bytes(self.memory.get(addr + i, 0) for i in range(size))

    # -- session lifecycle -------------------------------------------------
    def _begin_debugging(self, path: str, debuggee_pid: int):
        self.debugging = True
        self.running = False
        self.log_lines.append(f"Debugging: {path}")
        # The real plugin publishes LOAD_DLL events during process init;
        # ntdll first, then the rest. The debugger stops at the entry
        # point with the main module + system DLLs already loaded.
        for modname, base in (
            (r"C:\Windows\System32\ntdll.dll", NTDLL_BASE),
            (r"C:\Windows\System32\kernel32.dll", K32_BASE),
        ):
            self.events.append(SimpleNamespace(
                event_type="EVENT_LOAD_DLL",
                event_data=SimpleNamespace(modname=modname, lpBaseOfDll=base),
            ))

    def start_session(self, target_exe="", cmdline="", current_dir=""):
        self._begin_debugging(target_exe, DEBUGGEE_PID)
        return DEBUGGER_PID

    def start_session_attach(self, pid):
        self._begin_debugging(f"<pid {pid}>", pid)
        return DEBUGGER_PID

    def terminate_session(self):
        self.terminate_calls += 1
        self.debugging = False
        self.running = False

    def detach_session(self):
        self.detach_calls += 1
        self.debugging = False

    def load_executable(self, target_exe, cmdline="", current_dir=""):
        self.load_calls.append((target_exe, cmdline, current_dir))
        self._begin_debugging(target_exe, DEBUGGEE_PID)
        return True

    def attach(self, pid):
        self.attach_calls.append(pid)
        self._begin_debugging(f"<pid {pid}>", pid)
        return True

    def unload_executable(self):
        self.unload_calls += 1
        self.debugging = False
        self.running = False
        return True

    # -- execution control ---------------------------------------------------
    def go(self):
        self.running = True
        return True

    def pause(self):
        self.running = False
        return True

    def stepi(self):
        self.running = False
        self.ctx.rip += 4
        return True

    def stepo(self):
        self.running = False
        self.ctx.rip += 5
        return True

    def is_running(self):
        return self.running

    def is_debugging(self):
        return self.debugging

    def wait_until_stopped(self, timeout=10):
        self.running = False
        return True

    # -- commands / eval / log ---------------------------------------------------
    def cmd_sync(self, cmd_str):
        self.cmd_history.append(cmd_str)
        if cmd_str == "badcmd":
            return False
        self.log_lines.append(f"Executed: {cmd_str}")
        if cmd_str.startswith("log "):
            self.log_lines.append(cmd_str[4:])
        return True

    def eval_sync(self, eval_str):
        expr = eval_str.strip()
        if expr == "mod.main()":
            return (MAIN_BASE, True)
        if expr == "pid":
            return (DEBUGGEE_PID if self.debugging else 0, True)
        if expr.lower().startswith("mod.size("):
            return (MAIN_SIZE, True)
        if expr.lower() == "kernel32!createfilew":
            # WinDbg-style '!' is NOT valid x64dbg expression syntax.
            return (0, False)
        if expr.lower() == "kernel32:createfilew":
            return (CREATEFILEW_ADDR, True)
        if expr.lower().startswith("0x"):
            return (int(expr, 16), True)
        return (0, False)

    def get_log(self, since_index=0, limit=0, filter=""):
        total = len(self.log_lines)
        start = min(since_index, total)
        msgs = self.log_lines[start:]
        if limit:
            msgs = msgs[:limit]
        next_index = start + len(msgs)
        return (next_index, msgs, total - next_index, 0)

    # -- state inspection ---------------------------------------------------------
    def get_reg(self, reg):
        if reg == "cip":
            return self.ctx.rip
        return int(getattr(self.ctx, reg))

    def get_regs(self):
        return SimpleNamespace(context=self.ctx)

    def read_memory(self, addr, size):
        if not self.debugging:
            raise RuntimeError("XERROR_NOT_DEBUGGING")
        if addr == 0xDEAD0000:
            raise RuntimeError("XERROR_READ_FAILED")
        return self._read(addr, size)

    def memmap(self):
        def page(base, alloc_base, size, ptype, info="", protect=PAGE_EXECUTE_READ):
            return SimpleNamespace(
                base_address=base, allocation_base=alloc_base,
                allocation_protect=protect, partition_id=0,
                region_size=size, state=MEM_COMMIT, protect=protect,
                type=ptype, info=info)
        return [
            # main module: header page + .text page (same allocation)
            page(MAIN_BASE, MAIN_BASE, 0x1000, MEM_IMAGE, ""),
            page(MAIN_BASE + 0x1000, MAIN_BASE, MAIN_SIZE - 0x1000,
                 MEM_IMAGE, ".text"),
            # ntdll
            page(NTDLL_BASE, NTDLL_BASE, NTDLL_SIZE, MEM_IMAGE, ".text"),
            # kernel32
            page(K32_BASE, K32_BASE, K32_SIZE, MEM_IMAGE, ".text"),
            # one private heap page (must NOT show up as a module)
            page(0x1F0000, 0x1F0000, 0x3000, MEM_PRIVATE, "Heap",
                 protect=PAGE_READWRITE),
        ]

    def disassemble_at(self, addr):
        # Addresses below the main image are undecodable.
        if addr < MAIN_BASE or addr >= MAIN_BASE + MAIN_SIZE:
            return None
        text, size = next(self._disasm_cycle)
        return SimpleNamespace(instruction=text,
                               symbolized_instruction=text,
                               argcount=0, instr_size=size, type=0, arg=[])

    def check_valid_read_ptr(self, addr):
        return self.debugging and addr != 0xDEAD0000

    # -- breakpoints ---------------------------------------------------------------- -
    def set_breakpoint(self, address_or_symbol):
        if isinstance(address_or_symbol, int):
            addr = address_or_symbol
            name = f"bpx_{addr:X}"
        else:
            # x64dbg resolves the symbol for bpx; the fake resolves the
            # same expressions eval knows about ("module:Symbol" form).
            val, ok = self.eval_sync(str(address_or_symbol))
            if not ok:
                return False
            addr = val
            name = f"bpx_{address_or_symbol}"
        self.breakpoints[addr] = SimpleNamespace(
            type=1, addr=addr, enabled=True, singleshoot=False,
            active=True, name=name, mod="", slot=0, typeEx=0, hwSize=0,
            hitCount=0, fastResume=False, silent=False, breakCondition="",
            logText="", logCondition="", commandText="",
            commandCondition="")
        return True

    def clear_breakpoint(self, target=None):
        if target is None:
            self.breakpoints.clear()
            return True
        if isinstance(target, int):
            return self.breakpoints.pop(target, None) is not None
        for addr, bp in list(self.breakpoints.items()):
            if bp.name == f"bpx_{target}" or bp.name == target:
                del self.breakpoints[addr]
                return True
        return False

    def get_breakpoints(self, bp_type):
        if bp_type != 1:
            return []
        return sorted(self.breakpoints.values(), key=lambda b: b.addr)

    # -- misc --------------------------------------------------------------------------
    def debugee_pid(self):
        return DEBUGGEE_PID if self.debugging else None

    def get_symbol_at(self, addr):
        return None

    def get_label_at(self, addr):
        return ""

    def get_latest_debug_event(self):
        if self.events:
            return self.events.pop(0)
        return None
