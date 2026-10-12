#!/usr/bin/env python3
"""Mock x64dbg bridge for development and tests.

Implements the exact HTTP contract in docs/BRIDGE.md with canned data,
using only the Python standard library, so the full MCP stack can be
exercised on any machine (including this Linux dev box) without a real
x64dbg. Nothing here talks to a real debugger.

Usage:  python mock_bridge.py [--host 127.0.0.1] [--port 27042]
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

MAIN_BASE = 0x140000000
ENTRY = MAIN_BASE + 0x1000

REGISTERS = {
    "rax": "0x0000000000000000", "rbx": "0x0000000140000000",
    "rcx": "0x0000000000000001", "rdx": "0x0000000000000000",
    "rsi": "0x0000000000000000", "rdi": "0x000000000014FB60",
    "rbp": "0x000000000014F9A0", "rsp": "0x000000000014F988",
    "r8": "0x000000000014F988", "r9": "0x0000000000000000",
    "r10": "0x0000000000000000", "r11": "0x0000000000000000",
    "r12": "0x0000000000000000", "r13": "0x0000000000000000",
    "r14": "0x0000000000000000", "r15": "0x0000000000000000",
    "rip": f"0x{ENTRY:X}", "eflags": "0x0000000000000246",
}

DISASM_POOL = [
    ("4883EC28", "sub rsp, 0x28"),
    ("488B05F91F0000", "mov rax, qword ptr ds:[0x140002000]"),
    ("4885C0", "test rax, rax"),
    ("7412", "je 0x140001025"),
    ("FF15E51F0000", "call qword ptr ds:[0x140003000]"),
    ("4883C428", "add rsp, 0x28"),
    ("C3", "ret"),
    ("CC", "int3"),
]

MODULES = [
    {"name": "sample.exe", "base": f"0x{MAIN_BASE:X}", "size": 24576,
     "path": "C:\\revlab\\samples\\sample.exe"},
    {"name": "ntdll.dll", "base": "0x7FFD12340000", "size": 2514944,
     "path": "C:\\Windows\\System32\\ntdll.dll"},
    {"name": "kernel32.dll", "base": "0x7FFD0FAB0000", "size": 794624,
     "path": "C:\\Windows\\System32\\kernel32.dll"},
    {"name": "KernelBase.dll", "base": "0x7FFD0D120000", "size": 3112960,
     "path": "C:\\Windows\\System32\\KernelBase.dll"},
]

CALLSTACK = [
    {"index": 0, "address": f"0x{ENTRY:X}", "module": "sample.exe", "symbol": "entry_point"},
    {"index": 1, "address": "0x7FFD0FABC410", "module": "kernel32.dll", "symbol": "BaseThreadInitThunk"},
    {"index": 2, "address": "0x7FFD1237E2C0", "module": "ntdll.dll", "symbol": "RtlUserThreadStart"},
]


class State:
    def __init__(self):
        self.counter = 0
        self.sessions: dict[str, dict] = {}

    def new_session(self, req: dict) -> dict:
        self.counter += 1
        sid = f"mock-session-{self.counter}"
        session = {
            "session_id": sid,
            "pid": req.get("pid", 4242),
            "path": req.get("path"),
            "state": "paused",
            "breakpoints": [],
        }
        self.sessions[sid] = session
        return session


STATE = State()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output clean
        pass

    # -- helpers ----------------------------------------------------------
    def _send(self, code: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return {}

    def _session(self, req: dict) -> dict | None:
        sid = req.get("session_id")
        if sid is None:
            qs = parse_qs(urlparse(self.path).query)
            sid = (qs.get("session_id") or [None])[0]
        session = STATE.sessions.get(sid)
        if session is None:
            self._send(404, {"error": f"unknown session: {sid}"})
        return session

    # -- routes -------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            return self._send(200, {"ok": True, "bridge": "mock/1.0"})
        if path == "/breakpoints":
            s = self._session({})
            if s:
                return self._send(200, {"breakpoints": s["breakpoints"]})
        elif path == "/registers":
            s = self._session({})
            if s:
                return self._send(200, {"registers": REGISTERS, "cip": REGISTERS["rip"]})
        elif path == "/callstack":
            s = self._session({})
            if s:
                return self._send(200, {"frames": CALLSTACK})
        elif path == "/modules":
            s = self._session({})
            if s:
                return self._send(200, {"modules": MODULES})
        else:
            return self._send(404, {"error": f"no route: GET {path}"})

    def do_POST(self):
        path = urlparse(self.path).path
        req = self._body()
        if path == "/session/start":
            s = STATE.new_session(req)
            return self._send(200, {
                "session_id": s["session_id"], "pid": s["pid"],
                "state": s["state"],
                "main_module": MODULES[0],
            })
        s = self._session(req)
        if s is None:
            return
        if path == "/session/stop":
            STATE.sessions.pop(s["session_id"], None)
            return self._send(200, {"ok": True})
        if path == "/control":
            action = req.get("action")
            s["state"] = "running" if action == "run" else "paused"
            if action in ("step_into", "step_over"):
                REGISTERS["rip"] = f"0x{ENTRY + 7:X}"
            return self._send(200, {"state": s["state"], "cip": REGISTERS["rip"]})
        if path == "/cmd":
            return self._send(200, {"output": f"mock executed: {req.get('command', '')}"})
        if path == "/breakpoints":
            bp = {"address": req.get("address"), "location": req.get("location"),
                  "enabled": True}
            s["breakpoints"].append(bp)
            return self._send(200, bp)
        if path == "/memory":
            size = int(req.get("size", 0))
            addr = req.get("address", "0x0")
            base = int(addr, 16) if isinstance(addr, str) else addr
            data = bytes(((base + i) * 7 + 3) & 0xFF for i in range(size))
            # Plant an MZ at the start of the main module image for realism.
            if base == MAIN_BASE and size >= 2:
                data = b"MZ" + data[2:]
            return self._send(200, {"address": addr, "size": size, "hex": data.hex()})
        if path == "/disasm":
            count = int(req.get("count", 16))
            addr = req.get("address", "0x0")
            base = int(addr, 16) if isinstance(addr, str) else addr
            instructions = []
            offset = 0
            for i in range(count):
                raw, text = DISASM_POOL[i % len(DISASM_POOL)]
                instructions.append({
                    "address": f"0x{base + offset:X}",
                    "bytes": raw.lower(),
                    "text": text,
                })
                offset += len(raw) // 2
            return self._send(200, {"instructions": instructions})
        return self._send(404, {"error": f"no route: POST {path}"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        req = self._body()
        if path == "/breakpoints":
            s = self._session(req)
            if s is None:
                return
            target = req.get("address") or req.get("location")
            s["breakpoints"] = [
                bp for bp in s["breakpoints"]
                if bp.get("address") != target and bp.get("location") != target
            ]
            return self._send(200, {"ok": True})
        return self._send(404, {"error": f"no route: DELETE {path}"})


def main():
    parser = argparse.ArgumentParser(description="Mock x64dbg bridge (canned data)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=27042)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mock bridge listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
