#!/usr/bin/env python3
"""revlab x64dbg bridge adapter.

Implements the HTTP bridge contract in ../docs/BRIDGE.md on top of the
real x64dbg-automate Python client (package ``x64dbg_automate``), so
revlab-mcp's ``debugger/x64dbg.py`` can drive a live x64dbg on the
analysis host. Standard library only for the HTTP layer; the debugger
client is injected (see automate_client.py), which is what makes this
service testable without Windows.

Run (spawn mode -- adapter launches x64dbg per session):
    set XAUTO_X64DBG_PATH=C:\\x64dbg\\release\\x64\\x64dbg.exe
    python adapter.py --host 127.0.0.1 --port 27042

Run (remote mode -- attach to a running x64dbg with the Automate
plugin in 'remote' mode):
    set XAUTO_REMOTE_HOST=127.0.0.1
    set XAUTO_REMOTE_REQ_PORT=27001
    set XAUTO_REMOTE_PUB_PORT=27002
    python adapter.py --host 127.0.0.1 --port 27042

Keep the listener on loopback: the only intended client is the
revlab-mcp server on the same host (see ../docs/BRIDGE.md).
"""

from __future__ import annotations

import argparse
import json
import ntpath
import os
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from automate_client import (  # noqa: E402
    BP_NORMAL,
    MEM_IMAGE,
    AutomateClient,
    ClientFactory,
    default_factory_from_env,
)

ADAPTER_NAME = "revlab-x64dbg-adapter/1.0.0"

REGS_64 = ["rax", "rbx", "rcx", "rdx", "rbp", "rsp", "rsi", "rdi",
           "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
           "rip", "eflags", "cs", "ds", "es", "fs", "gs", "ss",
           "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"]
REGS_32 = ["eax", "ebx", "ecx", "edx", "ebp", "esp", "esi", "edi",
           "eip", "eflags", "cs", "ds", "es", "fs", "gs", "ss",
           "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"]


class BridgeError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def parse_address(value) -> int:
    """Accept int, '0x...' hex, bare hex, or decimal (same rules as
    revlab's debugger.base.parse_address)."""
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    if text.isdigit():
        return int(text, 10)
    return int(text, 16)


def fmt_address(value: int, width: int = 0) -> str:
    if width:
        return f"0x{value:0{width}X}"
    return f"0x{value:X}"


class Session:
    def __init__(self, session_id: str, client: AutomateClient):
        self.session_id = session_id
        self.client = client
        self.target_path: str | None = None
        self.debuggee_pid: int | None = None
        self.main_module: dict | None = None
        # addr -> location string exactly as requested via the bridge
        # (x64dbg itself does not preserve it; see README "Known gaps").
        self.bp_registry: dict[int, str] = {}
        # base -> {"name": ..., "path": ...} learned from LOAD_DLL events
        self.module_names: dict[int, dict] = {}
        self.log_cursor: int = 0


class SessionManager:
    """Owns the single live debug session.

    The contract's "one bridge session == one debuggee" maps naturally
    onto x64dbg-automate: one client owns one x64dbg (spawn mode) or is
    connected to one x64dbg (remote mode). A second /session/start
    while a session is active is a 409, unlike the mock bridge which
    happily hosts many fake sessions.
    """

    def __init__(self, mode: str,
                 spawn_factory: ClientFactory | None = None,
                 remote_client: AutomateClient | None = None):
        if mode not in ("spawn", "remote"):
            raise ValueError(f"unknown mode: {mode}")
        self.mode = mode
        self._spawn_factory = spawn_factory
        self._remote_client = remote_client
        self.session: Session | None = None
        self.lock = threading.RLock()

    # -- helpers ---------------------------------------------------------
    def _require_session(self, session_id) -> Session:
        sess = self.session
        if sess is None or sess.session_id != session_id:
            raise BridgeError(404, f"unknown session: {session_id}")
        return sess

    def _new_client(self, target_exe: str | None) -> AutomateClient:
        if self.mode == "remote":
            return self._remote_client
        return self._spawn_factory(target_exe)

    @staticmethod
    def _cleanup_client(client: AutomateClient) -> None:
        """Best-effort teardown of a client whose session failed to
        start (spawn mode may have left a debugger process behind).
        Remote-mode clients are shared and must be left alone."""
        try:
            client.terminate_session()
        except Exception:
            try:
                client.detach_session()
            except Exception:
                pass

    @staticmethod
    def _drain_module_events(sess: Session) -> None:
        """Fold EVENT_LOAD_DLL records into the session's module table.

        The automate client queues pub/sub events from connection time;
        drain opportunistically so /modules can attach real file paths
        to the image ranges reported by memmap().
        """
        client = sess.client
        try:
            while True:
                event = client.get_latest_debug_event()
                if event is None:
                    return
                etype = getattr(event.event_type, "value", event.event_type)
                data = event.event_data
                if str(etype) == "EVENT_LOAD_DLL" and data is not None:
                    path = getattr(data, "modname", "") or ""
                    base = getattr(data, "lpBaseOfDll", 0) or 0
                    if base:
                        sess.module_names[int(base)] = {
                            # ntpath: the paths are Windows paths no
                            # matter what OS this process runs on.
                            "name": ntpath.basename(path) if path else "",
                            "path": path,
                        }
                elif str(etype) == "EVENT_UNLOAD_DLL" and data is not None:
                    base = getattr(data, "lpBaseOfDll", 0) or 0
                    sess.module_names.pop(int(base), None)
        except Exception:
            # Event draining is best-effort enrichment; never fail a
            # request because the event queue misbehaved.
            return

    @staticmethod
    def _image_groups(client: AutomateClient) -> list[tuple[int, int]]:
        """(base, size) per loaded image, from memmap(). Exact data:
        pages of type MEM_IMAGE grouped by allocation_base."""
        groups: dict[int, int] = {}
        for page in client.memmap():
            if int(page.type) != MEM_IMAGE:
                continue
            base = int(page.allocation_base)
            end = int(page.base_address) + int(page.region_size)
            groups[base] = max(groups.get(base, 0), end)
        return sorted((base, end - base) for base, end in groups.items())

    def _derive_main_module(self, sess: Session) -> dict:
        client = sess.client
        base = None
        try:
            val, ok = client.eval_sync("mod.main()")
            if ok and val:
                base = int(val)
        except Exception:
            base = None
        groups = []
        if base is None:
            groups = self._image_groups(client)
            if groups:
                base = groups[0][0]
        size = 0
        if base is not None:
            try:
                val, ok = client.eval_sync(f"mod.size(0x{base:X})")
                if ok and val:
                    size = int(val)
            except Exception:
                size = 0
            if not size:
                if not groups:
                    groups = self._image_groups(client)
                size = dict(groups).get(base, 0)
        info = sess.module_names.get(base or 0, {})
        name = info.get("name", "")
        path = info.get("path", "")
        if sess.target_path:
            # For a launch we know the exact file; it wins over events.
            path = sess.target_path
            name = ntpath.basename(sess.target_path)
        if base is not None and path:
            sess.module_names[base] = {"name": name, "path": path}
        return {
            "name": name,
            "base": fmt_address(base or 0),
            "size": size,
            "path": path,
        }

    def _current_state(self, sess: Session) -> tuple[str, str]:
        client = sess.client
        try:
            state = "running" if client.is_running() else "paused"
        except Exception:
            state = "paused"
        cip = "0x0"
        try:
            if client.is_debugging():
                cip = fmt_address(int(client.get_reg("cip")))
        except Exception:
            cip = "0x0"
        return state, cip

    # -- endpoints ---------------------------------------------------------
    def health(self) -> dict:
        return {
            "ok": True,
            "bridge": ADAPTER_NAME,
            "backend": "x64dbg-automate",
            "mode": self.mode,
            "session_active": self.session is not None,
        }

    def start_session(self, req: dict) -> dict:
        with self.lock:
            if self.session is not None:
                raise BridgeError(
                    409, "a debug session is already active on this "
                         f"bridge: {self.session.session_id}; stop it first")
            path = (req.get("path") or "").strip()
            pid = req.get("pid")
            arguments = req.get("arguments") or ""
            cwd = req.get("cwd") or ""
            if not path and pid is None:
                raise BridgeError(400, "either 'path' or 'pid' is required")
            if path and pid is not None:
                raise BridgeError(400, "give either 'path' or 'pid', not both")

            client = self._new_client(path or None)
            sess = Session(uuid.uuid4().hex, client)
            try:
                if self.mode == "remote":
                    if path:
                        if not client.load_executable(path, arguments, cwd):
                            raise BridgeError(
                                400, f"failed to load executable: {path}")
                    else:
                        if not client.attach(int(pid)):
                            raise BridgeError(
                                400, f"failed to attach to pid {pid}")
                else:
                    if path:
                        client.start_session(path, arguments, cwd)
                    else:
                        client.start_session_attach(int(pid))
            except BridgeError:
                if self.mode == "spawn":
                    self._cleanup_client(client)
                raise
            except Exception as exc:
                if self.mode == "spawn":
                    self._cleanup_client(client)
                raise BridgeError(400, f"session start failed: {exc}") from exc

            sess.target_path = path or None
            try:
                sess.debuggee_pid = client.debugee_pid()
            except Exception:
                sess.debuggee_pid = int(pid) if pid is not None else None
            try:
                sess.log_cursor = client.get_log(0, 0, "")[0]
            except Exception:
                sess.log_cursor = 0
            self._drain_module_events(sess)
            sess.main_module = self._derive_main_module(sess)
            state, _ = self._current_state(sess)
            self.session = sess
            return {
                "session_id": sess.session_id,
                "pid": sess.debuggee_pid,
                "state": state,
                "main_module": sess.main_module,
            }

    def stop_session(self, req: dict) -> dict:
        with self.lock:
            sess = self._require_session(req.get("session_id"))
            try:
                if self.mode == "remote":
                    # Stop the debuggee; the analyst's x64dbg stays up
                    # and stays connected for the next session.
                    sess.client.unload_executable()
                else:
                    sess.client.terminate_session()
            except Exception:
                # The session is over from the bridge's perspective no
                # matter what the debugger thinks. In spawn mode try a
                # clean detach as a last resort; in remote mode leave
                # the shared client connected for the next session.
                if self.mode == "spawn":
                    try:
                        sess.client.detach_session()
                    except Exception:
                        pass
            self.session = None
            return {"ok": True}

    def control(self, req: dict) -> dict:
        with self.lock:
            sess = self._require_session(req.get("session_id"))
            client = sess.client
            action = req.get("action")
            try:
                if action == "run":
                    ok = client.go()
                    # Optional adapter extension (not in BRIDGE.md):
                    # callers that want run-to-next-stop semantics can
                    # pass wait_stop_timeout (seconds).
                    wait = req.get("wait_stop_timeout")
                    if ok and wait:
                        client.wait_until_stopped(timeout=int(wait))
                elif action == "pause":
                    ok = client.pause()
                elif action == "step_into":
                    ok = client.stepi()
                elif action == "step_over":
                    ok = client.stepo()
                else:
                    raise BridgeError(400, f"unknown control action: {action}")
            except BridgeError:
                raise
            except Exception as exc:
                raise BridgeError(400, f"control {action} failed: {exc}") from exc
            if not ok:
                raise BridgeError(400, f"control {action} was rejected by x64dbg")
            state, cip = self._current_state(sess)
            return {"state": state, "cip": cip}

    def command(self, req: dict) -> dict:
        with self.lock:
            sess = self._require_session(req.get("session_id"))
            client = sess.client
            command = req.get("command") or ""
            if not command:
                raise BridgeError(400, "missing 'command'")
            # cmd_sync returns only a bool in x64dbg-automate; the
            # textual result of a command lives in the debugger log,
            # which the plugin captures. Diff the log around the call.
            ok = client.cmd_sync(command)
            output = ""
            try:
                next_index, messages, _remaining, _evicted = client.get_log(
                    since_index=sess.log_cursor)
                sess.log_cursor = next_index
                output = "\n".join(messages)
            except Exception:
                output = ""
            if not ok:
                raise BridgeError(400, f"x64dbg command failed: {command}")
            return {"output": output}

    def set_breakpoint(self, req: dict) -> dict:
        with self.lock:
            sess = self._require_session(req.get("session_id"))
            client = sess.client
            address = req.get("address")
            location = req.get("location")
            if address is None and not location:
                raise BridgeError(400, "either 'address' or 'location' is required")
            addr = None
            if address is not None:
                addr = parse_address(address)
                ok = client.set_breakpoint(addr)
            else:
                # Resolve first when possible so the response can carry
                # the numeric address; fall back to letting x64dbg's
                # bpx command resolve the name itself. BRIDGE.md uses
                # WinDbg-style "module!Symbol"; x64dbg's expression
                # syntax for the same symbol is "module:Symbol", so try
                # the translated form as well.
                candidates = [location]
                if "!" in location:
                    candidates.append(location.replace("!", ":"))
                resolved = None
                for candidate in candidates:
                    try:
                        val, success = client.eval_sync(candidate)
                        if success and val:
                            resolved = int(val)
                            break
                    except Exception:
                        continue
                if resolved is not None:
                    addr = resolved
                    ok = client.set_breakpoint(addr)
                else:
                    ok = client.set_breakpoint(location)
                    addr = self._find_new_breakpoint(sess)
            if not ok:
                raise BridgeError(
                    400, f"failed to set breakpoint: {address or location}")
            if addr is not None and location:
                sess.bp_registry[addr] = location
            return {
                "address": fmt_address(addr) if addr is not None else None,
                "location": location,
                "enabled": True,
            }

    def _find_new_breakpoint(self, sess: Session) -> int | None:
        """After setting a breakpoint by an unresolvable-up-front name,
        find it by diffing the debugger's breakpoint list against the
        ones this bridge already knows about."""
        try:
            known = set(sess.bp_registry)
            for bp in sess.client.get_breakpoints(BP_NORMAL):
                if int(bp.addr) not in known:
                    return int(bp.addr)
        except Exception:
            pass
        return None

    def list_breakpoints(self, session_id) -> dict:
        with self.lock:
            sess = self._require_session(session_id)
            out = []
            for bp in sess.client.get_breakpoints(BP_NORMAL):
                addr = int(bp.addr)
                out.append({
                    "address": fmt_address(addr),
                    "location": sess.bp_registry.get(addr),
                    "enabled": bool(bp.enabled),
                })
            return {"breakpoints": out}

    def delete_breakpoint(self, req: dict) -> dict:
        with self.lock:
            sess = self._require_session(req.get("session_id"))
            client = sess.client
            address = req.get("address")
            location = req.get("location")
            if address is not None:
                addr = parse_address(address)
                ok = client.clear_breakpoint(addr)
            elif location:
                addr = None
                for known_addr, known_loc in sess.bp_registry.items():
                    if known_loc == location:
                        addr = known_addr
                        break
                ok = client.clear_breakpoint(addr if addr is not None else location)
            else:
                raise BridgeError(400, "either 'address' or 'location' is required")
            if not ok:
                raise BridgeError(404, "breakpoint not found")
            if address is not None:
                sess.bp_registry.pop(parse_address(address), None)
            elif location:
                for known_addr, known_loc in list(sess.bp_registry.items()):
                    if known_loc == location:
                        sess.bp_registry.pop(known_addr, None)
            return {"ok": True}

    def registers(self, session_id) -> dict:
        with self.lock:
            sess = self._require_session(session_id)
            dump = sess.client.get_regs()
            ctx = dump.context
            if hasattr(ctx, "rip"):
                names, cip_name, width = REGS_64, "rip", 16
            else:
                names, cip_name, width = REGS_32, "eip", 8
            regs = {}
            for name in names:
                if hasattr(ctx, name):
                    regs[name] = fmt_address(int(getattr(ctx, name)), width)
            return {"registers": regs, "cip": regs.get(cip_name, "0x0")}

    def read_memory(self, req: dict) -> dict:
        with self.lock:
            sess = self._require_session(req.get("session_id"))
            addr = parse_address(req.get("address", 0))
            size = int(req.get("size", 0))
            if size <= 0:
                raise BridgeError(400, "size must be positive")
            try:
                data = sess.client.read_memory(addr, size)
            except Exception as exc:
                # The plugin's read is all-or-nothing across a region
                # boundary; a failure here is a client error, not a 500.
                raise BridgeError(400, f"memory read failed: {exc}") from exc
            return {"address": fmt_address(addr), "size": len(data),
                    "hex": data.hex()}

    def disassemble(self, req: dict) -> dict:
        with self.lock:
            sess = self._require_session(req.get("session_id"))
            client = sess.client
            addr = parse_address(req.get("address", 0))
            count = int(req.get("count", 16))
            instructions = []
            for _ in range(max(0, count)):
                ins = client.disassemble_at(addr)
                if ins is None:
                    break
                size = int(ins.instr_size)
                raw = ""
                if size > 0:
                    try:
                        raw = client.read_memory(addr, size).hex()
                    except Exception:
                        raw = ""
                instructions.append({
                    "address": fmt_address(addr),
                    "bytes": raw,
                    "text": ins.instruction,
                })
                if size <= 0:
                    # Never spin forever on a zero-length decode.
                    break
                addr += size
            return {"instructions": instructions}

    def callstack(self, session_id) -> dict:
        with self.lock:
            self._require_session(session_id)
            raise BridgeError(
                501, "not_implemented: x64dbg-automate exposes no "
                     "call-stack API (no RPC in the plugin and no client "
                     "method), so this bridge cannot serve /callstack "
                     "honestly. See bridge_adapter/README.md.")

    def modules(self, session_id) -> dict:
        with self.lock:
            sess = self._require_session(session_id)
            self._drain_module_events(sess)
            out = []
            for base, size in self._image_groups(sess.client):
                info = sess.module_names.get(base, {})
                out.append({
                    "name": info.get("name", ""),
                    "base": fmt_address(base),
                    "size": size,
                    "path": info.get("path", ""),
                })
            return {"modules": out}


# ---------------------------------------------------------------------------
# HTTP layer (stdlib only, mirrors mock_bridge.py's routing style)
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    manager: SessionManager = None  # set by main()/tests

    def log_message(self, *args):  # keep the console clean
        pass

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

    def _query_session_id(self):
        qs = parse_qs(urlparse(self.path).query)
        return (qs.get("session_id") or [None])[0]

    def _dispatch(self, fn):
        try:
            self._send(200, fn())
        except BridgeError as exc:
            self._send(exc.status, {"error": exc.message})
        except Exception as exc:  # noqa: BLE001 - last-resort guard
            self._send(500, {"error": f"internal bridge error: {exc}"})

    def do_GET(self):
        path = urlparse(self.path).path
        mgr = self.manager
        if path == "/health":
            return self._dispatch(mgr.health)
        sid = self._query_session_id()
        if path == "/breakpoints":
            return self._dispatch(lambda: mgr.list_breakpoints(sid))
        if path == "/registers":
            return self._dispatch(lambda: mgr.registers(sid))
        if path == "/callstack":
            return self._dispatch(lambda: mgr.callstack(sid))
        if path == "/modules":
            return self._dispatch(lambda: mgr.modules(sid))
        return self._send(404, {"error": f"no route: GET {path}"})

    def do_POST(self):
        path = urlparse(self.path).path
        mgr = self.manager
        req = self._body()
        if path == "/session/start":
            return self._dispatch(lambda: mgr.start_session(req))
        if path == "/session/stop":
            return self._dispatch(lambda: mgr.stop_session(req))
        if path == "/control":
            return self._dispatch(lambda: mgr.control(req))
        if path == "/cmd":
            return self._dispatch(lambda: mgr.command(req))
        if path == "/breakpoints":
            return self._dispatch(lambda: mgr.set_breakpoint(req))
        if path == "/memory":
            return self._dispatch(lambda: mgr.read_memory(req))
        if path == "/disasm":
            return self._dispatch(lambda: mgr.disassemble(req))
        return self._send(404, {"error": f"no route: POST {path}"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        if path == "/breakpoints":
            req = self._body()
            return self._dispatch(lambda: self.manager.delete_breakpoint(req))
        return self._send(404, {"error": f"no route: DELETE {path}"})


def make_server(host: str, port: int,
                manager: SessionManager) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"manager": manager})
    return ThreadingHTTPServer((host, port), handler)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="revlab x64dbg bridge adapter (x64dbg-automate backend)")
    parser.add_argument("--host", default=os.environ.get("BRIDGE_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("BRIDGE_PORT", "27042")))
    parser.add_argument("--x64dbg-path",
                        default=os.environ.get("XAUTO_X64DBG_PATH", "x64dbg"),
                        help="spawn mode: path to x64dbg.exe/x32dbg.exe "
                             "or the x96dbg.exe launcher")
    args = parser.parse_args(argv)

    # CLI path wins over the env default when explicitly different is
    # overkill; simply re-export it for the factory builder.
    if args.x64dbg_path:
        os.environ["XAUTO_X64DBG_PATH"] = args.x64dbg_path
    mode, factory_or_client = default_factory_from_env()
    if mode == "remote":
        manager = SessionManager("remote", remote_client=factory_or_client)
    else:
        manager = SessionManager("spawn", spawn_factory=factory_or_client)
    server = make_server(args.host, args.port, manager)
    print(f"revlab x64dbg bridge adapter listening on "
          f"http://{args.host}:{args.port} (mode={mode}, "
          f"backend=x64dbg-automate)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
