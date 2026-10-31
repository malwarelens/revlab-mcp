#!/usr/bin/env python3
"""revlab-mcp -- LAN malware reverse-engineering MCP server.

Runs on the analysis host. AI agents on the operator's workstation
connect over the LAN (Streamable HTTP + Bearer token) and drive:

  * a sample store (samples never leave this host, never downloadable)
  * static triage (vendored triage.py)
  * dynamic debugging via an x64dbg bridge (see docs/BRIDGE.md)
  * Frida instrumentation (optional dependency)
  * unpacking helpers (pe-sieve, PE carving, memory dumps to artifacts)

Configuration is entirely via RELAB_* environment variables (config.py).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

import capa_tools
import ghidra_tools
import inbox as inbox_mod
import report as report_mod
import unpack as unpack_mod
from audit import AuditLog, audited
from config import Config, load_config
from debugger import DebuggerBackend, DebuggerError, make_backend
from frida_tools import FridaManager
from samples import SampleStore
from sessions import SessionManager

BASE_DIR = Path(__file__).resolve().parent
TRIAGE_SCRIPT = BASE_DIR / "vendor" / "triage.py"


def _server_version() -> str:
    try:
        return (BASE_DIR / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"


# ---------------------------------------------------------------------------
# Bearer token middleware (pure ASGI, wraps the FastMCP Starlette app)
# ---------------------------------------------------------------------------

class BearerAuthMiddleware:
    def __init__(self, app, token: str):
        self.app = app
        self.expected = f"Bearer {token}"

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = {k.lower(): v for k, v in scope.get("headers") or []}
            provided = headers.get(b"authorization", b"").decode("utf-8", "replace")
            if provided != self.expected:
                body = json.dumps({"error": "unauthorized"}).encode()
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())],
                })
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Server assembly
# ---------------------------------------------------------------------------

def build_server(cfg: Config) -> FastMCP:
    audit_log = AuditLog(cfg.audit_log)
    audit = audited(audit_log)
    store = SampleStore(cfg.samples_dir)
    sessions = SessionManager(cfg.sessions_file)
    frida_mgr = FridaManager(cfg.artifacts_dir / "frida")

    mcp = FastMCP("revlab-mcp", host=cfg.host, port=cfg.port,
                  instructions=(
                      "Malware reverse-engineering lab server. Samples stay on "
                      "this host: register them with register_sample (or bulk-"
                      "register a drop folder with scan_inbox), analyse "
                      "with static_triage, capa_analyze and ghidra_analyze, "
                      "debug via the debug_* tools (x64dbg bridge; pass "
                      "session_id to route calls to a per-session debugger), "
                      "instrument with frida_* "
                      "tools, unpack with pe_sieve_scan / dump_memory_region "
                      "/ carve_pe_from_dump, check the platform with "
                      "lab_health, and summarise a finished session "
                      "with compose_session_report. "
                      "No tool returns sample bytes."))

    # -- debugger backends: one shared default + one per analysis session --
    # Calls without session_id go to the "current" backend -- the one
    # most recently launched/attached -- which preserves the original
    # single-session workflow. Calls with session_id route to the
    # backend instance bound to that analysis session; each analysis
    # session owns at most one backend instance, so concurrent debug
    # sessions never cross-talk.
    default_backend = make_backend(cfg.bridge_url)
    session_backends: dict[str, DebuggerBackend] = {}
    current: dict = {"key": "", "backend": default_backend}

    # -- helpers ------------------------------------------------------------
    def no_backend() -> dict:
        return {"ok": False, "configured": False,
                "error": "no debugger bridge configured; set "
                         "RELAB_X64DBG_BRIDGE_URL on the analysis host"}

    def backend_for(session_id: str = "", create: bool = False):
        """Resolve the backend for a call: the per-session instance
        when session_id is given (optionally creating it), else the
        current backend."""
        if session_id:
            inst = session_backends.get(session_id)
            if inst is None and create:
                inst = make_backend(cfg.bridge_url)
                if inst is not None:
                    session_backends[session_id] = inst
            return inst
        return current["backend"]

    def guard(inst, fn, *args, **kwargs) -> dict:
        if inst is None:
            return no_backend()
        try:
            return fn(*args, **kwargs)
        except DebuggerError as exc:
            return {"ok": False, "configured": True, "error": str(exc)}

    def routed(session_id: str, method: str, *args, **kwargs) -> dict:
        """Call `method` on the backend bound to session_id (or the
        current backend when session_id is empty)."""
        inst = backend_for(session_id)
        if inst is None:
            return no_backend()
        return guard(inst, getattr(inst, method), *args, **kwargs)

    # -- health-check helpers -------------------------------------------------
    def _dir_writable(path) -> bool:
        try:
            return path is not None and Path(path).is_dir() \
                and os.access(path, os.W_OK)
        except OSError:
            return False

    def _bridge_health() -> dict:
        if not cfg.bridge_url:
            return {"configured": False, "url": None, "reachable": None,
                    "health": None}
        try:
            resp = httpx.get(f"{cfg.bridge_url.rstrip('/')}/health",
                             timeout=3.0, trust_env=False)
            health = None
            if resp.status_code == 200:
                try:
                    health = resp.json()
                except ValueError:
                    health = None
            return {"configured": True, "url": cfg.bridge_url,
                    "reachable": resp.status_code == 200,
                    "status_code": resp.status_code, "health": health}
        except Exception as exc:  # noqa: BLE001 - health reports, not raises
            return {"configured": True, "url": cfg.bridge_url,
                    "reachable": False, "health": None,
                    "error": f"{type(exc).__name__}: {exc}"}

    def _tool_count() -> int | None:
        manager = getattr(mcp, "_tool_manager", None)
        tools = getattr(manager, "_tools", None)
        return len(tools) if isinstance(tools, dict) else None

    def run_triage(sample_id: str) -> dict:
        path = store.stored_path(sample_id)
        cache_dir = cfg.artifacts_dir / "triage"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{sample_id}.json"
        if cache_file.is_file():
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                cached = None
            if isinstance(cached, dict):
                return cached
            # A corrupt cache (partial write from a killed triage run)
            # or valid JSON of the wrong shape must not fail the tool:
            # fall through and recompute, overwriting the bad file.
        proc = subprocess.run(
            [sys.executable, str(TRIAGE_SCRIPT), str(path),
             "--json", str(cache_file)],
            capture_output=True, text=True, timeout=600,
            cwd=str(cfg.artifacts_dir))
        if proc.returncode != 0 or not cache_file.is_file():
            raise RuntimeError(
                f"triage.py failed (rc={proc.returncode}): {proc.stderr[-500:]}")
        return json.loads(cache_file.read_text(encoding="utf-8"))

    # -- sample store ---------------------------------------------------------
    @mcp.tool()
    @audit
    def register_sample(source_path: str) -> dict:
        """Register a sample file that already exists on the analysis host.

        The file is copied into the sample store and addressed by its
        SHA-256 from then on. Only metadata is returned -- sample bytes
        never leave the analysis host.
        """
        return {"ok": True, **store.register(source_path)}

    @mcp.tool()
    @audit
    def list_samples() -> dict:
        """List all registered samples (metadata only)."""
        samples = store.list_samples()
        return {"ok": True, "count": len(samples), "samples": samples}

    @mcp.tool()
    @audit
    def get_sample_info(sample_id: str) -> dict:
        """Metadata for one sample (sample_id = SHA-256 hex)."""
        return {"ok": True, **store.get_info(sample_id)}

    @mcp.tool()
    @audit
    def scan_inbox() -> dict:
        """Register every file in the RELAB_INBOX_DIR drop directory.

        New files are copied into the sample store; already-registered
        files and per-file failures are reported separately. Source
        files are never deleted or modified.
        """
        return inbox_mod.scan_inbox(store, cfg.inbox_dir)

    # -- static analysis ------------------------------------------------------
    @mcp.tool()
    @audit
    def static_triage(sample_id: str) -> dict:
        """Full static triage of a registered sample (hashes, file type,
        PE structure, IOCs, suspicious APIs, YARA matches, indicators).

        Purely static: the sample is never executed. Results are cached
        per sample under artifacts/triage/.
        """
        return {"ok": True, "sample_id": sample_id, "triage": run_triage(sample_id)}

    @mcp.tool()
    @audit
    def get_strings_summary(sample_id: str) -> dict:
        """Lightweight view over the triage result: string counts plus the
        extracted IOCs, suspicious API names and triage indicators."""
        triage = run_triage(sample_id)
        return {
            "ok": True,
            "sample_id": sample_id,
            "file_type": triage.get("file_type"),
            "size": triage.get("size"),
            "ascii_string_count": triage.get("strings", {}).get("ascii_count"),
            "utf16_string_count": triage.get("strings", {}).get("utf16_count"),
            "iocs": triage.get("iocs"),
            "suspicious_apis": triage.get("suspicious_apis"),
            "indicators": triage.get("indicators"),
        }

    @mcp.tool()
    @audit
    def capa_analyze(sample_id: str) -> dict:
        """Capability detection with capa (ATT&CK / MBC grouped summary).

        Requires capa on the analysis host (RELAB_CAPA_PATH or PATH);
        returns a structured 'not configured' result otherwise. The
        sample is analysed in place on this host and never executed by
        revlab itself.
        """
        return capa_tools.run_capa(store.stored_path(sample_id),
                                   sample_id=sample_id)

    @mcp.tool()
    @audit
    def ghidra_analyze(sample_id: str) -> dict:
        """Deep static analysis with Ghidra headless: function
        inventory, import mapping, decompiled snippets for functions
        that call suspicious APIs, and string-reference hotspots.

        Requires Ghidra on the analysis host (RELAB_GHIDRA_PATH or
        analyzeHeadless on PATH); returns a structured 'not
        configured' result otherwise. The sample is imported in place
        on this host; the temporary project is deleted afterwards.
        """
        return ghidra_tools.run_ghidra(store.stored_path(sample_id),
                                       sample_id=sample_id)

    # -- debugger (x64dbg bridge) ---------------------------------------------
    @mcp.tool()
    @audit
    def debug_status(session_id: str = "") -> dict:
        """Debugger bridge status. Without session_id: the current
        backend plus every per-session backend. With session_id: the
        backend bound to that analysis session."""
        if default_backend is None and not session_backends:
            return no_backend()
        if session_id:
            inst = session_backends.get(session_id)
            if inst is None:
                return {"ok": True, "configured": True,
                        "session_id": session_id, "active": False,
                        "bridge_session": None, "pid": None,
                        "note": "no debugger backend bound to this "
                                "session yet; debug_launch into it first"}
            return {"ok": True, "configured": True, "session_id": session_id,
                    "backend": inst.name, "active": inst.active,
                    "bridge_session": inst.bridge_session_id, "pid": inst.pid}
        inst = current["backend"]
        return {"ok": True, "configured": True,
                "backend": inst.name if inst else None,
                "bridge_url": cfg.bridge_url,
                "active": inst.active if inst else False,
                "bridge_session": inst.bridge_session_id if inst else None,
                "pid": inst.pid if inst else None,
                "current_session": current["key"] or None,
                "debug_sessions": {
                    key: {"active": b.active,
                          "bridge_session": b.bridge_session_id,
                          "pid": b.pid}
                    for key, b in session_backends.items()}}

    @mcp.tool()
    @audit
    def debug_launch(sample_id: str, arguments: str = "",
                     analysis_session: str = "", session_id: str = "") -> dict:
        """Launch a registered sample under the debugger (starts paused).

        Routing: session_id (or analysis_session) binds the launch to
        that analysis session's own backend instance, so several
        sessions can debug concurrently; without either, the shared
        current backend is used. Pass analysis_session to also link
        the bridge session into the analysis session record.
        """
        key = session_id or analysis_session
        inst = backend_for(key, create=True) if key else default_backend
        if inst is None:
            return no_backend()
        try:
            result = inst.launch(str(store.stored_path(sample_id)), arguments)
        except DebuggerError as exc:
            return {"ok": False, "configured": True, "error": str(exc)}
        current["key"] = key
        current["backend"] = inst
        if analysis_session:
            sessions.attach_debugger(analysis_session, inst.bridge_session_id)
            result["analysis_session"] = analysis_session
        if key:
            result["routed_session"] = key
        return result

    @mcp.tool()
    @audit
    def debug_attach(pid: int, analysis_session: str = "",
                     session_id: str = "") -> dict:
        """Attach the debugger to a running process on the analysis
        host. session_id / analysis_session route like debug_launch."""
        key = session_id or analysis_session
        inst = backend_for(key, create=True) if key else default_backend
        result = guard(inst, inst.attach, pid) if inst else no_backend()
        if result.get("ok"):
            current["key"] = key
            current["backend"] = inst
            if analysis_session:
                sessions.attach_debugger(analysis_session,
                                         inst.bridge_session_id)
                result["analysis_session"] = analysis_session
            if key:
                result["routed_session"] = key
        return result

    @mcp.tool()
    @audit
    def debug_terminate(session_id: str = "") -> dict:
        """Terminate a debug session: the one bound to session_id, or
        the current backend's session when session_id is empty."""
        inst = backend_for(session_id)
        if inst is None:
            return no_backend()
        result = guard(inst, inst.terminate)
        if result.get("ok"):
            # Unbind every routing entry that pointed at this instance
            # (an instance manages at most one live session; once it
            # ends, its session binding is gone too).
            for key in [k for k, b in session_backends.items() if b is inst]:
                session_backends.pop(key)
            if current["backend"] is inst:
                current["key"] = ""
                current["backend"] = default_backend
        return result

    @mcp.tool()
    @audit
    def debug_command(command: str, session_id: str = "") -> dict:
        """Send a raw command to the debugger via the bridge (escape
        hatch). session_id routes to that analysis session's debugger;
        empty routes to the current backend."""
        return routed(session_id, "command", command)

    @mcp.tool()
    @audit
    def debug_set_breakpoint(location: str, session_id: str = "") -> dict:
        """Set a breakpoint at an address ('0x401000') or 'module!symbol'."""
        return routed(session_id, "set_breakpoint", location)

    @mcp.tool()
    @audit
    def debug_list_breakpoints(session_id: str = "") -> dict:
        """List breakpoints in a debug session (current by default)."""
        return routed(session_id, "list_breakpoints")

    @mcp.tool()
    @audit
    def debug_delete_breakpoint(location: str, session_id: str = "") -> dict:
        """Delete a breakpoint by address or 'module!symbol'."""
        return routed(session_id, "delete_breakpoint", location)

    @mcp.tool()
    @audit
    def debug_run(session_id: str = "") -> dict:
        """Resume execution of the debuggee."""
        return routed(session_id, "run")

    @mcp.tool()
    @audit
    def debug_pause(session_id: str = "") -> dict:
        """Pause the debuggee."""
        return routed(session_id, "pause")

    @mcp.tool()
    @audit
    def debug_step_into(session_id: str = "") -> dict:
        """Single-step into the next instruction."""
        return routed(session_id, "step_into")

    @mcp.tool()
    @audit
    def debug_step_over(session_id: str = "") -> dict:
        """Single-step over the next instruction."""
        return routed(session_id, "step_over")

    @mcp.tool()
    @audit
    def debug_registers(session_id: str = "") -> dict:
        """Current register set of the paused debuggee."""
        return routed(session_id, "get_registers")

    @mcp.tool()
    @audit
    def debug_read_memory(address: str, size: int, session_id: str = "") -> dict:
        """Read debuggee memory as hex. Capped at 64 KiB per call by
        design; use dump_memory_region for larger regions."""
        return routed(session_id, "read_memory", address, size)

    @mcp.tool()
    @audit
    def debug_disassemble(address: str, count: int = 16,
                          session_id: str = "") -> dict:
        """Disassemble `count` instructions starting at `address`."""
        return routed(session_id, "disassemble", address, count)

    @mcp.tool()
    @audit
    def debug_callstack(session_id: str = "") -> dict:
        """Current call stack of the debuggee."""
        return routed(session_id, "get_callstack")

    @mcp.tool()
    @audit
    def debug_modules(session_id: str = "") -> dict:
        """Modules loaded in the debuggee."""
        return routed(session_id, "list_modules")

    # -- Frida ------------------------------------------------------------------
    @mcp.tool()
    @audit
    def frida_status() -> dict:
        """Whether Frida is installed on the analysis host, plus live sessions."""
        return frida_mgr.status()

    @mcp.tool()
    @audit
    def frida_spawn(program_path: str, argv: list[str] | None = None,
                    analysis_session: str = "") -> dict:
        """Spawn a program on the analysis host under Frida (suspended)."""
        result = frida_mgr.spawn(program_path, argv)
        if analysis_session and result.get("ok"):
            sessions.attach_frida(analysis_session, result["frida_session"])
        return result

    @mcp.tool()
    @audit
    def frida_spawn_sample(sample_id: str, argv: list[str] | None = None,
                           analysis_session: str = "") -> dict:
        """Spawn a registered sample under Frida (suspended). The sample
        path is resolved inside the store; it is never sent anywhere."""
        return frida_spawn(str(store.stored_path(sample_id)), argv, analysis_session)

    @mcp.tool()
    @audit
    def frida_attach(pid: int, analysis_session: str = "") -> dict:
        """Attach Frida to a running process on the analysis host."""
        result = frida_mgr.attach(pid)
        if analysis_session and result.get("ok"):
            sessions.attach_frida(analysis_session, result["frida_session"])
        return result

    @mcp.tool()
    @audit
    def frida_resume(frida_session: str) -> dict:
        """Resume a process spawned by frida_spawn."""
        return frida_mgr.resume(frida_session)

    @mcp.tool()
    @audit
    def frida_load_script(frida_session: str, source: str,
                          name: str = "script") -> dict:
        """Load an arbitrary Frida JS source string into a session."""
        return frida_mgr.load_script(frida_session, source, name)

    @mcp.tool()
    @audit
    def frida_load_api_monitor(frida_session: str) -> dict:
        """Load the bundled api_monitor.js (WinAPI behaviour hooks)."""
        return frida_mgr.load_bundled_script(frida_session, "api_monitor.js")

    @mcp.tool()
    @audit
    def frida_load_crypto_monitor(frida_session: str) -> dict:
        """Load the bundled crypto_monitor.js (CryptEncrypt /
        CryptDecrypt / BCryptEncrypt with data-length + hex previews)."""
        return frida_mgr.load_bundled_script(frida_session, "crypto_monitor.js")

    @mcp.tool()
    @audit
    def frida_load_process_network(frida_session: str) -> dict:
        """Load the bundled process_network.js (CreateProcess, WinINet /
        WinHTTP requests, DNS queries)."""
        return frida_mgr.load_bundled_script(frida_session,
                                             "process_network.js")

    @mcp.tool()
    @audit
    def frida_get_events(frida_session: str, limit: int = 200,
                         clear: bool = False) -> dict:
        """Read buffered events emitted by scripts in a Frida session."""
        return frida_mgr.get_events(frida_session, limit, clear)

    @mcp.tool()
    @audit
    def frida_events_digest(frida_session: str, recent: int = 10) -> dict:
        """Summarise a Frida session's events: counts grouped by API
        name plus the most recent events. Events are also persisted to
        artifacts/frida/<session>.jsonl as they arrive."""
        return frida_mgr.events_digest(frida_session, recent)

    @mcp.tool()
    @audit
    def frida_stop(frida_session: str) -> dict:
        """Unload scripts and detach a Frida session."""
        return frida_mgr.stop(frida_session)

    # -- unpacking ---------------------------------------------------------------
    @mcp.tool()
    @audit
    def pe_sieve_scan(pid: int) -> dict:
        """Scan a running process with pe-sieve (implants, hollowed /
        injected PEs). Requires RELAB_PESIEVE_PATH on the analysis host;
        returns a structured 'not configured' result otherwise."""
        return unpack_mod.pe_sieve_scan(cfg.pesieve_path, pid, cfg.artifacts_dir)

    @mcp.tool()
    @audit
    def dump_memory_region(address: str, size: int, session_id: str = "") -> dict:
        """Dump debuggee memory to artifacts/dumps/ via the debugger
        backend. Returns metadata (path, size, sha256) -- never bytes.
        session_id routes to that analysis session's debugger."""
        inst = backend_for(session_id)
        if inst is None:
            return no_backend()
        try:
            return unpack_mod.dump_memory_region(inst, address, size,
                                                 cfg.artifacts_dir)
        except DebuggerError as exc:
            return {"ok": False, "configured": True, "error": str(exc)}

    @mcp.tool()
    @audit
    def carve_pe_from_dump(file_path: str) -> dict:
        """Carve embedded PE images out of a file in the artifacts
        directory (e.g. a memory dump). Carved PEs are written to
        artifacts/carved/; only metadata is returned."""
        return unpack_mod.carve_pe_from_file(file_path, cfg.artifacts_dir)

    # -- analysis sessions ---------------------------------------------------------
    @mcp.tool()
    @audit
    def session_create(sample_id: str = "") -> dict:
        """Open an analysis session (optionally bound to a sample) that
        links debugger/Frida sessions and analyst notes."""
        if sample_id:
            store.get_info(sample_id)  # validate
        return {"ok": True, **sessions.create(sample_id or None)}

    @mcp.tool()
    @audit
    def session_list() -> dict:
        """List all analysis sessions."""
        items = sessions.list_sessions()
        return {"ok": True, "count": len(items), "sessions": items}

    @mcp.tool()
    @audit
    def session_get(session_id: str) -> dict:
        """Full record of one analysis session."""
        return {"ok": True, **sessions.get(session_id)}

    @mcp.tool()
    @audit
    def session_note(session_id: str, note: str) -> dict:
        """Append an analyst/agent note to an analysis session."""
        return {"ok": True, **sessions.add_note(session_id, note)}

    @mcp.tool()
    @audit
    def session_close(session_id: str) -> dict:
        """Mark an analysis session closed."""
        return {"ok": True, **sessions.close(session_id)}

    @mcp.tool()
    @audit
    def compose_session_report(session_id: str) -> dict:
        """Compose a Markdown report for an analysis session and write
        it to artifacts/reports/. Combines the sample metadata, static
        triage result, debugger activity (from the audit log), Frida
        events, pe-sieve/dump/carve artifact metadata and analyst
        notes. Returns the report path and summary counts."""
        session = sessions.get(session_id)
        triage, triage_error = None, None
        if session.get("sample_id"):
            try:
                triage = run_triage(session["sample_id"])
            except Exception as exc:  # noqa: BLE001 - report notes the failure
                triage_error = f"{type(exc).__name__}: {exc}"
        frida_events = {}
        for frida_id in session.get("frida_sessions") or []:
            try:
                frida_events[frida_id] = frida_mgr.get_events(frida_id)
            except Exception as exc:  # noqa: BLE001 - e.g. server restarted
                frida_events[frida_id] = {"ok": False, "error": str(exc)}
        result = report_mod.compose_session_report(
            session_id, sessions=sessions, store=store, triage=triage,
            triage_error=triage_error, frida_events=frida_events,
            artifacts_dir=cfg.artifacts_dir, audit_log_path=cfg.audit_log)
        return {"ok": True, **result}

    # -- platform health ---------------------------------------------------------
    @mcp.tool()
    @audit
    def lab_health() -> dict:
        """One-shot platform self-check: configuration summary (bind
        address/port, sample-store and artifacts writability), bridge
        /health reachability, per-integration status for capa / ghidra
        / frida / pe-sieve (available / configured / missing), sample
        and session counts, and the number of registered tools."""
        capa_path = capa_tools.find_capa()
        ghidra_path = ghidra_tools.find_ghidra()
        frida_state = frida_mgr.status()
        sieve = cfg.pesieve_path
        all_sessions = sessions.list_sessions()
        return {
            "ok": True,
            "version": _server_version(),
            "config": {
                "host": cfg.host,
                "port": cfg.port,
                "token_auth": bool(cfg.token),
                "samples_dir": str(cfg.samples_dir),
                "samples_writable": _dir_writable(cfg.samples_dir),
                "artifacts_dir": str(cfg.artifacts_dir),
                "artifacts_writable": _dir_writable(cfg.artifacts_dir),
                "inbox_dir": str(cfg.inbox_dir) if cfg.inbox_dir else None,
                "inbox_configured": cfg.inbox_dir is not None,
            },
            "bridge": _bridge_health(),
            "integrations": {
                "capa": {"status": "available" if capa_path else "missing",
                         "path": capa_path},
                "ghidra": {"status": "available" if ghidra_path else "missing",
                           "path": ghidra_path},
                "frida": {"status": "available" if frida_state["available"]
                          else "missing",
                          "version": frida_state["version"]},
                "pe_sieve": {
                    "status": ("available" if sieve and Path(sieve).is_file()
                               else "configured" if sieve else "missing"),
                    "path": sieve},
            },
            "samples": {"count": len(store.list_samples())},
            "sessions": {
                "total": len(all_sessions),
                "open": sum(1 for s in all_sessions
                            if s.get("status") == "open"),
            },
            "tools": {"count": _tool_count()},
        }

    return mcp


def main() -> None:
    cfg = load_config()
    mcp = build_server(cfg)
    app = mcp.streamable_http_app()
    if cfg.token:
        app = BearerAuthMiddleware(app, cfg.token)
    print(f"revlab-mcp listening on http://{cfg.host}:{cfg.port}/mcp "
          f"(token auth: {'on' if cfg.token else 'OFF - loopback only'}, "
          f"bridge: {cfg.bridge_url or 'not configured'}, "
          f"pe-sieve: {cfg.pesieve_path or 'not configured'})", flush=True)
    import uvicorn
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level="info")


if __name__ == "__main__":
    main()
