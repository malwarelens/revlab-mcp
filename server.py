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
import subprocess
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

import unpack as unpack_mod
from audit import AuditLog, audited
from config import Config, load_config
from debugger import DebuggerError, make_backend
from frida_tools import FridaManager
from samples import SampleStore
from sessions import SessionManager

BASE_DIR = Path(__file__).resolve().parent
TRIAGE_SCRIPT = BASE_DIR / "vendor" / "triage.py"


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
    frida_mgr = FridaManager()
    backend = make_backend(cfg.bridge_url)

    mcp = FastMCP("revlab-mcp", host=cfg.host, port=cfg.port,
                  instructions=(
                      "Malware reverse-engineering lab server. Samples stay on "
                      "this host: register them with register_sample, analyse "
                      "with static_triage, debug via the debug_* tools (x64dbg "
                      "bridge), instrument with frida_* tools, and unpack with "
                      "pe_sieve_scan / dump_memory_region / carve_pe_from_dump. "
                      "No tool returns sample bytes."))

    # -- helpers ------------------------------------------------------------
    def no_backend() -> dict:
        return {"ok": False, "configured": False,
                "error": "no debugger bridge configured; set "
                         "RELAB_X64DBG_BRIDGE_URL on the analysis host"}

    def guard(fn, *args, **kwargs) -> dict:
        if backend is None:
            return no_backend()
        try:
            return fn(*args, **kwargs)
        except DebuggerError as exc:
            return {"ok": False, "configured": True, "error": str(exc)}

    def run_triage(sample_id: str) -> dict:
        path = store.stored_path(sample_id)
        cache_dir = cfg.artifacts_dir / "triage"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{sample_id}.json"
        if cache_file.is_file():
            return json.loads(cache_file.read_text(encoding="utf-8"))
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

    # -- debugger (x64dbg bridge) ---------------------------------------------
    @mcp.tool()
    @audit
    def debug_status() -> dict:
        """Whether a debugger bridge is configured and a session is live."""
        if backend is None:
            return no_backend()
        return {"ok": True, "configured": True, "backend": backend.name,
                "bridge_url": cfg.bridge_url, "active": backend.active,
                "bridge_session": backend.bridge_session_id, "pid": backend.pid}

    @mcp.tool()
    @audit
    def debug_launch(sample_id: str, arguments: str = "",
                     analysis_session: str = "") -> dict:
        """Launch a registered sample under the debugger (starts paused).

        Pass analysis_session (from session_create) to link the debug
        session into an analysis session.
        """
        if backend is None:
            return no_backend()
        try:
            result = backend.launch(str(store.stored_path(sample_id)), arguments)
        except DebuggerError as exc:
            return {"ok": False, "configured": True, "error": str(exc)}
        if analysis_session:
            sessions.attach_debugger(analysis_session, backend.bridge_session_id)
            result["analysis_session"] = analysis_session
        return result

    @mcp.tool()
    @audit
    def debug_attach(pid: int, analysis_session: str = "") -> dict:
        """Attach the debugger to a running process on the analysis host."""
        result = guard(backend.attach, pid) if backend else no_backend()
        if analysis_session and result.get("ok"):
            sessions.attach_debugger(analysis_session, backend.bridge_session_id)
            result["analysis_session"] = analysis_session
        return result

    @mcp.tool()
    @audit
    def debug_terminate() -> dict:
        """Terminate the current debug session."""
        return guard(backend.terminate) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_command(command: str) -> dict:
        """Send a raw command to the debugger via the bridge (escape hatch)."""
        return guard(backend.command, command) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_set_breakpoint(location: str) -> dict:
        """Set a breakpoint at an address ('0x401000') or 'module!symbol'."""
        return guard(backend.set_breakpoint, location) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_list_breakpoints() -> dict:
        """List breakpoints in the current debug session."""
        return guard(backend.list_breakpoints) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_delete_breakpoint(location: str) -> dict:
        """Delete a breakpoint by address or 'module!symbol'."""
        return guard(backend.delete_breakpoint, location) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_run() -> dict:
        """Resume execution of the debuggee."""
        return guard(backend.run) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_pause() -> dict:
        """Pause the debuggee."""
        return guard(backend.pause) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_step_into() -> dict:
        """Single-step into the next instruction."""
        return guard(backend.step_into) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_step_over() -> dict:
        """Single-step over the next instruction."""
        return guard(backend.step_over) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_registers() -> dict:
        """Current register set of the paused debuggee."""
        return guard(backend.get_registers) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_read_memory(address: str, size: int) -> dict:
        """Read debuggee memory as hex. Capped at 64 KiB per call by
        design; use dump_memory_region for larger regions."""
        return guard(backend.read_memory, address, size) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_disassemble(address: str, count: int = 16) -> dict:
        """Disassemble `count` instructions starting at `address`."""
        return guard(backend.disassemble, address, count) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_callstack() -> dict:
        """Current call stack of the debuggee."""
        return guard(backend.get_callstack) if backend else no_backend()

    @mcp.tool()
    @audit
    def debug_modules() -> dict:
        """Modules loaded in the debuggee."""
        return guard(backend.list_modules) if backend else no_backend()

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
    def frida_get_events(frida_session: str, limit: int = 200,
                         clear: bool = False) -> dict:
        """Read buffered events emitted by scripts in a Frida session."""
        return frida_mgr.get_events(frida_session, limit, clear)

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
    def dump_memory_region(address: str, size: int) -> dict:
        """Dump debuggee memory to artifacts/dumps/ via the debugger
        backend. Returns metadata (path, size, sha256) -- never bytes."""
        if backend is None:
            return no_backend()
        try:
            return unpack_mod.dump_memory_region(backend, address, size,
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
