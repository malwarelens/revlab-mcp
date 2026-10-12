"""End-to-end test: mock bridge + real MCP server + real MCP client.

Run:  .venv/bin/pytest tests/test_e2e.py -s
Everything runs on loopback with throwaway directories under tmp_path.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

# This dev sandbox exports proxy variables (with bracketed IPv6 no_proxy
# entries) that crash httpx's env parsing. Everything in this test is
# loopback, so drop them for the test process and its children.
for _var in ("http_proxy", "https_proxy", "all_proxy",
             "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
             "no_proxy", "NO_PROXY"):
    os.environ.pop(_var, None)
os.environ["NO_PROXY"] = "127.0.0.1,localhost"

import make_samples  # noqa: E402

TOKEN = "e2e-test-token"
EXPECTED_TOOLS = {
    "register_sample", "list_samples", "get_sample_info",
    "static_triage", "get_strings_summary",
    "debug_status", "debug_launch", "debug_attach", "debug_terminate",
    "debug_command", "debug_set_breakpoint", "debug_list_breakpoints",
    "debug_delete_breakpoint", "debug_run", "debug_pause",
    "debug_step_into", "debug_step_over", "debug_registers",
    "debug_read_memory", "debug_disassemble", "debug_callstack",
    "debug_modules",
    "frida_status", "frida_spawn", "frida_spawn_sample", "frida_attach",
    "frida_resume", "frida_load_script", "frida_load_api_monitor",
    "frida_get_events", "frida_stop",
    "pe_sieve_scan", "dump_memory_region", "carve_pe_from_dump",
    "session_create", "session_list", "session_get", "session_note",
    "session_close",
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float = 40.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError(f"port {port} never came up")


def _result(res) -> dict:
    assert not res.isError, f"tool call errored: {res.content}"
    sc = res.structuredContent
    if isinstance(sc, dict):
        if set(sc.keys()) == {"result"} and isinstance(sc["result"], dict):
            return sc["result"]
        return sc
    return json.loads(res.content[0].text)


async def _exercise(base_url: str, pe_path: Path, artifacts: Path) -> None:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with streamablehttp_client(base_url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            missing = EXPECTED_TOOLS - names
            assert not missing, f"missing tools: {missing}"

            async def call(name, **kwargs):
                return _result(await session.call_tool(name, kwargs))

            # -- samples + static analysis --------------------------------
            meta = await call("register_sample", source_path=str(pe_path))
            sample_id = meta["sample_id"]
            assert sample_id == hashlib.sha256(pe_path.read_bytes()).hexdigest()

            listing = await call("list_samples")
            assert listing["count"] == 1

            triage = await call("static_triage", sample_id=sample_id)
            assert triage["triage"]["hashes"]["sha256"] == sample_id
            assert "185.220.101.4" in triage["triage"]["iocs"]["ipv4"]

            summary = await call("get_strings_summary", sample_id=sample_id)
            assert summary["ascii_string_count"] > 0

            # -- analysis session ------------------------------------------
            sess = await call("session_create", sample_id=sample_id)
            sid = sess["session_id"]

            # -- debugger full flow over the mock bridge -------------------
            launched = await call("debug_launch", sample_id=sample_id,
                                  analysis_session=sid)
            assert launched["ok"] and launched["pid"] == 4242

            bp = await call("debug_set_breakpoint", location="0x140001000")
            assert bp["address"] == "0x140001000"
            bps = await call("debug_list_breakpoints")
            assert len(bps["breakpoints"]) == 1

            assert (await call("debug_run"))["state"] == "running"
            assert (await call("debug_pause"))["state"] == "paused"
            await call("debug_step_into")
            await call("debug_step_over")

            regs = await call("debug_registers")
            assert "rip" in regs["registers"]

            mem = await call("debug_read_memory", address="0x140000000", size=64)
            assert mem["hex"].startswith("4d5a") and len(mem["hex"]) == 128

            too_big = await call("debug_read_memory", address="0x140000000",
                                 size=70000)
            assert too_big["ok"] is False and "capped" in too_big["error"]

            dis = await call("debug_disassemble", address="0x140001000", count=4)
            assert len(dis["instructions"]) == 4

            stack = await call("debug_callstack")
            assert len(stack["frames"]) == 3
            mods = await call("debug_modules")
            assert any(m["name"] == "sample.exe" for m in mods["modules"])

            # -- unpacking helpers ------------------------------------------
            dump = await call("dump_memory_region", address="0x140000000",
                              size=4096)
            assert dump["written_size"] == 4096
            assert Path(dump["path"]).is_file()

            planted = artifacts / "planted_dump.bin"
            planted.write_bytes(b"\x00" * 16 + pe_path.read_bytes())
            carved = await call("carve_pe_from_dump", file_path=str(planted))
            assert carved["carved_count"] == 1

            pesieve = await call("pe_sieve_scan", pid=4242)
            assert pesieve["configured"] is False

            # -- frida degradation (frida not installed in this venv) -------
            status = await call("frida_status")
            assert status["available"] is False
            frida_try = await call("frida_attach", pid=4242)
            assert frida_try["ok"] is False and frida_try["configured"] is False

            # -- wrap up ------------------------------------------------------
            await call("session_note", session_id=sid, note="e2e was here")
            got = await call("session_get", session_id=sid)
            assert got["debugger_bridge_session"] == "mock-session-1"
            assert got["notes"][0]["note"] == "e2e was here"

            await call("debug_delete_breakpoint", location="0x140001000")
            assert (await call("debug_terminate"))["ok"]
            assert (await call("debug_status"))["active"] is False
            closed = await call("session_close", session_id=sid)
            assert closed["status"] == "closed"


def test_end_to_end(tmp_path):
    samples_dir = tmp_path / "samples"
    artifacts = tmp_path / "artifacts"
    paths = make_samples.build_samples(tmp_path / "inbox")
    bridge_port, server_port = _free_port(), _free_port()

    bridge = subprocess.Popen(
        [sys.executable, str(ROOT / "mock_bridge.py"), "--port", str(bridge_port)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env = dict(os.environ,
               RELAB_HOST="127.0.0.1", RELAB_PORT=str(server_port),
               RELAB_TOKEN=TOKEN,
               RELAB_SAMPLES_DIR=str(samples_dir),
               RELAB_ARTIFACTS_DIR=str(artifacts),
               RELAB_X64DBG_BRIDGE_URL=f"http://127.0.0.1:{bridge_port}",
               PYTHONUNBUFFERED="1")
    server_log = open(tmp_path / "server.log", "wb")
    server = subprocess.Popen(
        [sys.executable, str(ROOT / "server.py")], cwd=ROOT, env=env,
        stdout=server_log, stderr=subprocess.STDOUT)
    try:
        _wait_port(bridge_port)
        _wait_port(server_port)

        # unauthenticated requests are refused before reaching MCP
        resp = httpx.post(f"http://127.0.0.1:{server_port}/mcp",
                          json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                          timeout=5)
        assert resp.status_code == 401, resp.text

        asyncio.run(_exercise(f"http://127.0.0.1:{server_port}/mcp",
                              paths["pe"], artifacts))

        audit_file = artifacts / "audit.jsonl"
        assert audit_file.is_file()
        logged_tools = {json.loads(line)["tool"]
                        for line in audit_file.read_text().splitlines()}
        assert {"static_triage", "debug_launch", "register_sample"} <= logged_tools
    finally:
        server.terminate()
        bridge.terminate()
        server.wait(timeout=10)
        bridge.wait(timeout=10)
        server_log.close()
