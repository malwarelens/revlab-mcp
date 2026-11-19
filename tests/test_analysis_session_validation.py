"""Tests for analysis_session validation in the launch/attach tools.

debug_launch / debug_attach / frida_spawn / frida_attach used to bind
to analysis_session only *after* the side effect: a bogus id raised
ValueError from sessions.attach_debugger / attach_frida once the
debuggee was already launched, so the tool errored (unhandled
ToolError) even though the launch had succeeded -- and the agent lost
the bridge session id while the backend stayed bound under the bogus
key. The tools now validate the session first and return a structured
{"ok": False, ...} without launching anything.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
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
from config import Config  # noqa: E402
from server import build_server  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _call(mcp, name, **kwargs):
    async def _run():
        res = await mcp.call_tool(name, kwargs)
        assert res and res[0].text, f"{name} returned no content"
        return json.loads(res[0].text)

    return asyncio.run(_run())


@pytest.fixture()
def lab(tmp_path):
    """A server with a mock bridge and one registered PE sample."""
    paths = make_samples.build_samples(tmp_path / "inbox")
    port = _free_port()
    bridge = subprocess.Popen(
        [sys.executable, str(ROOT / "mock_bridge.py"), "--port", str(port)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("mock bridge did not come up")
        cfg = Config(samples_dir=tmp_path / "samples",
                     artifacts_dir=tmp_path / "artifacts",
                     bridge_url=url)
        mcp = build_server(cfg)
        meta = _call(mcp, "register_sample", source_path=str(paths["pe"]))
        yield mcp, meta["sample_id"]
    finally:
        bridge.terminate()
        try:
            bridge.wait(timeout=5)
        except subprocess.TimeoutExpired:
            bridge.kill()


def test_debug_launch_unknown_analysis_session_fails_before_launch(lab):
    """A bogus analysis_session used to launch the sample and then
    fail with an unhandled ToolError from attach_debugger, leaving a
    live debuggee bound under the bogus key. Now it fails structured
    and launches nothing."""
    mcp, sample_id = lab
    result = _call(mcp, "debug_launch", sample_id=sample_id,
                   analysis_session="no-such-session")
    assert result["ok"] is False
    assert "unknown analysis session" in result["error"]
    status = _call(mcp, "debug_status")
    assert status["active"] is False
    assert status["debug_sessions"] == {}


def test_debug_attach_unknown_analysis_session_fails_before_attach(lab):
    """Same ordering bug on the attach path: attach first, then the
    ValueError from attach_debugger."""
    mcp, _sample_id = lab
    result = _call(mcp, "debug_attach", pid=4242,
                   analysis_session="no-such-session")
    assert result["ok"] is False
    assert "unknown analysis session" in result["error"]
    status = _call(mcp, "debug_status")
    assert status["active"] is False
    assert status["debug_sessions"] == {}


def test_debug_launch_known_analysis_session_still_links(lab):
    """Happy path unchanged: a real session links the bridge session
    into the analysis session record."""
    mcp, sample_id = lab
    sess = _call(mcp, "session_create", sample_id=sample_id)
    sid = sess["session_id"]
    launched = _call(mcp, "debug_launch", sample_id=sample_id,
                     analysis_session=sid)
    assert launched["ok"] is True
    assert launched["analysis_session"] == sid
    got = _call(mcp, "session_get", session_id=sid)
    assert got["debugger_bridge_session"] == launched["session_id"]
    assert _call(mcp, "debug_terminate")["ok"] is True


@pytest.mark.parametrize("tool,kwargs", [
    ("frida_spawn", {"program_path": "C:\\x.exe"}),
    ("frida_attach", {"pid": 4242}),
])
def test_frida_tools_unknown_analysis_session_fail_first(lab, tool, kwargs):
    """The frida launch/attach tools validate the session before
    touching Frida, so a bogus id reports the bad session instead of
    (with frida installed) spawning and then failing to link it."""
    mcp, _sample_id = lab
    result = _call(mcp, tool, analysis_session="no-such-session", **kwargs)
    assert result["ok"] is False
    assert "unknown analysis session" in result["error"]
