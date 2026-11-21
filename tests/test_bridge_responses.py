"""Bridge response-shape tests: the x64dbg bridge is a separate service
on the analysis host, so its HTTP responses are not fully trusted.

A bridge returning a JSON list / string / number (instead of the
documented object) used to crash launch/attach/terminate on .get() /
**-unpacking with AttributeError / TypeError, and a malformed "hex"
field (a number, a list, odd-length or non-hex text) used to crash
read_memory_bytes in bytes.fromhex with TypeError / ValueError. Neither
is a DebuggerError, so the server's guard() did not translate it and
both surfaced as unhandled tool errors. Both are now DebuggerError,
which the server turns into the structured {"ok": False, ...} result.

The same holds for the backend's numeric arguments: read_memory /
disassemble / attach coerced size / count / pid with a bare int(),
so a non-numeric value raised ValueError -- which guard() does not
catch -- instead of the structured error. Those are DebuggerError
now, as is a non-positive disassemble count.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
            "all_proxy", "ALL_PROXY", "grpc_proxy", "GRPC_PROXY"):
    os.environ.pop(var, None)

from debugger import DebuggerError, X64dbgBackend  # noqa: E402


def _backend(handler) -> X64dbgBackend:
    """A backend whose HTTP transport is the given MockTransport handler."""
    backend = X64dbgBackend("http://127.0.0.1:9")
    backend._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://127.0.0.1:9", timeout=60.0, trust_env=False)
    return backend


def _launched(handler) -> X64dbgBackend:
    """A backend that launched once against a well-shaped /session/start."""
    def start(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/session/start":
            return httpx.Response(200, json={"session_id": "s1", "pid": 4242})
        return handler(request)

    backend = _backend(start)
    launched = backend.launch("/tmp/x.exe")
    assert launched["session_id"] == "s1"
    return backend


@pytest.mark.parametrize("body", [b"[1, 2, 3]", b'"ok"', b"42", b"null"])
def test_bridge_non_object_json_is_debugger_error(body):
    """A non-object JSON document from the bridge must not crash the
    client on .get() / **-unpacking: launch raises DebuggerError, and
    a getter on an already-launched session does the same."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    with pytest.raises(DebuggerError):
        _backend(handler).launch("/tmp/x.exe")

    def getter(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    with pytest.raises(DebuggerError):
        _launched(getter).get_registers()


@pytest.mark.parametrize("bad_hex", [123, "zz", "abc", ["00ff"], None])
def test_bridge_malformed_hex_is_debugger_error(bad_hex):
    """A malformed "hex" field in a /memory response must not crash
    bytes.fromhex: read_memory_bytes raises DebuggerError instead."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"hex": bad_hex})

    backend = _launched(handler)
    with pytest.raises(DebuggerError):
        backend.read_memory_bytes("0x140001000", 16)


def test_bridge_well_shaped_responses_still_flow():
    """The shape guards must not break the happy path: a well-shaped
    launch and memory read still work through the same code."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/memory":
            return httpx.Response(
                200, json={"address": "0x140001000", "size": 2,
                           "hex": "00ff"})
        return httpx.Response(200, json={"session_id": "s1", "pid": 4242})

    backend = _backend(handler)
    assert backend.launch("/tmp/x.exe")["session_id"] == "s1"
    assert backend.read_memory_bytes("0x140001000", 2) == b"\x00\xff"


@pytest.mark.parametrize("bad_number", ["abc", "1k", None, [16]])
def test_malformed_numeric_arguments_are_debugger_error(bad_number):
    """Numeric tool arguments are coerced with a bare int() in
    read_memory / disassemble / attach, so a non-numeric value used
    to raise ValueError -- which the server's guard() does not catch
    (only DebuggerError) -- surfacing as an unhandled tool error
    instead of the structured {"ok": False, ...} result. They now
    raise DebuggerError, like parse_address() already does for a
    malformed address; a non-positive disassemble count is rejected
    the same way read_memory already rejects a non-positive size."""
    with pytest.raises(DebuggerError):
        _backend(lambda r: httpx.Response(200, json={})).attach(bad_number)

    with pytest.raises(DebuggerError):
        _backend(lambda r: httpx.Response(200, json={})).read_memory(
            "0x140001000", bad_number)

    backend = _launched(lambda r: httpx.Response(200, json={}))
    with pytest.raises(DebuggerError):
        backend.disassemble("0x140001000", bad_number)
    for bad_count in (0, -4):
        with pytest.raises(DebuggerError):
            backend.disassemble("0x140001000", bad_count)
