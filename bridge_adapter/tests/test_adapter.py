"""Contract-shape tests for every BRIDGE.md endpoint, driven over
real HTTP against the adapter with a fake x64dbg-automate client."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_automate import (  # noqa: E402
    CREATEFILEW_ADDR,
    DEBUGGEE_PID,
    K32_BASE,
    K32_SIZE,
    MAIN_BASE,
    MAIN_SIZE,
    NTDLL_BASE,
    NTDLL_SIZE,
)

SAMPLE = r"C:\samples\sample.exe"


# ---------------------------------------------------------------- health

def test_health(bridge):
    client, _fake = bridge
    resp = client.get("/health")
    assert resp.status == 200
    assert resp.payload["ok"] is True
    assert "x64dbg" in resp.payload["bridge"]


# ------------------------------------------------------- session lifecycle

def test_start_by_path(started):
    _client, _fake, _sid, payload = started
    assert payload["session_id"]
    # pid must be the DEBUGGEE pid (4242), not the debugger pid (7777)
    # that start_session() returns.
    assert payload["pid"] == DEBUGGEE_PID
    assert payload["state"] == "paused"
    mm = payload["main_module"]
    assert mm["base"] == "0x140000000"
    assert mm["size"] == MAIN_SIZE
    assert mm["name"] == "sample.exe"
    assert mm["path"] == SAMPLE


def test_start_by_pid(bridge):
    client, fake = bridge
    resp = client.post("/session/start", {"pid": 4321})
    assert resp.status == 200
    assert resp.payload["pid"] == DEBUGGEE_PID  # fake reports its debuggee


def test_start_requires_path_or_pid(bridge):
    client, _fake = bridge
    resp = client.post("/session/start", {})
    assert resp.status == 400
    assert "error" in resp.payload


def test_second_start_conflicts(started):
    client, _fake, _sid, _payload = started
    resp = client.post("/session/start", {"path": SAMPLE})
    assert resp.status == 409


def test_stop_terminates_and_forgets_session(started):
    client, fake, sid, _payload = started
    resp = client.post("/session/stop", {"session_id": sid})
    assert resp.status == 200
    assert resp.payload == {"ok": True}
    assert fake.terminate_calls == 1
    # The session id is now unknown to every endpoint.
    resp = client.get(f"/registers?session_id={sid}")
    assert resp.status == 404
    # And a fresh session can be started afterwards.
    resp = client.post("/session/start", {"path": SAMPLE})
    assert resp.status == 200


def test_unknown_session_is_404(bridge):
    client, _fake = bridge
    # Session existence is checked before anything else — including on
    # /callstack, which is 501 only for a *valid* session.
    for path in ("/registers", "/modules", "/callstack", "/breakpoints"):
        resp = client.get(f"{path}?session_id=nope")
        assert resp.status == 404, path


# ---------------------------------------------------------------- control

def test_control_run_then_pause(started):
    client, _fake, sid, _ = started
    resp = client.post("/control", {"session_id": sid, "action": "run"})
    assert resp.status == 200
    assert resp.payload["state"] == "running"
    assert resp.payload["cip"].startswith("0x")

    resp = client.post("/control", {"session_id": sid, "action": "pause"})
    assert resp.payload["state"] == "paused"


def test_control_steps_advance_cip(started):
    client, _fake, sid, _ = started
    before = client.get(f"/registers?session_id={sid}").payload["cip"]
    resp = client.post("/control", {"session_id": sid, "action": "step_into"})
    assert resp.payload["state"] == "paused"
    assert resp.payload["cip"] != before
    resp = client.post("/control", {"session_id": sid, "action": "step_over"})
    assert resp.status == 200


def test_control_unknown_action(started):
    client, _fake, sid, _ = started
    resp = client.post("/control", {"session_id": sid, "action": "explode"})
    assert resp.status == 400


# ---------------------------------------------------------------- command

def test_command_output_comes_from_log_diff(started):
    client, _fake, sid, _ = started
    resp = client.post("/cmd", {"session_id": sid, "command": "log hello-revlab"})
    assert resp.status == 200
    assert "hello-revlab" in resp.payload["output"]
    # A second command must not replay the first one's output.
    resp = client.post("/cmd", {"session_id": sid, "command": "log second"})
    assert "hello-revlab" not in resp.payload["output"]
    assert "second" in resp.payload["output"]


def test_command_failure_is_400(started):
    client, _fake, sid, _ = started
    resp = client.post("/cmd", {"session_id": sid, "command": "badcmd"})
    assert resp.status == 400
    assert "badcmd" in resp.payload["error"]


# ------------------------------------------------------------- breakpoints

def test_breakpoint_by_address_roundtrip(started):
    client, _fake, sid, _ = started
    addr = "0x140001000"
    resp = client.post("/breakpoints", {"session_id": sid, "address": addr})
    assert resp.status == 200
    assert resp.payload == {"address": addr, "location": None, "enabled": True}

    resp = client.get(f"/breakpoints?session_id={sid}")
    bps = resp.payload["breakpoints"]
    assert len(bps) == 1
    assert bps[0]["address"] == addr
    assert bps[0]["enabled"] is True

    resp = client.delete("/breakpoints", {"session_id": sid, "address": addr})
    assert resp.payload == {"ok": True}
    resp = client.get(f"/breakpoints?session_id={sid}")
    assert resp.payload["breakpoints"] == []


def test_breakpoint_by_location_resolves_and_echoes(started):
    client, _fake, sid, _ = started
    loc = "kernel32!CreateFileW"  # contract's WinDbg-style example
    resp = client.post("/breakpoints", {"session_id": sid, "location": loc})
    assert resp.status == 200
    # Adapter translates module!Sym -> module:Sym for x64dbg eval and
    # reports the resolved address; the location echoes the request.
    assert resp.payload["address"] == "0x7FFC0E012340"
    assert resp.payload["location"] == loc

    resp = client.get(f"/breakpoints?session_id={sid}")
    bps = resp.payload["breakpoints"]
    assert len(bps) == 1
    assert bps[0]["location"] == loc  # adapter registry round-trips it

    resp = client.delete("/breakpoints", {"session_id": sid, "location": loc})
    assert resp.payload == {"ok": True}
    resp = client.get(f"/breakpoints?session_id={sid}")
    assert resp.payload["breakpoints"] == []


def test_delete_missing_breakpoint_is_404(started):
    client, _fake, sid, _ = started
    resp = client.delete("/breakpoints",
                         {"session_id": sid, "address": "0x140009999"})
    assert resp.status == 404


# -------------------------------------------------------------- inspection

def test_registers_shape(started):
    client, _fake, sid, _ = started
    resp = client.get(f"/registers?session_id={sid}")
    assert resp.status == 200
    regs = resp.payload["registers"]
    assert regs["rip"] == "0x0000000140001000"
    assert regs["rax"] == "0x0000000000001111"
    assert resp.payload["cip"] == regs["rip"]


def test_read_memory(started):
    client, _fake, sid, _ = started
    resp = client.post("/memory", {"session_id": sid,
                                   "address": "0x140000000", "size": 4})
    assert resp.status == 200
    assert resp.payload["hex"] == "4d5a9000"  # MZ header from the fake
    assert resp.payload["size"] == 4


def test_read_memory_unreadable_is_400(started):
    client, _fake, sid, _ = started
    resp = client.post("/memory", {"session_id": sid,
                                   "address": "0xDEAD0000", "size": 16})
    assert resp.status == 400


def test_disasm_includes_bytes_from_memory(started):
    client, _fake, sid, _ = started
    resp = client.post("/disasm", {"session_id": sid,
                                   "address": "0x140001000", "count": 3})
    assert resp.status == 200
    ins = resp.payload["instructions"]
    assert len(ins) == 3
    first = ins[0]
    assert first["address"] == "0x140001000"
    assert first["text"] == "sub rsp, 0x28"
    # bytes come from read_memory(addr, instr_size): 4 bytes of 0x90.
    assert first["bytes"] == "90909090"
    # addresses advance by instruction size
    assert ins[1]["address"] == "0x140001004"


def test_modules_from_memmap_with_event_names(started):
    client, _fake, sid, _ = started
    resp = client.get(f"/modules?session_id={sid}")
    assert resp.status == 200
    mods = {m["base"]: m for m in resp.payload["modules"]}
    # exactly the three image allocations; the private heap page is out
    assert len(mods) == 3
    main = mods["0x140000000"]
    assert main["name"] == "sample.exe"
    assert main["size"] == MAIN_SIZE
    assert main["path"] == SAMPLE
    ntdll = mods["0x7FFC10000000"]
    assert ntdll["name"] == "ntdll.dll"
    assert ntdll["size"] == NTDLL_SIZE
    assert ntdll["path"] == r"C:\Windows\System32\ntdll.dll"
    k32 = mods["0x7FFC0E000000"]
    assert k32["name"] == "kernel32.dll"
    assert k32["size"] == K32_SIZE


def test_callstack_is_explicit_not_implemented(started):
    client, _fake, sid, _ = started
    resp = client.get(f"/callstack?session_id={sid}")
    assert resp.status == 501
    assert "not_implemented" in resp.payload["error"]


# ------------------------------------------------------------ remote mode

def test_remote_mode_lifecycle_uses_load_and_unload(remote_bridge):
    client, fake = remote_bridge
    resp = client.post("/session/start", {"path": SAMPLE})
    assert resp.status == 200
    assert fake.load_calls and fake.load_calls[0][0] == SAMPLE
    assert fake.terminate_calls == 0
    sid = resp.payload["session_id"]

    resp = client.post("/session/stop", {"session_id": sid})
    assert resp.payload == {"ok": True}
    # Remote mode must NOT kill the analyst's x64dbg.
    assert fake.unload_calls == 1
    assert fake.terminate_calls == 0

    # The same connected client serves the next session.
    resp = client.post("/session/start", {"pid": 999})
    assert resp.status == 200
    assert fake.attach_calls == [999]
