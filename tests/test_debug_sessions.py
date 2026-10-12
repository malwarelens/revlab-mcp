"""Multi-debug-session tests: two X64dbgBackend instances against one
mock bridge must not cross-talk (breakpoints, run state, registers).

The mock bridge always supported multiple bridge sessions; these
tests pin the isolation at the client level, which is what the
server's per-analysis-session backend routing relies on.
"""

from __future__ import annotations

import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
            "all_proxy", "ALL_PROXY", "grpc_proxy", "GRPC_PROXY"):
    __import__("os").environ.pop(var, None)

from debugger import X64dbgBackend  # noqa: E402

PORT = 18799  # distinct from the e2e port


def _wait_health(url: str, proc: subprocess.Popen, seconds: float = 15.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"mock bridge exited rc={proc.returncode}")
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    raise RuntimeError("mock bridge did not become healthy")


@pytest.fixture()
def bridge_url():
    proc = subprocess.Popen(
        [sys.executable, str(BASE_DIR / "mock_bridge.py"),
         "--port", str(PORT)],
        cwd=BASE_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{PORT}"
    try:
        _wait_health(url, proc)
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_two_backends_do_not_crosstalk(bridge_url, tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 32)

    backend_a = X64dbgBackend(bridge_url)
    backend_b = X64dbgBackend(bridge_url)
    launched_a = backend_a.launch(str(sample))
    launched_b = backend_b.launch(str(sample))
    # mock /session/start returns its handle as "session_id"
    assert launched_a["session_id"] != launched_b["session_id"]
    assert backend_a.bridge_session_id != backend_b.bridge_session_id
    assert backend_a.active and backend_b.active

    # Breakpoints are per bridge session.
    backend_a.set_breakpoint("0x140001000")
    assert len(backend_a.list_breakpoints()["breakpoints"]) == 1
    assert backend_b.list_breakpoints()["breakpoints"] == []

    # Run state is independent: run/pause/step on A never touches B.
    regs_b_before = backend_b.get_registers()
    backend_a.run()
    backend_a.pause()
    backend_a.step_into()
    regs_a = backend_a.get_registers()
    regs_b = backend_b.get_registers()
    assert regs_a["registers"]["rip"] != regs_b["registers"]["rip"]
    assert regs_b["registers"]["rip"] == regs_b_before["registers"]["rip"]

    # Terminating A leaves B fully usable.
    backend_a.terminate()
    assert backend_a.active is False
    assert backend_b.active is True
    assert backend_b.list_modules()["modules"]
    backend_b.terminate()
    assert backend_b.active is False


def test_second_launch_rejected_per_instance(bridge_url, tmp_path):
    """One backend instance = at most one live debug session (the
    per-session routing invariant on the server side)."""
    from debugger import DebuggerError

    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    backend = X64dbgBackend(bridge_url)
    backend.launch(str(sample))
    with pytest.raises(DebuggerError):
        backend.launch(str(sample))
    backend.terminate()
