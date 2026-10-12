"""x64dbg backend: speaks the HTTP bridge contract in docs/BRIDGE.md.

The bridge is a small service living next to x64dbg on the analysis host
(recommended implementation: an x64dbg-automate style plugin). This
client only needs its base URL (RELAB_X64DBG_BRIDGE_URL).
"""

from __future__ import annotations

import httpx

from .base import (MAX_READ_MEMORY, DebuggerBackend, DebuggerError,
                   fmt_address, parse_address)


class X64dbgBackend(DebuggerBackend):
    name = "x64dbg"

    def __init__(self, bridge_url: str, timeout: float = 60.0):
        super().__init__()
        self.bridge_url = bridge_url.rstrip("/")
        # trust_env=False: the bridge is a local/LAN service; ambient
        # proxy environment variables must never reroute or break it.
        self._client = httpx.Client(base_url=self.bridge_url, timeout=timeout,
                                    trust_env=False)

    # -- transport --------------------------------------------------------
    def _request(self, method: str, path: str, **kwargs) -> dict:
        try:
            resp = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise DebuggerError(f"bridge unreachable at {self.bridge_url}: {exc}") from exc
        if resp.status_code >= 400:
            detail = ""
            try:
                detail = resp.json().get("error", "")
            except Exception:  # noqa: BLE001
                detail = resp.text[:200]
            raise DebuggerError(f"bridge {method} {path} -> HTTP {resp.status_code}: {detail}")
        try:
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise DebuggerError(f"bridge {method} {path} returned non-JSON") from exc

    def _session(self) -> str:
        if not self.bridge_session_id:
            raise DebuggerError("no active debug session; call debug_launch or debug_attach first")
        return self.bridge_session_id

    # -- session ----------------------------------------------------------
    def _require_idle(self, action: str) -> None:
        # Invariant (see base.py): one backend instance manages at most
        # one live debug session. Re-launching would silently orphan
        # the previous bridge session, so refuse instead.
        if self.active:
            raise DebuggerError(
                f"this backend already has an active session "
                f"({self.bridge_session_id}); terminate it before {action}")

    def launch(self, sample_path: str, arguments: str = "") -> dict:
        self._require_idle("launching again")
        data = self._request("POST", "/session/start",
                             json={"path": sample_path, "arguments": arguments})
        self.bridge_session_id = data.get("session_id")
        self.pid = data.get("pid")
        return {"ok": True, "backend": self.name, **data}

    def attach(self, pid: int) -> dict:
        self._require_idle("attaching again")
        data = self._request("POST", "/session/start", json={"pid": int(pid)})
        self.bridge_session_id = data.get("session_id")
        self.pid = data.get("pid", int(pid))
        return {"ok": True, "backend": self.name, **data}

    def terminate(self) -> dict:
        sid = self._session()
        data = self._request("POST", "/session/stop", json={"session_id": sid})
        self.bridge_session_id = None
        self.pid = None
        return {"ok": True, **data}

    # -- raw command ------------------------------------------------------
    def command(self, command: str) -> dict:
        return self._request("POST", "/cmd",
                             json={"session_id": self._session(), "command": command})

    # -- breakpoints ------------------------------------------------------
    def set_breakpoint(self, location: str) -> dict:
        payload = {"session_id": self._session()}
        if "!" in location:  # module!symbol form
            payload["location"] = location
        else:
            payload["address"] = fmt_address(parse_address(location))
        return self._request("POST", "/breakpoints", json=payload)

    def list_breakpoints(self) -> dict:
        return self._request("GET", "/breakpoints",
                             params={"session_id": self._session()})

    def delete_breakpoint(self, location: str) -> dict:
        payload = {"session_id": self._session()}
        if "!" in location:
            payload["location"] = location
        else:
            payload["address"] = fmt_address(parse_address(location))
        return self._request("DELETE", "/breakpoints", json=payload)

    # -- execution control --------------------------------------------------
    def _control(self, action: str) -> dict:
        return self._request("POST", "/control",
                             json={"session_id": self._session(), "action": action})

    def run(self) -> dict:
        return self._control("run")

    def pause(self) -> dict:
        return self._control("pause")

    def step_into(self) -> dict:
        return self._control("step_into")

    def step_over(self) -> dict:
        return self._control("step_over")

    # -- state inspection ---------------------------------------------------
    def get_registers(self) -> dict:
        return self._request("GET", "/registers",
                             params={"session_id": self._session()})

    def read_memory(self, address, size: int) -> dict:
        size = int(size)
        if size <= 0:
            raise DebuggerError("size must be positive")
        if size > MAX_READ_MEMORY:
            raise DebuggerError(
                f"read_memory is capped at {MAX_READ_MEMORY} bytes per call "
                f"(requested {size}); read in chunks or use dump_memory_region")
        data = self._request("POST", "/memory", json={
            "session_id": self._session(),
            "address": fmt_address(parse_address(address)),
            "size": size,
        })
        return data

    def read_memory_bytes(self, address, size: int) -> bytes:
        data = self.read_memory(address, size)
        return bytes.fromhex(data.get("hex", ""))

    def disassemble(self, address, count: int = 16) -> dict:
        return self._request("POST", "/disasm", json={
            "session_id": self._session(),
            "address": fmt_address(parse_address(address)),
            "count": int(count),
        })

    def get_callstack(self) -> dict:
        return self._request("GET", "/callstack",
                             params={"session_id": self._session()})

    def list_modules(self) -> dict:
        return self._request("GET", "/modules",
                             params={"session_id": self._session()})
