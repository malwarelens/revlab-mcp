"""x64dbg backend: speaks the HTTP bridge contract in docs/BRIDGE.md.

The bridge is a small service living next to x64dbg on the analysis host
(recommended implementation: an x64dbg-automate style plugin). This
client only needs its base URL (RELAB_X64DBG_BRIDGE_URL).
"""

from __future__ import annotations

import httpx

from .base import (MAX_READ_MEMORY, DebuggerBackend, DebuggerError,
                   fmt_address, parse_address)


def _as_int(value, what: str) -> int:
    """Coerce a numeric tool argument, raising DebuggerError (not
    ValueError) on a non-numeric value, so the server's guard() turns
    it into the structured {"ok": False, ...} result -- the same
    contract parse_address() already keeps for addresses. A bare
    int() here used to surface as an unhandled tool error."""
    try:
        return int(value)
    except (TypeError, ValueError):
        raise DebuggerError(f"invalid {what}: {value!r}") from None


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
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise DebuggerError(f"bridge {method} {path} returned non-JSON") from exc
        # Every caller assumes an object: launch/attach/terminate call
        # .get() and **-unpack it, and the server indexes the result
        # (result["analysis_session"], result.get("ok")). A bridge
        # returning a JSON list / string / number used to crash those
        # call sites with AttributeError / TypeError, surfacing as an
        # unhandled tool error instead of the structured DebuggerError
        # the guard() wrapper turns into {"ok": False, ...}.
        if not isinstance(data, dict):
            raise DebuggerError(
                f"bridge {method} {path} returned non-object JSON "
                f"({type(data).__name__}); expected a JSON object")
        return data

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
        pid = _as_int(pid, "pid")
        data = self._request("POST", "/session/start", json={"pid": pid})
        self.bridge_session_id = data.get("session_id")
        self.pid = data.get("pid", pid)
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
        size = _as_int(size, "size")
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
        hex_text = data.get("hex", "")
        # The bridge's "hex" field is the only thing between a memory
        # dump and the file on disk: a non-string value (a number, a
        # list, ...) or malformed hex (odd length, non-hex chars) used
        # to crash bytes.fromhex with TypeError / ValueError, which
        # dump_memory_region does not catch (it only translates
        # DebuggerError), surfacing as an unhandled tool error.
        if not isinstance(hex_text, str):
            raise DebuggerError(
                "bridge returned a non-string 'hex' field for the memory "
                f"read ({type(hex_text).__name__}); expected hex text")
        try:
            return bytes.fromhex(hex_text)
        except ValueError as exc:
            raise DebuggerError(
                f"bridge returned malformed hex for the memory read: {exc}"
            ) from exc

    def disassemble(self, address, count: int = 16) -> dict:
        count = _as_int(count, "count")
        if count <= 0:
            raise DebuggerError("count must be positive")
        return self._request("POST", "/disasm", json={
            "session_id": self._session(),
            "address": fmt_address(parse_address(address)),
            "count": count,
        })

    def get_callstack(self) -> dict:
        return self._request("GET", "/callstack",
                             params={"session_id": self._session()})

    def list_modules(self) -> dict:
        return self._request("GET", "/modules",
                             params={"session_id": self._session()})
