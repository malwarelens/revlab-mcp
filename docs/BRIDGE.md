# x64dbg Bridge Contract

revlab-mcp never talks to x64dbg directly. On the analysis host, a small
**bridge service** sits next to x64dbg and exposes the debugger over
plain HTTP/JSON. `debugger/x64dbg.py` is the client of this contract;
`mock_bridge.py` in the repo root is a reference implementation with
canned data (used by the test-suite on non-Windows machines).

* Base URL: configured with `RELAB_X64DBG_BRIDGE_URL`, e.g.
  `http://127.0.0.1:27042`. The bridge should listen on loopback only;
  the MCP server is the only intended client.
* All request/response bodies are JSON. Addresses are hex strings
  (`"0x140001000"`). Errors: HTTP 4xx/5xx with `{"error": "..."}`.
* One bridge session == one debuggee.

## Recommended implementation

Anything that speaks this contract works. The natural way to build the
real bridge is an **x64dbg plugin in the style of
[x64dbg-automate](https://github.com/mrexodia/x64dbg-automate)**
(or a small C++/Python plugin using the x64dbg SDK bridgemain API)
that maps the endpoints below onto x64dbg commands and the
`DbgValFromString` / `DbgMemRead` / `DbgDisasmAt` / stack-walk APIs.
Keep the plugin dumb: all policy (caps, auditing, sample handling)
lives in the MCP server.

## Endpoints

### `GET /health`
→ `{"ok": true, "bridge": "<name/version>"}`

### `POST /session/start`
Start a debug session. Launch:
```json
{"path": "C:\\revlab\\samples\\store\\<sha256>", "arguments": "", "cwd": "..."}
```
or attach: `{"pid": 4242}`

→
```json
{"session_id": "opaque-string", "pid": 4242, "state": "paused",
 "main_module": {"name": "sample.exe", "base": "0x140000000",
                 "size": 24576, "path": "..."}}
```

### `POST /session/stop`
`{"session_id": "..."}` → `{"ok": true}` — terminates the debuggee.

### `POST /control`
`{"session_id": "...", "action": "run" | "pause" | "step_into" | "step_over"}`
→ `{"state": "running" | "paused", "cip": "0x140001000"}`

### `POST /cmd`
Raw x64dbg command passthrough (escape hatch).
`{"session_id": "...", "command": "bp kernel32!CreateFileW"}`
→ `{"output": "..."}`

### `POST /breakpoints`
Set a breakpoint. Either by address:
`{"session_id": "...", "address": "0x140001000"}`
or by symbol: `{"session_id": "...", "location": "kernel32!CreateFileW"}`
→ `{"address": "0x...", "location": null, "enabled": true}`

### `GET /breakpoints?session_id=...`
→ `{"breakpoints": [{"address": "0x...", "location": null, "enabled": true}]}`

### `DELETE /breakpoints`
JSON body like POST. → `{"ok": true}`

### `GET /registers?session_id=...`
→ `{"registers": {"rax": "0x0", "rbx": "0x0", "...": "...", "rip": "0x140001000"},
    "cip": "0x140001000"}`

### `POST /memory`
`{"session_id": "...", "address": "0x140000000", "size": 256}`
→ `{"address": "0x140000000", "size": 256, "hex": "4d5a9000..."}`
The MCP server caps `size` at 65536 per call; the bridge may cap lower.

### `POST /disasm`
`{"session_id": "...", "address": "0x140001000", "count": 16}`
→ `{"instructions": [{"address": "0x140001000", "bytes": "4883ec28",
                      "text": "sub rsp, 0x28"}, ...]}`

### `GET /callstack?session_id=...`
→ `{"frames": [{"index": 0, "address": "0x...", "module": "sample.exe",
                 "symbol": "entry_point"}, ...]}`

### `GET /modules?session_id=...`
→ `{"modules": [{"name": "sample.exe", "base": "0x140000000",
                  "size": 24576, "path": "C:\\..."}, ...]}`
