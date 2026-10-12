# revlab-mcp

A LAN malware reverse-engineering platform exposed as an **MCP server**.
The server runs on a (Windows) analysis host inside an isolated lab
network; an AI agent on the operator's workstation connects over
**Streamable HTTP + Bearer token** and drives static analysis, live
debugging (via x64dbg), Frida instrumentation and basic unpacking —
while **samples never leave the analysis host**.

```
 operator workstation                     analysis host (isolated VLAN)
+------------------+   LAN, HTTP + Bearer  +-------------------------------+
|                  | --------------------> |  revlab-mcp (this server)     |
|   AI agent /     |   MCP tools, JSON     |   |- sample store (SHA-256)   |
|   MCP client     | <-------------------- |   |- static triage (vendor/)  |
|                  |   results only --     |   |- debugger client ------+  |
+------------------+   never sample bytes  |   |- Frida manager         |  |
                                           |   |- pe-sieve / carving    |  |
                                           +---|----------|---------------|  |
                                               |          | bridge HTTP    |
                                            samples/   artifacts/          |
                                                          v                |
                                                   +-------------+         |
                                                   | bridge svc  |---------+
                                                   |  + x64dbg   |
                                                   +-------------+
```

## Security model

* **Samples are host-bound.** A sample is registered from a local path
  *on the analysis host*, copied into the store and addressed by its
  SHA-256. **No tool returns sample bytes or offers a download.** Tool
  results are metadata, text and JSON analysis data only.
* **Memory reads are the single deliberate exception**: debugging is
  impossible without them, so `debug_read_memory` returns hex, hard
  capped at **64 KiB per call**. Bulk extraction goes through
  `dump_memory_region`, which writes dumps to `artifacts/` on the host
  and returns only metadata (path, size, SHA-256).
* **Token auth is mandatory off-loopback.** If `RELAB_HOST` is not a
  loopback address and `RELAB_TOKEN` is unset, the server refuses to
  start. Every request must carry `Authorization: Bearer <token>`.
* **Audit log.** Every tool call appends a JSONL record (timestamp,
  tool, argument summary, status, duration) to `artifacts/audit.jsonl`.
  Result payloads are never logged, so the log is not a side channel.
* **Lab hygiene (your responsibility):** run the analysis host with no
  internet route (host-only / isolated VLAN), snapshot it, and treat
  every debuggee as hostile. The server binds one interface; keep the
  Windows Firewall rule scoped to the operator workstation's IP.

## Quick start (development, loopback)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python mock_bridge.py --port 27042 &          # fake debugger
RELAB_X64DBG_BRIDGE_URL=http://127.0.0.1:27042 \
  .venv/bin/python server.py                            # http://127.0.0.1:8765/mcp
.venv/bin/pytest tests/                                 # unit + end-to-end
```

## Deployment on the Windows analysis host

1. Install Python 3.11+ and copy this project to e.g. `C:\revlab\revlab-mcp`.
2. Create the environment and install dependencies (PowerShell):

   ```powershell
   cd C:\revlab\revlab-mcp
   py -m venv .venv
   .\.venv\Scripts\pip install -r requirements.txt
   .\.venv\Scripts\pip install frida frida-tools yara-python   # optional but recommended
   ```

3. Install the debugger bridge next to x64dbg. The bridge is any small
   service implementing **[docs/BRIDGE.md](docs/BRIDGE.md)** — the
   recommended route is an x64dbg plugin in the style of
   *x64dbg-automate*. For a smoke test without x64dbg, run
   `mock_bridge.py` instead (canned data, no real debugging).
4. (Optional) Download [pe-sieve](https://github.com/hasherezade/pe-sieve)
   and note its path for `RELAB_PESIEVE_PATH`.
5. Create a samples drop folder and an artifacts folder, then set the
   environment and start the server:

   ```powershell
   $env:RELAB_HOST = "192.168.56.10"          # analysis host's LAN IP
   $env:RELAB_PORT = "8765"
   $env:RELAB_TOKEN = "<long random token>"
   $env:RELAB_SAMPLES_DIR = "C:\revlab\samples"
   $env:RELAB_ARTIFACTS_DIR = "C:\revlab\artifacts"
   $env:RELAB_X64DBG_BRIDGE_URL = "http://127.0.0.1:27042"
   $env:RELAB_PESIEVE_PATH = "C:\tools\pe-sieve64.exe"
   .\.venv\Scripts\python server.py
   ```

6. Allow inbound TCP 8765 in Windows Firewall **from the workstation
   IP only**, on the Private profile.
7. Point the agent's MCP client at it, e.g.:

   ```json
   { "mcpServers": { "revlab": {
       "type": "streamable-http",
       "url": "http://192.168.56.10:8765/mcp",
       "headers": { "Authorization": "Bearer <long random token>" } } } }
   ```

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `RELAB_HOST` | `127.0.0.1` | Bind address. Non-loopback **requires** `RELAB_TOKEN`. |
| `RELAB_PORT` | `8765` | Bind port. |
| `RELAB_TOKEN` | — | Bearer token for agent authentication. |
| `RELAB_SAMPLES_DIR` | `./samples` | Sample store (content-addressed by SHA-256) + `index.json`. |
| `RELAB_ARTIFACTS_DIR` | `./artifacts` | Triage cache, dumps, carved PEs, pe-sieve output, sessions, audit log. |
| `RELAB_X64DBG_BRIDGE_URL` | — | Base URL of the x64dbg bridge (docs/BRIDGE.md). Unset → debugger tools report "not configured". |
| `RELAB_PESIEVE_PATH` | — | Path to pe-sieve executable. Unset → `pe_sieve_scan` reports "not configured". |
| `RELAB_AUDIT_LOG` | `<artifacts>/audit.jsonl` | Audit log location. |

## Tools (38)

**Samples** — `register_sample` (from a host-local path; metadata only),
`list_samples`, `get_sample_info`.

**Static analysis** — `static_triage` (hashes, file type, PE structure,
IOCs, suspicious APIs, YARA, indicators; the sample is read, never
executed), `get_strings_summary`.

**Debugging (x64dbg bridge)** — `debug_status`, `debug_launch`,
`debug_attach`, `debug_terminate`, `debug_command` (raw passthrough),
`debug_set_breakpoint` / `debug_list_breakpoints` /
`debug_delete_breakpoint`, `debug_run`, `debug_pause`,
`debug_step_into`, `debug_step_over`, `debug_registers`,
`debug_read_memory` (hex, ≤ 64 KiB), `debug_disassemble`,
`debug_callstack`, `debug_modules`.

**Frida** — `frida_status`, `frida_spawn`, `frida_spawn_sample`,
`frida_attach`, `frida_resume`, `frida_load_script`,
`frida_load_api_monitor` (bundled `frida_scripts/api_monitor.js`:
CreateFile/registry/injection/network/crypto hooks),
`frida_get_events`, `frida_stop`. If Frida is not installed on the
host, these return a structured "not available" result.

**Unpacking** — `pe_sieve_scan` (process scan for injected/hollowed
PEs), `dump_memory_region` (region → `artifacts/dumps/`, metadata
returned), `carve_pe_from_dump` (pure-Python PE carving from a dump in
`artifacts/`, carved images → `artifacts/carved/`).

**Sessions** — `session_create`, `session_list`, `session_get`,
`session_note`, `session_close`. A session links a sample, the debugger
bridge session, Frida sessions and notes; state persists in
`artifacts/sessions.json`.

## Layout

```
server.py            FastMCP app, auth middleware, all tools
config.py            RELAB_* environment configuration + token rule
audit.py             JSONL audit logging decorator
samples.py           content-addressed sample store
sessions.py          persistent analysis sessions
debugger/            backend abstraction + x64dbg bridge client
mock_bridge.py       canned-data bridge for dev/tests (stdlib only)
frida_tools.py       Frida manager (optional dependency)
frida_scripts/       bundled instrumentation (api_monitor.js)
unpack.py            pe-sieve runner, memory dumps, PE carver
vendor/              triage.py + YARA rules (from malware-triage-toolkit)
docs/BRIDGE.md       the x64dbg bridge HTTP contract
tests/               unit tests + full end-to-end test (mock bridge)
```

## Testing

```bash
.venv/bin/pytest tests/
```

Unit tests cover config enforcement, the sample store (including
path-traversal resistance), session persistence and the PE carver.
The end-to-end test starts the mock bridge and the real server,
connects with a real MCP client, and drives the full debugger flow,
static triage, Frida degradation and session flow. All test samples are
synthetic and harmless (an EICAR string and a `struct`-built minimal
PE) — no real malware is used anywhere in this project.

> Note on SDK version: this project uses the FastMCP API of the
> official Python SDK 1.x (`mcp>=1.9,<2`). In SDK 2.x FastMCP was
> renamed to `MCPServer`; migrating is a small, planned change.

## Roadmap

* capa integration (capability detection) as a static tool
* Ghidra headless summaries (functions, decompilation snippets)
* Scylla integration for IAT reconstruction after dumping
* OEP-finding heuristics (ESP law / memory-breakpoint automation)
* Multiple concurrent debug sessions; TLS for the MCP endpoint
