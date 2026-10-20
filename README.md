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

## Demo

[**examples/demo_session.md**](examples/demo_session.md) is a real,
recorded agent session — not a mock-up of one. It was produced by
running `examples/run_demo.py`, which starts the mock bridge and the
server, then drives the full workflow with a real MCP client:
register a sample → open a session → static triage → launch under
the debugger → breakpoint → registers / memory / disassembly →
memory dump → PE carving → session report → close. Register values
and disassembly are the mock bridge's canned fixtures (on a real
host the identical calls drive x64dbg), and the capa / pe-sieve /
Frida steps show the platform's "not configured" results verbatim,
because those tools are deliberately absent from the demo
environment. The composed session report is appended in full.

Regenerate it any time with:

```bash
.venv/bin/python examples/run_demo.py
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
| `RELAB_CAPA_PATH` | — (PATH lookup) | Path to the capa executable. Unset and not on `PATH` → `capa_analyze` reports "not configured". |
| `RELAB_GHIDRA_PATH` | — (PATH lookup) | Path to the `analyzeHeadless` executable, or a Ghidra install directory (its `support/` is searched). Unset and not on `PATH` → `ghidra_analyze` reports "not configured". |
| `RELAB_INBOX_DIR` | — | Sample drop directory bulk-registered by `scan_inbox`. Unset → `scan_inbox` reports "not configured". |
| `RELAB_AUDIT_LOG` | `<artifacts>/audit.jsonl` | Audit log location. |

## Tools (46)

**Samples** — `register_sample` (from a host-local path; metadata only),
`list_samples`, `get_sample_info`, `scan_inbox` (bulk-register every
file in the `RELAB_INBOX_DIR` drop directory — new / existing / failed
reported separately, source files left in place).

**Static analysis** — `static_triage` (hashes, file type, PE structure,
IOCs, suspicious APIs, YARA, indicators; the sample is read, never
executed), `get_strings_summary`, `capa_analyze` (capa capability
detection, grouped by ATT&CK tactic and MBC objective; requires capa
on the host — `RELAB_CAPA_PATH` or `PATH` — and degrades to a
structured "not configured" result without it), `ghidra_analyze`
(Ghidra headless: function inventory, import mapping, decompiled
snippets for functions that call suspicious APIs, string-reference
hotspots; requires Ghidra on the host — `RELAB_GHIDRA_PATH` or `PATH`
— and degrades the same way).

**Debugging (x64dbg bridge)** — `debug_status`, `debug_launch`,
`debug_attach`, `debug_terminate`, `debug_command` (raw passthrough),
`debug_set_breakpoint` / `debug_list_breakpoints` /
`debug_delete_breakpoint`, `debug_run`, `debug_pause`,
`debug_step_into`, `debug_step_over`, `debug_registers`,
`debug_read_memory` (hex, ≤ 64 KiB), `debug_disassemble`,
`debug_callstack`, `debug_modules`. Every debug tool accepts a
`session_id`: each analysis session owns its own backend instance,
so several sessions can debug concurrently without cross-talk;
without it, calls go to the most recently launched backend.

**Frida** — `frida_status`, `frida_spawn`, `frida_spawn_sample`,
`frida_attach`, `frida_resume`, `frida_load_script`,
`frida_load_api_monitor` (bundled `frida_scripts/api_monitor.js`:
CreateFile/registry/injection/network/crypto hooks),
`frida_load_crypto_monitor` (`crypto_monitor.js`: CryptEncrypt /
CryptDecrypt / BCryptEncrypt with data lengths and 64-byte hex
previews), `frida_load_process_network` (`process_network.js`:
CreateProcess, WinINet/WinHTTP requests, DNS queries),
`frida_get_events`, `frida_events_digest` (per-API counts + latest
events), `frida_stop`. Events are buffered per session and also
appended to `artifacts/frida/<session>.jsonl` as they arrive. If
Frida is not installed on the host, these return a structured
"not available" result.

**Unpacking** — `pe_sieve_scan` (process scan for injected/hollowed
PEs), `dump_memory_region` (region → `artifacts/dumps/`, metadata
returned), `carve_pe_from_dump` (pure-Python PE carving from a dump in
`artifacts/`, carved images → `artifacts/carved/`).

**Sessions** — `session_create`, `session_list`, `session_get`,
`session_note`, `session_close`, `compose_session_report` (renders a
Markdown report for the session — sample metadata, triage, debugger
activity from the audit log, Frida events, artifact metadata, notes —
into `artifacts/reports/`). A session links a sample, the debugger
bridge session, Frida sessions and notes; state persists in
`artifacts/sessions.json`.

**Platform** — `lab_health` (one-shot self-check: configuration
summary and store/artifacts writability, bridge `/health`
reachability, capa / Ghidra / Frida / pe-sieve status, sample and
session counts, registered tool count).

## Layout

```
server.py            FastMCP app, auth middleware, all tools
config.py            RELAB_* environment configuration + token rule
audit.py             JSONL audit logging decorator
samples.py           content-addressed sample store
sessions.py          persistent analysis sessions
capa_tools.py        capa runner + ATT&CK/MBC-grouped result summary
ghidra_tools.py      Ghidra headless runner + export summary
inbox.py             RELAB_INBOX_DIR bulk registration (scan_inbox)
report.py            session report composition (Markdown)
debugger/            backend abstraction + x64dbg bridge client
mock_bridge.py       canned-data bridge for dev/tests (stdlib only)
frida_tools.py       Frida manager (optional dependency)
frida_scripts/       bundled instrumentation (api_monitor.js,
                     crypto_monitor.js, process_network.js)
ghidra_scripts/      bundled Ghidra export script (export_analysis.py)
unpack.py            pe-sieve runner, memory dumps, PE carver
vendor/              triage.py + YARA rules (from malware-triage-toolkit)
docs/BRIDGE.md       the x64dbg bridge HTTP contract
tests/               unit tests + full end-to-end test (mock bridge)
examples/            run_demo.py + demo_session.md (recorded demo)
```

## Quality

The test suite is the contract for this project; it runs in full
locally and in CI, and nothing is merged on a red suite.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest tests/ -q
```

* **Unit tests** (`tests/test_units.py`, `tests/test_capa.py`,
  `tests/test_report.py`, `tests/test_ghidra.py`,
  `tests/test_inbox.py`, `tests/test_frida_events.py`,
  `tests/test_audit.py`, `tests/test_unpack.py`,
  `tests/test_state_recovery.py`,
  `tests/test_debug_sessions.py`) cover config enforcement (including
  the non-loopback token rule), the sample store (including
  path-traversal resistance), session persistence, state-file
  recovery from unparseable and non-object JSON, the PE carver, the
  capa result parser, session report composition against real triage
  output, the Ghidra runner against a fake analyzeHeadless, inbox
  bulk-registration accounting (new / existing / failed), Frida
  event persistence to JSONL and the per-API digest, the audit log's
  no-payload contract (argument/result summarisation and truncation,
  ok/error logging), the unpack wrappers (carve-from-file artifacts
  jailing and de-duplication, memory-dump 64 KiB chunking with
  short/empty-read stops, pe-sieve degradation and stdout parsing
  against a fake executable), bundled-script
  syntax (`node --check`), and two-backend debug isolation against
  the mock bridge (breakpoints, run state and registers stay
  per-session).
* **End-to-end test** (`tests/test_e2e.py`) starts the mock bridge
  and the real server, connects with a real MCP client, asserts the
  full tool list (all 46 tools), and drives: auth refusal (401),
  sample registration, static triage through the vendored `triage.py`
  subprocess, `capa_analyze` against a fake capa executable
  (`tests/fake_capa.py`), the full debugger flow over the mock
  bridge, memory dumping, PE carving, pe-sieve / Frida degradation,
  session flow, report composition, the audit log contents,
  `ghidra_analyze` against a fake analyzeHeadless
  (`tests/fake_ghidra.py`), inbox scanning, the `lab_health`
  self-check structure, and two concurrent debug sessions routed by
  analysis session with no cross-talk.
* **CI** (`.github/workflows/ci.yml`) runs exactly the command above
  on GitHub Actions (Ubuntu) for every push and pull request, on
  Python 3.11 and 3.12.

All test samples are synthetic and harmless (an EICAR string and a
`struct`-built minimal PE) — no real malware is used anywhere in
this project.

> Note on SDK version: this project uses the FastMCP API of the
> official Python SDK 1.x (`mcp>=1.9,<2`). In SDK 2.x FastMCP was
> renamed to `MCPServer`; migrating is a small, planned change.

## Roadmap

* Scylla integration for IAT reconstruction after dumping
* OEP-finding heuristics (ESP law / memory-breakpoint automation)
* TLS for the MCP endpoint
