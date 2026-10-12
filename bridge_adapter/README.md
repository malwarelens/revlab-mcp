# revlab x64dbg Bridge Adapter

The real bridge behind revlab-mcp's `debugger/x64dbg.py`. It runs on
the Windows analysis host next to x64dbg, serves the HTTP contract in
[`../docs/BRIDGE.md`](../docs/BRIDGE.md), and drives x64dbg through the
**x64dbg-automate** plugin + Python client (`x64dbg_automate`).

```
revlab-mcp server ──HTTP (BRIDGE.md)──► bridge_adapter/adapter.py
                                            │  x64dbg_automate client
                                            │  (ZeroMQ + msgpack)
                                            ▼
                                   x64dbg + Automate plugin
```

Two operating modes:

| Mode | How x64dbg runs | `/session/start` maps to | `/session/stop` maps to |
|---|---|---|---|
| **spawn** (default) | The adapter launches a fresh x64dbg per session | `X64DbgClient.start_session()` / `start_session_attach()` | `terminate_session()` — kills the debugger and the debuggee |
| **remote** | You keep your own x64dbg open; the Automate plugin is configured to remote mode | `load_executable()` / `attach()` | `unload_executable()` — stops the debuggee, **your x64dbg stays open and connected** |

Both modes enforce the contract's shape: one bridge == one active
session == one debuggee. A second `/session/start` while busy gets
HTTP 409 (the mock bridge allows many fake sessions; a real debugger
does not).

---

## Windows installation

### 1. Prerequisites

* A recent x64dbg snapshot build (<https://x64dbg.com>).
* Latest Microsoft Visual C++ Runtime Redistributable (x64 and x86) —
  required by the plugin.
* Python 3.10+ from python.org. **Do not use the Microsoft Store
  build** — upstream warns it may not work with the client library.

### 2. Install the Automate plugin into x64dbg

1. Download the latest release archive from
   <https://github.com/dariushoule/x64dbg-automate/releases>.
2. Extract the entire contents of the archive's `Release` directory
   into the debugger's `plugins` directory (create it if needed):
   * 64-bit: `x64dbg\release\x64\plugins`
   * 32-bit: `x64dbg\release\x32\plugins`
3. Start x64dbg once and confirm the log shows the Automate plugin
   loaded. Plugin settings live in `x64dbg.ini` under `[XAutomate]`
   (`Mode`, `BindAddress`, `ReqRepPort`, `PubSubPort`).
   * For **spawn mode**, leave `Mode=local` (the default).
   * For **remote mode**, set `Mode=remote`, pick two free ports for
     `ReqRepPort` / `PubSubPort`, and restart x64dbg.

### 3. Configure x64dbg breakpoints

Upstream's examples (and this adapter's `/session/start`, which
reports `state: "paused"`) assume x64dbg is configured to:

* break on the **entry breakpoint** and the **system breakpoint**,
* **skip TLS breakpoints**.

Set these under Options → Preferences → Events before first use.

### 4. Install the adapter

Copy the `bridge_adapter/` directory to the analysis host, then:

```bat
cd bridge_adapter
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt` pins `x64dbg_automate==0.9.2`. **Keep the plugin
and the client in step**: they negotiate a protocol compatibility
string (`ghost_fungus` in 0.9.x) at connect time and refuse to talk to
mismatched versions (`AssertionError: Incompatible x64dbg plugin and
client versions ...`).

### 5. Start the adapter

Spawn mode (adapter launches x64dbg for each session):

```bat
set XAUTO_X64DBG_PATH=C:\x64dbg\release\x64\x64dbg.exe
python adapter.py --host 127.0.0.1 --port 27042
```

* `XAUTO_X64DBG_PATH` may also point at the `x96dbg.exe` launcher; the
  adapter resolves it to `x64dbg.exe`/`x32dbg.exe` by reading the
  target's PE bitness, mirroring upstream's MCP server.
* Per-session attach (`/session/start` with `{"pid": ...}`) spawns a
  *separate* x64dbg instance attached to that process — it does not
  hijack an x64dbg you already have open.

Remote mode (attach to your running x64dbg):

```bat
set XAUTO_REMOTE_HOST=127.0.0.1
set XAUTO_REMOTE_REQ_PORT=27001
set XAUTO_REMOTE_PUB_PORT=27002
python adapter.py --host 127.0.0.1 --port 27042
```

The ports are the plugin's `[XAutomate]` `ReqRepPort`/`PubSubPort`
from step 2. The adapter connects (and PING/PONGs) at startup, so a
wrong port fails immediately instead of at the first debug call.

Keep the listener on **loopback**. The contract has no
authentication (authorization comes from revlab-mcp's bearer token);
never expose the bridge port to a network you do not fully trust.

### 6. Point revlab-mcp at the adapter

On the machine running revlab-mcp:

```bat
set RELAB_X64DBG_BRIDGE_URL=http://127.0.0.1:27042
```

(When revlab-mcp runs on a *different* host than x64dbg, bind the
adapter to the analysis host's LAN address instead and use that URL —
accepting the trust note above.)

Smoke test:

```bat
curl http://127.0.0.1:27042/health
:: {"ok": true, "bridge": "revlab-x64dbg-adapter/1.0.0", ...}
```

---

## Contract mapping

Every row was implemented against the upstream source (see
"API references" below), not against memory.

| BRIDGE.md endpoint | x64dbg-automate calls | Notes |
|---|---|---|
| `GET /health` | — (local state) | Adds `backend` / `mode` / `session_active` fields; the revlab client passes extras through. |
| `POST /session/start` `{path}` | spawn: `X64DbgClient(x64dbg_path=…)` then `start_session(path, args, cwd)`; remote: `load_executable(...)` | Response `pid` is the **debuggee** PID from `debugee_pid()` (eval `pid`) — *not* `start_session()`'s return value, which is the **debugger** PID. |
| `POST /session/start` `{pid}` | spawn: `start_session_attach(pid)`; remote: `attach(pid)` | |
| `POST /session/stop` | spawn: `terminate_session()`; remote: `unload_executable()` | Contract says "terminates the debuggee". In spawn mode killing the debugger also kills the debuggee. In remote mode `stop` kills the debuggee but deliberately leaves the analyst's x64dbg running. |
| `POST /control` `run` | `go()` | `go()` returns as soon as the debuggee is *running*; it does not wait for the next breakpoint (see "Adapter extensions"). `state`/`cip` are sampled afterwards via `is_running()` / `get_reg('cip')`. |
| `POST /control` `pause` | `pause()` | Blocks until the debuggee has actually stopped. |
| `POST /control` `step_into` / `step_over` | `stepi()` / `stepo()` | Both block until stopped, so `cip` in the response is the post-step value. |
| `POST /cmd` | `cmd_sync(cmd)` + `get_log()` diff | **automate returns only a bool for a command** — there is no output string anywhere in the API. The adapter reconstructs `output` from the debugger log lines the plugin captured between log-cursor snapshots. Commands that print nothing yield `""`. A `false` return becomes HTTP 400 with the partial output attached. |
| `POST /breakpoints` `{address}` | `set_breakpoint(int)` | |
| `POST /breakpoints` `{location}` | `eval_sync(location)` → `set_breakpoint(int)`; falls back to `set_breakpoint(str)` | The contract's `module!Symbol` form is WinDbg syntax; x64dbg expressions use `module:Symbol`. The adapter tries the location as-is, then with `!`→`:`, before deferring to `bpx`. Response carries the **resolved** address. |
| `GET /breakpoints` | `get_breakpoints(BreakpointType.BpNormal)` | Software breakpoints only (that is all the contract models). `location` is echoed from the adapter's own registry — see "Known gaps". |
| `DELETE /breakpoints` | `clear_breakpoint(int \| str)` | By-location deletes resolve through the adapter registry first. Missing breakpoint → HTTP 404. |
| `GET /registers` | `get_regs()` → `.context` | Register names/width come from the `RegDump64`/`RegDump32` context models; `cip` mirrors `rip`/`eip`. |
| `POST /memory` | `read_memory(addr, size)` | The plugin's read is **all-or-nothing**: any byte outside a committed region fails the whole read (HTTP 400). No partial reads. |
| `POST /disasm` | `disassemble_at(addr)` loop, advancing by `instr_size` | The automate `Instruction` model has **no raw-bytes field**, so `bytes` is filled from `read_memory(addr, instr_size)`; if that read fails, `bytes` is `""`. A zero-length decode stops the walk (never loops). |
| `GET /callstack` | — | **Not implemented — HTTP 501.** See below. |
| `GET /modules` | `memmap()` grouped by `allocation_base` over `MEM_IMAGE` pages + `EVENT_LOAD_DLL` records | `base`/`size` are exact. `name`/`path` are learned from the plugin's pub/sub `EVENT_LOAD_DLL` events (drained on each request) and, for the main module of a launch, from the known target path. See "Known gaps". |

`main_module` in the `/session/start` response: base from
`eval_sync("mod.main()")`, size from `eval_sync("mod.size(base)")`,
with memmap-derived fallbacks for both.

### Session start state assumption

`/session/start` reports `state: "paused"` because of the step-3
x64dbg configuration (break on entry + system breakpoint). If you
turn those breakpoints off, the debuggee will be running when the
call returns and the adapter will honestly report `"running"`.

### Adapter extensions (beyond BRIDGE.md)

* `POST /control {"action": "run", "wait_stop_timeout": <seconds>}` —
  after `go()`, also wait for the debuggee to stop again (capped by
  the timeout). Useful for run-to-breakpoint workflows. Unknown fields
  are ignored by contract, so this is additive only.
* Error bodies are always `{"error": "..."}` per the contract;
  statuses used: 400 bad/rejected request, 404 unknown session or
  breakpoint, 409 session already active, 501 not implemented.

---

## Unsupported / partial — explicit list

* **`GET /callstack` → 501 `not_implemented`.** x64dbg-automate has
  no call-stack capability at any layer: the plugin exposes ~28 RPC
  commands (none for stack walking), the Python client has no method,
  and upstream's own MCP server ships no call-stack tool. Rather than
  fabricate frames from a raw stack scan, the bridge refuses.
  *Suggested contract revision:* either drop `/callstack` from
  BRIDGE.md, or add a separately-named, explicitly heuristic endpoint
  (e.g. `POST /stackscan`) so no consumer mistakes scanned return
  addresses for a real unwind.
* **`/modules` `name`/`path` are best-effort.** There is no module
  enumeration RPC. Bases and sizes are exact (from `memmap()`), but a
  module's file path is only known if its `EVENT_LOAD_DLL` was
  observed during this session (normal for everything loaded after
  connect) or it is the launched target. Otherwise `name`/`path` are
  `""` — never guessed.
* **Breakpoint `location` round-trip is adapter-kept state.**
  x64dbg stores breakpoints by resolved address with an
  adapter-generated name (`bpx_<symbol>`); the original
  `module!Symbol` string is not recoverable from the debugger. The
  adapter remembers locations for breakpoints set *through the
  bridge*; breakpoints created by hand in the x64dbg GUI list with
  `location: null`. Restarting the adapter forgets the registry
  (breakpoints themselves live in x64dbg and persist).
* **Hardware and memory breakpoints are not exposed.** automate
  supports them (`set_hardware_breakpoint`, `set_memory_breakpoint`),
  but BRIDGE.md's breakpoint endpoints model only an
  address/location pair, so there is nothing to map them to.
* **One session at a time.** See the mode table. The mock bridge's
  multi-session behavior does not survive contact with a real
  debugger.
* **`/cmd` output is the debugger log, not a return value.** If a
  command's effect isn't logged by x64dbg, `output` is empty even
  though the command succeeded.

---

## Development & tests (any OS)

The client layer is an injectable protocol (`automate_client.py`), so
the whole HTTP surface is testable without Windows/x64dbg: the suite
injects `tests/fake_automate.py`, runs the real server on an ephemeral
port, and asserts wire shapes for every contract endpoint, both
session modes, and the 501 path.

```bat
pip install pytest
python -m pytest bridge_adapter/tests -q
:: 22 passed
```

The suite was additionally driven end-to-end through revlab-mcp's own
`X64dbgBackend` client (launch → registers → run/step → breakpoints
→ disasm → memory → modules → cmd → terminate) to verify the adapter
satisfies the real consumer, not just the contract text.

## API references (verified 2026-10)

* Python client source: <https://github.com/dariushoule/x64dbg-automate-pyclient>
  (`x64dbg_automate/__init__.py`, `commands_xauto.py`, `hla_xauto.py`,
  `events.py`, `models.py`, `mcp_server.py`)
* Plugin source: <https://github.com/dariushoule/x64dbg-automate>
* Docs: <https://dariushoule.github.io/x64dbg-automate-pyclient/>
  (installation / quickstart / remote sessions)
* PyPI: <https://pypi.org/project/x64dbg_automate/> — 0.9.2, Python ≥ 3.10
* Upstream overview: <https://x64dbg.com/blog/2025/03/04/automate-introduction/>

Note: the project is by **Darius Houle** (GitHub `dariushoule`), MIT
licensed. (Not `darwin/x64dbg-automate` — that name does not exist.)

---

## Windows field-test checklist (still unverified — needs the real host)

Everything above is source-verified and Linux-tested with a fake
client; none of it has touched a real x64dbg yet. On first deployment,
verify in order:

1. Plugin loads in x64dbg; plugin/client versions negotiate (no
   `Incompatible x64dbg plugin and client versions` assertion).
2. `GET /health`, then `/session/start` on a benign sample: state is
   `paused` (validates the entry/system breakpoint configuration),
   `pid` is the *debuggee's* PID (cross-check in Task Manager),
   `main_module` base/size match x64dbg's memory map.
3. `/registers` against the GUI register view; one `step_into` and
   compare `cip`.
4. Breakpoint by address and by `kernel32!CreateFileW` location: hit
   in the GUI, listed by the bridge, deletable by both forms.
5. `/memory` at the image base returns the real MZ bytes; a read
   straddling a region boundary returns 400 (all-or-nothing).
6. `/disasm` text/bytes against the GUI disassembly for the same
   address, including an instruction whose bytes cross-check.
7. `/modules` paths for system DLLs (validates the LOAD_DLL event
   enrichment), including after loading a DLL mid-session.
8. `/cmd` with a log-producing command (e.g. `log "x"`) and with a
   state-changing command; check the output diffing doesn't leak
   previous commands' lines.
9. `/session/stop` in spawn mode closes the adapter-spawned x64dbg;
   in remote mode leaves your x64dbg open and reusable for the next
   session.
10. A 32-bit target through the `x96dbg.exe` launcher path
    (bitness resolution → `x32dbg.exe`, `RegDump32` registers).
