# Changelog

All notable changes to revlab-mcp are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **pe-sieve scan output directory** — `pe_sieve_scan` built its
  per-run output path as `Path(...) / f"pid{pid}_" + <timestamp>`;
  because `/` binds tighter than `+`, the expression evaluated to
  `PosixPath + str` and raised `TypeError` whenever pe-sieve was
  configured with an existing executable, so a configured scan could
  never run. The timestamp concatenation is now parenthesised.
  Previously the configured path was only exercised up to the
  "not configured" / "not found" early returns.

### Added

- **Unpack unit tests** — new `tests/test_unpack.py` pins the
  tool-facing unpack wrappers directly: `carve_pe_from_file` jails
  its source to the artifacts directory (including `..` traversal)
  and de-duplicates identical carved images; `dump_memory_region`
  rejects non-positive sizes, chunks backend reads at the 64 KiB cap,
  stops on short/empty reads and returns metadata only;
  `pe_sieve_scan` degrades when not configured / not found / timed
  out and parses the JSON document out of a fake executable's noisy
  stdout (raw-output fallback otherwise). Writing these tests is
  what exposed the output-directory bug above.

- **Config / session unit tests** — new `tests/test_config_sessions.py`
  pins the token rule beyond the three cases in `test_units.py`:
  loopback spellings (`localhost` in any case, `::1`, the rest of
  127.0.0.0/8) start without a token, while `0.0.0.0`, `::`, LAN
  addresses and plain hostnames (not IP literals, so never provably
  loopback) are refused without one; empty/blank environment values
  fall back to defaults, and the inbox / audit-log plumbing is
  covered. For `sessions.py` it pins unknown-session errors on every
  entry point, corrupt-state recovery, Frida attach de-duplication
  and fresh-session defaults. Previously both modules were only
  exercised on their happy paths.

- **Audit-log unit tests** — new `tests/test_audit.py` pins the audit
  log's no-payload contract directly: argument summarisation truncates
  long strings, caps list/dict sizes and applies the overall length
  cap; result summaries carry shape only (keys / length / type), never
  values; `AuditLog.write` emits the documented JSONL fields with
  error truncation; and the `audited` decorator logs ok/error calls
  and re-raises. Previously `audit.py` was only exercised indirectly
  through the end-to-end test.

## [1.2.0] - 2026-10-12

### Added

- **Ghidra headless integration** — new `ghidra_tools.py` module,
  bundled export script `ghidra_scripts/export_analysis.py` and
  `ghidra_analyze` MCP tool. Locates `analyzeHeadless` via
  `RELAB_GHIDRA_PATH` (executable or install directory) or the host
  `PATH`, imports the sample into a throwaway project, and returns a
  structured summary: function inventory, import mapping, decompiled
  snippets for functions that call suspicious APIs, and
  string-reference hotspots. Structured "not configured" degradation
  without Ghidra. Tested end-to-end against a fake analyzeHeadless
  (`tests/fake_ghidra.py`).
- **Multiple concurrent debug sessions** — the debugger client is no
  longer a singleton: every analysis session can own its own backend
  instance, and all `debug_*` tools (plus `dump_memory_region`)
  accept a `session_id` that routes the call. Calls without one keep
  going to the most recently launched ("current") backend, preserving
  the 1.x single-session workflow. Terminating a session unbinds its
  routing entry. The mock bridge's register file is now per bridge
  session (it previously shared one global), so parallel sessions
  provably do not cross-talk — covered by client-level tests and a
  two-session end-to-end leg.
- **Frida script library + event persistence** — two new bundled
  scripts: `crypto_monitor.js` (CryptEncrypt / CryptDecrypt /
  BCryptEncrypt; events carry data lengths and 64-byte hex previews
  of the output buffers) and `process_network.js` (CreateProcess,
  WinINet / WinHTTP requests, DNS queries), loaded via
  `frida_load_crypto_monitor` / `frida_load_process_network`. Events
  are now also appended to `artifacts/frida/<session>.jsonl` as they
  arrive, and the new `frida_events_digest` tool returns per-API
  counts plus the most recent events for a session.
- **Sample inbox** — new `inbox.py` module and `scan_inbox` tool:
  bulk-registers every file dropped into `RELAB_INBOX_DIR`,
  reporting new / already-registered / failed files separately.
  Source files are never deleted or modified.
- **Health self-check** — new `lab_health` tool: configuration
  summary (bind address/port, token auth, sample-store and artifacts
  writability, inbox), bridge `/health` reachability, per-integration
  status for capa / Ghidra / Frida / pe-sieve, sample and session
  counts, and the registered tool count.

### Changed

- Tool count: 40 → 46 (`ghidra_analyze`, `scan_inbox`,
  `frida_load_crypto_monitor`, `frida_load_process_network`,
  `frida_events_digest`, `lab_health`).
- `X64dbgBackend.launch` / `attach` now enforce the documented
  one-live-session-per-instance invariant and raise `DebuggerError`
  instead of silently orphaning the previous bridge session.
- Configuration: new `RELAB_INBOX_DIR` (sample drop directory).

## [1.1.0] - 2026-10-12

### Added

- **capa integration** — new `capa_tools.py` module and `capa_analyze`
  MCP tool. Locates capa via `RELAB_CAPA_PATH` or the host `PATH`,
  runs it against a registered sample and returns its capabilities
  condensed and grouped by MITRE ATT&CK tactic and MBC objective.
  Without capa installed it returns the platform's structured
  "not configured" result. Covered by unit tests and by the end-to-end
  test using a fake capa executable (`tests/fake_capa.py`).
- **Session report composition** — new `report.py` module and
  `compose_session_report` MCP tool. Renders one Markdown report per
  analysis session (sample metadata, static triage, debugger activity
  recovered from the audit log, Frida events, pe-sieve / dump / carve
  artifact metadata, analyst notes) into `artifacts/reports/` and
  returns the path plus summary counts.
- **Continuous integration** — `.github/workflows/ci.yml` runs the
  full pytest suite (unit tests + mock-bridge end-to-end, including
  the triage subprocess) on GitHub Actions / Ubuntu with Python 3.11
  and 3.12.
- **Recorded demo** — `examples/run_demo.py` drives a complete agent
  session (register → triage → debug → dump → carve → report)
  against the mock bridge with a synthetic sample; the real
  transcript is committed as `examples/demo_session.md` and linked
  from the README's new Demo section.
- README **Quality** section documenting how the tests are organised
  and how CI runs them.

### Changed

- Tool count: 38 → 40 (`capa_analyze`, `compose_session_report`).

## [1.0.0] - 2026-10-12

### Added

- Initial release. FastMCP server (Streamable HTTP) with Bearer-token
  auth (mandatory for non-loopback binds) and a JSONL audit log of
  every tool call.
- Content-addressed sample store: samples registered from host-local
  paths, addressed by SHA-256, never downloadable.
- Static triage via the vendored `triage.py` (hashes, PE structure,
  IOCs, suspicious APIs, YARA) with per-sample result caching.
- Debugger abstraction with an x64dbg bridge HTTP client
  (`docs/BRIDGE.md` contract): launch/attach, breakpoints, run/pause/
  stepping, registers, memory reads (hex, ≤ 64 KiB), disassembly,
  call stack, modules; plus `mock_bridge.py`, a canned-data bridge
  for development and tests.
- Frida session management with a bundled `api_monitor.js`
  (file/registry/injection/network/crypto hooks); structured
  degradation when Frida is not installed.
- Unpacking helpers: pe-sieve process scans, memory dumps to
  `artifacts/` (metadata only), pure-Python PE carving from dumps.
- Persistent analysis sessions linking a sample, the debugger bridge
  session, Frida sessions and analyst notes.
- Unit tests and a full end-to-end test (mock bridge + real server +
  real MCP client). All test samples are synthetic and harmless.
