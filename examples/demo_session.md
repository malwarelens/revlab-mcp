# Demo session — revlab-mcp end to end

*Generated 2026-10-12 07:28 UTC by `examples/run_demo.py`. Everything below is
the real output of a real run: the MCP server and the mock bridge were
started on loopback, and a real MCP client drove the session.*

## What you are looking at

An AI agent's typical workflow against revlab-mcp:

1. register a sample that already sits on the analysis host,
2. open an analysis session and run static triage,
3. launch the sample under the debugger and inspect it,
4. dump memory and carve an unpacked PE out of a dump,
5. compose the session report and close out.

Two honesty notes:

* The debugger here is `mock_bridge.py` (canned data per
  `docs/BRIDGE.md`), so register values, disassembly and module lists
  are the mock's fixtures. On a real analysis host the *identical*
  tool calls drive x64dbg through the same contract.
* The sample is the synthetic PE from `tests/make_samples.py`
  (SHA-256 `acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74`), and capa / pe-sieve / Frida are
  deliberately not installed in this environment — their steps below
  show the platform's structured "not configured" results verbatim.

Paths under the demo workspace are throwaway temp directories.

## Transcript

### 1. Register the sample (host-local path)

Tool call: `register_sample`

Request:

```json
{
  "source_path": "/tmp/revlab-demo-kqwz7qw4/inbox/sample_pe.exe"
}
```

Response (summary):

```json
{
  "sample_id": "acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74",
  "original_name": "sample_pe.exe",
  "size": 1536,
  "md5": "493ae41d9edb339fa5a56ef9189d2980"
}
```

### 2. Open an analysis session

Tool call: `session_create`

Request:

```json
{
  "sample_id": "acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74"
}
```

Response (summary):

```json
{
  "session_id": "2746b3b21afc4f53860dca2a53b4a97a",
  "status": "open",
  "created_at": "2026-10-12T07:28:37.022004+00:00"
}
```

### 3. Static triage (never executes the sample)

Tool call: `static_triage`

Request:

```json
{
  "sample_id": "acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74"
}
```

Response (summary):

```json
{
  "file_type": "PE / DOS executable (MZ header)",
  "sha256": "acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74",
  "entropy": 1.362,
  "ioc_counts": {
    "urls": 1,
    "ipv4": 1,
    "domains": 1,
    "run_keys": 1,
    "file_paths": 1
  },
  "urls": [
    "http://evil.example.com/payload.bin"
  ],
  "ipv4": [
    "185.220.101.4"
  ],
  "run_keys": [
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
  ],
  "indicators": [
    "Strings reference the registry Run/RunOnce keys, a common persistence location.",
    "Network indicators (URLs / IPv4 addresses) were found in strings; check whether they are contacted at runtime."
  ]
}
```

### 4. Capability detection (capa not installed here)

Tool call: `capa_analyze`

Request:

```json
{
  "sample_id": "acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74"
}
```

Response (summary):

```json
{
  "ok": false,
  "configured": false,
  "error": "capa is not available on the analysis host; set RELAB_CAPA_PATH to the capa executable or put capa on PATH"
}
```

### 5. Launch under the debugger (starts paused)

Tool call: `debug_launch`

Request:

```json
{
  "sample_id": "acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74",
  "analysis_session": "2746b3b21afc4f53860dca2a53b4a97a"
}
```

Response (summary):

```json
{
  "ok": true,
  "pid": 4242,
  "state": "paused",
  "analysis_session": "2746b3b21afc4f53860dca2a53b4a97a"
}
```

### 6. Set a breakpoint at the entry point

Tool call: `debug_set_breakpoint`

Request:

```json
{
  "location": "0x140001000"
}
```

Response (summary):

```json
{
  "address": "0x140001000",
  "location": null,
  "enabled": true
}
```

### 7. List breakpoints

Tool call: `debug_list_breakpoints`

Request:

```json
{}
```

Response (summary):

```json
{
  "breakpoints": [
    {
      "address": "0x140001000",
      "location": null,
      "enabled": true
    }
  ]
}
```

### 8. Run

Tool call: `debug_run`

Request:

```json
{}
```

Response (summary):

```json
{
  "state": "running",
  "cip": "0x140001000"
}
```

### 9. Pause

Tool call: `debug_pause`

Request:

```json
{}
```

Response (summary):

```json
{
  "state": "paused",
  "cip": "0x140001000"
}
```

### 10. Single-step into

Tool call: `debug_step_into`

Request:

```json
{}
```

Response (summary):

```json
{
  "state": "paused",
  "cip": "0x140001007"
}
```

### 11. Read registers

Tool call: `debug_registers`

Request:

```json
{}
```

Response (summary):

```json
{
  "rax": "0x0000000000000000",
  "rbx": "0x0000000140000000",
  "rsp": "0x000000000014F988",
  "rip": "0x140001007"
}
```

### 12. Disassemble at the entry point

Tool call: `debug_disassemble`

Request:

```json
{
  "address": "0x140001000",
  "count": 6
}
```

Response (summary):

```text
0x140001000  4883ec28         sub rsp, 0x28
0x140001004  488b05f91f0000   mov rax, qword ptr ds:[0x140002000]
0x14000100B  4885c0           test rax, rax
0x14000100E  7412             je 0x140001025
0x140001010  ff15e51f0000     call qword ptr ds:[0x140003000]
0x140001016  4883c428         add rsp, 0x28
```

### 13. Call stack

Tool call: `debug_callstack`

Request:

```json
{}
```

Response (summary):

```text
#0 0x140001000  sample.exe!entry_point
#1 0x7FFD0FABC410  kernel32.dll!BaseThreadInitThunk
#2 0x7FFD1237E2C0  ntdll.dll!RtlUserThreadStart
```

### 14. Loaded modules

Tool call: `debug_modules`

Request:

```json
{}
```

Response (summary):

```text
sample.exe       base=0x140000000 size=24576
ntdll.dll        base=0x7FFD12340000 size=2514944
kernel32.dll     base=0x7FFD0FAB0000 size=794624
KernelBase.dll   base=0x7FFD0D120000 size=3112960
```

### 15. Read memory at the image base

Tool call: `debug_read_memory`

Request:

```json
{
  "address": "0x140000000",
  "size": 64
}
```

Response (summary):

```json
{
  "address": "0x140000000",
  "size": 64,
  "hex_prefix": "4d5a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc…"
}
```

### 16. Dump the region to artifacts (metadata only)

Tool call: `dump_memory_region`

Request:

```json
{
  "address": "0x140000000",
  "size": 4096
}
```

Response (summary):

```json
{
  "path": "/tmp/revlab-demo-kqwz7qw4/artifacts/dumps/dump_140000000_4096_20261012T072837Z.bin",
  "written_size": 4096,
  "sha256": "ed2a5fc06d56344973e8d3e92eba400f6975904da7c9744dae508fa8c2d1f212"
}
```

### 17. Carve PEs out of the dump

Tool call: `carve_pe_from_dump`

Request:

```json
{
  "file_path": "/tmp/revlab-demo-kqwz7qw4/artifacts/dumps/dump_140000000_4096_20261012T072837Z.bin"
}
```

Response (summary):

```json
{
  "carved_count": 0,
  "carved": []
}
```

> The mock bridge's memory is a synthetic byte pattern (with an `MZ` planted at the image base), not a real PE image, so carving it correctly finds nothing. The next step shows carving against a dump file that does embed a PE.

### 18. Carve a dump file with an embedded PE

Tool call: `carve_pe_from_dump`

Request:

```json
{
  "file_path": "/tmp/revlab-demo-kqwz7qw4/artifacts/planted_dump.bin"
}
```

Response (summary):

```json
{
  "carved_count": 1,
  "carved": [
    {
      "offset": 16,
      "size": 1536,
      "sections": 2,
      "machine": "0x014C",
      "sha256": "acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74"
    }
  ]
}
```

### 19. pe-sieve process scan (not configured here)

Tool call: `pe_sieve_scan`

Request:

```json
{
  "pid": 4242
}
```

Response (summary):

```json
{
  "ok": false,
  "configured": false,
  "error": "pe-sieve is not configured on the analysis host; set RELAB_PESIEVE_PATH to the pe-sieve executable"
}
```

### 20. Frida status (not installed here)

Tool call: `frida_status`

Request:

```json
{}
```

Response (summary):

```json
{
  "available": false,
  "active_sessions": [],
  "note": "frida python package is not installed on the analysis host; Frida tools are unavailable (pip install frida frida-tools)."
}
```

An analyst note is added with `session_note` (text omitted here; it appears in the report).

### 21. Compose the session report

Tool call: `compose_session_report`

Request:

```json
{
  "session_id": "2746b3b21afc4f53860dca2a53b4a97a"
}
```

Response (summary):

```json
{
  "path": "/tmp/revlab-demo-kqwz7qw4/artifacts/reports/2746b3b21afc4f53860dca2a53b4a97a.md",
  "bytes": 3726,
  "summary": {
    "iocs": 5,
    "indicators": 2,
    "debug_events": 11,
    "frida_events": 0,
    "notes": 1,
    "pe_sieve_runs": 0,
    "dumps": 1,
    "carved": 1
  }
}
```

### 22. Terminate the debug session

Tool call: `debug_terminate`

Request:

```json
{}
```

Response (summary):

```json
{
  "ok": true
}
```

### 23. Close the analysis session

Tool call: `session_close`

Request:

```json
{
  "session_id": "2746b3b21afc4f53860dca2a53b4a97a"
}
```

Response (summary):

```json
{
  "status": "closed",
  "closed_at": "2026-10-12T07:28:38.213507+00:00"
}
```

## Appendix: the composed session report

This is the file `compose_session_report` wrote at the end of the
session (verbatim):

```markdown
# Analysis session report

- Session: `2746b3b21afc4f53860dca2a53b4a97a` (status: open, created: 2026-10-12T07:28:37.022004+00:00, closed: —)
- Report generated: 2026-10-12T07:28:38.167093+00:00

## Sample

- Original name: `sample_pe.exe`
- SHA-256: `acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74`
- MD5: `493ae41d9edb339fa5a56ef9189d2980`
- Size: 1536 bytes
- Registered: 2026-10-12T07:28:37.006948+00:00

## Static triage

- File type: PE / DOS executable (MZ header)
- Size: 1536 bytes; overall entropy: 1.362
- MD5: `493ae41d9edb339fa5a56ef9189d2980`
- SHA-1: `ca9e0b3da0f47ffa8b3c279bf681aec3ef61d32e`
- SHA-256: `acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74`

### PE structure

- Machine: x86 (32-bit); subsystem: 3; image base: 0x400000; entry point RVA: 0x00001000; imphash: ``; overlay: 0 bytes

| Section | VirtSize | RawSize | Entropy | Flags |
|---|---|---|---|---|
| .text | 384 | 512 | 0.159 | CODE,EXEC,READ |
| .data | 512 | 512 | 2.487 | IDATA,READ,WRITE |

### IOCs

- **URLs** (1):
  - `http://evil.example.com/payload.bin`
- **IPv4 addresses** (1):
  - `185.220.101.4`
- **Domains** (1):
  - `evil.example.com`
- **Registry Run keys** (1):
  - `Software\Microsoft\Windows\CurrentVersion\Run\Updater`
- **File paths** (1):
  - `C:\Users\victim\AppData\Roaming\upd.exe`

### Triage indicators

- Strings reference the registry Run/RunOnce keys, a common persistence location.
- Network indicators (URLs / IPv4 addresses) were found in strings; check whether they are contacted at runtime.

YARA: yara-python is not installed; YARA scan skipped

## Debug activity

- Debugger bridge session: `mock-session-1`

| Time (UTC) | Tool | Status | Arguments |
|---|---|---|---|
| 2026-10-12T07:28:37.385255+00:00 | `debug_launch` | ok | {"args": [], "kwargs": {"sample_id": "acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74", "arguments": ""… |
| 2026-10-12T07:28:37.468085+00:00 | `debug_set_breakpoint` | ok | {"args": [], "kwargs": {"location": "0x140001000", "session_id": ""}} |
| 2026-10-12T07:28:37.519963+00:00 | `debug_list_breakpoints` | ok | {"args": [], "kwargs": {"session_id": ""}} |
| 2026-10-12T07:28:37.570028+00:00 | `debug_run` | ok | {"args": [], "kwargs": {"session_id": ""}} |
| 2026-10-12T07:28:37.624966+00:00 | `debug_pause` | ok | {"args": [], "kwargs": {"session_id": ""}} |
| 2026-10-12T07:28:37.676073+00:00 | `debug_step_into` | ok | {"args": [], "kwargs": {"session_id": ""}} |
| 2026-10-12T07:28:37.737113+00:00 | `debug_registers` | ok | {"args": [], "kwargs": {"session_id": ""}} |
| 2026-10-12T07:28:37.805011+00:00 | `debug_disassemble` | ok | {"args": [], "kwargs": {"address": "0x140001000", "count": 6, "session_id": ""}} |
| 2026-10-12T07:28:37.854960+00:00 | `debug_callstack` | ok | {"args": [], "kwargs": {"session_id": ""}} |
| 2026-10-12T07:28:37.914275+00:00 | `debug_modules` | ok | {"args": [], "kwargs": {"session_id": ""}} |
| 2026-10-12T07:28:37.975923+00:00 | `debug_read_memory` | ok | {"args": [], "kwargs": {"address": "0x140000000", "size": 64, "session_id": ""}} |

## Frida events

No Frida session was attached to this analysis session.

## Unpacking / scan artifacts

### Memory dumps

- `/tmp/revlab-demo-kqwz7qw4/artifacts/dumps/dump_140000000_4096_20261012T072837Z.bin` — 4096 bytes (2026-10-12T07:28:38.026698+00:00)

### Carved PEs

- `/tmp/revlab-demo-kqwz7qw4/artifacts/carved/acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74.bin` — 1536 bytes, sha256 `acfd20f4278648d4101bd1b90f96e4cfdaf81437ba0365d28289ee06c7b1bf74`

## Analyst notes

- `2026-10-12T07:28:38.109918+00:00` Loader-like entry point; Run-key persistence string present — verify its target at runtime.
```
