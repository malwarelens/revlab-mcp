#!/usr/bin/env python3
"""Run a full agent session against the mock bridge and record it.

Starts mock_bridge.py + server.py on loopback with throwaway
directories, drives the session an agent would run (register ->
triage -> debug -> dump -> carve -> report) through a real MCP
client, and writes the transcript to examples/demo_session.md.

The sample is the synthetic PE from tests/make_samples.py and the
debugger is the canned-data mock bridge, so every output below is
real but nothing dangerous is involved. capa, pe-sieve and Frida are
deliberately *not* configured in this environment, which also
demonstrates the structured degradation results.

Usage:  .venv/bin/python examples/run_demo.py
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

# Same proxy-env guard as tests/test_e2e.py: everything is loopback.
for _var in ("http_proxy", "https_proxy", "all_proxy",
             "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
             "no_proxy", "NO_PROXY"):
    os.environ.pop(_var, None)
os.environ["NO_PROXY"] = "127.0.0.1,localhost"

import make_samples  # noqa: E402

TOKEN = "demo-token"
OUT = ROOT / "examples" / "demo_session.md"
MAIN_BASE = "0x140000000"
ENTRY = "0x140001000"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float = 40.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError(f"port {port} never came up")


def _result(res) -> dict:
    if res.isError:
        raise RuntimeError(f"tool call errored: {res.content}")
    sc = res.structuredContent
    if isinstance(sc, dict):
        if set(sc.keys()) == {"result"} and isinstance(sc["result"], dict):
            return sc["result"]
        return sc
    return json.loads(res.content[0].text)


def _pick(d: dict, *keys: str) -> dict:
    return {k: d[k] for k in keys if k in d}


class Transcript:
    def __init__(self):
        self.steps: list[str] = []
        self._n = 0

    def step(self, title: str, tool: str, request: dict, summary,
             lang: str = "json") -> None:
        self._n += 1
        if isinstance(summary, (dict, list)):
            body = json.dumps(summary, indent=2, ensure_ascii=False)
        else:
            body = str(summary)
        self.steps.append(
            f"### {self._n}. {title}\n\n"
            f"Tool call: `{tool}`\n\n"
            f"Request:\n\n```json\n{json.dumps(request, indent=2)}\n```\n\n"
            f"Response (summary):\n\n```{lang}\n{body}\n```\n")

    def note(self, text: str) -> None:
        self.steps.append(text + "\n")


async def _run(base_url: str, pe_path: Path, artifacts: Path,
               transcript: Transcript) -> dict:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with streamablehttp_client(base_url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            async def call(name, **kwargs):
                return _result(await session.call_tool(name, kwargs))

            meta = await call("register_sample", source_path=str(pe_path))
            sample_id = meta["sample_id"]
            transcript.step("Register the sample (host-local path)",
                            "register_sample", {"source_path": str(pe_path)},
                            _pick(meta, "sample_id", "original_name", "size", "md5"))

            sess = await call("session_create", sample_id=sample_id)
            sid = sess["session_id"]
            transcript.step("Open an analysis session", "session_create",
                            {"sample_id": sample_id},
                            _pick(sess, "session_id", "status", "created_at"))

            tri = (await call("static_triage", sample_id=sample_id))["triage"]
            iocs = tri["iocs"]
            transcript.step("Static triage (never executes the sample)",
                            "static_triage", {"sample_id": sample_id}, {
                                "file_type": tri["file_type"],
                                "sha256": tri["hashes"]["sha256"],
                                "entropy": tri["entropy"],
                                "ioc_counts": {k: len(v) for k, v in iocs.items() if v},
                                "urls": iocs["urls"], "ipv4": iocs["ipv4"],
                                "run_keys": iocs["run_keys"],
                                "indicators": tri["indicators"],
                            })

            capa = await call("capa_analyze", sample_id=sample_id)
            transcript.step("Capability detection (capa not installed here)",
                            "capa_analyze", {"sample_id": sample_id}, capa)

            launched = await call("debug_launch", sample_id=sample_id,
                                  analysis_session=sid)
            transcript.step("Launch under the debugger (starts paused)",
                            "debug_launch",
                            {"sample_id": sample_id, "analysis_session": sid},
                            _pick(launched, "ok", "pid", "state",
                                  "bridge_session", "analysis_session"))

            bp = await call("debug_set_breakpoint", location=ENTRY)
            transcript.step("Set a breakpoint at the entry point",
                            "debug_set_breakpoint", {"location": ENTRY}, bp)
            bps = await call("debug_list_breakpoints")
            transcript.step("List breakpoints", "debug_list_breakpoints",
                            {}, bps)

            run = await call("debug_run")
            transcript.step("Run", "debug_run", {}, _pick(run, "state", "cip"))
            paused = await call("debug_pause")
            transcript.step("Pause", "debug_pause", {},
                            _pick(paused, "state", "cip"))
            step = await call("debug_step_into")
            transcript.step("Single-step into", "debug_step_into", {},
                            _pick(step, "state", "cip"))

            regs = (await call("debug_registers"))["registers"]
            transcript.step("Read registers", "debug_registers", {},
                            {k: regs[k] for k in ("rax", "rbx", "rsp", "rip")})

            dis = await call("debug_disassemble", address=ENTRY, count=6)
            lines = [f"{i['address']}  {i['bytes']:<16} {i['text']}"
                     for i in dis["instructions"]]
            transcript.step("Disassemble at the entry point",
                            "debug_disassemble",
                            {"address": ENTRY, "count": 6},
                            "\n".join(lines), lang="text")

            stack = await call("debug_callstack")
            lines = [f"#{f['index']} {f['address']}  {f['module']}!{f['symbol']}"
                     for f in stack["frames"]]
            transcript.step("Call stack", "debug_callstack", {},
                            "\n".join(lines), lang="text")

            mods = await call("debug_modules")
            lines = [f"{m['name']:<16} base={m['base']} size={m['size']}"
                     for m in mods["modules"]]
            transcript.step("Loaded modules", "debug_modules", {},
                            "\n".join(lines), lang="text")

            mem = await call("debug_read_memory", address=MAIN_BASE, size=64)
            transcript.step("Read memory at the image base",
                            "debug_read_memory",
                            {"address": MAIN_BASE, "size": 64},
                            {"address": mem["address"], "size": mem["size"],
                             "hex_prefix": mem["hex"][:64] + "…"})

            dump = await call("dump_memory_region", address=MAIN_BASE,
                              size=4096)
            transcript.step("Dump the region to artifacts (metadata only)",
                            "dump_memory_region",
                            {"address": MAIN_BASE, "size": 4096},
                            _pick(dump, "path", "written_size", "sha256"))

            carved = await call("carve_pe_from_dump",
                                file_path=dump["path"])
            transcript.step("Carve PEs out of the dump",
                            "carve_pe_from_dump", {"file_path": dump["path"]},
                            _pick(carved, "carved_count", "carved"))
            transcript.note(
                "> The mock bridge's memory is a synthetic byte pattern "
                "(with an `MZ` planted at the image base), not a real PE "
                "image, so carving it correctly finds nothing. The next "
                "step shows carving against a dump file that does embed "
                "a PE.")

            planted = artifacts / "planted_dump.bin"
            planted.write_bytes(b"\x00" * 16 + pe_path.read_bytes())
            carved2 = await call("carve_pe_from_dump",
                                 file_path=str(planted))
            transcript.step("Carve a dump file with an embedded PE",
                            "carve_pe_from_dump", {"file_path": str(planted)},
                            {"carved_count": carved2["carved_count"],
                             "carved": [_pick(c, "offset", "size", "sections",
                                               "machine", "sha256")
                                        for c in carved2["carved"]]})

            pesieve = await call("pe_sieve_scan", pid=4242)
            transcript.step("pe-sieve process scan (not configured here)",
                            "pe_sieve_scan", {"pid": 4242}, pesieve)

            frida = await call("frida_status")
            transcript.step("Frida status (not installed here)",
                            "frida_status", {},
                            _pick(frida, "available", "active_sessions", "note"))

            await call("session_note", session_id=sid,
                       note="Loader-like entry point; Run-key persistence "
                            "string present — verify its target at runtime.")
            transcript.note("An analyst note is added with `session_note` "
                            "(text omitted here; it appears in the report).")

            report = await call("compose_session_report", session_id=sid)
            transcript.step("Compose the session report",
                            "compose_session_report", {"session_id": sid},
                            _pick(report, "path", "bytes", "summary"))

            term = await call("debug_terminate")
            transcript.step("Terminate the debug session", "debug_terminate",
                            {}, _pick(term, "ok"))
            closed = await call("session_close", session_id=sid)
            transcript.step("Close the analysis session", "session_close",
                            {"session_id": sid}, _pick(closed, "status", "closed_at"))

            return {"report_path": report["path"], "sample_id": sample_id}


def main() -> None:
    workspace = Path(tempfile.mkdtemp(prefix="revlab-demo-"))
    samples_dir = workspace / "samples"
    artifacts = workspace / "artifacts"
    paths = make_samples.build_samples(workspace / "inbox")
    bridge_port, server_port = _free_port(), _free_port()

    bridge = subprocess.Popen(
        [sys.executable, str(ROOT / "mock_bridge.py"), "--port", str(bridge_port)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env = dict(os.environ,
               RELAB_HOST="127.0.0.1", RELAB_PORT=str(server_port),
               RELAB_TOKEN=TOKEN,
               RELAB_SAMPLES_DIR=str(samples_dir),
               RELAB_ARTIFACTS_DIR=str(artifacts),
               RELAB_X64DBG_BRIDGE_URL=f"http://127.0.0.1:{bridge_port}",
               PYTHONUNBUFFERED="1")
    env.pop("RELAB_CAPA_PATH", None)   # demo shows capa degradation honestly
    env.pop("RELAB_PESIEVE_PATH", None)
    server_log = open(workspace / "server.log", "wb")
    server = subprocess.Popen(
        [sys.executable, str(ROOT / "server.py")], cwd=ROOT, env=env,
        stdout=server_log, stderr=subprocess.STDOUT)
    transcript = Transcript()
    try:
        _wait_port(bridge_port)
        _wait_port(server_port)
        outcome = asyncio.run(_run(f"http://127.0.0.1:{server_port}/mcp",
                                   paths["pe"], artifacts, transcript))
    finally:
        server.terminate()
        bridge.terminate()
        server.wait(timeout=10)
        bridge.wait(timeout=10)
        server_log.close()

    report_text = Path(outcome["report_path"]).read_text(encoding="utf-8")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc = f"""# Demo session — revlab-mcp end to end

*Generated {generated} by `examples/run_demo.py`. Everything below is
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
  (SHA-256 `{outcome["sample_id"]}`), and capa / pe-sieve / Frida are
  deliberately not installed in this environment — their steps below
  show the platform's structured "not configured" results verbatim.

Paths under the demo workspace are throwaway temp directories.

## Transcript

{chr(10).join(transcript.steps)}
## Appendix: the composed session report

This is the file `compose_session_report` wrote at the end of the
session (verbatim):

```markdown
{report_text}```
"""
    OUT.write_text(doc, encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
