#!/usr/bin/env python3
"""Fake Ghidra `analyzeHeadless` executable for tests.

Mimics the real invocation shape:

    analyzeHeadless <project_dir> <project_name> -import <file>
        -scriptPath <dir> -postScript export_analysis.py <out.json>
        -deleteProject

Behaviour:
  * the -import target must exist, else exit 2 (like a failed import)
  * the export script must exist under -scriptPath, else exit 3
  * writes a fixed export JSON document to the -postScript argument
  * FAKE_GHIDRA_MODE=garbage  -> writes non-JSON text as the output
  * FAKE_GHIDRA_MODE=nooutput -> exits 0 but writes nothing
"""

import json
import os
import sys
from pathlib import Path

DOCUMENT = {
    "program": {"name": "sample.exe", "language": "x86:LE:64:default",
                "compiler": "windows", "executable_format": "Portable Executable (PE)"},
    "functions": [
        {"name": "entry", "address": "0x140001000", "size": 42,
         "signature": "undefined entry(void)"},
        {"name": "FUN_140001050", "address": "0x140001050", "size": 210,
         "signature": "undefined FUN_140001050(void)"},
        {"name": "inject_payload", "address": "0x140001200", "size": 340,
         "signature": "undefined inject_payload(void)"},
    ],
    "imports": [
        {"name": "VirtualAllocEx", "library": "KERNEL32", "address": "0x140002000"},
        {"name": "CreateFileW", "library": "KERNEL32", "address": "0x140002008"},
    ],
    "suspicious_calls": [
        {"function": "inject_payload", "address": "0x140001200",
         "apis": ["VirtualAllocEx", "WriteProcessMemory"],
         "decompiled": "void inject_payload(void)\n{\n"
                       "  HANDLE h = OpenProcess(0x1f0fff,0,0x1234);\n"
                       "  LPVOID p = VirtualAllocEx(h,0,0x1000,0x3000,0x40);\n"
                       "  WriteProcessMemory(h,p,buf,0x1000,0);\n}\n"},
    ],
    "string_hotspots": [
        {"value": "http://c2.invalid/beacon", "address": "0x140003000",
         "references": 4},
        {"value": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "address": "0x140003040", "references": 2},
    ],
}


def _arg(argv: list[str], flag: str) -> str | None:
    if flag in argv:
        idx = argv.index(flag)
        if idx + 1 < len(argv):
            return argv[idx + 1]
    return None


def main() -> int:
    argv = sys.argv[1:]
    print("INFO  HeadlessAnalyzer - analyzeHeadless (fake) starting")
    target = _arg(argv, "-import")
    if target is None or not Path(target).is_file():
        print(f"ERROR Importer: file not found: {target}", file=sys.stderr)
        return 2
    script = _arg(argv, "-postScript")
    script_path = _arg(argv, "-scriptPath")
    if script is None:
        print("ERROR no -postScript given", file=sys.stderr)
        return 2
    if script_path is not None and not (Path(script_path) / script).is_file():
        print(f"ERROR script not found: {script} in {script_path}",
              file=sys.stderr)
        return 3
    idx = argv.index("-postScript")
    if idx + 2 >= len(argv):
        print("ERROR export script got no output path argument",
              file=sys.stderr)
        return 2
    out_path = Path(argv[idx + 2])

    mode = os.environ.get("FAKE_GHIDRA_MODE", "")
    if mode == "nooutput":
        print("INFO  analysis finished (fake, no export written)")
        return 0
    if mode == "garbage":
        out_path.write_text("this is not json at all", encoding="utf-8")
        return 0
    out_path.write_text(json.dumps(DOCUMENT, indent=1), encoding="utf-8")
    print(f"INFO  export_analysis: wrote {out_path} (fake)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
