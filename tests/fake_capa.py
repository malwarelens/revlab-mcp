#!/usr/bin/env python3
"""Fake capa executable for tests.

Prints a fixed capa-style `-j` JSON document to stdout, so capa_tools
and the capa_analyze MCP tool can be tested end-to-end without a real
capa installation. Behaviour:

* last argv element must be an existing file (the "sample"), otherwise
  exits 3 with an error on stderr, like real capa on a missing file;
* if FAKE_CAPA_GARBAGE=1 is set, prints non-JSON garbage instead.
"""

import json
import os
import sys
from pathlib import Path

DOC = {
    "meta": {
        "sample": {"sha256": "0" * 64, "path": "sample"},
        "flavor": "static",
        "version": "8.0.0",
        "extractor": "fake",
    },
    "rules": {
        "inject code into process": {
            "meta": {
                "name": "inject code into process",
                "namespace": "host-interaction/process/inject",
                "scope": "function",
                "att&ck": [
                    {"id": "T1055", "tactic": "Defense Evasion",
                     "technique": "Process Injection"},
                    {"id": "T1055", "tactic": "Privilege Escalation",
                     "technique": "Process Injection"},
                ],
                "mbc": [
                    {"id": "OC0003", "objective": "Process",
                     "behavior": "Inject Code"},
                ],
            },
            "matches": {
                "4198400": {"success": True, "locations": [4198400]},
                "4198500": {"success": True, "locations": [4198500]},
            },
        },
        "persist via Run registry key": {
            "meta": {
                "name": "persist via Run registry key",
                "namespace": "persistence/registry",
                "scope": "file",
                "att&ck": [
                    {"id": "T1547.001", "tactic": "Persistence",
                     "technique": "Boot or Logon Autostart Execution: "
                                  "Registry Run Keys"},
                ],
                "mbc": [
                    {"id": "OC0008", "objective": "Persistence",
                     "behavior": "Registry Run Key"},
                ],
            },
            "matches": {
                "4199000": {"success": True, "locations": [4199000]},
            },
        },
        "encode data with base64": {
            "meta": {
                "name": "encode data with base64",
                "namespace": "data-manipulation/encoding/base64",
                "scope": "instruction",
                "att&ck": [],
                "mbc": [
                    {"id": "C0005", "objective": "Communication",
                     "behavior": "Encode Data"},
                ],
            },
            "matches": {
                "4199100": {"success": True, "locations": [4199100]},
            },
        },
    },
}


def main() -> int:
    if os.environ.get("FAKE_CAPA_GARBAGE") == "1":
        print("this is not json at all")
        return 0
    sample = sys.argv[-1] if len(sys.argv) > 1 else ""
    if not Path(sample).is_file():
        print(f"fake-capa: no such file: {sample}", file=sys.stderr)
        return 3
    json.dump(DOC, sys.stdout)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
