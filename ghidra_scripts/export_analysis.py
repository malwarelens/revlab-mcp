# -*- coding: utf-8 -*-
# export_analysis.py -- revlab-mcp bundled Ghidra headless export script.
#
# Run by ghidra_tools.py via analyzeHeadless:
#   analyzeHeadless <projdir> <proj> -import <sample> \
#       -scriptPath <repo>/ghidra_scripts \
#       -postScript export_analysis.py <output.json> -deleteProject
#
# Exports a single JSON document:
#   program            name / language / compiler of the analysed binary
#   functions          [{name, address, size, signature}] for every function
#   imports            [{name, library, address}] external (imported) symbols
#   suspicious_calls   [{function, address, apis, decompiled}] -- functions
#                      that call one of SUSPICIOUS_APIS, with a decompiled
#                      C snippet (truncated) from the DecompInterface
#   string_hotspots    [{value, address, references}] defined strings with
#                      the most cross-references (URLs/APIs hide here)
#
# Written in the Jython dialect Ghidra ships: no f-strings, no pathlib,
# Java interop via the ghidra.* packages. Every section is best-effort --
# a failure in one exporter never aborts the whole export.

import json

from ghidra.app.decompiler import DecompInterface
from ghidra.program.util import DefinedDataIterator
from ghidra.util.task import ConsoleTaskMonitor

# APIs whose callers are worth a decompilation snippet. Kept in sync
# (loosely, by hand) with the suspicious-API list in vendor/triage.py.
SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "NtWriteVirtualMemory", "QueueUserAPC", "SetThreadContext",
    "CreateProcessW", "CreateProcessA", "WinExec", "ShellExecuteW",
    "InternetOpenW", "InternetOpenA", "InternetConnectW", "InternetReadFile",
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
    "URLDownloadToFileW", "URLDownloadToFileA",
    "RegCreateKeyExW", "RegSetValueExW", "CreateServiceW",
    "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
    "GetProcAddress", "LoadLibraryW", "LoadLibraryA",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "OpenProcess", "CreateToolhelp32Snapshot",
    "GetAsyncKeyState", "SetWindowsHookExW",
]

MAX_DECOMP_SNIPPET = 6000
monitor = ConsoleTaskMonitor()


def _addr(obj):
    try:
        return "0x%x" % obj.getOffset()
    except Exception:
        return str(obj)


def export_functions(program):
    out = []
    fm = program.getFunctionManager()
    for fn in fm.getFunctions(True):
        try:
            out.append({
                "name": fn.getName(),
                "address": _addr(fn.getEntryPoint()),
                "size": int(fn.getBody().getNumAddresses()),
                "signature": str(fn.getSignature()),
            })
        except Exception:
            continue
    return out


def export_imports(program):
    out = []
    st = program.getSymbolTable()
    try:
        external = st.getExternalSymbols()
        for sym in external:
            try:
                loc = sym.getParentNamespace()
                out.append({
                    "name": sym.getName(),
                    "library": loc.getName() if loc else None,
                    "address": _addr(sym.getAddress()),
                })
            except Exception:
                continue
    except Exception:
        pass
    return out


def export_suspicious(program):
    fm = program.getFunctionManager()
    wanted = set(SUSPICIOUS_APIS)
    hits = {}  # entry-point offset -> {"function": fn, "apis": set()}
    for fn in fm.getFunctions(True):
        try:
            called = fn.getCalledFunctions(monitor)
        except Exception:
            continue
        for callee in called:
            name = callee.getName()
            # Ghidra names thunks/imports like "VirtualAllocEx" or
            # "EXT_VirtualAllocEx" depending on the loader; match on the
            # bare API name as a suffix too.
            matched = None
            if name in wanted:
                matched = name
            else:
                for api in wanted:
                    if name.endswith(api):
                        matched = api
                        break
            if matched:
                key = fn.getEntryPoint().getOffset()
                entry = hits.setdefault(key, {"function": fn, "apis": set()})
                entry["apis"].add(matched)

    out = []
    decompiler = None
    try:
        decompiler = DecompInterface()
        decompiler.openProgram(program)
    except Exception:
        decompiler = None
    for key in sorted(hits):
        fn = hits[key]["function"]
        snippet = None
        if decompiler is not None:
            try:
                res = decompiler.decompileFunction(fn, 60, monitor)
                if res and res.decompileCompleted():
                    snippet = res.getDecompiledFunction().getC()
                    if snippet and len(snippet) > MAX_DECOMP_SNIPPET:
                        snippet = snippet[:MAX_DECOMP_SNIPPET] + "\n/* ... truncated ... */"
            except Exception:
                snippet = None
        out.append({
            "function": fn.getName(),
            "address": _addr(fn.getEntryPoint()),
            "apis": sorted(hits[key]["apis"]),
            "decompiled": snippet,
        })
    if decompiler is not None:
        try:
            decompiler.dispose()
        except Exception:
            pass
    return out


def export_string_hotspots(program, limit=50):
    refs = program.getReferenceManager()
    out = []
    try:
        strings = DefinedDataIterator.definedStrings(program)
        for data in strings:
            try:
                count = refs.getReferenceCountTo(data.getAddress())
                if count <= 0:
                    continue
                value = data.getValue()
                out.append({
                    "value": str(value)[:300],
                    "address": _addr(data.getAddress()),
                    "references": int(count),
                })
            except Exception:
                continue
    except Exception:
        pass
    out.sort(key=lambda item: -item["references"])
    return out[:limit]


def main():
    args = getScriptArgs()
    if not args:
        printerr("export_analysis.py: expected output JSON path as script arg")
        return
    out_path = args[0]
    program = currentProgram
    doc = {
        "program": {
            "name": program.getName(),
            "language": str(program.getLanguageID()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
            "executable_format": str(program.getExecutableFormat()),
        },
        "functions": export_functions(program),
        "imports": export_imports(program),
        "suspicious_calls": export_suspicious(program),
        "string_hotspots": export_string_hotspots(program),
    }
    fh = open(out_path, "w")
    try:
        fh.write(json.dumps(doc, indent=1))
    finally:
        fh.close()
    print("export_analysis: wrote %s (%d functions, %d imports, "
          "%d suspicious callers)" % (out_path, len(doc["functions"]),
                                      len(doc["imports"]),
                                      len(doc["suspicious_calls"])))


main()
