#!/usr/bin/env python3
"""triage.py -- static malware triage helper.

Performs *static* analysis only: it reads the sample's bytes and never
executes, loads, or emulates it. Run it inside an isolated analysis VM.

Features
--------
* MD5 / SHA1 / SHA256 / SHA512 hashes and file-type identification by magic
* ASCII and UTF-16 string extraction
* IOC extraction: URLs, IPv4 addresses, domains, e-mail addresses,
  registry Run-key paths, file paths, suspicious API names
* PE parsing via pefile (architecture, timestamp, sections + entropy,
  imports, imphash, entry point, overlay)
* Optional YARA scanning via yara-python
* Static triage indicators for analyst review

All optional dependencies (pefile, yara-python) degrade gracefully:
the tool still runs and notes what was skipped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from datetime import datetime, timezone

try:
    import pefile  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    pefile = None

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yara = None

TOOL_VERSION = "1.0.0"
HIGH_ENTROPY_THRESHOLD = 7.2

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES = [
    (b"MZ", "PE / DOS executable (MZ header)"),
    (b"\x7fELF", "ELF executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O (32-bit, reverse endian)"),
    (b"\xce\xfa\xed\xfe", "Mach-O (32-bit)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O (64-bit, reverse endian)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O (64-bit)"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal / Java class"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive (also JAR/APK/Office OOXML)"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document (legacy Office)"),
    (b"{\rtf", "RTF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"#!", "Script (shebang)"),
]

MACHINE_TYPES = {
    0x014C: "x86 (32-bit)",
    0x8664: "x86-64 (64-bit)",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
    0x0200: "IA-64",
}

# API names grouped by the behaviour they are commonly associated with.
# This is a triage aid only -- legitimate software uses most of these too.
SUSPICIOUS_APIS = {
    "process_injection": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
        "NtQueueApcThread", "SetThreadContext", "NtMapViewOfSection",
        "OpenProcess",
    ],
    "execution": [
        "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA",
        "CreateProcessW", "system", "ShellExecuteExA", "ShellExecuteExW",
    ],
    "persistence": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
        "RegCreateKeyExW", "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW", "SetWindowsHookExA",
        "SetWindowsHookExW",
    ],
    "network": [
        "InternetOpenA", "InternetOpenW", "InternetConnectA",
        "InternetConnectW", "HttpSendRequestA", "HttpSendRequestW",
        "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen",
        "socket", "connect", "send", "recv", "WSAStartup",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA",
        "CryptAcquireContextW", "BCryptEncrypt", "BCryptDecrypt",
        "BCryptOpenAlgorithmProvider",
    ],
    "anti_analysis": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA",
        "OutputDebugStringW", "GetTickCount", "QueryPerformanceCounter",
    ],
    "dynamic_resolution": [
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LdrLoadDll",
        "VirtualAlloc", "VirtualProtect", "VirtualProtectEx",
    ],
}

FILE_EXTENSION_BLOCKLIST = {
    # NOTE: "com" is deliberately absent -- as a TLD it is far more common
    # than the legacy .com executable extension, and triage candidates are
    # reviewed by an analyst anyway.
    "exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "vbs", "js",
    "jse", "wsf", "wsh", "msi", "txt", "log", "dat", "bin", "tmp", "ini",
    "cfg", "conf", "json", "xml", "html", "htm", "php", "asp", "aspx",
    "jsp", "py", "pyc", "c", "cpp", "h", "hpp", "class", "jar", "zip",
    "rar", "7z", "gz", "tar", "pdf", "doc", "docx", "xls", "xlsx",
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "db", "sqlite",
}

URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")
WIN_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\s\"'<>|]+)")
ENV_PATH_RE = re.compile(r"%[A-Za-z_]+%\\(?:[^\s\"'<>|]+)")
UNIX_PATH_RE = re.compile(r"(?<![\w/])/(?:usr|etc|tmp|var|home|opt|bin|sbin)/[^\s\"'<>]+")
RUN_KEY_RE = re.compile(r"CurrentVersion\\Run(Once)?\b", re.IGNORECASE)
ASCII_STR_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_STR_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
UTF16BE_STR_RE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def detect_file_type(data: bytes) -> str:
    for magic, label in MAGIC_SIGNATURES:
        if data.startswith(magic):
            return label
    if data:
        sample = data[:4096]
        printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127)
        if printable / len(sample) > 0.9:
            return "Text / script (no known magic)"
    return "Unknown binary data"


def extract_strings(data: bytes):
    ascii_strings = [m.group().decode("ascii") for m in ASCII_STR_RE.finditer(data)]
    utf16_strings = []
    for pattern, encoding in ((UTF16LE_STR_RE, "utf-16-le"), (UTF16BE_STR_RE, "utf-16-be")):
        for m in pattern.finditer(data):
            try:
                utf16_strings.append(m.group().decode(encoding))
            except UnicodeDecodeError:
                continue
    return ascii_strings, utf16_strings


def valid_ipv4(candidate: str) -> bool:
    parts = candidate.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def extract_iocs(strings):
    iocs = {
        "urls": set(),
        "ipv4": set(),
        "domains": set(),
        "emails": set(),
        "run_keys": set(),
        "file_paths": set(),
    }
    for s in strings:
        for url in URL_RE.findall(s):
            iocs["urls"].add(url.rstrip(".,;:"))
        for ip in IPV4_RE.findall(s):
            if valid_ipv4(ip):
                iocs["ipv4"].add(ip)
        for email in EMAIL_RE.findall(s):
            iocs["emails"].add(email)
        for domain in DOMAIN_RE.findall(s):
            tld = domain.rsplit(".", 1)[-1].lower()
            if tld not in FILE_EXTENSION_BLOCKLIST and not valid_ipv4(domain):
                iocs["domains"].add(domain)
        if RUN_KEY_RE.search(s):
            iocs["run_keys"].add(s)
        for path in WIN_PATH_RE.findall(s) + ENV_PATH_RE.findall(s) + UNIX_PATH_RE.findall(s):
            iocs["file_paths"].add(path.rstrip(".,;"))
    return {k: sorted(v) for k, v in iocs.items()}


def find_suspicious_apis(strings, imported_names):
    """Return {category: [api, ...]} found in strings or the import table.

    String matching uses token boundaries so that e.g. "VirtualAlloc" is
    not reported when only "VirtualAllocEx" is present.
    """
    found = {}
    imported_lower = {name.lower() for name in imported_names}
    api_patterns = {}
    for apis in SUSPICIOUS_APIS.values():
        for api in apis:
            api_patterns[api] = re.compile(
                r"(?<![A-Za-z0-9_])" + re.escape(api) + r"(?![A-Za-z0-9])",
                re.IGNORECASE)
    for category, apis in SUSPICIOUS_APIS.items():
        hits = []
        for api in apis:
            if api.lower() in imported_lower:
                hits.append(api)
                continue
            pattern = api_patterns[api]
            if any(pattern.search(s) for s in strings):
                hits.append(api)
        if hits:
            found[category] = sorted(hits)
    return found


# ---------------------------------------------------------------------------
# PE analysis
# ---------------------------------------------------------------------------

def section_flags(characteristics: int) -> str:
    flags = []
    if characteristics & 0x00000020:
        flags.append("CODE")
    if characteristics & 0x00000040:
        flags.append("IDATA")
    if characteristics & 0x20000000:
        flags.append("EXEC")
    if characteristics & 0x40000000:
        flags.append("READ")
    if characteristics & 0x80000000:
        flags.append("WRITE")
    return ",".join(flags) if flags else "-"


def analyze_pe(path: str, file_size: int):
    info = {"available": pefile is not None}
    if pefile is None:
        info["error"] = "pefile is not installed; PE parsing skipped"
        return info
    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception as exc:
        info["is_pe"] = False
        info["error"] = f"pefile could not parse this file: {exc}"
        return info

    info["is_pe"] = True
    machine = pe.FILE_HEADER.Machine
    info["machine"] = MACHINE_TYPES.get(machine, f"unknown (0x{machine:04x})")
    info["machine_raw"] = f"0x{machine:04x}"
    timestamp = pe.FILE_HEADER.TimeDateStamp
    info["timestamp_raw"] = timestamp
    try:
        info["timestamp_utc"] = datetime.fromtimestamp(
            timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        info["timestamp_utc"] = "invalid"
    info["entry_point_rva"] = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}"
    info["image_base"] = f"0x{pe.OPTIONAL_HEADER.ImageBase:x}"
    info["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
    info["num_sections"] = pe.FILE_HEADER.NumberOfSections

    sections = []
    for section in pe.sections:
        raw_size = section.SizeOfRawData
        sections.append({
            "name": section.Name.decode("utf-8", "replace").strip("\x00") or "(unnamed)",
            "virtual_size": section.Misc_VirtualSize,
            "virtual_address": f"0x{section.VirtualAddress:08x}",
            "raw_size": raw_size,
            "entropy": round(section.get_entropy(), 3),
            "flags": section_flags(section.Characteristics),
        })
    info["sections"] = sections

    imports = {}
    imported_names = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", "replace") if entry.dll else "(unknown dll)"
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode("utf-8", "replace")
                else:
                    name = f"ordinal_{imp.ordinal}"
                funcs.append(name)
                imported_names.append(name)
            imports[dll] = sorted(funcs)
    info["imports"] = imports
    info["imported_functions"] = imported_names
    try:
        info["imphash"] = pe.get_imphash()
    except Exception:
        info["imphash"] = None

    overlay_offset = pe.get_overlay_data_start_offset()
    info["overlay_size"] = (file_size - overlay_offset) if overlay_offset else 0
    pe.close()
    return info


# ---------------------------------------------------------------------------
# YARA scanning
# ---------------------------------------------------------------------------

def run_yara(data: bytes, rules_dir: str | None):
    result = {"available": yara is not None, "matches": []}
    if yara is None:
        result["note"] = "yara-python is not installed; YARA scan skipped"
        return result
    if not rules_dir:
        result["note"] = "no rules directory provided; YARA scan skipped"
        return result
    if not os.path.isdir(rules_dir):
        result["note"] = f"rules directory not found: {rules_dir}; YARA scan skipped"
        return result
    rule_files = {}
    for name in sorted(os.listdir(rules_dir)):
        if name.lower().endswith((".yar", ".yara")):
            stem = os.path.splitext(name)[0]
            namespace = re.sub(r"\W", "_", stem)
            rule_files[namespace] = os.path.join(rules_dir, name)
    if not rule_files:
        result["note"] = f"no .yar/.yara files in {rules_dir}; YARA scan skipped"
        return result
    try:
        rules = yara.compile(filepaths=rule_files)
    except Exception as exc:
        result["note"] = f"YARA rule compilation failed: {exc}"
        return result
    result["rules_loaded"] = sorted(rule_files)
    try:
        matches = rules.match(data=data)
    except Exception as exc:
        result["note"] = f"YARA scan failed: {exc}"
        return result
    for match in matches:
        result["matches"].append({
            "rule": match.rule,
            "namespace": match.namespace,
            "description": (match.meta or {}).get("description", ""),
        })
    return result


# ---------------------------------------------------------------------------
# Triage indicators
# ---------------------------------------------------------------------------

def build_indicators(results):
    """Static observations for analyst review -- NOT a detection verdict."""
    indicators = []
    pe = results.get("pe", {})
    iocs = results.get("iocs", {})
    apis = results.get("suspicious_apis", {})

    if pe.get("is_pe"):
        for section in pe.get("sections", []):
            if section["entropy"] > HIGH_ENTROPY_THRESHOLD and section["raw_size"] > 0:
                indicators.append(
                    f"Section '{section['name']}' has high entropy "
                    f"({section['entropy']}), which can indicate packed or "
                    "encrypted content (also common in installers and "
                    "protected commercial software).")
            if "EXEC" in section["flags"] and "WRITE" in section["flags"]:
                indicators.append(
                    f"Section '{section['name']}' is both writable and "
                    "executable (RWX), which is unusual for ordinary "
                    "compiler output.")
        if pe.get("overlay_size"):
            indicators.append(
                f"{pe['overlay_size']} bytes of overlay data appended after "
                "the last section; overlays are used by installers/SFX "
                "archives and also to hide extra payloads.")
        ts = pe.get("timestamp_raw", 0)
        if ts == 0:
            indicators.append("PE compile timestamp is zero (often stripped "
                              "or forged; many packers zero it).")
        elif pe.get("timestamp_utc") != "invalid":
            ts_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            if ts_dt > datetime.now(timezone.utc):
                indicators.append(
                    f"PE compile timestamp ({pe['timestamp_utc']}) is in "
                    "the future, which suggests a forged timestamp.")

    if iocs.get("run_keys"):
        indicators.append(
            "Strings reference the registry Run/RunOnce keys, a common "
            "persistence location.")
    if iocs.get("urls") or iocs.get("ipv4"):
        indicators.append(
            "Network indicators (URLs / IPv4 addresses) were found in "
            "strings; check whether they are contacted at runtime.")
    for category in ("process_injection", "anti_analysis", "persistence", "network", "crypto"):
        if category in apis:
            indicators.append(
                f"References to {category.replace('_', ' ')}-associated "
                f"APIs: {', '.join(apis[category])}.")
    for match in results.get("yara", {}).get("matches", []):
        indicators.append(
            f"YARA rule matched: {match['rule']} "
            f"({match.get('description') or 'no description'}).")
    if not indicators:
        indicators.append("No notable static indicators were identified by "
                          "the checks above. This does not mean the file is "
                          "benign; dynamic analysis may reveal more.")
    return indicators


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_markdown(r):
    lines = []
    lines.append("# Static Triage Report")
    lines.append("")
    lines.append(f"- **File:** `{r['file_name']}`")
    lines.append(f"- **Path analysed:** `{r['path']}`")
    lines.append(f"- **Analysed (UTC):** {r['analysed_utc']}")
    lines.append(f"- **Tool:** triage.py {TOOL_VERSION}")
    lines.append("")
    lines.append("> Static analysis only -- the sample was never executed. "
                 "Indicators below are observations for analyst review, "
                 "**not a detection verdict**.")
    lines.append("")

    lines.append("## File identification")
    lines.append("")
    lines.append(f"- Size: {r['size']} bytes")
    lines.append(f"- Type (magic): {r['file_type']}")
    lines.append(f"- Overall entropy: {r['entropy']}")
    lines.append("")

    lines.append("## Hashes")
    lines.append("")
    for algo, digest in r["hashes"].items():
        lines.append(f"- {algo.upper()}: `{digest}`")
    lines.append("")

    lines.append("## Strings")
    lines.append("")
    lines.append(f"- ASCII strings: {r['strings']['ascii_count']}")
    lines.append(f"- UTF-16 strings: {r['strings']['utf16_count']}")
    lines.append("")

    pe = r["pe"]
    lines.append("## PE analysis")
    lines.append("")
    if not pe.get("available"):
        lines.append(f"- Skipped: {pe.get('error', 'pefile unavailable')}")
    elif not pe.get("is_pe"):
        lines.append(f"- Not a parseable PE: {pe.get('error', 'n/a')}")
    else:
        lines.append(f"- Architecture: {pe['machine']} ({pe['machine_raw']})")
        lines.append(f"- Compile timestamp: {pe['timestamp_utc']} (raw {pe['timestamp_raw']})")
        lines.append(f"- Entry point RVA: {pe['entry_point_rva']}")
        lines.append(f"- Image base: {pe['image_base']}")
        lines.append(f"- Subsystem: {pe['subsystem']}")
        lines.append(f"- Imphash: `{pe['imphash']}`" if pe.get("imphash") else "- Imphash: n/a")
        lines.append(f"- Overlay size: {pe['overlay_size']} bytes")
        lines.append("")
        lines.append("### Sections")
        lines.append("")
        lines.append("| Name | VirtSize | RawSize | Entropy | Flags |")
        lines.append("|------|----------|---------|---------|-------|")
        for s in pe["sections"]:
            lines.append(f"| {s['name']} | {s['virtual_size']} | {s['raw_size']} "
                         f"| {s['entropy']} | {s['flags']} |")
        lines.append("")
        lines.append("### Imports")
        lines.append("")
        if pe["imports"]:
            for dll, funcs in pe["imports"].items():
                lines.append(f"- **{dll}** ({len(funcs)}): {', '.join(funcs)}")
        else:
            lines.append("- No import directory entries parsed.")
    lines.append("")

    lines.append("## Extracted IOCs (from strings)")
    lines.append("")
    labels = {
        "urls": "URLs",
        "ipv4": "IPv4 addresses",
        "domains": "Domains",
        "emails": "E-mail addresses",
        "run_keys": "Registry Run-key references",
        "file_paths": "File paths",
    }
    for key, label in labels.items():
        values = r["iocs"].get(key, [])
        lines.append(f"### {label} ({len(values)})")
        lines.append("")
        if values:
            for value in values:
                lines.append(f"- `{value}`")
        else:
            lines.append("- none")
        lines.append("")

    lines.append("## Suspicious API references")
    lines.append("")
    if r["suspicious_apis"]:
        lines.append("Found in strings and/or the import table. Most of these "
                     "APIs are dual-use and appear in legitimate software.")
        lines.append("")
        for category, apis in sorted(r["suspicious_apis"].items()):
            lines.append(f"- **{category}**: {', '.join(apis)}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## YARA scan")
    lines.append("")
    y = r["yara"]
    if not y.get("available"):
        lines.append(f"- Skipped: {y.get('note', 'yara-python unavailable')}")
    elif y.get("note"):
        lines.append(f"- Skipped: {y['note']}")
    else:
        lines.append(f"- Rules loaded: {', '.join(y.get('rules_loaded', []))}")
        if y["matches"]:
            for match in y["matches"]:
                desc = f" -- {match['description']}" if match.get("description") else ""
                lines.append(f"- **MATCH** `{match['rule']}`{desc}")
        else:
            lines.append("- No rule matches.")
    lines.append("")

    lines.append("## Static triage indicators (analyst review)")
    lines.append("")
    for indicator in r["indicators"]:
        lines.append(f"- {indicator}")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by triage.py -- static indicators only, not a "
                 "detection verdict.*")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def analyse(path: str, rules_dir: str | None) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()

    hashes = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }

    ascii_strings, utf16_strings = extract_strings(data)
    all_strings = ascii_strings + utf16_strings
    iocs = extract_iocs(all_strings)

    pe_info = analyze_pe(path, len(data)) if data.startswith(b"MZ") else {
        "available": pefile is not None, "is_pe": False,
        "error": "no MZ header; not a PE file",
    }
    imported_names = pe_info.get("imported_functions", []) if pe_info.get("is_pe") else []
    suspicious = find_suspicious_apis(all_strings, imported_names)
    yara_result = run_yara(data, rules_dir)

    results = {
        "file_name": os.path.basename(path),
        "path": os.path.abspath(path),
        "analysed_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "size": len(data),
        "file_type": detect_file_type(data),
        "entropy": round(shannon_entropy(data), 3),
        "hashes": hashes,
        "strings": {
            "ascii_count": len(ascii_strings),
            "utf16_count": len(utf16_strings),
        },
        "pe": pe_info,
        "iocs": iocs,
        "suspicious_apis": suspicious,
        "yara": yara_result,
    }
    results["indicators"] = build_indicators(results)
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Static malware triage: hashes, strings, IOCs, PE "
                    "parsing and YARA -- never executes the sample.")
    parser.add_argument("sample", help="path to the file to analyse")
    parser.add_argument("--rules", default=None,
                        help="directory containing .yar/.yara rules "
                             "(default: ./yara_rules next to this script, "
                             "if it exists)")
    parser.add_argument("--out", default=None,
                        help="write the Markdown report to this path "
                             "(default: print to stdout)")
    parser.add_argument("--json", nargs="?", const="auto", default=None,
                        metavar="PATH",
                        help="also write a JSON report; optionally give a "
                             "path (default: derived from the report path)")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.sample):
        print(f"error: sample not found: {args.sample}", file=sys.stderr)
        return 2

    rules_dir = args.rules
    if rules_dir is None:
        default_rules = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "yara_rules")
        rules_dir = default_rules if os.path.isdir(default_rules) else None

    results = analyse(args.sample, rules_dir)
    report = render_markdown(results)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Markdown report written to {args.out}")
    else:
        print(report)

    if args.json is not None:
        if args.json == "auto":
            base = args.out or (args.sample + ".triage")
            json_path = os.path.splitext(base)[0] + ".json"
        else:
            json_path = args.json
        serialisable = {k: v for k, v in results.items()
                        if k != "pe" or True}
        # imported_functions may be large; keep it, it is plain data.
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(serialisable, fh, indent=2, ensure_ascii=False)
        print(f"JSON report written to {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
