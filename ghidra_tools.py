"""Ghidra headless integration: function/decompilation summaries.

Ghidra (https://ghidra-sre.org) is an *optional* external tool on the
analysis host. This module locates `analyzeHeadless`, imports a
registered sample into a throwaway project, runs the bundled export
script (ghidra_scripts/export_analysis.py) and condenses its JSON
output into a structured summary: function inventory, import mapping,
functions that call suspicious APIs (with decompiled snippets) and
string-reference hotspots.

Location order:
  1. RELAB_GHIDRA_PATH environment variable -- either the
     analyzeHeadless executable itself or a Ghidra installation
     directory (its support/ subdirectory is searched)
  2. `analyzeHeadless` on the host PATH

If Ghidra is not available, run_ghidra() returns the same structured
"not configured" envelope the other optional integrations use. The
sample is imported from its store path on the analysis host -- never
copied anywhere else -- and the temporary project is deleted
afterwards (-deleteProject plus a TemporaryDirectory).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ENV_VAR = "RELAB_GHIDRA_PATH"
SCRIPTS_DIR = Path(__file__).resolve().parent / "ghidra_scripts"
EXPORT_SCRIPT = "export_analysis.py"
DEFAULT_TIMEOUT = 1800

MAX_FUNCTIONS_RETURNED = 200
MAX_IMPORTS_RETURNED = 300
MAX_SUSPICIOUS_RETURNED = 25
MAX_SNIPPET_CHARS = 2400
MAX_HOTSPOTS_RETURNED = 25


def _headless_in(install_dir: Path) -> Path | None:
    for candidate in (install_dir / "support" / "analyzeHeadless",
                      install_dir / "support" / "analyzeHeadless.bat",
                      install_dir / "analyzeHeadless",
                      install_dir / "analyzeHeadless.bat"):
        if candidate.is_file():
            return candidate
    return None


def find_ghidra() -> str | None:
    """Resolve the analyzeHeadless executable path, or None."""
    explicit = os.environ.get(ENV_VAR)
    if explicit and explicit.strip():
        candidate = Path(explicit.strip()).expanduser()
        if candidate.is_file():
            return str(candidate)
        if candidate.is_dir():
            found = _headless_in(candidate)
            if found is not None:
                return str(found)
        return None
    return shutil.which("analyzeHeadless")


def parse_ghidra_output(data: dict) -> dict:
    """Condense export_analysis.py's JSON document into a summary.

    Returns {function_count, functions, import_count, imports,
    suspicious_functions, string_hotspots}. Long lists are capped
    (with a *_truncated flag); decompiled snippets are truncated.
    Defensive against schema variations: unexpected items are skipped,
    a non-dict document is treated as empty, non-list sections are
    ignored, and a hotspot whose references count is not numeric sorts
    as zero instead of crashing the sort (a string count would make
    the unary minus raise TypeError).
    """
    if not isinstance(data, dict):
        data = {}
    functions_in = data.get("functions") or []
    if not isinstance(functions_in, list):
        functions_in = []
    functions = []
    for fn in functions_in:
        if not isinstance(fn, dict):
            continue
        functions.append({
            "name": fn.get("name"),
            "address": fn.get("address"),
            "size": fn.get("size"),
            "signature": fn.get("signature"),
        })

    imports_in = data.get("imports") or []
    if not isinstance(imports_in, list):
        imports_in = []
    imports = []
    for imp in imports_in:
        if not isinstance(imp, dict):
            continue
        imports.append({
            "name": imp.get("name"),
            "library": imp.get("library"),
            "address": imp.get("address"),
        })

    suspicious_in = data.get("suspicious_calls") or []
    if not isinstance(suspicious_in, list):
        suspicious_in = []
    suspicious = []
    for hit in suspicious_in:
        if not isinstance(hit, dict):
            continue
        snippet = hit.get("decompiled")
        if isinstance(snippet, str) and len(snippet) > MAX_SNIPPET_CHARS:
            snippet = snippet[:MAX_SNIPPET_CHARS] + "\n/* ... truncated ... */"
        apis_in = hit.get("apis")
        if isinstance(apis_in, str):
            apis = [apis_in]
        elif isinstance(apis_in, (list, tuple)):
            apis = list(apis_in)
        else:
            apis = []
        suspicious.append({
            "function": hit.get("function"),
            "address": hit.get("address"),
            "apis": apis,
            "decompiled": snippet,
        })

    hotspots_in = data.get("string_hotspots") or []
    if not isinstance(hotspots_in, list):
        hotspots_in = []
    hotspots = []
    for spot in hotspots_in:
        if not isinstance(spot, dict):
            continue
        hotspots.append({
            "value": spot.get("value"),
            "address": spot.get("address"),
            "references": spot.get("references"),
        })

    def _hotspot_rank(item: dict) -> int | float:
        refs = item.get("references")
        if isinstance(refs, bool) or not isinstance(refs, (int, float)):
            return 0
        return -refs

    hotspots.sort(key=_hotspot_rank)

    return {
        "program": data.get("program"),
        "function_count": len(functions),
        "functions": functions[:MAX_FUNCTIONS_RETURNED],
        "functions_truncated": len(functions) > MAX_FUNCTIONS_RETURNED,
        "import_count": len(imports),
        "imports": imports[:MAX_IMPORTS_RETURNED],
        "imports_truncated": len(imports) > MAX_IMPORTS_RETURNED,
        "suspicious_functions": suspicious[:MAX_SUSPICIOUS_RETURNED],
        "suspicious_count": len(suspicious),
        "string_hotspots": hotspots[:MAX_HOTSPOTS_RETURNED],
    }


def run_ghidra(sample_path, sample_id: str | None = None,
               timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Run Ghidra headless analysis against a sample on the host."""
    exe = find_ghidra()
    if exe is None:
        return {"ok": False, "configured": False,
                "error": "Ghidra headless is not available on the analysis "
                         f"host; set {ENV_VAR} to the analyzeHeadless "
                         "executable (or Ghidra install directory), or put "
                         "analyzeHeadless on PATH"}
    if not (SCRIPTS_DIR / EXPORT_SCRIPT).is_file():
        return {"ok": False, "configured": True, "sample_id": sample_id,
                "error": f"bundled export script missing: "
                         f"{SCRIPTS_DIR / EXPORT_SCRIPT}"}

    with tempfile.TemporaryDirectory(prefix="revlab-ghidra-") as tmp:
        tmpdir = Path(tmp)
        project_dir = tmpdir / "project"
        project_dir.mkdir()
        out_json = tmpdir / "export.json"
        cmd = [exe, str(project_dir), "revlab_tmp",
               "-import", str(sample_path),
               "-scriptPath", str(SCRIPTS_DIR),
               "-postScript", EXPORT_SCRIPT, str(out_json),
               "-deleteProject"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"ok": False, "configured": True, "sample_id": sample_id,
                    "error": f"Ghidra headless timed out after {timeout}s"}
        except OSError as exc:
            return {"ok": False, "configured": True, "sample_id": sample_id,
                    "error": f"failed to run analyzeHeadless: {exc}"}

        if not out_json.is_file():
            return {"ok": False, "configured": True, "sample_id": sample_id,
                    "error": "Ghidra produced no export JSON "
                             "(analysis or export script failed)",
                    "returncode": proc.returncode,
                    "stderr": (proc.stderr or "")[-2000:],
                    "stdout_tail": (proc.stdout or "")[-2000:]}
        try:
            parsed = json.loads(out_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            return {"ok": False, "configured": True, "sample_id": sample_id,
                    "error": f"Ghidra export JSON unreadable: {exc}"}

    result = {"ok": True, "configured": True, "sample_id": sample_id,
              "ghidra_path": exe, "returncode": proc.returncode}
    result.update(parse_ghidra_output(parsed))
    return result
