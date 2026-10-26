"""capa integration: capability detection for registered samples.

capa (https://github.com/mandiant/capa) is an *optional* external tool
on the analysis host. This module locates it, runs it against a sample
file on the host and condenses its JSON output into a capability
summary grouped by MITRE ATT&CK tactic and MBC objective.

Location order:
  1. RELAB_CAPA_PATH environment variable (explicit path to the binary)
  2. `capa` on the host PATH

If capa is not available, run_capa() returns the same structured
"not configured" envelope the other optional integrations use, so the
rest of the platform keeps working. The sample is analysed in place on
the analysis host -- it is never copied anywhere by this module.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

ENV_VAR = "RELAB_CAPA_PATH"
DEFAULT_TIMEOUT = 600


def find_capa() -> str | None:
    """Resolve the capa executable path, or None if not available."""
    explicit = os.environ.get(ENV_VAR)
    if explicit and explicit.strip():
        candidate = Path(explicit.strip()).expanduser()
        return str(candidate) if candidate.is_file() else None
    return shutil.which("capa")


def _clean_attack(entries) -> list[dict]:
    out = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        out.append({
            "id": entry.get("id"),
            "tactic": entry.get("tactic"),
            "technique": entry.get("technique"),
        })
    return out


def _clean_mbc(entries) -> list[dict]:
    out = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        out.append({
            "id": entry.get("id"),
            "objective": entry.get("objective"),
            "behavior": entry.get("behavior"),
        })
    return out


def parse_capa_output(data: dict) -> dict:
    """Condense capa's `-j` JSON document into a grouped summary.

    Returns {capability_count, capabilities, by_attack_tactic,
    by_mbc_objective}. Defensive against schema variations across capa
    versions: anything unexpected is skipped rather than fatal. A
    non-dict document is treated as empty, a non-dict rules section
    is ignored, and a non-dict rule or meta section is treated as
    empty (the rule still counts under its key, as the "broken" case
    already did) instead of crashing on .get() / indexing.
    """
    if not isinstance(data, dict):
        data = {}
    rules = data.get("rules") or {}
    if not isinstance(rules, dict):
        rules = {}
    capabilities: list[dict] = []
    by_tactic: dict[str, list[str]] = {}
    by_objective: dict[str, list[str]] = {}

    for key in sorted(rules):
        rule = rules[key] or {}
        if not isinstance(rule, dict):
            rule = {}
        meta = rule.get("meta") or {}
        if not isinstance(meta, dict):
            meta = {}
        name = meta.get("name") or key
        attack = _clean_attack(meta.get("att&ck"))
        mbc = _clean_mbc(meta.get("mbc"))
        matches = rule.get("matches") or {}
        match_count = len(matches) if isinstance(matches, dict) else 0
        capabilities.append({
            "name": name,
            "namespace": meta.get("namespace"),
            "scope": meta.get("scope"),
            "match_count": match_count,
            "attack": attack,
            "mbc": mbc,
        })
        for entry in attack:
            tactic = entry.get("tactic")
            if tactic:
                by_tactic.setdefault(tactic, [])
                if name not in by_tactic[tactic]:
                    by_tactic[tactic].append(name)
        for entry in mbc:
            objective = entry.get("objective")
            if objective:
                by_objective.setdefault(objective, [])
                if name not in by_objective[objective]:
                    by_objective[objective].append(name)

    return {
        "capability_count": len(capabilities),
        "capabilities": capabilities,
        "by_attack_tactic": {k: sorted(v) for k, v in sorted(by_tactic.items())},
        "by_mbc_objective": {k: sorted(v) for k, v in sorted(by_objective.items())},
    }


def run_capa(sample_path, sample_id: str | None = None,
             timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Run capa against a sample file that lives on the analysis host."""
    exe = find_capa()
    if exe is None:
        return {"ok": False, "configured": False,
                "error": "capa is not available on the analysis host; set "
                         f"{ENV_VAR} to the capa executable or put capa on PATH"}
    try:
        proc = subprocess.run(
            [exe, "-j", str(sample_path)],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "configured": True, "sample_id": sample_id,
                "error": f"capa timed out after {timeout}s"}
    except OSError as exc:
        return {"ok": False, "configured": True, "sample_id": sample_id,
                "error": f"failed to run capa: {exc}"}

    stdout = proc.stdout or ""
    parsed = None
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        start = stdout.find("{")
        if start >= 0:
            try:
                parsed = json.loads(stdout[start:])
            except json.JSONDecodeError:
                parsed = None
    if parsed is None:
        return {"ok": False, "configured": True, "sample_id": sample_id,
                "error": "capa produced no parseable JSON output",
                "returncode": proc.returncode,
                "stderr": (proc.stderr or "")[:2000]}

    result = {"ok": True, "configured": True, "sample_id": sample_id,
              "capa_path": exe, "returncode": proc.returncode}
    result.update(parse_capa_output(parsed))
    return result
