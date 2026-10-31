"""Tests for static-triage cache recovery (server.py::run_triage).

A triage run killed mid-write leaves a partial JSON cache file behind,
and a cache file of the wrong top-level shape is one stray write away.
Both used to crash static_triage (and, for the wrong-shape case,
get_strings_summary via triage.get) with an unhandled tool error
instead of recomputing. These tests pin the recovery through the real
server tools, called in-process via FastMCP's call_tool.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import make_samples  # noqa: E402
from config import Config  # noqa: E402
from server import build_server  # noqa: E402


def _call(mcp, name, **kwargs):
    async def _run():
        res = await mcp.call_tool(name, kwargs)
        assert res and res[0].text, f"{name} returned no content"
        return json.loads(res[0].text)

    return asyncio.run(_run())


def _lab(tmp_path):
    """A server with one registered PE sample and its triage cached."""
    paths = make_samples.build_samples(tmp_path / "inbox")
    cfg = Config(samples_dir=tmp_path / "samples",
                 artifacts_dir=tmp_path / "artifacts")
    mcp = build_server(cfg)
    meta = _call(mcp, "register_sample", source_path=str(paths["pe"]))
    sample_id = meta["sample_id"]
    first = _call(mcp, "static_triage", sample_id=sample_id)
    assert first["ok"] is True
    assert first["triage"]["hashes"]["sha256"] == sample_id
    cache = tmp_path / "artifacts" / "triage" / f"{sample_id}.json"
    assert cache.is_file()
    return mcp, sample_id, cache


def test_partial_json_cache_is_recomputed(tmp_path):
    mcp, sample_id, cache = _lab(tmp_path)
    # Partial write, as from a triage run killed mid-write.
    cache.write_text('{"hashes": {"sha256": "abc", ')
    again = _call(mcp, "static_triage", sample_id=sample_id)
    assert again["ok"] is True
    assert again["triage"]["hashes"]["sha256"] == sample_id
    # The bad file is replaced by a valid cache.
    assert json.loads(cache.read_text())["hashes"]["sha256"] == sample_id


def test_wrong_shape_cache_is_recomputed(tmp_path):
    mcp, sample_id, cache = _lab(tmp_path)
    cache.write_text("[1, 2, 3]")
    again = _call(mcp, "static_triage", sample_id=sample_id)
    assert again["ok"] is True
    assert again["triage"]["hashes"]["sha256"] == sample_id
    # ... and the downstream consumer no longer crashes on it either.
    summary = _call(mcp, "get_strings_summary", sample_id=sample_id)
    assert summary["ok"] is True
    assert summary["ascii_string_count"] > 0


def test_valid_dict_cache_is_still_served(tmp_path):
    mcp, sample_id, cache = _lab(tmp_path)
    cache.write_text(json.dumps({"marker": "from-cache",
                                 "hashes": {"sha256": sample_id}}))
    served = _call(mcp, "static_triage", sample_id=sample_id)
    assert served["triage"]["marker"] == "from-cache"
