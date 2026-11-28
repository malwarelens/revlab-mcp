"""Tests for static-triage cache recovery (server.py::run_triage).

A triage run killed mid-write leaves a partial JSON cache file behind,
and a cache file of the wrong top-level shape is one stray write away.
Both used to crash static_triage (and, for the wrong-shape case,
get_strings_summary via triage.get) with an unhandled tool error
instead of recomputing. These tests pin the recovery through the real
server tools, called in-process via FastMCP's call_tool.

The same two shapes can also come out of the recompute path itself:
a triage run that exits 0 while writing partial or wrong-shaped JSON.
That used to leak the raw JSONDecodeError (or serve the bare list,
crashing get_strings_summary) instead of failing cleanly; the last
two tests pin the named failure for that case.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import make_samples  # noqa: E402
import server  # noqa: E402 -- monkeypatched TRIAGE_SCRIPT below
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


def _lab_uncomputed(monkeypatch, tmp_path, payload: str):
    """A server with one registered PE sample and no triage cache yet,
    whose triage script exits 0 while writing `payload` as the cache
    file -- as a triage.py that succeeds yet produces garbage would."""
    script = tmp_path / "fake_triage.py"
    script.write_text(
        "import sys\n"
        "out = sys.argv[sys.argv.index('--json') + 1]\n"
        f"open(out, 'w').write({payload!r})\n"
    )
    monkeypatch.setattr(server, "TRIAGE_SCRIPT", script)
    paths = make_samples.build_samples(tmp_path / "inbox")
    cfg = Config(samples_dir=tmp_path / "samples",
                 artifacts_dir=tmp_path / "artifacts")
    mcp = build_server(cfg)
    meta = _call(mcp, "register_sample", source_path=str(paths["pe"]))
    return mcp, meta["sample_id"]


def test_recomputed_partial_json_is_a_named_failure(monkeypatch, tmp_path):
    """A triage run that exits 0 but writes partial JSON used to leak
    the raw JSONDecodeError out of static_triage / get_strings_summary
    as an unhandled tool error. The failure now names the cache file,
    matching the triage-failed shape."""
    mcp, sample_id = _lab_uncomputed(monkeypatch, tmp_path,
                                     '{"hashes": {"sha256": "abc", ')
    with pytest.raises(Exception, match="unreadable triage cache"):
        _call(mcp, "static_triage", sample_id=sample_id)
    with pytest.raises(Exception, match="unreadable triage cache"):
        _call(mcp, "get_strings_summary", sample_id=sample_id)


def test_recomputed_wrong_shape_cache_is_a_named_failure(monkeypatch,
                                                         tmp_path):
    """A triage run that exits 0 but writes a JSON list used to be
    served verbatim as the triage result by static_triage, and crashed
    get_strings_summary with AttributeError on triage.get. Both now
    fail naming the wrong top-level shape instead."""
    mcp, sample_id = _lab_uncomputed(monkeypatch, tmp_path, "[1, 2, 3]")
    with pytest.raises(Exception, match="wrong top-level shape"):
        _call(mcp, "static_triage", sample_id=sample_id)
    with pytest.raises(Exception, match="wrong top-level shape"):
        _call(mcp, "get_strings_summary", sample_id=sample_id)


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


@pytest.mark.parametrize("bad_strings", ["hand-edited", 42, None, ["a"]])
def test_malformed_strings_field_in_cache_does_not_crash_summary(
        tmp_path, bad_strings):
    """A valid top-level dict cache is served verbatim, so a
    hand-edited "strings" field of the wrong shape used to crash
    get_strings_summary with AttributeError on .get() ('str' object
    has no attribute 'get'), while static_triage served the same
    cache fine. The summary now treats the malformed field as
    absent and still returns the other fields."""
    mcp, sample_id, cache = _lab(tmp_path)
    cache.write_text(json.dumps({"file_type": "PE", "size": 123,
                                 "strings": bad_strings,
                                 "iocs": {}, "suspicious_apis": {},
                                 "indicators": []}))
    summary = _call(mcp, "get_strings_summary", sample_id=sample_id)
    assert summary["ok"] is True
    assert summary["ascii_string_count"] is None
    assert summary["utf16_string_count"] is None
    assert summary["file_type"] == "PE"
