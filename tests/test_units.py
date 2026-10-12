"""Unit tests for revlab-mcp (run: .venv/bin/pytest tests/test_units.py)."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import make_samples  # noqa: E402
from config import load_config  # noqa: E402
from samples import SampleStore  # noqa: E402
from sessions import SessionManager  # noqa: E402
from unpack import carve_pe  # noqa: E402


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def _clean_env(monkeypatch, tmp_path):
    for key in ("RELAB_HOST", "RELAB_PORT", "RELAB_TOKEN", "RELAB_SAMPLES_DIR",
                "RELAB_ARTIFACTS_DIR", "RELAB_X64DBG_BRIDGE_URL",
                "RELAB_PESIEVE_PATH", "RELAB_AUDIT_LOG"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("RELAB_SAMPLES_DIR", str(tmp_path / "samples"))
    monkeypatch.setenv("RELAB_ARTIFACTS_DIR", str(tmp_path / "artifacts"))


def test_config_loopback_without_token_ok(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    cfg = load_config()
    assert cfg.host == "127.0.0.1"
    assert cfg.token is None


def test_config_non_loopback_without_token_refused(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RELAB_HOST", "0.0.0.0")
    with pytest.raises(SystemExit):
        load_config()


def test_config_non_loopback_with_token_ok(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RELAB_HOST", "192.168.1.50")
    monkeypatch.setenv("RELAB_TOKEN", "s3cret")
    monkeypatch.setenv("RELAB_PORT", "9999")
    cfg = load_config()
    assert cfg.token == "s3cret"
    assert cfg.port == 9999


# ---------------------------------------------------------------------------
# sample store
# ---------------------------------------------------------------------------

def test_register_and_lookup(tmp_path):
    paths = make_samples.build_samples(tmp_path / "inbox")
    store = SampleStore(tmp_path / "store")
    meta = store.register(str(paths["pe"]))
    expected_sha = hashlib.sha256(paths["pe"].read_bytes()).hexdigest()
    assert meta["sample_id"] == expected_sha
    assert meta["sha256"] == expected_sha
    assert meta["size"] == paths["pe"].stat().st_size
    # content-addressed storage: the stored file lives inside the store root
    stored = store.stored_path(expected_sha)
    assert stored.parent == (tmp_path / "store")
    assert stored.read_bytes() == paths["pe"].read_bytes()
    # re-registering is idempotent
    again = store.register(str(paths["pe"]))
    assert again["already_registered"] is True
    assert len(store.list_samples()) == 1
    assert store.get_info(expected_sha)["original_name"] == "sample_pe.exe"


def test_register_rejects_missing_and_directory(tmp_path):
    store = SampleStore(tmp_path / "store")
    with pytest.raises(ValueError):
        store.register(str(tmp_path / "does-not-exist.bin"))
    with pytest.raises(ValueError):
        store.register(str(tmp_path))


def test_sample_id_traversal_rejected(tmp_path):
    store = SampleStore(tmp_path / "store")
    for bad in ("../../etc/passwd", "..%2f..%2fetc", "a" * 63, "Z" * 64,
                "", "../" + "a" * 60):
        with pytest.raises(ValueError):
            store.get_info(bad)
        with pytest.raises(ValueError):
            store.stored_path(bad)


def test_register_from_explicit_local_path(tmp_path):
    # A file outside the store (operator's drop folder) can be registered
    # via its explicit local path; it is copied, never referenced in place.
    outside = tmp_path / "drop" / "weird name (1).bin"
    outside.parent.mkdir()
    outside.write_bytes(b"hello revlab")
    store = SampleStore(tmp_path / "store")
    meta = store.register(str(outside))
    assert meta["original_name"] == "weird_name_1_.bin"  # sanitised
    assert store.stored_path(meta["sample_id"]).is_file()


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------

def test_sessions_persist(tmp_path):
    mgr = SessionManager(tmp_path / "sessions.json")
    s = mgr.create(sample_id="a" * 64)
    mgr.attach_debugger(s["session_id"], "bridge-1")
    mgr.attach_frida(s["session_id"], "frida-1")
    mgr.add_note(s["session_id"], "hit CreateFileW breakpoint")
    reloaded = SessionManager(tmp_path / "sessions.json")
    got = reloaded.get(s["session_id"])
    assert got["debugger_bridge_session"] == "bridge-1"
    assert got["frida_sessions"] == ["frida-1"]
    assert got["notes"][0]["note"] == "hit CreateFileW breakpoint"
    closed = reloaded.close(s["session_id"])
    assert closed["status"] == "closed" and closed["closed_at"]


# ---------------------------------------------------------------------------
# carve_pe
# ---------------------------------------------------------------------------

def test_carve_pe_finds_embedded(tmp_path):
    pe = make_samples.build_min_pe()
    blob = b"\xAA" * 100 + pe + b"\xBB" * 37 + b"MZ" + b"\x00" * 10
    carved = carve_pe(blob, tmp_path)
    assert len(carved) == 1
    hit = carved[0]
    assert hit["offset"] == 100
    assert hit["size"] == len(pe)
    assert hit["sha256"] == hashlib.sha256(pe).hexdigest()
    assert Path(hit["path"]).read_bytes() == pe


def test_carve_pe_skips_truncated_and_garbage(tmp_path):
    pe = make_samples.build_min_pe()
    truncated = pe[:-20]
    assert carve_pe(truncated, tmp_path) == []
    assert carve_pe(b"MZ" + b"\x00" * 500, tmp_path) == []
    assert carve_pe(b"no pe here at all", tmp_path) == []
