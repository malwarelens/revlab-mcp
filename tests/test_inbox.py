"""Tests for the sample inbox scanner (inbox.py) and the Config
RELAB_INBOX_DIR wiring."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import inbox as inbox_mod  # noqa: E402
from config import load_config  # noqa: E402
from samples import SampleStore  # noqa: E402


@pytest.fixture()
def store(tmp_path):
    return SampleStore(tmp_path / "samples")


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def test_scan_inbox_unconfigured(store):
    result = inbox_mod.scan_inbox(store, None)
    assert result["ok"] is False
    assert result["configured"] is False
    assert "RELAB_INBOX_DIR" in result["error"]


def test_scan_inbox_missing_directory(store, tmp_path):
    result = inbox_mod.scan_inbox(store, tmp_path / "nope")
    assert result["ok"] is False
    assert result["configured"] is True


def test_scan_inbox_new_existing_failed(store, tmp_path):
    box = tmp_path / "inbox"
    box.mkdir()
    first = _write(box / "a.bin", b"AAAA")
    second = _write(box / "b.bin", b"BBBB")
    _write(box / "a-copy.bin", b"AAAA")          # same bytes as a.bin
    (box / "subdir").mkdir()                    # must be skipped
    _write(box / "subdir" / "nested.bin", b"CCCC")

    # Pre-register b.bin so it shows up as "existing".
    store.register(str(second))

    result = inbox_mod.scan_inbox(store, box)
    assert result["ok"] is True
    assert result["scanned"] == 3
    assert result["counts"] == {"new": 1, "existing": 2, "failed": 0}
    # Sorted scan order registers a-copy.bin first (it is the "new"
    # one); a.bin then hashes to the same sample and counts existing.
    assert result["new"][0]["name"] == "a-copy.bin"
    existing_names = {item["name"] for item in result["existing"]}
    assert existing_names == {"a.bin", "b.bin"}
    # Source files are never deleted or modified.
    assert first.is_file() and second.is_file()
    # Everything scannable is now in the store (a/b only).
    assert len(store.list_samples()) == 2


def test_scan_inbox_reports_per_file_failures(store, tmp_path, monkeypatch):
    box = tmp_path / "inbox"
    box.mkdir()
    _write(box / "good.bin", b"GGGG")
    _write(box / "bad.bin", b"BBBB")

    real_register = store.register

    def flaky_register(path):
        if path.endswith("bad.bin"):
            raise ValueError("simulated registration failure")
        return real_register(path)

    monkeypatch.setattr(store, "register", flaky_register)
    result = inbox_mod.scan_inbox(store, box)
    assert result["counts"] == {"new": 1, "existing": 0, "failed": 1}
    assert result["failed"][0]["name"] == "bad.bin"
    assert "simulated" in result["failed"][0]["error"]


def test_config_inbox_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("RELAB_HOST", "127.0.0.1")
    monkeypatch.setenv("RELAB_SAMPLES_DIR", str(tmp_path / "samples"))
    monkeypatch.setenv("RELAB_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("RELAB_INBOX_DIR", str(tmp_path / "inbox"))
    cfg = load_config()
    assert cfg.inbox_dir == tmp_path / "inbox"
