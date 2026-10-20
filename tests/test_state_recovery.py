"""Unit tests for state-file recovery in samples.py and sessions.py.

Both stores persist their state as a JSON object on disk and already
recover to empty when the file is unparseable. These tests pin the
sibling case: a file that *is* valid JSON but whose top level is not
an object (a truncated write from another tool, a hand-edited file,
a ``null`` placeholder). Previously that payload was returned as-is,
so the first ``list_samples()`` / ``list_sessions()`` call crashed
with ``AttributeError: ... has no attribute 'values'`` instead of
recovering.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from samples import SampleStore  # noqa: E402
from sessions import SessionManager  # noqa: E402

_NON_OBJECT_PAYLOADS = ["[]", "123", "4.5", '"text"', "null", "true"]
_UNPARSEABLE_PAYLOADS = ["{not json", "", "{"]


@pytest.mark.parametrize("payload", _NON_OBJECT_PAYLOADS + _UNPARSEABLE_PAYLOADS)
def test_sample_store_recovers_from_bad_index(tmp_path, payload):
    root = tmp_path / "store"
    root.mkdir()
    (root / "index.json").write_text(payload, encoding="utf-8")
    store = SampleStore(root)
    assert store.list_samples() == []
    # Still usable afterwards: registering writes a clean index.
    src = tmp_path / "drop.bin"
    src.write_bytes(b"hello revlab")
    meta = store.register(str(src))
    reloaded = SampleStore(root)
    assert reloaded.get_info(meta["sample_id"])["sha256"] == meta["sha256"]


@pytest.mark.parametrize("payload", _NON_OBJECT_PAYLOADS + _UNPARSEABLE_PAYLOADS)
def test_session_manager_recovers_from_bad_state(tmp_path, payload):
    state = tmp_path / "sessions.json"
    state.write_text(payload, encoding="utf-8")
    mgr = SessionManager(state)
    assert mgr.list_sessions() == []
    s = mgr.create(sample_id="c" * 64)  # still usable, overwrites cleanly
    assert SessionManager(state).get(s["session_id"])["sample_id"] == "c" * 64


def test_valid_object_state_is_kept(tmp_path):
    # A well-formed object must load untouched (no over-eager reset).
    root = tmp_path / "store"
    src = tmp_path / "a.bin"
    src.write_bytes(b"payload")
    store = SampleStore(root)
    meta = store.register(str(src))
    assert SampleStore(root).list_samples()[0]["sample_id"] == meta["sample_id"]

    state = tmp_path / "sessions.json"
    mgr = SessionManager(state)
    s = mgr.create()
    assert SessionManager(state).get(s["session_id"])["status"] == "open"
