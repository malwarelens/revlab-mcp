"""Unit tests for config loopback/token rules and session edge cases.

The token rule in ``config.py`` is the platform's hard security rule:
binding to a non-loopback address requires ``RELAB_TOKEN``. The three
cases in ``test_units.py`` pin the default host, ``0.0.0.0`` and one
LAN address; these tests pin the remaining spellings an operator can
actually type -- ``localhost`` in either case, IPv6 ``::1``, the rest
of 127.0.0.0/8, and a plain hostname (not an IP literal, so not
provably loopback and therefore token-gated) -- plus the empty-string
env fallback and the inbox / audit-log plumbing.

``sessions.py`` is likewise only exercised on its happy path in
``test_units.py``; here we pin unknown-session errors on every entry
point, corrupt-state recovery, Frida attach de-duplication and the
defaults of a freshly created session.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config import load_config  # noqa: E402
from sessions import SessionManager  # noqa: E402

_RELAB_KEYS = (
    "RELAB_HOST", "RELAB_PORT", "RELAB_TOKEN", "RELAB_SAMPLES_DIR",
    "RELAB_ARTIFACTS_DIR", "RELAB_X64DBG_BRIDGE_URL", "RELAB_PESIEVE_PATH",
    "RELAB_INBOX_DIR", "RELAB_AUDIT_LOG",
)


def _clean_env(monkeypatch, tmp_path):
    for key in _RELAB_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("RELAB_SAMPLES_DIR", str(tmp_path / "samples"))
    monkeypatch.setenv("RELAB_ARTIFACTS_DIR", str(tmp_path / "artifacts"))


# ---------------------------------------------------------------------------
# config: loopback spellings never require a token
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host", [
    "localhost", "LOCALHOST", "LocalHost",
    "127.0.0.1", "127.0.0.2", "127.255.255.254", "::1",
])
def test_config_loopback_spellings_without_token_ok(monkeypatch, tmp_path, host):
    _clean_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RELAB_HOST", host)
    cfg = load_config()
    assert cfg.host == host
    assert cfg.token is None


@pytest.mark.parametrize("host", [
    "0.0.0.0", "::", "192.168.56.10", "10.0.0.5", "analysis-host",
    "host.example.lan",
])
def test_config_non_loopback_spellings_without_token_refused(
        monkeypatch, tmp_path, host):
    # A plain hostname is not an IP literal, so it can never be proven
    # loopback: the conservative refusal is the intended behaviour.
    _clean_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RELAB_HOST", host)
    with pytest.raises(SystemExit):
        load_config()


def test_config_hostname_with_token_ok(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RELAB_HOST", "analysis-host")
    monkeypatch.setenv("RELAB_TOKEN", "tok")
    cfg = load_config()
    assert cfg.host == "analysis-host"
    assert cfg.token == "tok"


def test_config_empty_and_blank_env_fall_back_to_defaults(
        monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RELAB_HOST", "")
    monkeypatch.setenv("RELAB_TOKEN", "   ")
    monkeypatch.setenv("RELAB_PORT", "")
    cfg = load_config()
    assert cfg.host == "127.0.0.1"
    assert cfg.token is None
    assert cfg.port == 8765


def test_config_inbox_and_audit_plumbing(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    assert load_config().inbox_dir is None  # unset -> scan_inbox degrades

    monkeypatch.setenv("RELAB_INBOX_DIR", str(tmp_path / "drop"))
    monkeypatch.setenv("RELAB_AUDIT_LOG", str(tmp_path / "custom.jsonl"))
    cfg = load_config()
    assert cfg.inbox_dir == tmp_path / "drop"
    assert cfg.audit_log == tmp_path / "custom.jsonl"
    # Default audit log and sessions file live under the artifacts dir.
    assert cfg.sessions_file == tmp_path / "artifacts" / "sessions.json"
    _clean_env(monkeypatch, tmp_path)
    assert load_config().audit_log == tmp_path / "artifacts" / "audit.jsonl"


# ---------------------------------------------------------------------------
# sessions: edge cases beyond the happy path
# ---------------------------------------------------------------------------

def test_session_create_defaults(tmp_path):
    mgr = SessionManager(tmp_path / "sessions.json")
    s = mgr.create()
    assert s["sample_id"] is None
    assert s["status"] == "open"
    assert s["closed_at"] is None
    assert s["debugger_bridge_session"] is None
    assert s["frida_sessions"] == [] and s["notes"] == []
    assert mgr.list_sessions()[0]["session_id"] == s["session_id"]


def test_session_unknown_id_rejected_everywhere(tmp_path):
    mgr = SessionManager(tmp_path / "sessions.json")
    mgr.create()
    for call in (
        lambda: mgr.get("nope"),
        lambda: mgr.attach_debugger("nope", "bridge-1"),
        lambda: mgr.attach_frida("nope", "frida-1"),
        lambda: mgr.add_note("nope", "hello"),
        lambda: mgr.close("nope"),
    ):
        with pytest.raises(ValueError):
            call()


def test_session_corrupt_state_file_recovers_empty(tmp_path):
    state = tmp_path / "sessions.json"
    state.write_text("{not json", encoding="utf-8")
    mgr = SessionManager(state)
    assert mgr.list_sessions() == []
    s = mgr.create(sample_id="b" * 64)  # still usable, overwrites cleanly
    assert SessionManager(state).get(s["session_id"])["sample_id"] == "b" * 64


def test_session_attach_frida_deduplicates(tmp_path):
    mgr = SessionManager(tmp_path / "sessions.json")
    s = mgr.create()
    mgr.attach_frida(s["session_id"], "frida-1")
    mgr.attach_frida(s["session_id"], "frida-1")
    mgr.attach_frida(s["session_id"], "frida-2")
    assert mgr.get(s["session_id"])["frida_sessions"] == ["frida-1", "frida-2"]
