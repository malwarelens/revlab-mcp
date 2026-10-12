"""Unit tests for the capa integration (capa_tools.py).

Uses tests/fake_capa.py -- a script that prints a fixed capa-style
JSON document -- so no real capa installation is needed.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import make_samples  # noqa: E402
import capa_tools  # noqa: E402

FAKE_CAPA = ROOT / "tests" / "fake_capa.py"


@pytest.fixture()
def fake_capa(monkeypatch, tmp_path):
    """An executable copy of the fake capa script + a sample file."""
    exe = tmp_path / "fake_capa.py"
    exe.write_text(FAKE_CAPA.read_text(encoding="utf-8"), encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    sample = make_samples.build_samples(tmp_path / "inbox")["pe"]
    monkeypatch.setenv(capa_tools.ENV_VAR, str(exe))
    return exe, sample


def _no_capa(monkeypatch, tmp_path):
    monkeypatch.delenv(capa_tools.ENV_VAR, raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))  # empty dir: no capa on PATH


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

def test_find_capa_via_env(fake_capa):
    exe, _sample = fake_capa
    assert capa_tools.find_capa() == str(exe)


def test_find_capa_env_points_at_missing_file(monkeypatch, tmp_path):
    monkeypatch.setenv(capa_tools.ENV_VAR, str(tmp_path / "nope"))
    assert capa_tools.find_capa() is None


def test_find_capa_absent(monkeypatch, tmp_path):
    _no_capa(monkeypatch, tmp_path)
    assert capa_tools.find_capa() is None


# ---------------------------------------------------------------------------
# degradation + error handling
# ---------------------------------------------------------------------------

def test_run_capa_not_configured(monkeypatch, tmp_path):
    _no_capa(monkeypatch, tmp_path)
    paths = make_samples.build_samples(tmp_path / "inbox")
    result = capa_tools.run_capa(paths["pe"], sample_id="a" * 64)
    assert result["ok"] is False
    assert result["configured"] is False
    assert capa_tools.ENV_VAR in result["error"]


def test_run_capa_unparseable_output(fake_capa, monkeypatch):
    _exe, sample = fake_capa
    monkeypatch.setenv("FAKE_CAPA_GARBAGE", "1")
    result = capa_tools.run_capa(sample, sample_id="b" * 64)
    assert result["ok"] is False
    assert result["configured"] is True


def test_run_capa_missing_sample(fake_capa, tmp_path):
    result = capa_tools.run_capa(tmp_path / "ghost.bin")
    assert result["ok"] is False
    assert result["configured"] is True


# ---------------------------------------------------------------------------
# happy path through the fake capa
# ---------------------------------------------------------------------------

def test_run_capa_success(fake_capa):
    _exe, sample = fake_capa
    result = capa_tools.run_capa(sample, sample_id="c" * 64)
    assert result["ok"] is True and result["configured"] is True
    assert result["sample_id"] == "c" * 64
    assert result["capability_count"] == 3
    caps = {c["name"]: c for c in result["capabilities"]}
    assert caps["inject code into process"]["match_count"] == 2
    assert caps["inject code into process"]["namespace"] == \
        "host-interaction/process/inject"
    assert result["by_attack_tactic"] == {
        "Defense Evasion": ["inject code into process"],
        "Persistence": ["persist via Run registry key"],
        "Privilege Escalation": ["inject code into process"],
    }
    assert result["by_mbc_objective"] == {
        "Communication": ["encode data with base64"],
        "Persistence": ["persist via Run registry key"],
        "Process": ["inject code into process"],
    }


# ---------------------------------------------------------------------------
# parser robustness
# ---------------------------------------------------------------------------

def test_parse_capa_output_tolerates_gaps():
    summary = capa_tools.parse_capa_output({
        "rules": {
            "bare rule": {"meta": {"name": "bare rule"}},
            "no meta": {"matches": {"1": {}}},
            "broken": None,
        },
    })
    assert summary["capability_count"] == 3
    assert summary["by_attack_tactic"] == {}
    assert summary["by_mbc_objective"] == {}
    names = {c["name"] for c in summary["capabilities"]}
    assert names == {"bare rule", "no meta", "broken"}
