"""Configuration for revlab-mcp.

All configuration comes from environment variables (prefix RELAB_).
See README.md for the full list. The one hard rule enforced here:

    Binding to a non-loopback address REQUIRES RELAB_TOKEN to be set.
    Without a token the server refuses to start on a network interface.
"""

from __future__ import annotations

import ipaddress
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _is_loopback(host: str) -> bool:
    if host.lower() in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 8765
    token: str | None = None
    samples_dir: Path = field(default_factory=lambda: BASE_DIR / "samples")
    artifacts_dir: Path = field(default_factory=lambda: BASE_DIR / "artifacts")
    bridge_url: str | None = None
    pesieve_path: str | None = None
    audit_log_path: Path | None = None

    @property
    def audit_log(self) -> Path:
        return self.audit_log_path or (self.artifacts_dir / "audit.jsonl")

    @property
    def sessions_file(self) -> Path:
        return self.artifacts_dir / "sessions.json"


def load_config() -> Config:
    """Build a Config from the environment, enforcing the token rule."""
    cfg = Config(
        host=_env("RELAB_HOST", "127.0.0.1"),
        port=int(_env("RELAB_PORT", "8765")),
        token=_env("RELAB_TOKEN"),
        samples_dir=Path(_env("RELAB_SAMPLES_DIR", str(BASE_DIR / "samples"))),
        artifacts_dir=Path(_env("RELAB_ARTIFACTS_DIR", str(BASE_DIR / "artifacts"))),
        bridge_url=_env("RELAB_X64DBG_BRIDGE_URL"),
        pesieve_path=_env("RELAB_PESIEVE_PATH"),
    )
    if audit := _env("RELAB_AUDIT_LOG"):
        cfg.audit_log_path = Path(audit)

    if not _is_loopback(cfg.host) and not cfg.token:
        print(
            "FATAL: RELAB_HOST=%s is not a loopback address but RELAB_TOKEN "
            "is not set. Refusing to expose an unauthenticated analysis "
            "server on the network. Set RELAB_TOKEN or bind to 127.0.0.1."
            % cfg.host,
            file=sys.stderr,
        )
        raise SystemExit(2)

    cfg.samples_dir.mkdir(parents=True, exist_ok=True)
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
    return cfg
