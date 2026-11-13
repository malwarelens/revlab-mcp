"""Configuration for revlab-mcp.

All configuration comes from environment variables (prefix RELAB_).
See README.md for the full list. The one hard rule enforced here:

    Binding to a non-loopback address REQUIRES RELAB_TOKEN to be set.
    Without a token the server refuses to start on a network interface.
"""

from __future__ import annotations

import ipaddress
import os
import re
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


# A RELAB_HOST value with a trailing :<digits> suffix -- the operator
# put host:port in the wrong variable (e.g. 127.0.0.1:8765, [::1]:8765).
_HOST_PORT_RE = re.compile(r"^(?P<host>\[[^\]]+\]|[^:]+):(?P<port>\d+)$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _looks_like_host_with_port(host: str) -> bool:
    """True when RELAB_HOST carries a :port suffix instead of a bare
    bind address.

    A bare loopback spelling or IP literal is never this (so ``::1``
    and ``::`` are safe: they parse as IP addresses first). Anything
    else shaped as ``<host>:<digits>`` -- an IP, ``localhost``, a
    bracketed IPv6 literal or a plain hostname before the colon --
    is the host:port typo. Unshaped garbage (``1:2:3``, ``not a host``)
    is left to the existing token / bind-time behaviour.
    """
    if _is_loopback(host):
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    match = _HOST_PORT_RE.match(host)
    if not match:
        return False
    inner = match.group("host")
    if inner.startswith("[") and inner.endswith("]"):
        try:
            ipaddress.ip_address(inner[1:-1])
        except ValueError:
            return False
        return True
    if inner.lower() == "localhost":
        return True
    try:
        ipaddress.ip_address(inner)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(inner))


@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 8765
    token: str | None = None
    samples_dir: Path = field(default_factory=lambda: BASE_DIR / "samples")
    artifacts_dir: Path = field(default_factory=lambda: BASE_DIR / "artifacts")
    bridge_url: str | None = None
    pesieve_path: str | None = None
    inbox_dir: Path | None = None
    audit_log_path: Path | None = None

    @property
    def audit_log(self) -> Path:
        return self.audit_log_path or (self.artifacts_dir / "audit.jsonl")

    @property
    def sessions_file(self) -> Path:
        return self.artifacts_dir / "sessions.json"


def _parse_port(raw: str | None) -> int:
    """Parse RELAB_PORT, failing fast with a clear message.

    A typo (``RELAB_PORT=eighty``) used to crash load_config() with a
    bare ValueError traceback, and an out-of-range value (0, 99999)
    only failed later at bind time with a confusing socket error.
    Reject both up front, mirroring the token rule's FATAL +
    SystemExit(2) shape; an unset / blank value falls back to 8765
    via _env().
    """
    try:
        port = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        print(
            "FATAL: RELAB_PORT=%r is not a valid port number "
            "(expected an integer 1-65535)." % (raw,),
            file=sys.stderr,
        )
        raise SystemExit(2)
    if not 1 <= port <= 65535:
        print(
            "FATAL: RELAB_PORT=%d is out of range "
            "(expected an integer 1-65535)." % port,
            file=sys.stderr,
        )
        raise SystemExit(2)
    return port


def load_config() -> Config:
    """Build a Config from the environment, enforcing the token rule."""
    cfg = Config(
        host=_env("RELAB_HOST", "127.0.0.1"),
        port=_parse_port(_env("RELAB_PORT", "8765")),
        token=_env("RELAB_TOKEN"),
        samples_dir=Path(_env("RELAB_SAMPLES_DIR", str(BASE_DIR / "samples"))),
        artifacts_dir=Path(_env("RELAB_ARTIFACTS_DIR", str(BASE_DIR / "artifacts"))),
        bridge_url=_env("RELAB_X64DBG_BRIDGE_URL"),
        pesieve_path=_env("RELAB_PESIEVE_PATH"),
    )
    if inbox := _env("RELAB_INBOX_DIR"):
        cfg.inbox_dir = Path(inbox)
    if audit := _env("RELAB_AUDIT_LOG"):
        cfg.audit_log_path = Path(audit)

    if _looks_like_host_with_port(cfg.host):
        # Same fail-fast shape as _parse_port: a host:port value in
        # RELAB_HOST used to be misread as a non-loopback address
        # (a misleading FATAL about the missing token) or, with a
        # token set, accepted and only failed later at bind time with
        # a confusing socket error. Refuse it before the token rule
        # so the operator gets the real diagnosis.
        print(
            "FATAL: RELAB_HOST=%s looks like a host:port value; "
            "RELAB_HOST takes only the bind address, put the port "
            "in RELAB_PORT instead." % cfg.host,
            file=sys.stderr,
        )
        raise SystemExit(2)

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
