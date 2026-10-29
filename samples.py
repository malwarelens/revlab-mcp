"""Sample store.

Samples live ONLY on the analysis host. An operator drops a file on the
host (or points the tool at an explicit local path on the host), the
sample is copied into the store under its SHA-256 and from then on is
addressed exclusively by that hash.

Hard rules enforced here:
* Sample *content* is never returned by any function in this module --
  only metadata (hashes, size, names, timestamps).
* Sample ids are validated as 64-char lowercase hex, so an id can never
  be a path-traversal payload.
* Stored files are named by hash inside the store directory; the
  original file name is kept as sanitised metadata only, so a hostile
  file name cannot escape the store directory either.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path

_SAMPLE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def is_valid_sample_id(sample_id: str) -> bool:
    return bool(_SAMPLE_ID_RE.match(sample_id or ""))


def _sanitise_name(name: str) -> str:
    cleaned = _UNSAFE_NAME_CHARS.sub("_", Path(name).name)
    return cleaned[:120] or "sample"


def _hash_file(path: Path) -> tuple[str, str, int]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha256.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return sha256.hexdigest(), md5.hexdigest(), size


class SampleStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / "index.json"
        self._lock = threading.Lock()
        self._index: dict[str, dict] = self._load()

    # -- internal ---------------------------------------------------------
    def _load(self) -> dict:
        if self.index_path.is_file():
            try:
                data = json.loads(self.index_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}
            # Valid JSON with the wrong top-level shape (a list, a
            # number, null, ...) is just as corrupt as unparseable
            # JSON: recover empty instead of crashing on .values().
            if not isinstance(data, dict):
                return {}
            # A corrupt entry inside an otherwise valid object is no
            # better: dict(<non-dict>) in list_samples()/get_info()
            # would crash, so drop non-dict entries and keep the rest.
            return {k: v for k, v in data.items() if isinstance(v, dict)}
        return {}

    def _save(self) -> None:
        tmp = self.index_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._index, indent=2), encoding="utf-8")
        tmp.replace(self.index_path)

    # -- public API -------------------------------------------------------
    def register(self, source_path: str) -> dict:
        """Copy a local file on the analysis host into the store.

        `source_path` is an explicit path on the analysis host (typed by
        the operator / agent in the tool call). The file is stored under
        its SHA-256; only metadata is returned.
        """
        src = Path(source_path).expanduser()
        if not src.is_file():
            raise ValueError(f"source is not an existing file on the analysis host: {source_path}")
        src = src.resolve()

        sha256, md5, size = _hash_file(src)
        with self._lock:
            if sha256 in self._index:
                meta = dict(self._index[sha256])
                meta["already_registered"] = True
                return meta

            stored_name = sha256  # content-addressed: cannot traverse
            dest = self.root / stored_name
            if dest.resolve().parent != self.root.resolve():
                raise ValueError("internal error: store path escaped the samples directory")
            shutil.copyfile(src, dest)

            meta = {
                "sample_id": sha256,
                "sha256": sha256,
                "md5": md5,
                "size": size,
                "original_name": _sanitise_name(src.name),
                "source_path": str(src),
                "registered_at": datetime.now(timezone.utc).isoformat(),
            }
            self._index[sha256] = meta
            self._save()
            return dict(meta)

    def list_samples(self) -> list[dict]:
        with self._lock:
            return [dict(m) for m in self._index.values()]

    def get_info(self, sample_id: str) -> dict:
        if not is_valid_sample_id(sample_id):
            raise ValueError(f"invalid sample id (expected 64-char sha256 hex): {sample_id!r}")
        with self._lock:
            meta = self._index.get(sample_id)
        if meta is None:
            raise ValueError(f"unknown sample id: {sample_id}")
        return dict(meta)

    def stored_path(self, sample_id: str) -> Path:
        """Internal use only (triage, debugger launch). Never serialised
        into a tool result as a download -- it is a host-local path."""
        self.get_info(sample_id)  # validates id + existence
        return self.root / sample_id
