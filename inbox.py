"""Sample inbox: bulk-register files dropped into a host directory.

An operator (or a file share / sync job on the analysis host) drops
candidate samples into RELAB_INBOX_DIR. scan_inbox() walks the top
level of that directory and registers every regular file into the
sample store, reporting new registrations, already-known files and
per-file failures separately.

Source files are NEVER deleted or modified -- registration copies the
file into the content-addressed store, and the result only notes that
the source remains in place.
"""

from __future__ import annotations

from pathlib import Path

ENV_VAR = "RELAB_INBOX_DIR"


def scan_inbox(store, inbox_dir) -> dict:
    """Register every top-level file in `inbox_dir` into `store`.

    `store` is a samples.SampleStore; `inbox_dir` a Path or None.
    Returns the platform's structured envelope with per-file detail.
    """
    if inbox_dir is None:
        return {"ok": False, "configured": False,
                "error": f"no sample inbox configured; set {ENV_VAR} on "
                         "the analysis host to a drop directory"}
    root = Path(inbox_dir)
    if not root.is_dir():
        return {"ok": False, "configured": True,
                "error": f"inbox directory does not exist: {root}"}

    new_items: list[dict] = []
    existing_items: list[dict] = []
    failed_items: list[dict] = []
    scanned = 0
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        if not entry.is_file():
            continue  # subdirectories / sockets / broken links: not samples
        scanned += 1
        try:
            meta = store.register(str(entry))
        except Exception as exc:  # noqa: BLE001 - report per file, keep going
            failed_items.append({"path": str(entry), "name": entry.name,
                                 "error": f"{type(exc).__name__}: {exc}"})
            continue
        # "original_name" is the name the sample was FIRST registered
        # under in the store; "name" is this dropped file's own name
        # (they differ when identical bytes arrive under a new name).
        item = {"path": str(entry), "name": entry.name,
                "sample_id": meta["sample_id"],
                "original_name": meta["original_name"],
                "size": meta["size"], "sha256": meta["sha256"]}
        if meta.get("already_registered"):
            existing_items.append(item)
        else:
            new_items.append(item)

    return {
        "ok": True,
        "configured": True,
        "inbox_dir": str(root),
        "scanned": scanned,
        "counts": {"new": len(new_items),
                   "existing": len(existing_items),
                   "failed": len(failed_items)},
        "new": new_items,
        "existing": existing_items,
        "failed": failed_items,
        "note": "source files are left in place; registration copies "
                "them into the sample store",
    }
