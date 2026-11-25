"""Pin storage.

A pin is a trust anchor: the fingerprint a human already reviewed. Everything else
in the tool is a comparison against these pins.

Storage is a single JSON file under ``$PINDRIFT_HOME`` (default ``~/.pindrift``).
No database, no daemon, no network. That keeps the trust boundary small enough to
audit in one sitting, which matters for a tool whose job is to be trusted.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import ServerFingerprint

SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def home() -> Path:
    override = os.environ.get("PINDRIFT_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".pindrift"


def pins_path() -> Path:
    return home() / "pins.json"


def _empty() -> dict[str, Any]:
    return {"schema": SCHEMA_VERSION, "created_at": utc_now(), "pins": {}}


def load() -> dict[str, Any]:
    path = pins_path()
    if not path.is_file():
        return _empty()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty()
    if not isinstance(payload, dict) or "pins" not in payload:
        return _empty()
    pins = payload.get("pins")
    if not isinstance(pins, dict):
        payload["pins"] = {}
    return payload


def save(payload: dict[str, Any]) -> Path:
    path = pins_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload.setdefault("schema", SCHEMA_VERSION)
    payload["updated_at"] = utc_now()

    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(path.parent), delete=False, suffix=".tmp"
    )
    try:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    finally:
        handle.close()
    os.replace(handle.name, path)
    return path


def get(server_id: str) -> ServerFingerprint | None:
    entry = load()["pins"].get(server_id)
    if not isinstance(entry, dict):
        return None
    fingerprint = entry.get("fingerprint")
    if not isinstance(fingerprint, dict):
        return None
    return ServerFingerprint.from_dict(fingerprint)


def pinned_ids() -> set[str]:
    return set(load()["pins"].keys())


def put(fingerprint: ServerFingerprint, reason: str = "manual") -> Path:
    payload = load()
    payload["pins"][fingerprint.server_id] = {
        "pinned_at": utc_now(),
        "reason": reason,
        "fingerprint": fingerprint.to_dict(),
    }
    return save(payload)


def put_many(fingerprints: list[ServerFingerprint], reason: str = "manual") -> Path:
    payload = load()
    stamp = utc_now()
    for fingerprint in fingerprints:
        payload["pins"][fingerprint.server_id] = {
            "pinned_at": stamp,
            "reason": reason,
            "fingerprint": fingerprint.to_dict(),
        }
    return save(payload)


def drop(server_id: str) -> bool:
    payload = load()
    if server_id not in payload["pins"]:
        return False
    del payload["pins"][server_id]
    save(payload)
    return True


def pinned_at(server_id: str) -> str | None:
    entry = load()["pins"].get(server_id)
    if isinstance(entry, dict):
        value = entry.get("pinned_at")
        return str(value) if value else None
    return None
