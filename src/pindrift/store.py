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

from . import trust
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
    return {"schema": SCHEMA_VERSION, "created_at": utc_now(), "pins": {}, "aliases": {}}


def load_path(path: Path) -> dict[str, Any]:
    """Read a named pin file strictly.

    Used for baselines the caller named explicitly. A corrupt baseline must be an
    error, not an empty pin set: "no pins" silently turns every server into an
    unpinned new discovery, which is exactly the wrong conclusion to act on.
    """
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict) or not isinstance(payload.get("pins"), dict):
        # Callers treat every invalid pin document the same way.
        raise ValueError("not a pindrift pin file (missing a 'pins' object)")  # noqa: TRY004
    return payload


def load(path: Path | None = None) -> dict[str, Any]:
    """Read the pin file, tolerating a missing or unreadable one.

    The implicit home file is allowed to be broken: a half-written or hand-edited
    file should not make every command crash. An explicitly named baseline goes
    through :func:`load_path` instead.
    """
    path = path or pins_path()
    if not path.is_file():
        return _empty()
    try:
        return load_path(path)
    except (OSError, ValueError):
        return _empty()


def save(payload: dict[str, Any], path: Path | None = None) -> Path:
    path = path or pins_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload.setdefault("schema", SCHEMA_VERSION)
    payload["updated_at"] = utc_now()

    # Any write changes updated_at, so an old signature is necessarily stale. Sign
    # the document as it is about to be written, or leave it unsigned when no key is
    # configured. Never keep a signature that does not match its contents.
    payload.pop("signature", None)
    signature = trust.sign(payload)
    if signature is not None:
        payload["signature"] = signature

    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(path.parent), delete=False, suffix=".tmp"
    ) as handle:
        temporary = handle.name
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    return path


def from_payload(payload: dict[str, Any], server_id: str) -> ServerFingerprint | None:
    entry = payload.get("pins", {}).get(server_id)
    if not isinstance(entry, dict):
        return None
    fingerprint = entry.get("fingerprint")
    if not isinstance(fingerprint, dict):
        return None
    return ServerFingerprint.from_dict(fingerprint)


def get(server_id: str, path: Path | None = None) -> ServerFingerprint | None:
    return from_payload(load(path), server_id)


def pinned_ids(path: Path | None = None) -> set[str]:
    return set(load(path)["pins"].keys())


def alias_map(payload: dict[str, Any]) -> dict[str, str]:
    """Every known ``client:name`` alias and the canonical id it belongs to.

    A pin key is always an alias of itself. That is the migration path for pin files
    written before aliases existed: a server pinned as ``cursor:foo`` keeps that id
    even when a client that sorts earlier appears beside it.
    """
    pins = payload.get("pins")
    result: dict[str, str] = (
        {str(key): str(key) for key in pins} if isinstance(pins, dict) else {}
    )
    stored = payload.get("aliases")
    if isinstance(stored, dict):
        for alias, canonical in stored.items():
            alias = str(alias)
            canonical = str(canonical)
            # Ignore dangling mappings so removing a pin cannot resurrect it through
            # an alias that still points at the old id.
            if canonical in result:
                result[alias] = canonical
    return result


def _remember_aliases(payload: dict[str, Any], fingerprint: ServerFingerprint) -> None:
    stored = payload.get("aliases")
    if not isinstance(stored, dict):
        stored = {}
        payload["aliases"] = stored
    for alias in fingerprint.all_aliases:
        if alias:
            stored[alias] = fingerprint.server_id


def _write_document(path: Path | None) -> dict[str, Any]:
    """Document to merge new pins into.

    The implicit home file is read tolerantly; an explicitly named baseline is read
    strictly, so a corrupt team baseline is never overwritten with a fresh one.
    """
    if path is None:
        return load()
    return load_path(path) if path.is_file() else _empty()


def put(
    fingerprint: ServerFingerprint, reason: str = "manual", path: Path | None = None
) -> Path:
    payload = _write_document(path)
    payload["pins"][fingerprint.server_id] = {
        "pinned_at": utc_now(),
        "reason": reason,
        "fingerprint": fingerprint.to_dict(),
    }
    _remember_aliases(payload, fingerprint)
    return save(payload, path)


def put_many(
    fingerprints: list[ServerFingerprint], reason: str = "manual", path: Path | None = None
) -> Path:
    payload = _write_document(path)
    stamp = utc_now()
    for fingerprint in fingerprints:
        payload["pins"][fingerprint.server_id] = {
            "pinned_at": stamp,
            "reason": reason,
            "fingerprint": fingerprint.to_dict(),
        }
        _remember_aliases(payload, fingerprint)
    return save(payload, path)


def drop(server_id: str) -> bool:
    payload = load()
    if server_id not in payload["pins"]:
        return False
    del payload["pins"][server_id]
    stored = payload.get("aliases")
    if isinstance(stored, dict):
        for alias in [a for a, target in stored.items() if str(target) == server_id]:
            del stored[alias]
    save(payload)
    return True


def pinned_at(server_id: str, path: Path | None = None) -> str | None:
    entry = load(path)["pins"].get(server_id)
    if isinstance(entry, dict):
        value = entry.get("pinned_at")
        return str(value) if value else None
    return None
