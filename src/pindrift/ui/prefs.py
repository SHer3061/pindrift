"""Persistent preferences for the desktop UI.

Only presentation choices live here. No pins, no secrets, no probe results.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .. import store
from ..models import Severity
from ..probe import DEFAULT_TIMEOUT

THEMES = ("system", "light", "dark")


def prefs_path() -> Path:
    return store.home() / "ui.json"


def defaults() -> dict[str, Any]:
    return {
        "root": str(Path.cwd()),
        "includeProject": True,
        "dedupe": True,
        "timeout": DEFAULT_TIMEOUT,
        "failOn": Severity.HIGH.value,
        "theme": "system",
    }


def sanitise(payload: Any, fallback: dict[str, Any] | None = None) -> dict[str, Any]:
    base = dict(fallback or defaults())
    if not isinstance(payload, dict):
        return base

    root = payload.get("root")
    if isinstance(root, str) and root.strip():
        candidate = Path(root).expanduser()
        if candidate.is_absolute():
            base["root"] = str(candidate)
    if isinstance(payload.get("includeProject"), bool):
        base["includeProject"] = payload["includeProject"]
    if isinstance(payload.get("dedupe"), bool):
        base["dedupe"] = payload["dedupe"]
    timeout = payload.get("timeout")
    if isinstance(timeout, (int, float)) and not isinstance(timeout, bool):
        base["timeout"] = min(max(float(timeout), 1.0), 300.0)
    fail_on = payload.get("failOn")
    if fail_on in {severity.value for severity in Severity}:
        base["failOn"] = fail_on
    theme = payload.get("theme")
    if theme in THEMES:
        base["theme"] = theme
    return base


def load() -> dict[str, Any]:
    path = prefs_path()
    if not path.is_file():
        return defaults()
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return defaults()
    return sanitise(payload)


def save(payload: dict[str, Any]) -> dict[str, Any]:
    current = load()
    cleaned = sanitise(payload, current)
    path = prefs_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(path.parent), delete=False, suffix=".tmp"
    ) as handle:
        temporary = handle.name
        json.dump(cleaned, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    return cleaned
