from __future__ import annotations

import json
from pathlib import Path

from pindrift.ui import prefs


def test_defaults_are_saved_and_loaded() -> None:
    values = prefs.defaults()
    values["theme"] = "dark"
    values["timeout"] = 42
    saved = prefs.save(values)
    assert saved["theme"] == "dark"
    assert prefs.load()["timeout"] == 42.0


def test_unknown_keys_are_dropped() -> None:
    saved = prefs.save({"root": str(Path.cwd()), "unknown": "x"})
    assert "unknown" not in saved


def test_corrupt_file_falls_back_to_defaults() -> None:
    path = prefs.prefs_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{broken", encoding="utf-8")
    assert prefs.load() == prefs.defaults()


def test_timeout_is_clamped() -> None:
    saved = prefs.save({"timeout": 9999})
    assert saved["timeout"] == 300.0


def test_invalid_theme_is_ignored() -> None:
    saved = prefs.save({"theme": "neon"})
    assert saved["theme"] != "neon"


def test_saved_file_is_valid_json() -> None:
    prefs.save({"theme": "light"})
    payload = json.loads(prefs.prefs_path().read_text(encoding="utf-8"))
    assert payload["theme"] == "light"
