from __future__ import annotations

import sys
import types
from pathlib import Path

from pindrift.ui import app as ui_app


def test_assets_are_embedded_and_offline() -> None:
    html = ui_app.build_html()
    assert "Content-Security-Policy" in html
    assert "/*__PINDRIFT_CSS__*/" not in html
    assert "/*__PINDRIFT_JS__*/" not in html
    assert "innerHTML" not in html
    assert "http://" not in html
    assert "https://" not in html
    assert "file://" not in html


def test_create_window_receives_html_not_url(monkeypatch) -> None:
    calls = {}

    def create_window(*args, **kwargs):
        calls["kwargs"] = kwargs
        return object()

    fake = types.SimpleNamespace(
        settings={},
        create_window=create_window,
        start=lambda **kwargs: calls.setdefault("start", kwargs),
        OPEN_DIALOG=object(),
    )
    monkeypatch.setitem(sys.modules, "webview", fake)

    assert ui_app.main(root=Path.cwd()) == 0
    assert "html" in calls["kwargs"]
    assert "url" not in calls["kwargs"]
    assert calls["start"]["debug"] is False
    assert calls["start"]["private_mode"] is True


def test_missing_webview_returns_usage(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "webview", None)
    assert ui_app.main() == 64
