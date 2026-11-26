"""pywebview launcher for the desktop UI."""

from __future__ import annotations

import sys
from importlib.resources import files
from pathlib import Path

from ..models import Severity
from . import controller
from . import prefs as prefs_store
from .bridge import PindriftApi

EXIT_USAGE = 64


def _asset(name: str) -> str:
    return (files("pindrift.ui.web") / name).read_text(encoding="utf-8")


def build_html() -> str:
    shell = _asset("index.html")
    return shell.replace("/*__PINDRIFT_CSS__*/", _asset("app.css")).replace(
        "/*__PINDRIFT_JS__*/", _asset("app.js")
    )


def _hint() -> str:
    return (
        "Install the desktop extra, then retry:\n"
        '  pipx install "pindrift[desktop]"\n'
        "Linux also needs a WebView backend:\n"
        '  pipx inject pindrift "pywebview[qt]"\n'
        "  (or install WebKitGTK / python3-gi)"
    )


def main(
    root: Path | None = None,
    include_project: bool | None = None,
    dedupe: bool | None = None,
) -> int:
    try:
        import webview
    except Exception as exc:  # noqa: BLE001 - optional OS/WebView dependency
        print(f"pindrift gui: pywebview is not installed ({exc})", file=sys.stderr)
        print(_hint(), file=sys.stderr)
        return EXIT_USAGE

    values = prefs_store.load()
    if root is not None:
        values["root"] = str(root.expanduser())
    if include_project is not None:
        values["includeProject"] = include_project
    if dedupe is not None:
        values["dedupe"] = dedupe

    settings = controller.Settings(
        root=Path(values["root"]).expanduser(),
        include_project=bool(values["includeProject"]),
        dedupe=bool(values["dedupe"]),
        timeout=float(values["timeout"]),
        fail_on=Severity(values["failOn"]),
    )
    api = PindriftApi(settings, values)

    # The page is passed as a string, so pywebview never needs a file:// URL or a
    # loopback server. No remote URLs exist in the HTML either.
    try:
        window = webview.create_window(
            "pindrift",
            html=build_html(),
            js_api=api,
            width=1280,
            height=820,
            min_size=(1000, 640),
            text_select=True,
        )
    except Exception as exc:  # noqa: BLE001 - WebView2/GTK may be missing
        print(f"pindrift gui: cannot create the window: {exc}", file=sys.stderr)
        print(_hint(), file=sys.stderr)
        return EXIT_USAGE

    api.window = window
    start_options: dict[str, object] = {"debug": False, "private_mode": True}
    if sys.platform == "win32":
        start_options["gui"] = "edgechromium"

    try:
        webview.start(**start_options)
    except Exception as exc:  # noqa: BLE001 - display/WebView runtime failure
        print(f"pindrift gui: cannot start the webview: {exc}", file=sys.stderr)
        print(_hint(), file=sys.stderr)
        return EXIT_USAGE
    return 0
