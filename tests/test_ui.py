from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pindrift import service, sources, store
from pindrift.cli import main as cli_main
from pindrift.discover import ServerSpec
from pindrift.fingerprint import build
from pindrift.ui import app as ui_app
from pindrift.ui import controller


def spec() -> ServerSpec:
    return ServerSpec(
        client="test",
        name="srv",
        transport="stdio",
        command="node",
        args=["server.js"],
        source_path="/tmp/mcp.json",
    )


def test_gui_reports_missing_tkinter(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "tkinter", None)
    assert ui_app.main() == 64


def test_cli_gui_dispatches_to_app(monkeypatch) -> None:
    calls = []

    def fake_main(**kwargs):
        calls.append(kwargs)
        return 0

    monkeypatch.setattr(ui_app, "main", fake_main)
    assert cli_main(["gui", "--no-dedupe", "--no-project"]) == 0
    assert calls[0]["dedupe"] is False
    assert calls[0]["include_project"] is False


def test_inventory_loads_without_probing(monkeypatch) -> None:
    item = spec()
    monkeypatch.setattr(service, "load_specs", lambda **_: ([item], [], []))
    monkeypatch.setattr(
        service,
        "fingerprint_specs",
        lambda specs, *, do_probe, timeout: [build(item)],
    )

    inventory = controller.load_inventory(controller.Settings(root=Path.cwd()))

    assert len(inventory.specs) == 1
    assert inventory.fingerprints[0].server_id == "test:srv"


def test_pin_writes_to_the_store(monkeypatch) -> None:
    item = spec()
    monkeypatch.setattr(
        service, "fingerprint_specs", lambda specs, *, do_probe, timeout: [build(item)]
    )

    fingerprints = controller.pin([item], controller.Settings(root=Path.cwd()))

    assert store.get(fingerprints[0].server_id) is not None


def test_custom_source_appears_in_source_rows(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers": {}}', encoding="utf-8")
    sources.add(client="my-agent", path=config)

    rows = controller.source_rows(controller.Settings(root=Path.cwd()))

    custom = [row for row in rows if row.origin == "custom"]
    assert any(row.client == "my-agent" and row.exists for row in custom)


def test_result_detail_escapes_evidence() -> None:
    from pindrift.differ import compare

    result = compare(None, build(spec()))
    text = controller.result_for(result)
    assert "no pin yet" in text


def test_tk_app_builds() -> None:
    tk = pytest.importorskip("tkinter")
    from pindrift.ui.views import PindriftApp

    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    root.withdraw()
    try:
        PindriftApp(root, controller.Settings(root=Path.cwd()))
        root.update()
    finally:
        root.destroy()
