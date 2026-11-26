from __future__ import annotations

import time
from pathlib import Path

from pindrift import service
from pindrift.differ import summarise
from pindrift.discover import ServerSpec
from pindrift.fingerprint import build
from pindrift.ui import bridge, controller, prefs


def spec() -> ServerSpec:
    return ServerSpec(
        client="test",
        name="srv",
        transport="stdio",
        command="node",
        args=["server.js"],
        source_path="/tmp/mcp.json",
    )


def inventory() -> controller.Inventory:
    item = spec()
    return controller.Inventory(
        specs=[item],
        fingerprints=[build(item)],
        pinned_ids=set(),
        errors=[],
        sources=[],
        baseline_label="baseline test",
    )


def api() -> bridge.PindriftApi:
    return bridge.PindriftApi(
        controller.Settings(root=Path.cwd()),
        prefs.defaults(),
    )


def wait(api: bridge.PindriftApi, job_id: str) -> dict:
    for _ in range(200):
        response = api.job_status(job_id)
        assert response["ok"]
        job = response["data"]
        if job["state"] in ("done", "failed"):
            return job
        time.sleep(0.01)
    raise AssertionError("job did not finish")


def test_scan_does_not_probe(monkeypatch) -> None:
    instance = api()
    monkeypatch.setattr(controller, "load_inventory", lambda settings: inventory())
    monkeypatch.setattr(controller, "source_rows", lambda settings: [])

    response = instance.scan()

    assert response["ok"]
    assert response["data"]["servers"][0]["id"] == "test:srv"
    assert response["data"]["servers"][0]["hasManifest"] is False


def test_check_runs_as_a_job(monkeypatch) -> None:
    instance = api()
    instance.inventory = inventory()
    monkeypatch.setattr(controller, "load_inventory", lambda settings: inventory())
    monkeypatch.setattr(
        controller,
        "check",
        lambda settings, progress=None: service.ScanReport(
            results=[],
            summary=summarise([]),
            errors=[],
            sources=[],
            baseline_label="baseline test",
            pinned_ids=set(),
            exit_code=0,
        ),
    )

    start = instance.start_check()
    assert start["ok"]
    job = wait(instance, start["data"]["jobId"])

    assert job["state"] == "done"
    assert job["result"]["stats"]["total"] == 0


def test_write_requires_confirm(monkeypatch) -> None:
    instance = api()
    instance.inventory = inventory()
    response = instance.start_write({"ids": ["test:srv"], "mode": "pin"})
    assert response["ok"] is False
    assert response["error"]["code"] == "confirm_required"


def test_write_only_accepts_inventory_ids(monkeypatch) -> None:
    instance = api()
    instance.inventory = inventory()
    response = instance.start_write(
        {"ids": ["other:srv"], "mode": "pin", "confirm": True}
    )
    job = wait(instance, response["data"]["jobId"])
    assert job["state"] == "failed"


def test_write_pins_known_ids(monkeypatch) -> None:
    instance = api()
    instance.inventory = inventory()
    monkeypatch.setattr(controller, "pin", lambda specs, settings, progress=None: [])
    monkeypatch.setattr(controller, "load_inventory", lambda settings: inventory())

    response = instance.start_write(
        {"ids": ["test:srv"], "mode": "pin", "confirm": True}
    )
    job = wait(instance, response["data"]["jobId"])

    assert job["state"] == "done"
    assert job["result"]["written"] == []


def test_pick_file_without_window_is_reported() -> None:
    response = api().pick_file()
    assert response["ok"] is False
    assert response["error"]["code"] == "no_window"


def test_invalid_prefs_are_rejected() -> None:
    instance = api()
    response = instance.save_prefs(
        {
            "root": "relative",
            "timeout": 20,
            "failOn": "high",
            "theme": "system",
            "dedupe": True,
            "includeProject": True,
        }
    )
    assert response["ok"] is False
    assert response["error"]["code"] == "invalid_root"


def test_unknown_job_is_reported() -> None:
    response = api().job_status("missing")
    assert response["ok"] is False
    assert response["error"]["code"] == "unknown_job"
