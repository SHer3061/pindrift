from __future__ import annotations

from pathlib import Path

import pytest

from pindrift import service, store
from pindrift.discover import ServerSpec, SourceError
from pindrift.fingerprint import build
from pindrift.models import State


def spec(client: str = "test", name: str = "srv") -> ServerSpec:
    return ServerSpec(
        client=client,
        name=name,
        transport="stdio",
        command="node",
        args=["server.js"],
        source_path="/tmp/mcp.json",
    )


def test_scan_compares_against_the_home_baseline(monkeypatch) -> None:
    item = spec()
    store.put(build(item))
    monkeypatch.setattr(service, "load_specs", lambda **_: ([item], [], []))

    report = service.scan(service.ScanOptions(probe="none"))

    assert report.exit_code == 0
    assert report.results[0].state == State.OK
    assert report.pinned_ids == {"test:srv"}


def test_unpinned_servers_are_not_probed_in_auto_mode(monkeypatch) -> None:
    seen: list[bool] = []

    def fake_fingerprint(spec, *, do_probe, timeout):
        seen.append(do_probe)
        return build(spec)

    monkeypatch.setattr(service, "fingerprint_spec", fake_fingerprint)
    monkeypatch.setattr(service, "load_specs", lambda **_: ([spec()], [], []))

    report = service.scan(service.ScanOptions(probe="auto"))

    assert seen == [False]
    assert report.results[0].state == State.NEW


def test_missing_baseline_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(service.BaselineError, match="baseline not found"):
        service.scan(
            service.ScanOptions(baseline_path=tmp_path / "missing.json", probe="none")
        )


def test_selection_errors_are_explicit() -> None:
    with pytest.raises(service.SelectionError, match="no MCP server matched"):
        service.select([spec()], ["absent"])


def test_scan_keeps_source_errors(monkeypatch) -> None:
    monkeypatch.setattr(
        service,
        "load_specs",
        lambda **_: ([], [SourceError("bad", "/x", "invalid", level="warning")], []),
    )

    report = service.scan(service.ScanOptions(probe="none"))

    assert report.errors[0].level == "warning"
    assert report.results == []
