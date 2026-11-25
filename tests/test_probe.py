from __future__ import annotations

from pathlib import Path

from pindrift.discover import ServerSpec
from pindrift.probe import probe_spec


def make_spec(server: Path, python: str, mode: str) -> ServerSpec:
    return ServerSpec(
        client="test",
        name=f"fake-{mode}",
        transport="stdio",
        command=python,
        args=[str(server), "--mode", mode],
        source_path=str(server.parent / "config.json"),
    )


def test_probe_returns_manifest(fixture_server: Path, python_exe: str) -> None:
    tools, error = probe_spec(make_spec(fixture_server, python_exe, "clean"), timeout=45)
    assert error is None, error
    assert tools is not None
    assert [t.name for t in tools] == ["read_file", "list_dir"]


def test_probe_sees_poisoned_description(fixture_server: Path, python_exe: str) -> None:
    tools, error = probe_spec(make_spec(fixture_server, python_exe, "poisoned"), timeout=45)
    assert error is None, error
    assert tools is not None
    assert "\x1b" in tools[0].description


def test_probe_sees_escalated_manifest(fixture_server: Path, python_exe: str) -> None:
    tools, error = probe_spec(make_spec(fixture_server, python_exe, "escalated"), timeout=45)
    assert error is None, error
    assert tools is not None
    assert "write_file" in [t.name for t in tools]


def test_missing_command_reports_error() -> None:
    spec = ServerSpec(
        client="test",
        name="ghost",
        transport="stdio",
        command="definitely-not-a-real-binary-xyz",
        source_path="config.json",
    )
    tools, error = probe_spec(spec, timeout=5)
    assert tools is None
    assert error and "not found" in error


def test_remote_transport_is_not_probed() -> None:
    spec = ServerSpec(
        client="test",
        name="remote",
        transport="http",
        url="https://example.com/mcp",
        source_path="config.json",
    )
    tools, error = probe_spec(spec, timeout=5)
    assert tools is None
    assert error and "stdio" in error
