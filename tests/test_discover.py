from __future__ import annotations

import json
from pathlib import Path

from pindrift.discover import (
    ConfigSource,
    project_config_sources,
    parse_source,
)


def write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_parses_mcp_servers_container(tmp_path: Path) -> None:
    path = write_json(
        tmp_path / "mcp.json",
        {
            "mcpServers": {
                "files": {"command": "npx", "args": ["-y", "pkg"], "env": {"TOKEN": "x"}}
            }
        },
    )
    specs, error = parse_source(ConfigSource("test", path, "user"))
    assert error is None
    assert len(specs) == 1
    assert specs[0].name == "files"
    assert specs[0].transport == "stdio"
    assert specs[0].env_keys == ["TOKEN"]


def test_parses_vscode_servers_container(tmp_path: Path) -> None:
    path = write_json(
        tmp_path / "mcp.json",
        {"servers": {"remote": {"type": "http", "url": "https://example.com/mcp"}}},
    )
    specs, error = parse_source(ConfigSource("vscode", path, "user"))
    assert error is None
    assert specs[0].transport == "http"
    assert specs[0].url == "https://example.com/mcp"


def test_invalid_json_is_reported_not_raised(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    specs, error = parse_source(ConfigSource("test", path, "user"))
    assert specs == []
    assert error is not None
    assert "invalid JSON" in error.message


def test_utf8_bom_is_tolerated(tmp_path: Path) -> None:
    """PowerShell's Set-Content and many Windows editors emit a BOM."""
    path = tmp_path / "bom.json"
    payload = {"mcpServers": {"files": {"command": "npx", "args": ["-y", "pkg"]}}}
    path.write_text(json.dumps(payload), encoding="utf-8-sig")
    specs, error = parse_source(ConfigSource("test", path, "user"))
    assert error is None
    assert [spec.name for spec in specs] == ["files"]


def test_missing_file_is_reported(tmp_path: Path) -> None:
    specs, error = parse_source(ConfigSource("test", tmp_path / "nope.json", "user"))
    assert specs == []
    assert error is not None


def test_project_sources_found_by_walking_up(tmp_path: Path) -> None:
    write_json(tmp_path / ".mcp.json", {"mcpServers": {}})
    (tmp_path / ".git").mkdir()
    nested = tmp_path / "packages" / "app"
    nested.mkdir(parents=True)
    found = project_config_sources(nested)
    assert any(source.path.name == ".mcp.json" for source in found)


def test_project_sources_skip_when_no_config(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    nested = tmp_path / "sub"
    nested.mkdir()
    assert project_config_sources(nested) == []
