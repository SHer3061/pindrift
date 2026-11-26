from __future__ import annotations

import json
from pathlib import Path

import pytest

from pindrift import discover as discover_module
from pindrift import sources
from pindrift.cli import main as cli_main
from pindrift.discover import collect


def write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_add_list_remove_roundtrip(tmp_path: Path) -> None:
    config = write_json(tmp_path / "mcp.json", {"mcpServers": {}})
    source = sources.add(client="my-agent", path=config)

    loaded = sources.load()
    assert [item.id for item in loaded] == [source.id]
    assert loaded[0].path == config
    assert loaded[0].to_config_source().origin == "custom"

    assert sources.remove(source.id)
    assert sources.load() == []
    assert not sources.remove(source.id)


def test_same_path_replaces_instead_of_duplicating(tmp_path: Path) -> None:
    config = write_json(tmp_path / "mcp.json", {"mcpServers": {}})
    first = sources.add(client="one", path=config)
    second = sources.add(client="two", path=config)
    assert sources.load() == [second]
    assert first.id != second.id


def test_relative_path_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(sources.SourceRegistryError, match="absolute"):
        sources.add(client="x", path="mcp.json")


def test_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(sources.SourceRegistryError, match="not a regular file"):
        sources.add(client="x", path=tmp_path)


def test_yaml_source_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("extensions: {}\n", encoding="utf-8")
    with pytest.raises(sources.SourceRegistryError, match="YAML"):
        sources.add(client="goose", path=config, format="yaml")


def test_corrupt_registry_is_loud() -> None:
    path = sources.registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(sources.SourceRegistryError, match="invalid JSON"):
        sources.load()

    custom, errors = sources.discover_custom()
    assert custom == []
    assert errors and errors[0].level == "error"
    assert errors[0].client == "sources-registry"


def test_missing_custom_file_is_reported(tmp_path: Path) -> None:
    config = tmp_path / "missing.json"
    sources.add(client="my-agent", path=config)
    custom, errors = sources.discover_custom()
    assert custom == []
    assert errors and errors[0].level == "warning"
    assert "no longer exists" in errors[0].message


def test_collect_includes_custom_sources(tmp_path: Path, monkeypatch) -> None:
    config = write_json(
        tmp_path / "custom.json",
        {"mcpServers": {"files": {"command": "npx", "args": ["-y", "pkg"]}}},
    )
    sources.add(client="my-agent", path=config)
    monkeypatch.setattr(discover_module, "discover", lambda **_: [])

    specs, errors, found = collect(include_project=False)

    assert errors == []
    assert [spec.server_id for spec in specs] == ["my-agent:files"]
    assert found[0].origin == "custom"


def test_cli_sources_add_list_remove(tmp_path: Path, capsys) -> None:
    config = write_json(tmp_path / "custom.json", {"mcpServers": {}})

    assert cli_main(["sources", "add", "--client", "my-agent", "--path", str(config)]) == 0
    output = capsys.readouterr().out
    assert "my-agent" in output

    assert cli_main(["sources", "list", "--format", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    custom = [row for row in rows if row["origin"] == "custom"]
    assert custom[0]["client"] == "my-agent"
    assert custom[0]["exists"] is True

    assert cli_main(["sources", "test", "my-agent"]) == 0
    assert "0 server(s)" in capsys.readouterr().out

    assert cli_main(["sources", "remove", "my-agent"]) != 0
    source_id = sources.load()[0].id
    assert cli_main(["sources", "remove", source_id]) == 0
