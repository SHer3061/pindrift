from __future__ import annotations

import json
from pathlib import Path

from pindrift import discover as discover_module
from pindrift.discover import (
    ConfigSource,
    ServerSpec,
    collect,
    dedupe_specs,
    parse_source,
    project_config_sources,
    user_config_sources,
)
from pindrift.fingerprint import build
from pindrift.models import ServerFingerprint


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


def test_parses_zed_context_servers_and_command_block(tmp_path: Path) -> None:
    """Zed calls them context_servers and historically nested the command object."""
    path = write_json(
        tmp_path / "settings.json",
        {
            "context_servers": {
                "local": {
                    "command": {
                        "path": "npx",
                        "args": ["-y", "pkg"],
                        "env": {"TOKEN": "x"},
                    }
                },
                "remote": {
                    "url": "https://example.com/mcp",
                    "headers": {"Authorization": "Bearer x"},
                },
            }
        },
    )
    specs, error = parse_source(ConfigSource("zed", path, "user"))
    assert error is None
    by_name = {spec.name: spec for spec in specs}
    assert by_name["local"].command == "npx"
    assert by_name["local"].args == ["-y", "pkg"]
    assert by_name["local"].env_keys == ["TOKEN"]
    assert by_name["remote"].transport == "http"
    assert by_name["remote"].url == "https://example.com/mcp"


def test_claude_config_dir_override_is_honoured(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    claude = [s for s in user_config_sources() if s.client == "claude-code"]
    assert claude and claude[0].path == tmp_path / ".claude.json"


def test_zed_settings_is_a_known_user_source(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(discover_module.sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(tmp_path))
    zed = [s for s in user_config_sources() if s.client == "zed"]
    assert any(s.path == tmp_path / "Zed" / "settings.json" for s in zed)


def test_cline_extension_settings_are_a_known_source(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(discover_module.sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(tmp_path))
    cline = [s for s in user_config_sources() if s.client == "cline"]
    assert any(
        s.path
        == tmp_path
        / "Code"
        / "User"
        / "globalStorage"
        / "saoudrizwan.claude-dev"
        / "settings"
        / "cline_mcp_settings.json"
        for s in cline
    )
    assert any(s.path.name == "mcp.json" and s.path.parent.name == ".cline" for s in cline)


def test_jetbrains_sources_are_discovered_per_product(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(discover_module, "_jetbrains_roots", lambda: [tmp_path])
    ai = write_json(tmp_path / "IntelliJIdea2025.1" / "ai" / "mcp.json", {"mcpServers": {}})
    junie = write_json(tmp_path / "PyCharm2025.1" / "mcp.json", {"mcpServers": {}})
    sources = discover_module._jetbrains_user_sources()
    assert [s.path for s in sources] == [ai, junie]


def test_parses_list_shaped_mcp_servers(tmp_path: Path) -> None:
    """Continue writes mcpServers as a list of named entries, not a mapping."""
    path = write_json(
        tmp_path / "config.json",
        {
            "mcpServers": [
                {"name": "files", "command": "npx", "args": ["-y", "pkg"]},
                {"name": "remote", "url": "https://example.com/mcp"},
            ]
        },
    )
    specs, error = parse_source(ConfigSource("continue", path, "user"))
    assert error is None
    assert [spec.name for spec in specs] == ["files", "remote"]
    assert specs[0].command == "npx"


def test_continue_project_blocks_are_discovered(tmp_path: Path) -> None:
    block = write_json(
        tmp_path / ".continue" / "mcpServers" / "github.json",
        {
            "name": "github",
            "version": "0.0.1",
            "schema": "v1",
            "mcpServers": {"github": {"command": "npx", "args": ["-y", "pkg"]}},
        },
    )
    (tmp_path / ".git").mkdir()
    found = project_config_sources(tmp_path)
    assert any(s.client == "continue" and s.path == block for s in found)


def _two_client_specs(
    tmp_path: Path, second_args: list[str] | None = None
) -> list[ServerSpec]:
    first = write_json(
        tmp_path / "claude.json",
        {"mcpServers": {"files": {"command": "npx", "args": ["-y", "pkg"]}}},
    )
    second = write_json(
        tmp_path / "cursor.json",
        {
            "mcpServers": {
                "files": {"command": "npx", "args": second_args or ["-y", "pkg"]}
            }
        },
    )
    a, _ = parse_source(ConfigSource("claude-code", first, "user"))
    b, _ = parse_source(ConfigSource("cursor", second, "user"))
    return a + b


def test_dedupe_collapses_one_server_from_two_clients(tmp_path: Path) -> None:
    merged = dedupe_specs(_two_client_specs(tmp_path))
    assert len(merged) == 1
    assert merged[0].server_id == "claude-code:files"
    assert merged[0].all_clients == ["claude-code", "cursor"]
    assert len(merged[0].all_source_paths) == 2


def test_dedupe_keeps_different_launches_apart(tmp_path: Path) -> None:
    merged = dedupe_specs(_two_client_specs(tmp_path, second_args=["-y", "other-pkg"]))
    assert len(merged) == 2
    assert {spec.all_clients[0] for spec in merged} == {"claude-code", "cursor"}


def test_collect_dedupe_reports_one_result_and_names_both_clients(
    tmp_path: Path, monkeypatch
) -> None:
    specs = _two_client_specs(tmp_path)
    sources = [
        ConfigSource(spec.client, Path(spec.source_path), "user") for spec in specs
    ]
    monkeypatch.setattr(discover_module, "discover", lambda **_: sources)

    plain, errors, _ = collect(dedupe=False)
    assert errors == []
    assert len(plain) == 2

    merged, errors, _ = collect(dedupe=True)
    assert errors == []
    assert len(merged) == 1
    assert merged[0].all_clients == ["claude-code", "cursor"]


def test_fingerprint_keeps_every_client_after_dedupe(tmp_path: Path) -> None:
    merged = dedupe_specs(_two_client_specs(tmp_path))
    fingerprint = build(merged[0])
    assert fingerprint.all_clients == ["claude-code", "cursor"]
    assert fingerprint.to_dict()["clients"] == ["claude-code", "cursor"]
    restored = ServerFingerprint.from_dict(fingerprint.to_dict())
    assert restored.all_clients == ["claude-code", "cursor"]
