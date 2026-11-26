"""Stable pin identity for deduped servers (T3b).

The property under test: a server's pinned id is chosen once and then survives both
the client set changing and a legitimate launch change. Without it ``--dedupe`` is
only safe when the set of installed clients never changes, which is not a property a
CI baseline can rely on.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pindrift import store
from pindrift.cli import main as cli_main
from pindrift.differ import compare
from pindrift.discover import ConfigSource, ServerSpec, dedupe_specs, parse_source
from pindrift.fingerprint import build
from pindrift.models import Finding, ServerResult, Severity, State, ToolManifest
from pindrift.report import render_sarif


def write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def spec(
    client: str,
    name: str = "files",
    *,
    command: str = "node",
    args: list[str] | None = None,
    source: str = "/config/mcp.json",
) -> ServerSpec:
    return ServerSpec(
        client=client,
        name=name,
        transport="stdio",
        command=command,
        args=list(args or ["server.js"]),
        source_path=source,
        scope="user",
    )


def config_specs(tmp_path: Path, client: str, payload: dict) -> list[ServerSpec]:
    path = write_json(tmp_path / f"{client}.json", payload)
    specs, error = parse_source(ConfigSource(client, path, "user"))
    assert error is None
    return specs


def entry(command: str = "node", args: list[str] | None = None) -> dict:
    return {"command": command, "args": list(args or ["server.js"])}


def test_pin_keeps_its_id_when_an_earlier_sorting_client_is_added(
    tmp_path: Path, fake_home: Path
) -> None:
    """Acceptance: pin cursor:files, add claude-code:files, stay ok under --dedupe."""
    assert cli_main(["pin", "--all", "--dedupe", "--no-project", "--no-probe"]) == 0
    assert set(store.load()["pins"]) == {"cursor:files"}

    # claude-code sorts before cursor, which used to rename the merged server.
    write_json(fake_home / ".claude.json", {"mcpServers": {"files": entry()}})

    assert cli_main(["check", "--dedupe", "--no-project", "--no-probe"]) == 0
    assert set(store.load()["pins"]) == {"cursor:files"}


def test_id_survives_removing_the_original_client_without_a_repin(
    tmp_path: Path, fake_home: Path
) -> None:
    """The unambiguous same-name pin is enough when every recorded alias is gone."""
    assert cli_main(["pin", "--all", "--dedupe", "--no-project", "--no-probe"]) == 0
    write_json(fake_home / ".claude.json", {"mcpServers": {"files": entry()}})
    assert cli_main(["check", "--dedupe", "--no-project", "--no-probe"]) == 0

    (fake_home / ".cursor" / "mcp.json").unlink()

    assert cli_main(["check", "--dedupe", "--no-project", "--no-probe"]) == 0
    assert set(store.load()["pins"]) == {"cursor:files"}


def test_pin_remembers_every_alias_and_survives_removing_the_original_client(
    tmp_path: Path, fake_home: Path
) -> None:
    assert cli_main(["pin", "--all", "--dedupe", "--no-project", "--no-probe"]) == 0
    write_json(fake_home / ".claude.json", {"mcpServers": {"files": entry()}})

    # A re-pin while both clients are present records claude-code:files as an alias.
    assert cli_main(["pin", "--all", "--dedupe", "--no-project", "--no-probe"]) == 0
    assert store.load()["aliases"]["claude-code:files"] == "cursor:files"
    assert store.load()["aliases"]["cursor:files"] == "cursor:files"

    (fake_home / ".cursor" / "mcp.json").unlink()

    assert cli_main(["check", "--dedupe", "--no-project", "--no-probe"]) == 0
    assert set(store.load()["pins"]) == {"cursor:files"}


def test_launch_change_is_reported_under_the_same_id(tmp_path: Path) -> None:
    """Acceptance: a changed command is drift on the same server, not missing + new."""
    original = spec("cursor")
    store.put(build(original), reason="test")
    aliases = store.alias_map(store.load())

    changed = config_specs(
        tmp_path,
        "cursor",
        {"mcpServers": {"files": entry("node", ["other.js"])}},
    )
    merged = dedupe_specs(changed, aliases)

    assert len(merged) == 1
    assert merged[0].server_id == "cursor:files"
    result = compare(store.get("cursor:files"), build(merged[0]))
    assert result.state == State.DRIFT
    assert {finding.kind for finding in result.findings} >= {"launch_changed"}


def test_same_name_with_different_launches_stays_distinct() -> None:
    merged = dedupe_specs(
        [
            spec("claude-code", command="node", args=["a.js"]),
            spec("cursor", command="node", args=["b.js"]),
        ]
    )
    assert len(merged) == 2
    assert len({item.server_id for item in merged}) == 2


def test_same_alias_set_with_different_launches_stays_distinct() -> None:
    """Two sources of the same client can define the same name with different code."""
    merged = dedupe_specs(
        [
            spec("claude-code", args=["a.js"], source="/repo-a/.mcp.json"),
            spec("claude-code", args=["b.js"], source="/repo-b/.mcp.json"),
        ]
    )
    assert len(merged) == 2
    ids = {item.server_id for item in merged}
    assert len(ids) == 2
    assert all(item.startswith("claude-code:files") for item in ids)


def test_a_pin_file_without_aliases_still_resolves(tmp_path: Path) -> None:
    """Migration: pre-T3b pins are keyed by client:name and must keep matching."""
    fingerprint = build(spec("cursor"))
    store.save(
        {
            "schema": 1,
            "pins": {
                "cursor:files": {
                    "pinned_at": "2026-01-01T00:00:00+00:00",
                    "reason": "legacy",
                    "fingerprint": fingerprint.to_dict(),
                }
            },
        }
    )

    assert "aliases" not in store.load()
    aliases = store.alias_map(store.load())
    merged = dedupe_specs([spec("claude-code"), spec("cursor")], aliases)

    assert len(merged) == 1
    assert merged[0].server_id == "cursor:files"
    assert compare(store.get("cursor:files"), build(merged[0])).state == State.OK

    # The original client is gone and no alias was ever recorded for the new one:
    # the unique pinned name still resolves the id.
    remaining = dedupe_specs([spec("claude-code")], aliases)
    assert remaining[0].server_id == "cursor:files"


def test_sarif_fingerprint_is_stable_across_alias_changes(tmp_path: Path) -> None:
    """Acceptance: adding or removing a client must not reopen a SARIF alert."""
    tools = [ToolManifest(name="read_file", description="read a file and overwrite it")]

    only_cursor = dedupe_specs(
        [spec("cursor")], {"cursor:files": "cursor:files"}
    )[0]
    both_clients = dedupe_specs(
        config_specs(
            tmp_path,
            "claude-code",
            {"mcpServers": {"files": entry()}},
        )
        + [spec("cursor")],
        {"cursor:files": "cursor:files"},
    )[0]

    def document(candidate: ServerSpec) -> dict:
        current = build(candidate, tools=tools)
        finding = Finding(
            server_id=current.server_id,
            kind="description_changed",
            severity=Severity.HIGH,
            title="tool description changed",
            detail="read_file",
        )
        result = ServerResult(fingerprint=current, state=State.DRIFT, findings=[finding])
        return json.loads(render_sarif([result]))

    before = document(only_cursor)["runs"][0]["results"][0]
    after = document(both_clients)["runs"][0]["results"][0]

    assert only_cursor.server_id == both_clients.server_id == "cursor:files"
    assert before["properties"]["server"] == after["properties"]["server"]
    assert before["partialFingerprints"] == after["partialFingerprints"]


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Discover only the config files this test writes."""
    home = tmp_path / "home"
    home.mkdir()
    write_json(home / ".cursor" / "mcp.json", {"mcpServers": {"files": entry()}})
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    return home
