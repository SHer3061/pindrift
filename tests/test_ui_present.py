from __future__ import annotations

import json

from pindrift.models import (
    Artifact,
    Finding,
    ServerFingerprint,
    ServerResult,
    Severity,
    State,
    ToolManifest,
)
from pindrift.ui import present


def fingerprint() -> ServerFingerprint:
    return ServerFingerprint(
        server_id="cursor:files",
        client="cursor",
        name="files",
        clients=["cursor"],
        transport="stdio",
        command="node",
        args=["server.js", "--token=secret-value"],
        env_keys=["TOKEN"],
        config_hash="abc",
        artifact=Artifact(kind="local", target="/tmp/server.js", sha256="d" * 64),
        tools=[ToolManifest(name="read_file", description="read a file", input_schema={"properties": {"path": {}}})],
        tools_hash="t" * 64,
        source_config="/tmp/mcp.json",
    )


def test_server_row_never_contains_env_values() -> None:
    row = present.server_row(fingerprint(), pinned=True)
    encoded = json.dumps(row)
    assert "TOKEN" not in encoded
    assert "secret-value" not in encoded
    assert row["id"] == "cursor:files"
    assert row["pinned"] is True


def test_server_row_escapes_control_characters() -> None:
    fp = fingerprint()
    fp.tools = [ToolManifest(name="x", description="before\x1bafter")]
    row = present.server_row(fp, pinned=False)
    description = row["tools"][0]["description"]
    assert "\x1b" not in description
    assert "\\x1b" in description


def test_server_row_truncates_long_text() -> None:
    fp = fingerprint()
    fp.tools = [ToolManifest(name="x", description="a" * 2000)]
    row = present.server_row(fp, pinned=False)
    assert len(row["tools"][0]["description"]) <= present.TEXT_LIMIT


def test_unknown_state_is_preserved() -> None:
    fp = fingerprint()
    result = ServerResult(
        fingerprint=fp,
        state=State.UNKNOWN,
        findings=[
            Finding(
                server_id=fp.server_id,
                kind="manifest_unverified",
                severity=Severity.MEDIUM,
                title="could not verify",
                detail="probe timed out",
                evidence=["timeout"],
            )
        ],
    )
    row = present.server_row(fp, pinned=True, result=result)
    assert row["state"] == "unknown"
    assert row["findings"][0]["kind"] == "manifest_unverified"


def test_source_row_marks_custom_sources() -> None:
    row = present.SourceRow(
        client="my-agent",
        path="/tmp/mcp.json",
        scope="user",
        origin="custom",
        format="json",
        exists=True,
        supported=True,
        note="",
        identifier="abc123",
    )
    payload = present.source_row(row)
    assert payload["custom"] is True
    assert payload["id"] == "abc123"
