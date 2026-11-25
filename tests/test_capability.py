from __future__ import annotations

from pindrift.capability import infer_capabilities, server_capabilities
from pindrift.models import Severity, ToolManifest


def make_tool(name: str, description: str = "", schema: dict | None = None) -> ToolManifest:
    return ToolManifest(
        name=name,
        description=description,
        input_schema=schema or {"type": "object", "properties": {}},
    )


def test_read_only_tool_has_no_write_capability() -> None:
    tool = make_tool(
        "read_file",
        "Read the contents of a text file from the workspace.",
        {"type": "object", "properties": {"path": {"type": "string"}}},
    )
    caps = infer_capabilities(tool)
    assert "fs.read" in caps
    assert "fs.write" not in caps
    assert "fs.delete" not in caps


def test_write_tool_is_high_risk() -> None:
    tool = make_tool(
        "write_file",
        "Write or overwrite a text file in the workspace.",
        {"type": "object", "properties": {"path": {}, "content": {}}},
    )
    caps = infer_capabilities(tool)
    assert "fs.write" in caps
    assert caps["fs.write"].risk is Severity.HIGH


def test_shell_tool_is_critical() -> None:
    tool = make_tool("run_command", "Execute a shell command in the project directory.")
    caps = infer_capabilities(tool)
    assert "exec.shell" in caps
    assert caps["exec.shell"].risk is Severity.CRITICAL


def test_credential_tool_is_critical() -> None:
    tool = make_tool("get_config", "Read an API key from the environment variable store.")
    caps = infer_capabilities(tool)
    assert "cred.read" in caps
    assert caps["cred.read"].risk is Severity.CRITICAL


def test_evidence_is_recorded() -> None:
    tool = make_tool("write_file", "Write content to a path.")
    hits = infer_capabilities(tool)
    assert hits["fs.write"].evidence
    assert any("name contains" in item for item in hits["fs.write"].evidence)


def test_chinese_description_is_understood() -> None:
    tool = make_tool("文件助手", "读取文件并返回文件内容。")
    caps = infer_capabilities(tool)
    assert "fs.read" in caps


def test_server_capabilities_attributes_tools() -> None:
    tools = [
        make_tool("read_file", "Read a file from disk."),
        make_tool("write_file", "Write a file to disk."),
    ]
    aggregate = server_capabilities(tools)
    assert aggregate["fs.read"] == ["read_file"]
    assert aggregate["fs.write"] == ["write_file"]


def test_plain_text_tool_yields_nothing() -> None:
    tool = make_tool("hello", "Say hello to the user.")
    assert infer_capabilities(tool) == {}
