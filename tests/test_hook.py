from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from pindrift import hook, store
from pindrift.cli import main as cli_main
from pindrift.discover import ServerSpec
from pindrift.fingerprint import build
from pindrift.models import Severity
from pindrift.probe import probe_spec

TIMEOUT = 45


@pytest.fixture(autouse=True)
def isolated_user_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep discovery away from the machine's real client configs."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))


def setup_server(
    tmp_path: Path, fixture_server: Path, python_exe: str, mode: str = "clean"
) -> tuple[Path, Path, ServerSpec]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_file = workspace / "mode.txt"
    state_file.write_text(mode + "\n", encoding="utf-8")
    config = {
        "mcpServers": {
            "demo-fs": {
                "command": python_exe,
                "args": [str(fixture_server), "--mode-file", str(state_file)],
            }
        }
    }
    config_path = workspace / ".mcp.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    spec = ServerSpec(
        client="claude-code",
        name="demo-fs",
        transport="stdio",
        command=python_exe,
        args=[str(fixture_server), "--mode-file", str(state_file)],
        source_path=str(config_path),
        scope="project",
    )
    return workspace, state_file, spec


def pin(spec: ServerSpec) -> None:
    tools, error = probe_spec(spec, timeout=TIMEOUT)
    assert error is None, error
    assert tools is not None
    store.put(build(spec, tools=tools, probed_at=store.utc_now()), reason="test")


def call_hook(
    payload: dict[str, object] | str,
    *,
    fail_on: Severity = Severity.HIGH,
    timeout: float = TIMEOUT,
) -> tuple[int, str, str]:
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    stdout, stderr = io.StringIO(), io.StringIO()
    code = hook.run_hook(
        host="claude-code",
        stream=io.StringIO(raw),
        stdout=stdout,
        stderr=stderr,
        fail_on=fail_on,
        timeout=timeout,
    )
    return code, stdout.getvalue(), stderr.getvalue()


def mcp_payload(workspace: Path, tool: str = "read_file") -> dict[str, object]:
    return {
        "session_id": "test-session",
        "cwd": str(workspace),
        "hook_event_name": "PreToolUse",
        "tool_name": f"mcp__demo-fs__{tool}",
        "tool_input": {},
    }


def test_hook_denies_drifted_server_and_names_gained_capability(
    tmp_path: Path, fixture_server: Path, python_exe: str
) -> None:
    workspace, state_file, spec = setup_server(tmp_path, fixture_server, python_exe)
    pin(spec)

    # Same config, same code on disk: only the runtime manifest escalates.
    state_file.write_text("escalated\n", encoding="utf-8")

    code, stdout, _ = call_hook(mcp_payload(workspace, "write_file"))
    assert code == hook.EXIT_DENY
    assert "fs.write" in stdout
    assert "write_file" in stdout
    assert "pindrift blocked this tool call" in stdout


def test_hook_allows_unchanged_server(
    tmp_path: Path, fixture_server: Path, python_exe: str
) -> None:
    workspace, _, spec = setup_server(tmp_path, fixture_server, python_exe)
    pin(spec)

    code, stdout, stderr = call_hook(mcp_payload(workspace))
    assert code == hook.EXIT_ALLOW
    assert stdout == ""
    assert stderr == ""


def test_hook_allows_builtin_tools_silently(
    tmp_path: Path, fixture_server: Path, python_exe: str
) -> None:
    workspace, _, _ = setup_server(tmp_path, fixture_server, python_exe)
    payload = {"cwd": str(workspace), "tool_name": "Bash", "tool_input": {"command": "ls"}}

    code, stdout, stderr = call_hook(payload)
    assert code == hook.EXIT_ALLOW
    assert stdout == ""
    assert stderr == ""


def test_hook_reports_malformed_input(tmp_path: Path) -> None:
    code, stdout, stderr = call_hook("{not json")
    assert code == hook.EXIT_MALFORMED
    assert stdout == ""
    assert "malformed input" in stderr


def test_hook_rejects_json_without_tool_name(tmp_path: Path) -> None:
    code, _, stderr = call_hook({"cwd": str(tmp_path)})
    assert code == hook.EXIT_MALFORMED
    assert "tool_name" in stderr


def test_hook_warns_when_server_is_unpinned(
    tmp_path: Path, fixture_server: Path, python_exe: str
) -> None:
    workspace, _, _ = setup_server(tmp_path, fixture_server, python_exe)

    code, stdout, stderr = call_hook(mcp_payload(workspace))
    assert code == hook.EXIT_ALLOW
    assert stdout == ""
    assert "no pin" in stderr
    assert "not verified" in stderr


def test_hook_warns_when_manifest_cannot_be_fetched(
    tmp_path: Path, fixture_server: Path, python_exe: str
) -> None:
    workspace, state_file, spec = setup_server(tmp_path, fixture_server, python_exe)
    pin(spec)
    state_file.unlink()  # server now exits before returning a manifest

    code, stdout, stderr = call_hook(mcp_payload(workspace))
    assert code == hook.EXIT_ALLOW
    assert stdout == ""
    assert "could not be verified" in stderr
    assert "cannot be ruled out" in stderr


def test_unverifiable_never_denies_even_at_medium_threshold(
    tmp_path: Path, fixture_server: Path, python_exe: str
) -> None:
    workspace, state_file, spec = setup_server(tmp_path, fixture_server, python_exe)
    pin(spec)
    state_file.unlink()

    code, _, _ = call_hook(mcp_payload(workspace), fail_on=Severity.MEDIUM)
    assert code == hook.EXIT_ALLOW


def test_fail_on_critical_allows_high_severity_drift(
    tmp_path: Path, fixture_server: Path, python_exe: str
) -> None:
    workspace, state_file, spec = setup_server(tmp_path, fixture_server, python_exe)
    pin(spec)
    state_file.write_text("escalated\n", encoding="utf-8")

    code, stdout, _ = call_hook(mcp_payload(workspace, "write_file"), fail_on=Severity.CRITICAL)
    assert code == hook.EXIT_ALLOW
    assert stdout == ""


def test_cli_wires_hook_to_stdin_and_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    fixture_server: Path,
    python_exe: str,
) -> None:
    workspace, state_file, spec = setup_server(tmp_path, fixture_server, python_exe)
    pin(spec)
    state_file.write_text("escalated\n", encoding="utf-8")

    payload = mcp_payload(workspace, "write_file")
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))

    code = cli_main(["hook", "--host", "claude-code", "--timeout", str(TIMEOUT)])
    captured = capsys.readouterr()
    assert code == hook.EXIT_DENY
    assert "fs.write" in captured.out
