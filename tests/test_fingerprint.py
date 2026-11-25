from __future__ import annotations

from pathlib import Path

from pindrift.discover import ServerSpec
from pindrift.fingerprint import build, hash_config, identify_artifact


def make_spec(**kwargs) -> ServerSpec:
    defaults = dict(
        client="test",
        name="srv",
        transport="stdio",
        command="node",
        args=["server.js"],
        env={"TOKEN": "abc"},
        env_keys=["TOKEN"],
        source_path="/tmp/mcp.json",
    )
    defaults.update(kwargs)
    return ServerSpec(**defaults)


def test_env_values_do_not_affect_config_hash() -> None:
    first = make_spec(env={"TOKEN": "abc"}, env_keys=["TOKEN"])
    second = make_spec(env={"TOKEN": "rotated-secret"}, env_keys=["TOKEN"])
    assert hash_config(first) == hash_config(second)


def test_env_key_set_does_affect_config_hash() -> None:
    first = make_spec(env_keys=["TOKEN"])
    second = make_spec(env_keys=["TOKEN", "AWS_SECRET_ACCESS_KEY"])
    assert hash_config(first) != hash_config(second)


def test_args_are_redacted_in_fingerprint() -> None:
    spec = make_spec(args=["server.js", "--api-key=supersecret"])
    assert all("supersecret" not in arg for arg in spec.redacted_args)


def test_local_script_is_hashed(tmp_path: Path) -> None:
    script = tmp_path / "server.py"
    script.write_text("print('hello')\n", encoding="utf-8")
    spec = make_spec(command="python", args=[str(script)])
    artifact = identify_artifact(spec)
    assert artifact.kind == "local"
    assert artifact.sha256 is not None
    assert len(artifact.sha256) == 64


def test_local_script_hash_changes_with_content(tmp_path: Path) -> None:
    script = tmp_path / "server.py"
    script.write_text("print('one')\n", encoding="utf-8")
    first = identify_artifact(make_spec(command="python", args=[str(script)]))
    script.write_text("print('two')\n", encoding="utf-8")
    second = identify_artifact(make_spec(command="python", args=[str(script)]))
    assert first.sha256 != second.sha256


def test_remote_server_is_not_locally_verifiable() -> None:
    spec = make_spec(command=None, args=[], transport="http", url="https://example.com/mcp")
    artifact = identify_artifact(spec)
    assert artifact.kind == "remote"


def test_npx_package_is_recorded() -> None:
    spec = make_spec(command="npx", args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"])
    artifact = identify_artifact(spec)
    assert artifact.kind == "npx"
    assert artifact.target == "@modelcontextprotocol/server-filesystem"


def test_build_produces_stable_tools_hash(tmp_path: Path) -> None:
    from pindrift.models import ToolManifest

    tools = [ToolManifest(name="b", description="second"), ToolManifest(name="a", description="first")]
    reordered = list(reversed(tools))
    assert build(make_spec(), tools=tools).tools_hash == build(make_spec(), tools=reordered).tools_hash


def test_build_without_tools_has_no_manifest() -> None:
    fp = build(make_spec())
    assert fp.tools is None
    assert fp.tools_hash is None
