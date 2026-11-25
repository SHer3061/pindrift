from __future__ import annotations

from pindrift import store
from pindrift.models import Artifact, ServerFingerprint, ToolManifest


def make_fingerprint(server_id: str = "test:srv", description: str = "hello") -> ServerFingerprint:
    tools = [ToolManifest(name="t", description=description)]
    return ServerFingerprint(
        server_id=server_id,
        client="test",
        name="srv",
        transport="stdio",
        command="node",
        args=["a.js"],
        env_keys=["TOKEN"],
        config_hash="h1",
        artifact=Artifact(kind="local", target="/x.js", sha256="abc"),
        tools=tools,
        tools_hash="ths",
        source_config="/tmp/mcp.json",
    )


def test_put_and_get_roundtrip() -> None:
    fingerprint = make_fingerprint()
    store.put(fingerprint, reason="test")
    loaded = store.get("test:srv")
    assert loaded is not None
    assert loaded.server_id == "test:srv"
    assert loaded.tools is not None
    assert loaded.tools[0].description == "hello"
    assert loaded.config_hash == "h1"


def test_pinned_ids_lists_everything() -> None:
    store.put_many([make_fingerprint("a:s"), make_fingerprint("b:s")])
    assert store.pinned_ids() == {"a:s", "b:s"}


def test_drop_removes_pin() -> None:
    store.put(make_fingerprint("a:s"))
    assert store.drop("a:s") is True
    assert store.get("a:s") is None
    assert store.drop("a:s") is False


def test_missing_pins_file_returns_empty() -> None:
    assert store.load()["pins"] == {}
    assert store.get("nope") is None


def test_corrupt_pins_file_does_not_crash() -> None:
    path = store.pins_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{{{ broken", encoding="utf-8")
    assert store.load()["pins"] == {}


def test_pins_path_honours_environment(isolated_home) -> None:
    assert str(store.home()).endswith("pindrift-home")
