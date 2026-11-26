from __future__ import annotations

import json
from pathlib import Path

import pytest

from pindrift import cli, store, trust
from pindrift.cli import main as cli_main
from pindrift.models import Artifact, ServerFingerprint, ToolManifest


def make_fingerprint(server_id: str = "test:srv", description: str = "hello") -> ServerFingerprint:
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
        tools=[ToolManifest(name="t", description=description)],
        tools_hash="ths",
        source_config="/tmp/mcp.json",
    )


@pytest.fixture
def signing_key(monkeypatch: pytest.MonkeyPatch) -> bytes:
    key = bytes.fromhex("11" * trust.KEY_BYTES)
    monkeypatch.setenv(trust.ENV_KEY, key.hex())
    return key


def test_writes_are_signed_when_a_key_is_available(signing_key: bytes) -> None:
    store.put(make_fingerprint(), reason="test")

    payload = store.load_path(store.pins_path())
    assert payload["signature"]["alg"] == trust.ALGORITHM
    verdict = trust.verify(payload)
    assert verdict.ok
    assert verdict.state == "valid"


def test_tampering_with_one_byte_fails_verification(signing_key: bytes) -> None:
    store.put(make_fingerprint(), reason="test")
    path = store.pins_path()

    text = path.read_text(encoding="utf-8")
    assert '"hello"' in text
    path.write_text(text.replace('"hello"', '"hellp"'), encoding="utf-8")

    verdict = trust.verify(store.load_path(path))
    assert not verdict.ok
    assert verdict.state == "invalid"
    assert "signature mismatch" in verdict.detail
    assert "modified after signing" in verdict.detail


def test_tampered_baseline_fails_the_verify_command(
    signing_key: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    store.put(make_fingerprint(), reason="test")
    path = store.pins_path()
    path.write_text(path.read_text(encoding="utf-8").replace("hello", "hellp"), encoding="utf-8")

    code = cli_main(["trust", "verify", "--baseline", str(path)])

    assert code == 3
    assert "signature mismatch" in capsys.readouterr().err


def test_reformatting_the_json_keeps_the_signature_valid(signing_key: bytes) -> None:
    store.put(make_fingerprint(), reason="test")
    path = store.pins_path()

    # The signature covers canonical content, not the bytes on disk, so `jq .` is safe.
    payload = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps(payload, indent=4), encoding="utf-8")

    assert trust.verify(store.load_path(path)).ok


def test_unsigned_baseline_is_not_accepted() -> None:
    store.put(make_fingerprint(), reason="test")

    verdict = trust.verify(store.load())
    assert not verdict.ok
    assert verdict.state == "unsigned"
    assert "not signed" in verdict.detail


def test_signed_baseline_without_the_key_is_not_accepted(
    signing_key: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.put(make_fingerprint(), reason="test")
    monkeypatch.delenv(trust.ENV_KEY)

    verdict = trust.verify(store.load())
    assert not verdict.ok
    assert verdict.state == "no_key"
    assert trust.ENV_KEY in verdict.detail


def test_trust_verify_reports_an_unsigned_home_store(
    capsys: pytest.CaptureFixture[str],
) -> None:
    store.put(make_fingerprint(), reason="test")

    assert cli_main(["trust", "verify"]) == 3
    assert "not signed" in capsys.readouterr().err


def test_environment_key_takes_precedence_over_the_key_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, key_file, created = trust.ensure_key()
    assert created
    assert key_file is not None and key_file.is_file()

    env_key = "22" * trust.KEY_BYTES
    monkeypatch.setenv(trust.ENV_KEY, env_key)
    assert trust.load_key() == bytes.fromhex(env_key)

    store.put(make_fingerprint(), reason="test")
    monkeypatch.delenv(trust.ENV_KEY)

    # Signed with the environment key, so the key file on disk does not verify it.
    assert trust.verify(store.load()).state == "invalid"


def test_writing_without_a_key_drops_a_stale_signature(
    signing_key: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.put(make_fingerprint(description="first"), reason="test")
    assert "signature" in store.load()

    monkeypatch.delenv(trust.ENV_KEY)
    store.put(make_fingerprint(description="second"), reason="test")

    assert "signature" not in store.load()


def test_short_environment_key_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(trust.ENV_KEY, "00" * 8)

    with pytest.raises(trust.TrustError, match="at least 32 bytes"):
        trust.load_key()


def test_trust_init_creates_a_key_and_signs_the_pins(
    capsys: pytest.CaptureFixture[str],
) -> None:
    store.put(make_fingerprint(), reason="test")
    assert "signature" not in store.load()

    code = cli_main(["trust", "init"])

    assert code == 0
    assert "trust key" in capsys.readouterr().out
    assert trust.key_path().is_file()
    assert trust.verify(store.load()).ok


def test_trust_init_writes_a_signed_repository_baseline(tmp_path: Path) -> None:
    store.put(make_fingerprint(), reason="test")
    target = tmp_path / "pindrift-baseline.json"

    assert cli_main(["trust", "init", "--baseline", str(target)]) == 0

    payload = store.load_path(target)
    assert set(payload["pins"]) == {"test:srv"}
    assert trust.verify(payload).ok


def test_trust_init_without_pins_is_a_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli_main(["trust", "init"]) == 64
    assert "no pins to sign" in capsys.readouterr().err


def test_check_refuses_a_tampered_baseline(
    signing_key: bytes, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store.put(make_fingerprint(), reason="test")
    baseline = tmp_path / "baseline.json"
    store.save(store.load(), baseline)
    baseline.write_text(
        baseline.read_text(encoding="utf-8").replace("hello", "hellp"), encoding="utf-8"
    )

    code = cli_main(["check", "--baseline", str(baseline), "--no-project", "--no-probe"])

    assert code == 3
    assert "refusing to use baseline" in capsys.readouterr().err


def test_pin_refuses_to_re_sign_an_unverified_baseline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    baseline = tmp_path / "baseline.json"
    store.put(make_fingerprint(), reason="test", path=baseline)
    assert "signature" not in store.load_path(baseline)

    monkeypatch.setenv(trust.ENV_KEY, "33" * trust.KEY_BYTES)
    monkeypatch.setattr(cli, "_load_specs", lambda args: ["fake-spec"])
    monkeypatch.setattr(
        cli, "_fingerprint_spec", lambda spec, do_probe, timeout: make_fingerprint()
    )

    code = cli_main(["pin", "--all", "--baseline", str(baseline)])

    assert code == 64
    assert "refusing to overwrite baseline" in capsys.readouterr().err
