from __future__ import annotations

import sys
from pathlib import Path

import pytest

FIXTURE_SERVER = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"


@pytest.fixture
def fixture_server() -> Path:
    assert FIXTURE_SERVER.is_file()
    return FIXTURE_SERVER


@pytest.fixture
def python_exe() -> str:
    return sys.executable


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Never touch the real ~/.pindrift during tests."""
    monkeypatch.setenv("PINDRIFT_HOME", str(tmp_path / "pindrift-home"))
    return tmp_path / "pindrift-home"
