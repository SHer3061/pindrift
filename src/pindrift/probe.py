"""Live probing of stdio MCP servers to capture their tool manifest.

Static config scanning can only see *how a server is launched*. It cannot see what
tools that server advertises at runtime, and the runtime manifest is precisely what
the model reads. Tool poisoning lives there.

Safety posture:

* probing executes third-party code, so it is opt-in per command and never runs
  against servers that have not already been trusted once (see ``cli.py``)
* every probe is bounded by a timeout and the child is always terminated
* stdout is parsed as JSON-RPC line by line; non-JSON banner output is ignored
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from . import __version__
from .discover import ServerSpec
from .models import ToolManifest

PROTOCOL_VERSION = "2024-11-05"
DEFAULT_TIMEOUT = 20.0
MAX_PAGES = 10


def _resolve_command(command: str) -> str | None:
    if Path(command).expanduser().is_file():
        return str(Path(command).expanduser())
    return shutil.which(command)


def _wrap_for_windows(path: str, args: list[str]) -> list[str]:
    """CreateProcess cannot start ``.cmd`` / ``.bat`` directly; route via cmd.exe."""
    if sys.platform == "win32" and path.lower().endswith((".cmd", ".bat")):
        return ["cmd.exe", "/c", path, *args]
    return [path, *args]


def _build_env(spec: ServerSpec) -> dict[str, str]:
    env = {str(k): str(v) for k, v in os.environ.items()}
    for key, value in spec.env.items():
        resolved = os.path.expandvars(value)
        env[key] = resolved
    return env


def _reader(stream: Any, sink: queue.Queue[Any]) -> None:
    try:
        for line in iter(stream.readline, ""):
            sink.put(line)
    except Exception as exc:  # noqa: BLE001 - any read failure must not kill the thread
        sink.put(exc)
    finally:
        sink.put(None)


def _rpc(request_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = params
    return payload


def probe_spec(
    spec: ServerSpec, timeout: float = DEFAULT_TIMEOUT
) -> tuple[list[ToolManifest] | None, str | None]:
    """Handshake with a stdio server and return its tool manifest.

    Returns ``(tools, error)``. On failure ``tools`` is ``None`` and the caller is
    expected to record ``UNKNOWN`` rather than a clean result.
    """
    if spec.transport != "stdio":
        return None, f"transport is '{spec.transport}'; only stdio servers can be probed"
    if not spec.command:
        return None, "no command configured"

    resolved = _resolve_command(spec.command)
    if not resolved:
        return None, f"command not found on PATH: {spec.command}"

    argv = _wrap_for_windows(resolved, spec.args)
    cwd = Path(spec.source_path).parent if spec.source_path else Path.cwd()
    if not cwd.is_dir():
        cwd = Path.cwd()

    popen_kwargs: dict[str, Any] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "bufsize": 1,
        "cwd": str(cwd),
        "env": _build_env(spec),
    }
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        proc = subprocess.Popen(argv, **popen_kwargs)
    except OSError as exc:
        return None, f"failed to start: {exc}"

    sink: queue.Queue[Any] = queue.Queue()
    watcher = threading.Thread(target=_reader, args=(proc.stdout, sink), daemon=True)
    watcher.start()

    deadline = time.monotonic() + timeout
    tools: list[ToolManifest] | None = None
    error: str | None = None

    try:
        assert proc.stdin is not None
        init = _rpc(
            1,
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "pindrift", "version": __version__},
            },
        )
        notes: list[dict[str, Any]] = [
            init,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            _rpc(2, "tools/list", {}),
        ]
        for payload in notes:
            proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()

        next_id = 3
        cursor: str | None = None
        collected: list[ToolManifest] = []
        awaiting: set[int] = {2}

        while awaiting:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                error = f"probe timed out after {timeout:g}s"
                break
            try:
                line = sink.get(timeout=remaining)
            except queue.Empty:
                error = f"probe timed out after {timeout:g}s"
                break
            if line is None:
                error = "server closed stdout before returning a manifest"
                break
            if isinstance(line, Exception):
                error = f"read error: {line}"
                break
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(message, dict):
                continue
            if message.get("id") not in awaiting:
                continue
            awaiting.discard(message["id"])

            if "error" in message:
                error = f"server error: {message['error']}"
                break

            result = message.get("result") or {}
            if not isinstance(result, dict):
                error = "malformed tools/list result"
                break
            for item in result.get("tools") or []:
                if isinstance(item, dict):
                    collected.append(ToolManifest.from_mcp(item))

            cursor = result.get("nextCursor")
            if cursor and len(awaiting) < MAX_PAGES:
                assert proc.stdin is not None
                proc.stdin.write(json.dumps(_rpc(next_id, "tools/list", {"cursor": cursor})) + "\n")
                proc.stdin.flush()
                awaiting.add(next_id)
                next_id += 1

        if error is None:
            tools = collected
    finally:
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:  # pragma: no cover
                pass

    if error and tools is None and proc.stderr is not None:
        try:
            stderr = proc.stderr.read() or ""
        except (OSError, ValueError):
            stderr = ""
        stderr = stderr.strip()
        if stderr:
            error = f"{error} | stderr: {stderr.splitlines()[-1][:200]}"

    return tools, error


def probe_many(
    specs: list[ServerSpec], timeout: float = DEFAULT_TIMEOUT
) -> dict[str, tuple[list[ToolManifest] | None, str | None]]:
    return {spec.server_id: probe_spec(spec, timeout=timeout) for spec in specs}
