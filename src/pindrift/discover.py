"""Discovery and parsing of MCP client configuration files.

The whole point of monitoring drift is to look where the drift actually happens,
which is the config files the agent hosts read at startup. That means covering the
real file layouts rather than one canonical format.

Parsing is deliberately tolerant: an unreadable file is reported, not fatal. A
monitor that crashes on the first malformed config is not a monitor.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .detect import redact_arg

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    tomllib = None  # type: ignore[assignment]

SERVER_CONTAINER_KEYS = ("mcpServers", "servers", "mcp_servers", "mcp")


@dataclass
class ConfigSource:
    client: str
    path: Path
    scope: str  # "user" | "project"


@dataclass
class ServerSpec:
    client: str
    name: str
    transport: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env_keys: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers_keys: list[str] = field(default_factory=list)
    source_path: str = ""
    scope: str = "user"
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def server_id(self) -> str:
        return f"{self.client}:{self.name}"

    @property
    def redacted_args(self) -> list[str]:
        return [redact_arg(a) for a in self.args]


@dataclass
class SourceError:
    client: str
    path: str
    message: str


def _home() -> Path:
    return Path.home()


def _appdata() -> Path:
    override = os.environ.get("APPDATA")
    if override:
        return Path(override)
    return _home() / "AppData" / "Roaming"


def _mac_support() -> Path:
    return _home() / "Library" / "Application Support"


def user_config_sources() -> list[ConfigSource]:
    """Every known per-user MCP config location for the current platform."""
    sources: list[ConfigSource] = [
        ConfigSource("claude-code", _home() / ".claude.json", "user"),
        ConfigSource("cursor", _home() / ".cursor" / "mcp.json", "user"),
        ConfigSource("windsurf", _home() / ".codeium" / "windsurf" / "mcp_config.json", "user"),
        ConfigSource("gemini-cli", _home() / ".gemini" / "settings.json", "user"),
        ConfigSource("codex", _home() / ".codex" / "config.toml", "user"),
    ]

    if sys.platform == "win32":
        sources += [
            ConfigSource("claude-desktop", _appdata() / "Claude" / "claude_desktop_config.json", "user"),
            ConfigSource("vscode", _appdata() / "Code" / "User" / "mcp.json", "user"),
            ConfigSource("vscode-insiders", _appdata() / "Code - Insiders" / "User" / "mcp.json", "user"),
        ]
    elif sys.platform == "darwin":
        sources += [
            ConfigSource(
                "claude-desktop",
                _mac_support() / "Claude" / "claude_desktop_config.json",
                "user",
            ),
            ConfigSource("vscode", _mac_support() / "Code" / "User" / "mcp.json", "user"),
        ]
    else:
        sources += [
            ConfigSource(
                "claude-desktop",
                _home() / ".config" / "Claude" / "claude_desktop_config.json",
                "user",
            ),
            ConfigSource("vscode", _home() / ".config" / "Code" / "User" / "mcp.json", "user"),
        ]
    return sources


def project_config_sources(root: Path | None = None) -> list[ConfigSource]:
    """Project-scoped configs, walking up from ``root`` to the filesystem root."""
    base = (root or Path.cwd()).resolve()
    found: list[ConfigSource] = []
    candidates = (
        (".mcp.json", "claude-code"),
        (".vscode/mcp.json", "vscode"),
        (".cursor/mcp.json", "cursor"),
    )
    for directory in [base, *base.parents]:
        for relative, client in candidates:
            path = directory / relative
            if path.is_file():
                found.append(ConfigSource(client, path, "project"))
        if (directory / ".git").exists():
            break
    return found


def discover(include_project: bool = True, root: Path | None = None) -> list[ConfigSource]:
    sources = [s for s in user_config_sources() if s.path.is_file()]
    if include_project:
        seen = {s.path.resolve() for s in sources}
        for source in project_config_sources(root):
            if source.path.resolve() not in seen:
                sources.append(source)
    return sources


def _extract_containers(payload: Any) -> dict[str, Any]:
    """Pull the server mapping out of a config document.

    Handles the several shapes in the wild: ``{"mcpServers": {...}}``,
    ``{"servers": {...}}`` (VS Code), nested under ``mcp``, and a bare mapping.
    """
    if not isinstance(payload, dict):
        return {}
    for key in SERVER_CONTAINER_KEYS:
        container = payload.get(key)
        if isinstance(container, dict):
            return container
    if any(isinstance(v, dict) and ("command" in v or "url" in v) for v in payload.values()):
        return payload
    return {}


def _coerce_str_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items()}


def _build_spec(client: str, name: str, entry: dict[str, Any], source: ConfigSource) -> ServerSpec:
    declared_type = str(entry.get("type") or "").lower()
    url = entry.get("url")
    command = entry.get("command")
    args = entry.get("args")
    env = _coerce_str_map(entry.get("env"))
    headers = _coerce_str_map(entry.get("headers"))

    if url:
        transport = "sse" if declared_type in ("sse", "") and "sse" in str(url).lower() else "http"
        if declared_type == "sse":
            transport = "sse"
    elif command:
        transport = "stdio"
    else:
        transport = "unknown"

    return ServerSpec(
        client=client,
        name=name,
        transport=transport,
        command=str(command) if command else None,
        args=[str(a) for a in args] if isinstance(args, list) else [],
        env_keys=sorted(env),
        env=env,
        url=str(url) if url else None,
        headers_keys=sorted(headers),
        source_path=str(source.path),
        scope=source.scope,
        raw=entry,
    )


def parse_source(source: ConfigSource) -> tuple[list[ServerSpec], SourceError | None]:
    """Read one config file. Returns (specs, error)."""
    try:
        # utf-8-sig also accepts plain UTF-8. Windows editors and PowerShell's
        # Set-Content write a BOM, and a monitor that chokes on one is useless.
        text = source.path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        return [], SourceError(source.client, str(source.path), f"unreadable: {exc}")
    except UnicodeDecodeError:
        return [], SourceError(source.client, str(source.path), "not valid UTF-8")

    payload: Any
    if source.path.suffix.lower() == ".toml":
        if tomllib is None:
            return [], SourceError(
                source.client, str(source.path), "TOML support requires Python 3.11+"
            )
        try:
            payload = tomllib.loads(text)
        except Exception as exc:  # tomllib raises TOMLDecodeError
            return [], SourceError(source.client, str(source.path), f"invalid TOML: {exc}")
    else:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            return [], SourceError(source.client, str(source.path), f"invalid JSON: {exc}")

    container = _extract_containers(payload)
    specs: list[ServerSpec] = []
    for name, entry in container.items():
        if not isinstance(entry, dict):
            continue
        specs.append(_build_spec(source.client, str(name), entry, source))
    return specs, None


def collect(
    include_project: bool = True, root: Path | None = None
) -> tuple[list[ServerSpec], list[SourceError], list[ConfigSource]]:
    sources = discover(include_project=include_project, root=root)
    specs: list[ServerSpec] = []
    errors: list[SourceError] = []
    for source in sources:
        parsed, error = parse_source(source)
        specs.extend(parsed)
        if error:
            errors.append(error)
    return specs, errors, sources


def iter_sources() -> Iterator[ConfigSource]:
    yield from discover()
