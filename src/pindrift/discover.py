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
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterator

from .detect import redact_arg

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    tomllib = None  # type: ignore[assignment]

SERVER_CONTAINER_KEYS = (
    "mcpServers",
    "servers",
    "mcp_servers",
    "mcp",
    "context_servers",  # Zed
)


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
    clients: list[str] = field(default_factory=list)
    source_paths: list[str] = field(default_factory=list)

    @property
    def server_id(self) -> str:
        return f"{self.client}:{self.name}"

    @property
    def all_clients(self) -> list[str]:
        """Every client that configures this server, not only the primary one."""
        return list(self.clients) or [self.client]

    @property
    def all_source_paths(self) -> list[str]:
        return list(self.source_paths) or [self.source_path]

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


def _claude_config_path() -> Path:
    """Claude Code honours CLAUDE_CONFIG_DIR for its user and local scopes."""
    override = os.environ.get("CLAUDE_CONFIG_DIR")
    if override:
        return Path(override).expanduser() / ".claude.json"
    return _home() / ".claude.json"


def _vscode_user_dirs() -> list[Path]:
    if sys.platform == "win32":
        base = _appdata()
        return [base / "Code" / "User", base / "Code - Insiders" / "User"]
    if sys.platform == "darwin":
        base = _mac_support()
        return [base / "Code" / "User", base / "Code - Insiders" / "User"]
    base = _home() / ".config"
    return [base / "Code" / "User", base / "Code - Insiders" / "User"]


def _jetbrains_roots() -> list[Path]:
    if sys.platform == "win32":
        return [_appdata() / "JetBrains"]
    if sys.platform == "darwin":
        return [_mac_support() / "JetBrains"]
    return [_home() / ".config" / "JetBrains"]


def _jetbrains_user_sources() -> list[ConfigSource]:
    """Every installed JetBrains product can carry its own AI Assistant config.

    The directory name includes the product and version, so it is discovered rather
    than guessed. Both the AI Assistant path and the plain ``mcp.json`` Junie writes
    are picked up.
    """
    found: list[ConfigSource] = []
    for root in _jetbrains_roots():
        if not root.is_dir():
            continue
        try:
            products = sorted(p for p in root.iterdir() if p.is_dir())
        except OSError:
            continue
        for product in products:
            for relative in (Path("ai") / "mcp.json", Path("mcp.json")):
                path = product / relative
                if path.is_file():
                    found.append(ConfigSource("jetbrains", path, "user"))
    return found


def user_config_sources() -> list[ConfigSource]:
    """Every known per-user MCP config location for the current platform."""
    sources: list[ConfigSource] = [
        ConfigSource("claude-code", _claude_config_path(), "user"),
        ConfigSource("cursor", _home() / ".cursor" / "mcp.json", "user"),
        ConfigSource("windsurf", _home() / ".codeium" / "windsurf" / "mcp_config.json", "user"),
        ConfigSource("gemini-cli", _home() / ".gemini" / "settings.json", "user"),
        ConfigSource("codex", _home() / ".codex" / "config.toml", "user"),
        ConfigSource("cline", _home() / ".cline" / "mcp.json", "user"),
        ConfigSource("continue", _home() / ".continue" / "config.json", "user"),
    ]

    # Cline ships as a VS Code extension and keeps its config in globalStorage.
    for user_dir in _vscode_user_dirs():
        sources.append(
            ConfigSource(
                "cline",
                user_dir / "globalStorage" / "saoudrizwan.claude-dev" / "settings"
                / "cline_mcp_settings.json",
                "user",
            )
        )

    if sys.platform == "win32":
        sources += [
            ConfigSource(
                "claude-desktop",
                _appdata() / "Claude" / "claude_desktop_config.json",
                "user",
            ),
            ConfigSource("vscode", _appdata() / "Code" / "User" / "mcp.json", "user"),
            ConfigSource(
                "vscode-insiders",
                _appdata() / "Code - Insiders" / "User" / "mcp.json",
                "user",
            ),
            ConfigSource("zed", _appdata() / "Zed" / "settings.json", "user"),
        ]
    elif sys.platform == "darwin":
        sources += [
            ConfigSource(
                "claude-desktop",
                _mac_support() / "Claude" / "claude_desktop_config.json",
                "user",
            ),
            ConfigSource("vscode", _mac_support() / "Code" / "User" / "mcp.json", "user"),
            ConfigSource("zed", _home() / ".config" / "zed" / "settings.json", "user"),
        ]
    else:
        sources += [
            ConfigSource(
                "claude-desktop",
                _home() / ".config" / "Claude" / "claude_desktop_config.json",
                "user",
            ),
            ConfigSource("vscode", _home() / ".config" / "Code" / "User" / "mcp.json", "user"),
            ConfigSource("zed", _home() / ".config" / "zed" / "settings.json", "user"),
        ]

    sources += _jetbrains_user_sources()
    return sources


def project_config_sources(root: Path | None = None) -> list[ConfigSource]:
    """Project-scoped configs, walking up from ``root`` to the filesystem root."""
    base = (root or Path.cwd()).resolve()
    found: list[ConfigSource] = []
    candidates = (
        (".mcp.json", "claude-code"),
        (".vscode/mcp.json", "vscode"),
        (".cursor/mcp.json", "cursor"),
        (".zed/settings.json", "zed"),
        (".idea/mcp.json", "jetbrains"),
    )
    for directory in [base, *base.parents]:
        for relative, client in candidates:
            path = directory / relative
            if path.is_file():
                found.append(ConfigSource(client, path, "project"))
        continue_dir = directory / ".continue" / "mcpServers"
        if continue_dir.is_dir():
            for path in sorted(continue_dir.glob("*.json")):
                found.append(ConfigSource("continue", path, "project"))
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
    ``{"servers": {...}}`` (VS Code), nested under ``mcp``, Zed's
    ``context_servers``, a bare mapping, and a list of entries each carrying ``name``
    (Continue's block format).
    """
    if not isinstance(payload, dict):
        return {}
    for key in SERVER_CONTAINER_KEYS:
        container = payload.get(key)
        if isinstance(container, dict):
            return container
        if isinstance(container, list):
            named = {
                str(entry["name"]): entry
                for entry in container
                if isinstance(entry, dict) and isinstance(entry.get("name"), str)
            }
            if named:
                return named
    if any(isinstance(v, dict) and ("command" in v or "url" in v) for v in payload.values()):
        return payload
    return {}


def _coerce_str_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items()}


def _command_parts(entry: dict[str, Any]) -> tuple[Any, Any, Any]:
    """Return (command, args, env), accepting Zed's nested command object.

    Zed historically wrote ``"command": {"path": ..., "args": [...], "env": {...}}``
    and now also accepts the flat form every other client uses. Both are real.
    """
    command = entry.get("command")
    args = entry.get("args")
    env = entry.get("env")
    if isinstance(command, dict):
        block = command
        command = block.get("path") or block.get("command")
        args = block.get("args") if args is None else args
        env = block.get("env") if env is None else env
    return command, args, env


def _build_spec(client: str, name: str, entry: dict[str, Any], source: ConfigSource) -> ServerSpec:
    declared_type = str(entry.get("type") or "").lower()
    url = entry.get("url")
    command, args, env_value = _command_parts(entry)
    env = _coerce_str_map(env_value)
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


def launch_key(spec: ServerSpec) -> tuple[Any, ...]:
    """Identity of a server as *configured*, independent of which client read it.

    The name is part of the key: two entries with different names are different
    aliases even when they launch the same command, and collapsing them would hide
    which one an agent actually calls.
    """
    return (
        spec.name,
        spec.transport,
        spec.command,
        tuple(spec.args),
        tuple(spec.env_keys),
        spec.url,
        tuple(spec.headers_keys),
    )


def dedupe_specs(specs: list[ServerSpec]) -> list[ServerSpec]:
    """Collapse identical launch definitions discovered through several clients.

    One server configured in three clients is one risk, not three, and probing it
    three times is three chances to execute the same code. The merged spec keeps the
    first client as ``client`` (and therefore as its ``server_id``) but records every
    client and source path so the report can still name them all.

    Entries with the same name and a *different* launch definition are kept apart on
    purpose: that difference is real drift, not duplication.

    The id is therefore client-dependent: adding a client that sorts earlier renames
    the merged server, which makes an existing pin look missing and the server look
    new. Stable pin identity is tracked as T3b in docs/TASKS.md; until it lands, keep
    the same client set between ``pin`` and ``check``.
    """
    groups: dict[tuple[Any, ...], list[ServerSpec]] = {}
    for spec in specs:
        groups.setdefault(launch_key(spec), []).append(spec)

    merged: list[ServerSpec] = []
    for group in groups.values():
        ordered = sorted(group, key=lambda s: (s.client, s.scope, s.source_path))
        primary = ordered[0]
        merged.append(
            replace(
                primary,
                clients=sorted({s.client for s in ordered}),
                source_paths=sorted({s.source_path for s in ordered}),
            )
        )
    merged.sort(key=lambda s: (s.name, s.client, s.source_path))
    return merged


def collect(
    include_project: bool = True,
    root: Path | None = None,
    dedupe: bool = False,
) -> tuple[list[ServerSpec], list[SourceError], list[ConfigSource]]:
    sources = discover(include_project=include_project, root=root)
    specs: list[ServerSpec] = []
    errors: list[SourceError] = []
    for source in sources:
        parsed, error = parse_source(source)
        specs.extend(parsed)
        if error:
            errors.append(error)
    if dedupe:
        specs = dedupe_specs(specs)
    return specs, errors, sources


def iter_sources() -> Iterator[ConfigSource]:
    yield from discover()
