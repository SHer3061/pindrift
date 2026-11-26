"""Discovery and parsing of MCP client configuration files.

The whole point of monitoring drift is to look where the drift actually happens,
which is the config files the agent hosts read at startup. That means covering the
real file layouts rather than one canonical format.

Parsing is deliberately tolerant: an unreadable file is reported, not fatal. A
monitor that crashes on the first malformed config is not a monitor.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .detect import redact_arg
from .jsoncfg import strip_jsonc

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
    format: str | None = None  # json | jsonc | toml | yaml
    container: str | None = None
    origin: str = "builtin"  # builtin | custom
    supported: bool = True
    note: str = ""


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
    canonical_id: str | None = None
    aliases: list[str] = field(default_factory=list)

    @property
    def server_id(self) -> str:
        return self.canonical_id or f"{self.client}:{self.name}"

    @property
    def all_aliases(self) -> list[str]:
        """Every ``client:name`` this spec was discovered under."""
        return list(self.aliases) or [self.server_id]

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
    level: str = "error"  # error | warning | info


def _home() -> Path:
    return Path.home()


def _appdata() -> Path:
    override = os.environ.get("APPDATA")
    if override:
        return Path(override)
    return _home() / "AppData" / "Roaming"


def _mac_support() -> Path:
    return _home() / "Library" / "Application Support"


def _xdg_config() -> Path:
    override = os.environ.get("XDG_CONFIG_HOME")
    if override:
        return Path(override).expanduser()
    return _home() / ".config"


def _copilot_home() -> Path:
    override = os.environ.get("COPILOT_HOME")
    if override:
        return Path(override).expanduser()
    return _home() / ".copilot"


def _app_roots() -> list[Path]:
    """Directories where desktop apps keep settings on the current platform."""
    if sys.platform == "win32":
        return [_appdata()]
    if sys.platform == "darwin":
        return [_mac_support(), _xdg_config()]
    return [_xdg_config(), _home() / ".local" / "share"]


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

    # Cline, Roo Code and Kilo Code ship as VS Code extensions and keep their
    # configs in globalStorage.
    for user_dir in _vscode_user_dirs():
        sources += [
            ConfigSource(
                "cline",
                user_dir / "globalStorage" / "saoudrizwan.claude-dev" / "settings"
                / "cline_mcp_settings.json",
                "user",
            ),
            ConfigSource(
                "roo-code",
                user_dir / "globalStorage" / "rooveterinaryinc.roo-cline" / "settings"
                / "cline_mcp_settings.json",
                "user",
            ),
            ConfigSource(
                "kilo-code",
                user_dir / "globalStorage" / "kilocode.kilo-code" / "settings"
                / "mcp_settings.json",
                "user",
            ),
        ]

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

    sources += [
        ConfigSource("workbuddy", _home() / ".workbuddy" / "mcp.json", "user"),
        ConfigSource("codebuddy", _home() / ".codebuddy" / "mcp.json", "user"),
        ConfigSource("copilot-cli", _copilot_home() / "mcp-config.json", "user"),
        ConfigSource("lmstudio", _home() / ".lmstudio" / "mcp.json", "user"),
        ConfigSource("warp", _home() / ".warp" / ".mcp.json", "user"),
        ConfigSource("augment", _home() / ".augment" / "settings.json", "user"),
        ConfigSource("kilo-code", _xdg_config() / "kilo" / "kilo.jsonc", "user", "jsonc"),
        ConfigSource(
            "opencode", _xdg_config() / "opencode" / "opencode.json", "user", "jsonc"
        ),
        ConfigSource(
            "opencode", _xdg_config() / "opencode" / "opencode.jsonc", "user", "jsonc"
        ),
        ConfigSource("amazon-q", _home() / ".aws" / "amazonq" / "mcp.json", "user"),
        ConfigSource("amazon-q", _home() / ".aws" / "amazonq" / "default.json", "user"),
        ConfigSource("devin", _xdg_config() / "devin" / "mcp_config.json", "user"),
        ConfigSource("trae", _home() / ".trae" / "mcp.json", "user"),
    ]

    # Workspace resources kept under the WorkBuddy home, not under the project.
    resources = _home() / ".workbuddy" / "project-resources"
    if resources.is_dir():
        try:
            projects = sorted(p for p in resources.iterdir() if p.is_dir())
        except OSError:
            projects = []
        for project in projects:
            path = project / "mcp.json"
            if path.is_file():
                sources.append(ConfigSource("workbuddy", path, "project"))

    # Electron apps whose userData directory differs by platform.
    for root in _app_roots():
        sources += [
            ConfigSource("trae", root / "Trae" / "User" / "mcp.json", "user"),
            ConfigSource("5ire", root / "5ire" / "mcp.json", "user"),
            ConfigSource("witsy", root / "Witsy" / "settings.json", "user"),
            ConfigSource("jan", root / "Jan" / "data" / "mcp_config.json", "user"),
            ConfigSource("devin", root / "Devin" / "mcp_config.json", "user"),
        ]

    sources += _jetbrains_user_sources()
    return sources


def unsupported_sources() -> list[ConfigSource]:
    """Known clients we can see but cannot parse without a YAML dependency.

    They are surfaced in ``sources list`` and the UI rather than silently omitted:
    "we found the file and cannot read it" is not the same as "there is nothing".
    """
    sources = [
        ConfigSource(
            "goose",
            _appdata() / "Block" / "goose" / "config" / "config.yaml",
            "user",
            "yaml",
            supported=False,
            note="YAML config; no YAML parser is bundled",
        ),
        ConfigSource(
            "goose",
            _xdg_config() / "goose" / "config.yaml",
            "user",
            "yaml",
            supported=False,
            note="YAML config; no YAML parser is bundled",
        ),
        ConfigSource(
            "dsh",
            _home() / ".dsh" / "profiles" / "desktop" / "cordis.patch.yml",
            "user",
            "yaml",
            supported=False,
            note="Cordis YAML; DSH has no MCP config, skills are not scanned yet",
        ),
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
        (".zed/settings.json", "zed"),
        (".idea/mcp.json", "jetbrains"),
        (".github/mcp.json", "copilot-cli"),
        (".roo/mcp.json", "roo-code"),
        ("kilo.jsonc", "kilo-code"),
        (".kilo/kilo.jsonc", "kilo-code"),
        ("opencode.json", "opencode"),
        ("opencode.jsonc", "opencode"),
        (".opencode/opencode.json", "opencode"),
        (".opencode/opencode.jsonc", "opencode"),
        (".amazonq/mcp.json", "amazon-q"),
        (".amazonq/default.json", "amazon-q"),
        (".warp/.mcp.json", "warp"),
        (".devin/mcp_config.json", "devin"),
        (".trae/mcp.json", "trae"),
        (".workbuddy/mcp.json", "workbuddy"),
        (".codebuddy/mcp.json", "codebuddy"),
    )
    for directory in [base, *base.parents]:
        for relative, client in candidates:
            path = directory / relative
            if path.is_file():
                fmt = "jsonc" if path.suffix.lower() == ".jsonc" else None
                if client in ("kilo-code", "opencode") and fmt is None:
                    fmt = "jsonc"
                found.append(ConfigSource(client, path, "project", fmt))
        continue_dir = directory / ".continue" / "mcpServers"
        if continue_dir.is_dir():
            for path in sorted(continue_dir.glob("*.json")):
                found.append(ConfigSource("continue", path, "project"))
        if (directory / ".git").exists():
            break
    return found


def discover(include_project: bool = True, root: Path | None = None) -> list[ConfigSource]:
    """Existing config files for built-in and custom sources, without duplicates."""
    candidates = list(user_config_sources())
    if include_project:
        candidates += project_config_sources(root)

    sources: list[ConfigSource] = []
    seen: set[Path] = set()
    for source in candidates:
        if not source.supported or not source.path.is_file():
            continue
        try:
            key = source.path.resolve()
        except OSError:
            key = source.path
        if key in seen:
            continue
        seen.add(key)
        sources.append(source)
    return sources


def _extract_containers(payload: Any, container: str | None = None) -> dict[str, Any]:
    """Pull the server mapping out of a config document.

    Handles the several shapes in the wild: ``{"mcpServers": {...}}``,
    ``{"servers": {...}}`` (VS Code), nested under ``mcp``, Zed's
    ``context_servers``, a bare mapping, and a list of entries each carrying ``name``
    (Continue's block format). ``container`` comes from a manually registered source
    and is tried first.
    """
    if not isinstance(payload, dict):
        return {}
    keys = (container, *SERVER_CONTAINER_KEYS) if container else SERVER_CONTAINER_KEYS
    for key in keys:
        value = payload.get(key)
        if isinstance(value, dict):
            return value
        if isinstance(value, list):
            named = {
                str(entry["name"]): entry
                for entry in value
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
    """Return (command, args, env), accepting Zed and array-style commands.

    Zed historically wrote ``"command": {"path": ..., "args": [...], "env": {...}}``.
    Kilo and OpenCode write ``"command": ["npx", "-y", "pkg"]`` and ``environment``.
    Both forms describe the same launch.
    """
    command = entry.get("command")
    args = entry.get("args")
    env = entry.get("env")
    if env is None:
        env = entry.get("environment")
    if isinstance(command, dict):
        block = command
        command = block.get("path") or block.get("command")
        args = block.get("args") if args is None else args
        env = block.get("env") if env is None else env
    elif isinstance(command, list):
        parts = [str(part) for part in command]
        command = parts[0] if parts else None
        extra = parts[1:]
        args = [*extra, *args] if isinstance(args, list) else extra
    return command, args, env


def _build_spec(client: str, name: str, entry: dict[str, Any], source: ConfigSource) -> ServerSpec:
    declared_type = str(entry.get("type") or "").lower()
    url = entry.get("url")
    command, args, env_value = _command_parts(entry)
    env = _coerce_str_map(env_value)
    headers = _coerce_str_map(entry.get("headers") or entry.get("staticHeaders"))

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
    fmt = source.format
    if fmt is None:
        suffix = source.path.suffix.lower()
        fmt = "toml" if suffix == ".toml" else "jsonc" if suffix == ".jsonc" else "json"
    if fmt == "yaml":
        return [], SourceError(
            source.client,
            str(source.path),
            "YAML configuration is not supported without a dependency",
            level="info",
        )

    if fmt == "toml":
        if tomllib is None:
            return [], SourceError(
                source.client, str(source.path), "TOML support requires Python 3.11+"
            )
        try:
            payload = tomllib.loads(text)
        except ValueError as exc:  # TOMLDecodeError is a ValueError
            return [], SourceError(source.client, str(source.path), f"invalid TOML: {exc}")
    else:
        try:
            if fmt == "jsonc":
                text = strip_jsonc(text)
            payload = json.loads(text)
        except ValueError as exc:
            label = "JSONC" if fmt == "jsonc" else "JSON"
            return [], SourceError(
                source.client, str(source.path), f"invalid {label}: {exc}"
            )

    container = _extract_containers(payload, source.container)
    specs: list[ServerSpec] = []
    disabled = 0
    for name, entry in container.items():
        if not isinstance(entry, dict):
            continue
        if entry.get("disabled") is True:
            disabled += 1
            continue
        specs.append(_build_spec(source.client, str(name), entry, source))
    error = (
        SourceError(
            source.client,
            str(source.path),
            f"{disabled} disabled server(s) skipped",
            level="info",
        )
        if disabled
        else None
    )
    return specs, error


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


def _resolve_alias(alias: str, aliases: Mapping[str, str] | None) -> tuple[str | None, bool]:
    """Follow a ``client:name`` alias to its persisted canonical id.

    The second element says whether the alias was known at all. A self-mapping (a
    pin written before aliases existed) therefore counts as known: the group must
    keep resolving to that pin instead of falling back to the alphabetically first
    client.
    """
    if not aliases or alias not in aliases:
        return None, False
    current = alias
    seen: set[str] = set()
    while current not in seen:
        seen.add(current)
        target = aliases.get(current)
        if not target:
            break
        current = target
    return current, True


def _identity_suffix(spec: ServerSpec) -> str:
    """Short, deterministic token for two same-named servers with different launches.

    Only appended when a canonical id would otherwise be duplicated. The id is
    persisted in the pin file once the server is pinned, so a later launch change
    does not rename it.
    """
    blob = json.dumps(launch_key(spec), ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:8]


@dataclass
class _Group:
    primary: ServerSpec
    ordered: list[ServerSpec]
    aliases: list[str]
    candidate: str
    mapped: bool


def dedupe_specs(
    specs: list[ServerSpec], aliases: Mapping[str, str] | None = None
) -> list[ServerSpec]:
    """Collapse identical launch definitions discovered through several clients.

    One server configured in three clients is one risk, not three, and probing it
    three times is three chances to execute the same code. The merged spec keeps one
    canonical id and records every ``client:name`` alias so the report can still
    name them all.

    ``aliases`` maps every alias seen before to the id it was pinned under. A group
    that contains a known alias keeps that id, which is what makes the identity
    survive both adding a client and a legitimate launch change. When every recorded
    alias is gone, an unambiguous pin with the same name is reused instead. Without
    either signal the first client alphabetically supplies the id, exactly as before,
    and the pin operation persists the group so the next run is stable.

    Entries with the same name and a *different* launch definition are kept apart on
    purpose: that difference is real drift, not duplication.
    """
    groups: dict[tuple[Any, ...], list[ServerSpec]] = {}
    name_counts: dict[str, int] = {}
    for spec in specs:
        groups.setdefault(launch_key(spec), []).append(spec)
        name_counts[spec.name] = name_counts.get(spec.name, 0) + 1

    # A pin key always aliases itself, so its suffix is the server name. When a
    # client that was never pinned is the only remaining config for that name, the
    # name is enough to keep the original id -- the explicit "match by name" rule for
    # losing every recorded alias. It is only used when the name is unambiguous both
    # among pins and within this run.
    pinned_by_name: dict[str, set[str]] = {}
    for alias, canonical in (aliases or {}).items():
        _, separator, name = alias.partition(":")
        if separator:
            pinned_by_name.setdefault(name, set()).add(canonical)

    entries: list[_Group] = []
    for group in groups.values():
        ordered = sorted(group, key=lambda s: (s.client, s.scope, s.source_path))
        primary = ordered[0]
        group_aliases = sorted({f"{s.client}:{s.name}" for s in ordered})
        resolved = {
            target
            for alias in group_aliases
            for target, known in [_resolve_alias(alias, aliases)]
            if known and target
        }
        mapped = bool(resolved)
        if resolved:
            candidate = min(resolved)
        elif name_counts[primary.name] == 1 and len(pinned_by_name.get(primary.name, ())) == 1:
            candidate = next(iter(pinned_by_name[primary.name]))
            mapped = True
        else:
            candidate = group_aliases[0]
        entries.append(_Group(primary, ordered, group_aliases, candidate, mapped))

    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.candidate] = counts.get(entry.candidate, 0) + 1

    used: set[str] = set()
    merged: list[ServerSpec] = []
    for entry in sorted(entries, key=lambda e: (e.candidate, _identity_suffix(e.primary))):
        primary = entry.primary
        candidate = entry.candidate
        # An unpinned collision cannot be authoritative: give both groups a stable
        # launch-derived suffix rather than letting client order pick a winner.
        if counts[candidate] > 1 and not entry.mapped:
            candidate = f"{candidate}#{_identity_suffix(primary)}"
        # Two pins that were deliberately mapped to one id are already inconsistent;
        # keep the first and make the other visible under its own id rather than
        # silently dropping a pinned server from the results.
        if candidate in used:
            candidate = f"{candidate}#{_identity_suffix(primary)}"
        used.add(candidate)
        merged.append(
            replace(
                primary,
                canonical_id=candidate,
                aliases=entry.aliases,
                clients=sorted({s.client for s in entry.ordered}),
                source_paths=sorted({s.source_path for s in entry.ordered}),
            )
        )
    merged.sort(key=lambda s: (s.name, s.server_id, s.source_path))
    return merged


def collect(
    include_project: bool = True,
    root: Path | None = None,
    dedupe: bool = False,
    aliases: Mapping[str, str] | None = None,
) -> tuple[list[ServerSpec], list[SourceError], list[ConfigSource]]:
    from . import sources as source_registry

    sources = discover(include_project=include_project, root=root)
    seen = {source.path.resolve() for source in sources}
    custom, errors = source_registry.discover_custom()
    for source in custom:
        try:
            key = source.path.resolve()
        except OSError:
            key = source.path
        if key not in seen:
            seen.add(key)
            sources.append(source)

    specs: list[ServerSpec] = []
    for source in sources:
        parsed, error = parse_source(source)
        specs.extend(parsed)
        if error:
            errors.append(error)
    if dedupe:
        specs = dedupe_specs(specs, aliases)
    return specs, errors, sources


def iter_sources() -> Iterator[ConfigSource]:
    yield from discover()
