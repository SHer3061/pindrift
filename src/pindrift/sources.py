"""Manually registered MCP config files.

Built-in discovery covers known clients. This registry is the escape hatch for a
client whose config layout is not built in: the user names the file once and it is
scanned like any other source.

The registry is deliberately additive. It can add a path, never remove, hide or
override a built-in source: otherwise a local file could silently shrink what the
monitor watches.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import store
from .discover import ConfigSource, SourceError

SCHEMA_VERSION = 1
SUPPORTED_FORMATS = ("json", "jsonc", "toml")


class SourceRegistryError(ValueError):
    """The registry is unreadable or contains an invalid entry."""


@dataclass(frozen=True)
class CustomSource:
    client: str
    path: Path
    scope: str = "user"
    format: str | None = None
    container: str | None = None

    @property
    def id(self) -> str:
        identity = f"{self.client}|{self.path}|{self.scope}"
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]

    def to_config_source(self) -> ConfigSource:
        return ConfigSource(
            client=self.client,
            path=self.path,
            scope=self.scope,
            format=self.format,
            container=self.container,
            origin="custom",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "client": self.client,
            "path": str(self.path),
            "scope": self.scope,
            "format": self.format,
            "container": self.container,
        }


def registry_path() -> Path:
    return store.home() / "sources.json"


def _empty() -> dict[str, Any]:
    return {"schema": SCHEMA_VERSION, "sources": []}


def _normalise_path(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise SourceRegistryError(f"source path must be absolute: {value}")
    return path


def _validate_format(value: Any) -> str | None:
    if value in (None, ""):
        return None
    fmt = str(value).lower()
    if fmt == "yaml":
        raise SourceRegistryError(
            "YAML sources are not supported without a runtime dependency"
        )
    if fmt not in SUPPORTED_FORMATS:
        raise SourceRegistryError(
            f"unsupported format {fmt!r}; use one of {', '.join(SUPPORTED_FORMATS)}"
        )
    return fmt


def _parse_entry(entry: Any) -> CustomSource:
    if not isinstance(entry, dict):
        raise SourceRegistryError("every source must be an object")
    client = str(entry.get("client") or "").strip()
    if not client:
        raise SourceRegistryError("every source needs a non-empty 'client'")
    raw_path = str(entry.get("path") or "").strip()
    if not raw_path:
        raise SourceRegistryError("every source needs a 'path'")
    scope = str(entry.get("scope") or "user")
    if scope not in ("user", "project"):
        raise SourceRegistryError(f"invalid scope {scope!r}")
    container = entry.get("container")
    return CustomSource(
        client=client,
        path=_normalise_path(raw_path),
        scope=scope,
        format=_validate_format(entry.get("format")),
        container=str(container) if container else None,
    )


def load(path: Path | None = None) -> list[CustomSource]:
    """Read the registry strictly. A missing file means no custom sources."""
    path = path or registry_path()
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise SourceRegistryError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SourceRegistryError(f"invalid JSON in {path}: {exc}") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("sources"), list):
        raise SourceRegistryError(f"{path} is not a pindrift sources file")
    return [_parse_entry(entry) for entry in payload["sources"]]


def save(sources: list[CustomSource], path: Path | None = None) -> Path:
    path = path or registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    document = _empty()
    document["updated_at"] = store.utc_now()
    document["sources"] = [source.to_dict() for source in sources]

    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(path.parent), delete=False, suffix=".tmp"
    ) as handle:
        temporary = handle.name
        json.dump(document, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    return path


def add(
    *,
    client: str,
    path: str | Path,
    scope: str = "user",
    format: str | None = None,
    container: str | None = None,
) -> CustomSource:
    source = CustomSource(
        client=client.strip(),
        path=_normalise_path(str(path)),
        scope=scope,
        format=_validate_format(format),
        container=container,
    )
    if not source.client:
        raise SourceRegistryError("client must not be empty")
    if source.path.exists() and not source.path.is_file():
        raise SourceRegistryError(f"source path is not a regular file: {source.path}")
    existing = load()
    kept = [item for item in existing if item.path != source.path]
    kept.append(source)
    save(kept)
    return source


def remove(identifier: str) -> bool:
    existing = load()
    kept = [
        item
        for item in existing
        if identifier not in (item.id, str(item.path))
    ]
    if len(kept) == len(existing):
        return False
    save(kept)
    return True


def discover_custom() -> tuple[list[ConfigSource], list[SourceError]]:
    """Custom sources plus loud errors for missing files or a corrupt registry."""
    try:
        entries = load()
    except SourceRegistryError as exc:
        return [], [
            SourceError(
                "sources-registry",
                str(registry_path()),
                str(exc),
                level="error",
            )
        ]

    sources: list[ConfigSource] = []
    errors: list[SourceError] = []
    for entry in entries:
        if not entry.path.is_file():
            errors.append(
                SourceError(
                    entry.client,
                    str(entry.path),
                    "configured source no longer exists",
                    level="warning",
                )
            )
            continue
        sources.append(entry.to_config_source())
    return sources, errors
