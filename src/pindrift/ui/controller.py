"""Backend operations for the desktop UI.

The UI never calls CLI command handlers: those write to stdout and return exit
codes. Everything here returns dataclasses and lets the view decide how to render.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .. import service, sources, store
from ..discover import (
    ConfigSource,
    ServerSpec,
    SourceError,
    parse_source,
    project_config_sources,
    unsupported_sources,
    user_config_sources,
)
from ..models import ServerFingerprint, Severity
from ..probe import DEFAULT_TIMEOUT


@dataclass
class Settings:
    root: Path
    include_project: bool = True
    dedupe: bool = True
    timeout: float = DEFAULT_TIMEOUT
    fail_on: Severity = Severity.HIGH


@dataclass
class Inventory:
    specs: list[ServerSpec]
    fingerprints: list[ServerFingerprint]
    pinned_ids: set[str]
    errors: list[SourceError]
    sources: list[ConfigSource]
    baseline_label: str


@dataclass
class SourceRow:
    client: str
    path: str
    scope: str
    origin: str
    format: str
    exists: bool
    supported: bool
    note: str
    identifier: str = ""


def load_inventory(settings: Settings) -> Inventory:
    payload = store.load()
    specs, errors, found = service.load_specs(
        root=settings.root,
        include_project=settings.include_project,
        dedupe=settings.dedupe,
        aliases=store.alias_map(payload),
    )
    fingerprints = service.fingerprint_specs(
        specs, do_probe=False, timeout=settings.timeout
    )
    stamp = payload.get("updated_at") or "no baseline"
    return Inventory(
        specs=specs,
        fingerprints=fingerprints,
        pinned_ids=set(payload.get("pins") or {}),
        errors=errors,
        sources=found,
        baseline_label=f"baseline {stamp}",
    )


def check(settings: Settings, progress: service.Progress | None = None) -> service.ScanReport:
    return service.scan(
        service.ScanOptions(
            root=settings.root,
            include_project=settings.include_project,
            dedupe=settings.dedupe,
            probe="auto",
            timeout=settings.timeout,
            fail_on=settings.fail_on,
        ),
        progress=progress,
    )


def _fingerprint_many(
    specs: list[ServerSpec],
    settings: Settings,
    progress: service.Progress | None,
) -> list[ServerFingerprint]:
    fingerprints: list[ServerFingerprint] = []
    total = len(specs)
    for index, spec in enumerate(specs):
        fingerprints.append(
            service.fingerprint_spec(spec, do_probe=True, timeout=settings.timeout)
        )
        if progress is not None:
            progress(index + 1, total, spec.server_id)
    return fingerprints


def pin(
    specs: list[ServerSpec],
    settings: Settings,
    progress: service.Progress | None = None,
) -> list[ServerFingerprint]:
    fingerprints = _fingerprint_many(specs, settings, progress)
    store.put_many(fingerprints, reason="ui-pin")
    return fingerprints


def approve(
    specs: list[ServerSpec],
    settings: Settings,
    progress: service.Progress | None = None,
) -> list[ServerFingerprint]:
    fingerprints = _fingerprint_many(specs, settings, progress)
    for fingerprint in fingerprints:
        store.put(fingerprint, reason="ui-approve")
    return fingerprints


def source_rows(settings: Settings) -> list[SourceRow]:
    rows: list[SourceRow] = []
    for source in [
        *user_config_sources(),
        *project_config_sources(settings.root),
        *unsupported_sources(),
    ]:
        if not source.path.is_file():
            continue
        rows.append(
            SourceRow(
                client=source.client,
                path=str(source.path),
                scope=source.scope,
                origin=source.origin,
                format=source.format or source.path.suffix.lstrip(".") or "json",
                exists=True,
                supported=source.supported,
                note=source.note,
            )
        )

    try:
        custom = sources.load()
    except sources.SourceRegistryError as exc:
        rows.append(
            SourceRow(
                client="sources-registry",
                path=str(sources.registry_path()),
                scope="user",
                origin="custom",
                format="json",
                exists=True,
                supported=False,
                note=str(exc),
            )
        )
        return rows

    for entry in custom:
        rows.append(
            SourceRow(
                client=entry.client,
                path=str(entry.path),
                scope=entry.scope,
                origin="custom",
                format=entry.format or entry.path.suffix.lstrip(".") or "json",
                exists=entry.path.is_file(),
                supported=True,
                note="" if entry.path.is_file() else "configured but missing",
                identifier=entry.id,
            )
        )
    return rows


def add_source(
    client: str,
    path: str,
    scope: str,
    format: str | None,
    container: str | None,
) -> sources.CustomSource:
    return sources.add(
        client=client, path=path, scope=scope, format=format, container=container
    )


def remove_source(identifier: str) -> bool:
    return sources.remove(identifier)


def test_source(identifier: str) -> tuple[int, list[str]]:
    entry = next(
        (
            item
            for item in sources.load()
            if identifier in (item.id, str(item.path), item.client)
        ),
        None,
    )
    if entry is None:
        return 0, [f"no source matched {identifier!r}"]
    if not entry.path.is_file():
        return 0, [f"{entry.client}: {entry.path}: missing"]
    specs, error = parse_source(entry.to_config_source())
    lines = [f"{entry.client}: {entry.path}: {len(specs)} server(s)"]
    if error:
        lines.append(f"{error.level}: {error.message}")
    return len(specs), lines
