"""Backend operations for the desktop UI.

The UI never calls CLI command handlers: those write to stdout and return exit
codes. Everything here returns dataclasses and lets the view decide how to render.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import service, sources, store
from ..capability import FACET_BY_NAME, server_capabilities
from ..differ import visible
from ..discover import (
    ConfigSource,
    SourceError,
    parse_source,
    project_config_sources,
    unsupported_sources,
    user_config_sources,
)
from ..models import ServerFingerprint, ServerResult, Severity, State
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
    specs: list
    fingerprints: list[ServerFingerprint]
    pinned_ids: set[str]
    errors: list[SourceError]
    sources: list[ConfigSource]


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
    specs, errors, found = service.load_specs(
        root=settings.root,
        include_project=settings.include_project,
        dedupe=settings.dedupe,
        aliases=store.alias_map(store.load()),
    )
    fingerprints = service.fingerprint_specs(
        specs, do_probe=False, timeout=settings.timeout
    )
    return Inventory(
        specs=specs,
        fingerprints=fingerprints,
        pinned_ids=store.pinned_ids(),
        errors=errors,
        sources=found,
    )


def check(settings: Settings) -> service.ScanReport:
    return service.scan(
        service.ScanOptions(
            root=settings.root,
            include_project=settings.include_project,
            dedupe=settings.dedupe,
            probe="auto",
            timeout=settings.timeout,
            fail_on=settings.fail_on,
        )
    )


def pin(specs: list, settings: Settings) -> list[ServerFingerprint]:
    fingerprints = service.fingerprint_specs(
        specs, do_probe=True, timeout=settings.timeout
    )
    store.put_many(fingerprints, reason="ui-pin")
    return fingerprints


def approve(specs: list, settings: Settings) -> list[ServerFingerprint]:
    fingerprints = service.fingerprint_specs(
        specs, do_probe=True, timeout=settings.timeout
    )
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


def state_label(state: State | None) -> str:
    return "not checked" if state is None else state.value


def result_for(result: ServerResult) -> str:
    fp = result.fingerprint
    lines = [
        f"{fp.server_id}",
        f"state        {result.state.value}",
        f"clients      {', '.join(fp.all_clients)}",
        f"transport    {fp.transport}",
        f"config       {fp.source_config}",
        f"artifact     {fp.artifact.kind} {fp.artifact.target}".rstrip(),
    ]
    if fp.artifact.sha256:
        lines.append(f"artifact sha {fp.artifact.sha256}")
    if fp.tools is None:
        lines.append("manifest     not captured")
    else:
        lines.append(f"tools        {', '.join(fp.tool_names) or 'none'}")
        capabilities = server_capabilities(fp.tools)
        if capabilities:
            lines.append(
                "capabilities "
                + ", ".join(
                    f"{name} ({FACET_BY_NAME[name].risk.value})"
                    for name in capabilities
                )
            )
        if fp.tools_hash:
            lines.append(f"tools sha    {fp.tools_hash}")
    if fp.probe_error:
        lines.append(f"probe error  {visible(fp.probe_error)}")
    if fp.all_aliases:
        lines.append(f"aliases      {', '.join(fp.all_aliases)}")
    if not result.findings:
        lines.append("")
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append("")
    for finding in result.findings:
        lines.append(f"[{finding.severity.value}] {finding.title}")
        if finding.detail:
            lines.append(f"  {visible(finding.detail)}")
        for evidence in finding.evidence:
            lines.append(f"  - {visible(evidence)}")
    return "\n".join(lines)


def inventory_detail(fingerprint: ServerFingerprint, pinned: bool) -> str:
    lines = [
        fingerprint.server_id,
        f"clients      {', '.join(fingerprint.all_clients)}",
        f"transport    {fingerprint.transport}",
        f"pinned       {'yes' if pinned else 'no'}",
        f"config       {fingerprint.source_config}",
        f"artifact     {fingerprint.artifact.kind} {fingerprint.artifact.target}".rstrip(),
    ]
    if fingerprint.artifact.sha256:
        lines.append(f"artifact sha {fingerprint.artifact.sha256}")
    if fingerprint.tools is None:
        lines.append("manifest     not captured (run Check to probe pinned servers)")
    else:
        lines.append(f"tools        {', '.join(fingerprint.tool_names) or 'none'}")
        capabilities = server_capabilities(fingerprint.tools)
        if capabilities:
            lines.append(
                "capabilities "
                + ", ".join(
                    f"{name} ({FACET_BY_NAME[name].risk.value})"
                    for name in capabilities
                )
            )
    return "\n".join(lines)


def source_detail(row: SourceRow) -> str:
    lines = [
        f"client       {row.client}",
        f"path         {row.path}",
        f"scope        {row.scope}",
        f"origin       {row.origin}",
        f"format       {row.format}",
        f"exists       {'yes' if row.exists else 'no'}",
        f"supported    {'yes' if row.supported else 'no'}",
    ]
    if row.note:
        lines.append(f"note         {row.note}")
    return "\n".join(lines)


def summary_text(report: service.ScanReport) -> str:
    summary = report.summary
    return (
        f"{summary.total} target(s): {summary.ok} ok, {summary.drift} drift, "
        f"{summary.new} new, {summary.missing} missing, {summary.unknown} unknown"
    )


def errors_text(errors: list[SourceError]) -> str:
    return "; ".join(
        f"{error.client} {error.path}: {error.message}"
        for error in errors
        if error.level != "info"
    )


def jsonable_row(row: SourceRow) -> dict[str, Any]:
    return {
        "client": row.client,
        "path": row.path,
        "scope": row.scope,
        "origin": row.origin,
        "format": row.format,
        "exists": row.exists,
        "supported": row.supported,
        "note": row.note,
        "id": row.identifier,
    }
