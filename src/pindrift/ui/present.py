"""Turn backend dataclasses into the JSON shape the web UI consumes.

Two rules are non-negotiable here:

* only ``ServerFingerprint`` data is exposed -- never ``ServerSpec.env`` values or
  raw headers;
* every string that came from a server passes through ``differ.visible()`` and is
  truncated before it reaches the DOM.
"""

from __future__ import annotations

from typing import Any

from .. import __version__
from ..capability import FACET_BY_NAME, infer_capabilities, server_capabilities
from ..detect import analyse_text
from ..differ import Summary, visible
from ..discover import SourceError
from ..models import Finding, ServerFingerprint, ServerResult
from .controller import Inventory, SourceRow

TEXT_LIMIT = 600
EVIDENCE_LIMIT = 20


def text(value: object, limit: int = TEXT_LIMIT) -> str:
    rendered = visible(str(value or ""))
    if len(rendered) <= limit:
        return rendered
    return rendered[: limit - 1] + "…"


def _finding(finding: Finding) -> dict[str, Any]:
    return {
        "kind": finding.kind,
        "severity": finding.severity.value,
        "title": text(finding.title, 200),
        "detail": text(finding.detail),
        "evidence": [text(item, 400) for item in finding.evidence[:EVIDENCE_LIMIT]],
    }


def _tool(tool) -> dict[str, Any]:
    hits = infer_capabilities(tool)
    content = analyse_text(tool.description)
    return {
        "name": text(tool.name, 120),
        "description": text(tool.description),
        "properties": [text(prop, 80) for prop in tool.schema_properties()],
        "capabilities": [
            {
                "facet": name,
                "label": FACET_BY_NAME[name].label,
                "risk": hit.risk.value,
                "evidence": [text(item, 200) for item in hit.evidence[:5]],
            }
            for name, hit in sorted(hits.items())
        ],
        "contentRisk": {
            "severity": content.severity().value if content.severity() else None,
            "summary": [text(item, 300) for item in content.summary()],
        },
    }


def server_row(
    fingerprint: ServerFingerprint,
    *,
    pinned: bool,
    result: ServerResult | None = None,
) -> dict[str, Any]:
    state = result.state.value if result is not None else None
    findings = [_finding(item) for item in (result.findings if result else [])]
    capabilities = [
        {
            "facet": name,
            "label": FACET_BY_NAME[name].label,
            "risk": FACET_BY_NAME[name].risk.value,
            "tools": [text(tool, 120) for tool in tools],
        }
        for name, tools in server_capabilities(fingerprint.tools or []).items()
    ]
    return {
        "id": fingerprint.server_id,
        "name": text(fingerprint.name, 160),
        "clients": [text(client, 80) for client in fingerprint.all_clients],
        "aliases": [text(alias, 160) for alias in fingerprint.all_aliases],
        "transport": fingerprint.transport,
        "state": state,
        "pinned": pinned,
        "configPath": text(fingerprint.source_config, 500),
        "configHash": fingerprint.config_hash,
        "artifact": {
            "kind": fingerprint.artifact.kind,
            "target": text(fingerprint.artifact.target, 500),
            "sha256": fingerprint.artifact.sha256,
            "files": fingerprint.artifact.files,
            "note": text(fingerprint.artifact.note, 300),
        },
        "hasManifest": fingerprint.tools is not None,
        "toolsHash": fingerprint.tools_hash,
        "probeError": text(fingerprint.probe_error, 400) if fingerprint.probe_error else None,
        "tools": [_tool(tool) for tool in (fingerprint.tools or [])],
        "capabilities": capabilities,
        "findings": findings,
    }


def source_error(error: SourceError) -> dict[str, Any]:
    return {
        "client": text(error.client, 120),
        "path": text(error.path, 500),
        "message": text(error.message, 400),
        "level": error.level,
    }


def source_row(row: SourceRow) -> dict[str, Any]:
    return {
        "id": row.identifier,
        "client": text(row.client, 120),
        "path": text(row.path, 500),
        "scope": row.scope,
        "origin": row.origin,
        "format": row.format,
        "exists": row.exists,
        "supported": row.supported,
        "note": text(row.note, 300),
        "custom": row.origin == "custom",
    }


def inventory_stats(inventory: Inventory) -> dict[str, int | None]:
    pinned = sum(1 for fp in inventory.fingerprints if fp.server_id in inventory.pinned_ids)
    return {
        "total": len(inventory.fingerprints),
        "pinned": pinned,
        "unpinned": len(inventory.fingerprints) - pinned,
        "ok": None,
        "drift": None,
        "new": None,
        "missing": None,
        "unknown": None,
    }


def summary_stats(summary: Summary, pinned: int) -> dict[str, int | None]:
    return {
        "total": summary.total,
        "pinned": pinned,
        "unpinned": max(summary.total - pinned, 0),
        "ok": summary.ok,
        "drift": summary.drift,
        "new": summary.new,
        "missing": summary.missing,
        "unknown": summary.unknown,
    }


def inventory_payload(inventory: Inventory) -> dict[str, Any]:
    return {
        "servers": [
            server_row(
                fingerprint,
                pinned=fingerprint.server_id in inventory.pinned_ids,
            )
            for fingerprint in inventory.fingerprints
        ],
        "sources": [],
        "stats": inventory_stats(inventory),
        "errors": [source_error(error) for error in inventory.errors],
        "baselineLabel": inventory.baseline_label,
    }


def report_payload(report) -> dict[str, Any]:
    pinned = len(report.pinned_ids)
    return {
        "servers": [
            server_row(
                result.fingerprint,
                pinned=result.fingerprint.server_id in report.pinned_ids,
                result=result,
            )
            for result in report.results
        ],
        "sources": [],
        "stats": summary_stats(report.summary, pinned),
        "errors": [source_error(error) for error in report.errors],
        "baselineLabel": report.baseline_label,
        "exitCode": report.exit_code,
    }


def bootstrap_payload(
    inventory: Inventory,
    prefs: dict[str, Any],
    sources: list[SourceRow],
) -> dict[str, Any]:
    payload = inventory_payload(inventory)
    payload["sources"] = [source_row(row) for row in sources]
    payload["app"] = {
        "version": __version__,
        "root": prefs.get("root", ""),
        "baselineLabel": inventory.baseline_label,
        "pinnedCount": len(inventory.pinned_ids),
    }
    payload["prefs"] = prefs
    return payload
