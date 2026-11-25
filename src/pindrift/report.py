"""Output rendering: human, JSON, SARIF.

SARIF exists so the result can gate CI without a bespoke parser. The text output
exists because a security tool that only speaks JSON does not get used.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .capability import FACET_BY_NAME, server_capabilities
from .differ import Summary
from .models import SARIF_LEVEL, SEVERITY_RANK, ServerFingerprint, ServerResult, Severity, State

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[90m"

SEVERITY_COLOR = {
    Severity.CRITICAL: "\x1b[1;91m",
    Severity.HIGH: "\x1b[91m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[90m",
}

STATE_COLOR = {
    State.DRIFT: "\x1b[91m",
    State.UNKNOWN: "\x1b[33m",
    State.NEW: "\x1b[36m",
    State.OK: "\x1b[32m",
    State.MISSING: "\x1b[90m",
}


def _supports_color(stream: Any) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


class Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, code: str) -> str:
        if not self.enabled or not code:
            return text
        return f"{code}{text}{RESET}"

    def severity(self, severity: Severity) -> str:
        return self.paint(f"{severity.value:<8}", SEVERITY_COLOR[severity])

    def state(self, state: State) -> str:
        return self.paint(f"{state.value:<7}", STATE_COLOR[state])


def _fmt_summary(summary: Summary) -> str:
    parts = [f"{summary.ok} ok", f"{summary.drift} drift", f"{summary.new} new"]
    if summary.missing:
        parts.append(f"{summary.missing} missing")
    parts.append(f"{summary.unknown} unverified")
    return f"{summary.total} server(s): " + ", ".join(parts)


def render_text(
    results: list[ServerResult],
    summary: Summary,
    *,
    baseline_label: str,
    stream: Any = None,
    verbose: bool = False,
) -> str:
    stream = stream or sys.stdout
    palette = Palette(_supports_color(stream))
    lines: list[str] = []

    header = f"pindrift {__version__}  |  {baseline_label}"
    lines.append(palette.paint(header, BOLD))
    lines.append(palette.paint(_fmt_summary(summary), DIM))
    lines.append("")

    hits = [r for r in results if r.state != State.OK]
    if not hits:
        lines.append(palette.paint("No drift detected. All pinned servers match.", "\x1b[32m"))
        return "\n".join(lines)

    for result in hits:
        fp = result.fingerprint
        lines.append(
            f"{palette.state(result.state)} {palette.paint(fp.server_id, BOLD)}"
            f"  {palette.paint(f'[{fp.transport}] {fp.artifact.kind}', DIM)}"
        )
        if result.state == State.UNKNOWN and fp.probe_error:
            lines.append(f"         {palette.paint(fp.probe_error, DIM)}")

        for finding in sorted(result.findings, key=lambda f: -SEVERITY_RANK[f.severity]):
            if finding.severity == Severity.INFO and not verbose:
                lines.append(
                    f"         {palette.severity(finding.severity)} "
                    f"{palette.paint(finding.title, DIM)}"
                )
                continue
            lines.append(f"         {palette.severity(finding.severity)} {finding.title}")
            if finding.detail:
                lines.append(f"                  {palette.paint(finding.detail, DIM)}")
            for item in finding.evidence[:5]:
                lines.append(f"                  {palette.paint(item, DIM)}")
        lines.append("")

    actionable = [r for r in hits if r.state == State.DRIFT]
    if actionable:
        names = ", ".join(r.fingerprint.server_id for r in actionable[:3])
        lines.append(
            palette.paint(
                f"Review the diff, then re-pin with:  pindrift approve <server>", DIM
            )
        )
        if len(actionable) <= 3:
            lines.append(palette.paint(f"  e.g.  pindrift approve {names.split(', ')[0]}", DIM))
    return "\n".join(lines)


def render_inventory(fingerprints: list[ServerFingerprint], pinned: set[str]) -> str:
    palette = Palette(_supports_color(sys.stdout))
    lines = [palette.paint(f"pindrift {__version__}  |  inventory", BOLD), ""]
    if not fingerprints:
        lines.append("No MCP servers found. Nothing to monitor yet.")
        return "\n".join(lines)

    for fp in fingerprints:
        mark = "*" if fp.server_id in pinned else " "
        caps = server_capabilities(fp.tools or [])
        cap_text = ", ".join(caps) if caps else ("unknown" if fp.tools is None else "none")
        lines.append(f"{mark} {palette.paint(fp.server_id, BOLD)}  [{fp.transport}]")
        lines.append(f"    config    {fp.source_config}")
        lines.append(f"    artifact  {fp.artifact.kind} {fp.artifact.target}".rstrip())
        if fp.artifact.sha256:
            lines.append(f"    digest    {fp.artifact.sha256[:32]}")
        tool_count = len(fp.tools) if fp.tools is not None else "not probed"
        lines.append(f"    tools     {tool_count}")
        lines.append(f"    caps      {cap_text}")
        lines.append("")
    lines.append(palette.paint("* = pinned", DIM))
    return "\n".join(lines)


def render_json(results: list[ServerResult], summary: Summary) -> str:
    payload = {
        "tool": {"name": "pindrift", "version": __version__},
        "summary": {
            "total": summary.total,
            "ok": summary.ok,
            "drift": summary.drift,
            "new": summary.new,
            "unknown": summary.unknown,
            "missing": summary.missing,
        },
        "servers": [
            {
                "server_id": result.fingerprint.server_id,
                "state": result.state.value,
                "transport": result.fingerprint.transport,
                "artifact": result.fingerprint.artifact.to_dict(),
                "tools": result.fingerprint.tool_names,
                "findings": [f.to_dict() for f in result.findings],
            }
            for result in results
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _file_uri(path: str) -> str:
    try:
        return Path(path).resolve().as_uri()
    except (OSError, ValueError):
        return "file:///"


def render_sarif(results: list[ServerResult]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for result in results:
        for finding in result.findings:
            if finding.severity == Severity.INFO and finding.kind == "unpinned":
                continue
            rule_id = f"pindrift/{finding.kind}"
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": finding.kind.replace("_", " ").title(),
                    "shortDescription": {"text": finding.kind.replace("_", " ")},
                    "defaultConfiguration": {"level": SARIF_LEVEL[finding.severity]},
                },
            )
            message = finding.title
            if finding.detail:
                message = f"{message}. {finding.detail}"
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": SARIF_LEVEL[finding.severity],
                    "message": {"text": message},
                    "properties": {
                        "server": result.fingerprint.server_id,
                        "severity": finding.severity.value,
                        "evidence": finding.evidence,
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": _file_uri(result.fingerprint.source_config)
                                },
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            )

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pindrift",
                        "version": __version__,
                        "informationUri": "https://github.com/SHer/pindrift",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(document, ensure_ascii=False, indent=2)


def capability_line(fingerprint: ServerFingerprint) -> str:
    caps = server_capabilities(fingerprint.tools or [])
    if not caps:
        return "none"
    return ", ".join(f"{name} ({FACET_BY_NAME[name].risk.value})" for name in caps)
