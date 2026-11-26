"""Output rendering: human, JSON, SARIF.

SARIF exists so the result can gate CI without a bespoke parser. The text output
exists because a security tool that only speaks JSON does not get used.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .capability import FACET_BY_NAME, server_capabilities
from .differ import Summary, visible
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


PROJECT_URI = "https://github.com/SHer/pindrift"
THREAT_MODEL_URI = f"{PROJECT_URI}/blob/main/docs/THREAT-MODEL.md"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
RULE_ID_PREFIX = "pindrift"


@dataclass(frozen=True)
class SarifRule:
    """Static metadata for one finding kind.

    Rules are declared here rather than derived from whatever a run happened to
    emit, so ``defaultConfiguration`` and ``helpUri`` do not change just because the
    same drift was graded differently on two machines. ``help_anchor`` must match a
    heading in docs/THREAT-MODEL.md; tests/test_report.py verifies that.
    """

    kind: str
    name: str
    title: str
    description: str
    help_anchor: str
    severity: Severity

    @property
    def rule_id(self) -> str:
        return f"{RULE_ID_PREFIX}/{self.kind}"

    @property
    def help_uri(self) -> str:
        base = f"{THREAT_MODEL_URI}#{self.help_anchor}" if self.help_anchor else THREAT_MODEL_URI
        return base

    def to_sarif(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "name": self.name,
            "shortDescription": {"text": self.title},
            "fullDescription": {"text": self.description},
            "helpUri": self.help_uri,
            "defaultConfiguration": {"level": SARIF_LEVEL[self.severity]},
            "properties": {
                "tags": ["security", "mcp", "supply-chain", self.kind],
            },
        }


_RULE_SPECS = (
    SarifRule(
        kind="description_risk",
        name="DescriptionRisk",
        title="Tool description contains risky content",
        description=(
            "A tool description contains content a human reviewer and the model "
            "would perceive differently: hidden characters, instruction-shaped "
            "phrasing, credential paths, suspicious URLs, or encoded blobs."
        ),
        help_anchor="tool-poisoning--hidden-instructions-in-a-description",
        severity=Severity.CRITICAL,
    ),
    SarifRule(
        kind="capability_added",
        name="CapabilityAdded",
        title="Tool gained a capability",
        description=(
            "An existing tool gained a capability facet that the approved manifest "
            "did not have. Severity follows the most dangerous facet gained."
        ),
        help_anchor="capability-escalation",
        severity=Severity.CRITICAL,
    ),
    SarifRule(
        kind="capability_removed",
        name="CapabilityRemoved",
        title="Tool lost a capability",
        description=(
            "An existing tool lost a capability facet. Usually benign, but it can "
            "also hide a replacement implementation behind an unchanged name."
        ),
        help_anchor="capability-escalation",
        severity=Severity.INFO,
    ),
    SarifRule(
        kind="tool_added",
        name="ToolAdded",
        title="Tool added after approval",
        description=(
            "A tool appeared in the manifest after the server was approved. Graded "
            "by what the new tool can do, not by the size of the diff."
        ),
        help_anchor="capability-escalation",
        severity=Severity.HIGH,
    ),
    SarifRule(
        kind="tool_removed",
        name="ToolRemoved",
        title="Tool removed",
        description="A tool present at approval time is no longer advertised.",
        help_anchor="rug-pull--silent-redefinition-after-approval",
        severity=Severity.LOW,
    ),
    SarifRule(
        kind="schema_changed",
        name="SchemaChanged",
        title="Tool input schema changed",
        description=(
            "A tool's input schema changed, so the server now accepts or requires "
            "different parameters. Added properties raise the severity."
        ),
        help_anchor="rug-pull--silent-redefinition-after-approval",
        severity=Severity.MEDIUM,
    ),
    SarifRule(
        kind="annotations_changed",
        name="AnnotationsChanged",
        title="Tool annotations changed",
        description=(
            "MCP annotations changed. They drive host-side permission prompts, so "
            "weakening them changes what the model is allowed to do without a "
            "prompt."
        ),
        help_anchor="capability-escalation",
        severity=Severity.MEDIUM,
    ),
    SarifRule(
        kind="launch_changed",
        name="LaunchChanged",
        title="Launch definition changed",
        description=(
            "The command or its arguments changed, so a different executable or "
            "code path now runs where the pinned one did."
        ),
        help_anchor="launch-definition-change",
        severity=Severity.HIGH,
    ),
    SarifRule(
        kind="env_changed",
        name="EnvChanged",
        title="Environment key set changed",
        description=(
            "The set of environment keys the server can read changed. New keys mean "
            "the server can reach configuration it could not reach before."
        ),
        help_anchor="launch-definition-change",
        severity=Severity.MEDIUM,
    ),
    SarifRule(
        kind="transport_changed",
        name="TransportChanged",
        title="Transport changed",
        description="The same server is now reached over a different transport.",
        help_anchor="launch-definition-change",
        severity=Severity.MEDIUM,
    ),
    SarifRule(
        kind="artifact_changed",
        name="ArtifactChanged",
        title="Artifact identity or digest changed",
        description=(
            "The code behind the server changed while the launch definition did "
            "not: a different target, or a different sha256 for the same target."
        ),
        help_anchor="artifact-swap",
        severity=Severity.HIGH,
    ),
    SarifRule(
        kind="artifact_unverifiable",
        name="ArtifactUnverifiable",
        title="Artifact can no longer be verified",
        description=(
            "The pinned artifact can no longer be found or read, so its digest "
            "cannot be checked. Absence of a mismatch is not a match."
        ),
        help_anchor="artifact-swap",
        severity=Severity.MEDIUM,
    ),
    SarifRule(
        kind="manifest_unverified",
        name="ManifestUnverified",
        title="Tool manifest could not be verified",
        description=(
            "The server did not return a tool manifest, so drift in tool "
            "definitions cannot be ruled out. This is not the same as clean."
        ),
        help_anchor="a-server-that-lies-about-its-own-manifest",
        severity=Severity.MEDIUM,
    ),
    SarifRule(
        kind="manifest_established",
        name="ManifestEstablished",
        title="Manifest captured for a previously unprobed pin",
        description=(
            "A tool manifest was captured for a server that was pinned without "
            "probing. Future runs can now detect tool-level drift."
        ),
        help_anchor="rug-pull--silent-redefinition-after-approval",
        severity=Severity.INFO,
    ),
    SarifRule(
        kind="server_missing",
        name="ServerMissing",
        title="Pinned server is no longer configured",
        description=(
            "A pinned server is absent from every discovered client config. "
            "Removing a config entry is also how monitoring of a server is stopped."
        ),
        help_anchor="assumed-attacker-capability",
        severity=Severity.MEDIUM,
    ),
    SarifRule(
        kind="unpinned",
        name="Unpinned",
        title="Server has no pin",
        description=(
            "No pin exists for this server, so there is no baseline to compare "
            "against. A clean check on a fresh machine is accepted risk, not a "
            "clean bill of health."
        ),
        help_anchor="malicious-code-that-behaves-identically",
        severity=Severity.INFO,
    ),
    SarifRule(
        kind="description_changed",
        name="DescriptionChanged",
        title="Tool description changed",
        description=(
            "A tool description changed without any content or capability signal. "
            "Low risk, but this is still text the model reads as instruction."
        ),
        help_anchor="limits-of-capability-inference",
        severity=Severity.LOW,
    ),
)

SARIF_RULES: dict[str, SarifRule] = {rule.kind: rule for rule in _RULE_SPECS}


def _fallback_rule(kind: str, severity: Severity) -> SarifRule:
    """Keep an unrecognised finding reportable instead of dropping it.

    A new kind must stay visible even before it gets curated metadata. The
    synthesised rule is still schema-valid; only its help link is less specific.
    """
    identifier = "".join(part.capitalize() for part in kind.replace("-", "_").split("_"))
    if not identifier or not identifier[0].isalpha():
        identifier = f"Finding{identifier}"
    return SarifRule(
        kind=kind,
        name=identifier,
        title=kind.replace("_", " "),
        description="pindrift reported a finding whose kind has no static rule entry.",
        help_anchor="",
        severity=severity,
    )


def _rule_for(kind: str, severity: Severity) -> SarifRule:
    return SARIF_RULES.get(kind) or _fallback_rule(kind, severity)


def _file_uri(path: str) -> str:
    try:
        return Path(path or ".").resolve().as_uri()
    except (OSError, ValueError):
        return "file:///"


def _partial_fingerprint(rule_id: str, server_id: str, title: str, detail: str) -> str:
    """Stable identity for one finding across runs.

    Evidence is deliberately excluded: it carries concrete values (digests, probe
    errors) that legitimately change between runs while the finding stays the same.
    Rule, server, title and detail identify the drift.
    """
    identity = "\x00".join((rule_id, server_id, title, detail))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def render_sarif(results: list[ServerResult]) -> str:
    rule_indexes: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    sarif_results: list[dict[str, Any]] = []

    for result in results:
        for finding in result.findings:
            if finding.severity == Severity.INFO and finding.kind == "unpinned":
                continue
            rule = _rule_for(finding.kind, finding.severity)
            if rule.rule_id not in rule_indexes:
                rule_indexes[rule.rule_id] = len(rules)
                rules.append(rule.to_sarif())
            index = rule_indexes[rule.rule_id]

            title = visible(finding.title)
            detail = visible(finding.detail)
            message = title if not detail else f"{title}. {detail}"
            sarif_results.append(
                {
                    "ruleId": rule.rule_id,
                    "ruleIndex": index,
                    "level": SARIF_LEVEL[finding.severity],
                    "message": {"text": message},
                    "partialFingerprints": {
                        f"{RULE_ID_PREFIX}/v1": _partial_fingerprint(
                            rule.rule_id, result.fingerprint.server_id, title, detail
                        )
                    },
                    "properties": {
                        "server": result.fingerprint.server_id,
                        "severity": finding.severity.value,
                        "evidence": [visible(item) for item in finding.evidence],
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
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pindrift",
                        "version": __version__,
                        "informationUri": PROJECT_URI,
                        "rules": rules,
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
