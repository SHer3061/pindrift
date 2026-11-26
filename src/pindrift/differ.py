"""Drift comparison.

Order of checks matters: cheap structural comparisons run first and short-circuit,
but a matching config hash never suppresses manifest analysis. The most important
attack in scope -- a server that starts identically and then advertises different
tools -- is invisible to config comparison by construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from .capability import FACET_BY_NAME, infer_capabilities
from .detect import analyse_text, diff_lines
from .models import (
    Finding,
    ServerFingerprint,
    ServerResult,
    Severity,
    State,
    ToolManifest,
    severity_at_least,
)

MAX_FINDINGS_PER_SERVER = 40


def visible(text: str) -> str:
    """Render control and invisible characters as escapes.

    Evidence has to survive being pasted into a terminal, an issue comment or a SARIF
    viewer. Printing a raw ESC sequence defeats the purpose of reporting it.
    """
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char in "\n\r\t":
            out.append(" ")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\x{code:02x}")
        elif (
            0x200B <= code <= 0x200F
            or 0x202A <= code <= 0x202E
            or 0x2060 <= code <= 0x2069
            or code == 0xFEFF
        ):
            out.append(f"\\u{code:04x}")
        elif 0xE0000 <= code <= 0xE007F:
            out.append(f"\\U{code:08x}")
        else:
            out.append(char)
    return "".join(out)


def _cap_map(tool: ToolManifest) -> dict[str, object]:
    return infer_capabilities(tool)


def _labels(facets: list[str]) -> str:
    return ", ".join(f"{f} ({FACET_BY_NAME[f].label})" for f in sorted(facets))


def _max_risk(facets: list[str]) -> Severity:
    if not facets:
        return Severity.INFO
    return max((FACET_BY_NAME[f].risk for f in facets), key=lambda s: list(Severity).index(s))


def _truncate(text: str, limit: int = 160) -> str:
    flat = " ".join(visible(text).split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "..."


def _compare_config(pin: ServerFingerprint, current: ServerFingerprint) -> list[Finding]:
    findings: list[Finding] = []
    sid = current.server_id

    if pin.command != current.command:
        findings.append(
            Finding(
                server_id=sid,
                kind="launch_changed",
                severity=Severity.HIGH,
                title="launch command changed",
                detail="A different executable now starts where the pinned one did.",
                evidence=[f"pinned: {pin.command}", f"current: {current.command}"],
            )
        )

    if pin.args != current.args:
        added = [a for a in current.args if a not in pin.args]
        removed = [a for a in pin.args if a not in current.args]
        findings.append(
            Finding(
                server_id=sid,
                kind="launch_changed",
                severity=Severity.HIGH,
                title="launch arguments changed",
                detail="Arguments decide which code path and which data the server gets.",
                evidence=[f"+ {a}" for a in added[:6]] + [f"- {a}" for a in removed[:6]],
            )
        )

    if pin.env_keys != current.env_keys:
        added = sorted(set(current.env_keys) - set(pin.env_keys))
        removed = sorted(set(pin.env_keys) - set(current.env_keys))
        findings.append(
            Finding(
                server_id=sid,
                kind="env_changed",
                severity=Severity.MEDIUM,
                title="environment variable set changed",
                detail="New environment keys mean the server can now read config it could not before.",
                evidence=[f"+ {k}" for k in added[:8]] + [f"- {k}" for k in removed[:8]],
            )
        )

    if pin.transport != current.transport:
        findings.append(
            Finding(
                server_id=sid,
                kind="transport_changed",
                severity=Severity.MEDIUM,
                title="transport changed",
                evidence=[f"pinned: {pin.transport}", f"current: {current.transport}"],
            )
        )
    return findings


def _compare_artifact(pin: ServerFingerprint, current: ServerFingerprint) -> list[Finding]:
    findings: list[Finding] = []
    sid = current.server_id
    before, after = pin.artifact, current.artifact

    if before.kind != after.kind or before.target != after.target:
        findings.append(
            Finding(
                server_id=sid,
                kind="artifact_changed",
                severity=Severity.MEDIUM,
                title="artifact identity changed",
                evidence=[
                    f"pinned: {before.kind} {before.target}",
                    f"current: {after.kind} {after.target}",
                ],
            )
        )
    elif before.sha256 and after.sha256 and before.sha256 != after.sha256:
        findings.append(
            Finding(
                server_id=sid,
                kind="artifact_changed",
                severity=Severity.HIGH,
                title="code digest changed",
                detail="Same launch definition, different bytes on disk.",
                evidence=[f"pinned: {before.sha256[:16]}", f"current: {after.sha256[:16]}"],
            )
        )
    elif before.sha256 and not after.sha256:
        findings.append(
            Finding(
                server_id=sid,
                kind="artifact_unverifiable",
                severity=Severity.MEDIUM,
                title="artifact can no longer be verified",
                detail="The pinned target exists no longer or is unreadable.",
                evidence=[f"pinned target: {before.target}"],
            )
        )
    return findings


def _compare_tool(
    sid: str, before: ToolManifest, after: ToolManifest
) -> list[Finding]:
    findings: list[Finding] = []
    if before.canonical() == after.canonical():
        return findings

    old_caps = set(_cap_map(before))
    new_caps = set(_cap_map(after))
    gained = sorted(new_caps - old_caps)
    lost = sorted(old_caps - new_caps)

    if gained:
        findings.append(
            Finding(
                server_id=sid,
                kind="capability_added",
                severity=_max_risk(gained),
                title=f"tool '{after.name}' gained capability",
                detail=_labels(gained),
                evidence=[
                    f"{f}: " + "; ".join(infer_capabilities(after)[f].evidence[:2]) for f in gained[:4]
                ],
            )
        )
    if lost:
        findings.append(
            Finding(
                server_id=sid,
                kind="capability_removed",
                severity=Severity.INFO,
                title=f"tool '{after.name}' lost capability",
                detail=_labels(lost),
            )
        )

    if before.description != after.description:
        added_lines, removed_lines = diff_lines(before.description, after.description)
        added_text = "\n".join(added_lines)
        risk = analyse_text(added_text) if added_text else analyse_text(after.description)

        if not risk.empty:
            severity = risk.severity() or Severity.LOW
            findings.append(
                Finding(
                    server_id=sid,
                    kind="description_risk",
                    severity=severity,
                    title=f"tool '{after.name}' description contains risky content",
                    detail="; ".join(risk.summary()),
                    evidence=[f"+ {_truncate(line)}" for line in added_lines[:6]],
                )
            )
        elif before.description.strip() != after.description.strip():
            findings.append(
                Finding(
                    server_id=sid,
                    kind="description_changed",
                    severity=Severity.LOW,
                    title=f"tool '{after.name}' description changed",
                    evidence=[f"+ {_truncate(line)}" for line in added_lines[:4]]
                    + [f"- {_truncate(line)}" for line in removed_lines[:4]],
                )
            )

    if before.schema_properties() != after.schema_properties():
        added_props = sorted(set(after.schema_properties()) - set(before.schema_properties()))
        removed_props = sorted(set(before.schema_properties()) - set(after.schema_properties()))
        findings.append(
            Finding(
                server_id=sid,
                kind="schema_changed",
                severity=Severity.MEDIUM if added_props else Severity.LOW,
                title=f"tool '{after.name}' input schema changed",
                evidence=[f"+ {p}" for p in added_props[:8]] + [f"- {p}" for p in removed_props[:8]],
            )
        )

    if before.annotations != after.annotations:
        findings.append(
            Finding(
                server_id=sid,
                kind="annotations_changed",
                severity=Severity.MEDIUM,
                title=f"tool '{after.name}' annotations changed",
                detail="Annotations drive host-side permission prompts; weakening them is meaningful.",
                evidence=[f"pinned: {before.annotations}", f"current: {after.annotations}"],
            )
        )
    return findings


def _compare_manifest(pin: ServerFingerprint, current: ServerFingerprint) -> list[Finding]:
    findings: list[Finding] = []
    sid = current.server_id
    before = {t.name: t for t in pin.tools or []}
    after = {t.name: t for t in current.tools or []}

    for name in sorted(set(after) - set(before)):
        tool = after[name]
        caps = sorted(_cap_map(tool))
        severity = _max_risk(caps)
        if severity == Severity.INFO:
            severity = Severity.MEDIUM
        findings.append(
            Finding(
                server_id=sid,
                kind="tool_added",
                severity=severity,
                title=f"tool '{name}' added after approval",
                detail=_labels(caps) if caps else "no capability inferred from the manifest",
                evidence=[f"description: {_truncate(tool.description)}"] if tool.description else [],
            )
        )

    for name in sorted(set(before) - set(after)):
        findings.append(
            Finding(
                server_id=sid,
                kind="tool_removed",
                severity=Severity.LOW,
                title=f"tool '{name}' removed",
            )
        )

    for name in sorted(set(before) & set(after)):
        findings.extend(_compare_tool(sid, before[name], after[name]))
    return findings


def compare(pin: ServerFingerprint | None, current: ServerFingerprint) -> ServerResult:
    """Compare a current fingerprint against its pin."""
    sid = current.server_id

    if pin is None:
        findings: list[Finding] = [
            Finding(
                server_id=sid,
                kind="unpinned",
                severity=Severity.INFO,
                title="no pin yet",
                detail="Nothing to compare against. Review and run `pindrift approve` to pin.",
            )
        ]
        for tool in current.tools or []:
            risk = analyse_text(tool.description)
            if not risk.empty:
                findings.append(
                    Finding(
                        server_id=sid,
                        kind="description_risk",
                        severity=risk.severity() or Severity.LOW,
                        title=f"tool '{tool.name}' description contains risky content",
                        detail="; ".join(risk.summary()),
                    )
                )
        return ServerResult(fingerprint=current, state=State.NEW, findings=findings)

    findings = []
    findings.extend(_compare_config(pin, current))
    findings.extend(_compare_artifact(pin, current))

    unverifiable = current.tools is None and pin.tools is not None
    if unverifiable:
        findings.append(
            Finding(
                server_id=sid,
                kind="manifest_unverified",
                severity=Severity.MEDIUM,
                title="tool manifest could not be verified",
                detail=(
                    "The server did not return a manifest, so drift in tool definitions "
                    "cannot be ruled out. This is not the same as clean."
                ),
                evidence=[current.probe_error or "probe unavailable"],
            )
        )
    elif current.tools is not None and pin.tools is not None:
        findings.extend(_compare_manifest(pin, current))
    elif current.tools is not None and pin.tools is None:
        findings.append(
            Finding(
                server_id=sid,
                kind="manifest_established",
                severity=Severity.INFO,
                title="manifest captured for a server pinned without probing",
                detail="Future runs can now detect tool-level drift.",
            )
        )

    if len(findings) > MAX_FINDINGS_PER_SERVER:
        findings = findings[:MAX_FINDINGS_PER_SERVER]

    if unverifiable:
        state = State.UNKNOWN
    elif any(severity_at_least(f.severity, Severity.LOW) for f in findings):
        state = State.DRIFT
    else:
        state = State.OK

    return ServerResult(fingerprint=current, state=state, findings=findings)


@dataclass
class Summary:
    ok: int = 0
    drift: int = 0
    new: int = 0
    unknown: int = 0
    missing: int = 0

    @property
    def total(self) -> int:
        return self.ok + self.drift + self.new + self.unknown + self.missing


def summarise(results: list[ServerResult]) -> Summary:
    summary = Summary()
    for result in results:
        setattr(summary, result.state.value, getattr(summary, result.state.value) + 1)
    return summary
