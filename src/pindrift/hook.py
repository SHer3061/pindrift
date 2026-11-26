"""Pre-tool-call hook for agent hosts.

``watch`` polls on a timer. A host that asks immediately before every tool call
closes the window between observation and use to zero, which is strictly stronger.
This module implements that path.

The hook is deliberately fail-open for anything it cannot verify, and loud about it:
a probe timeout must not stop the user's work, but a silent allow would turn "could
not check" into "checked and clean". Anything unverified prints a warning on stderr
and exits 0. Only findings that are independently verifiable can deny a call.

Exit codes::

    0  allow (including "nothing to compare" and "could not verify")
    1  malformed hook payload
    2  deny (findings at or above ``--fail-on``)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from . import service, store
from .differ import compare, visible
from .discover import ServerSpec
from .models import Finding, Severity, severity_at_least
from .probe import DEFAULT_TIMEOUT

EXIT_ALLOW = 0
EXIT_MALFORMED = 1
EXIT_DENY = 2

SUPPORTED_HOSTS = ("claude-code",)

# Which discovered client configs belong to each host.
HOST_CLIENTS: dict[str, str] = {"claude-code": "claude-code"}

MCP_TOOL_PREFIX = "mcp__"

# Findings that mean "we could not look", not "we looked and found drift". They are
# reported as warnings and never deny a call on their own.
UNVERIFIABLE_KINDS = frozenset({"manifest_unverified"})


class HookInputError(ValueError):
    """The payload on stdin is not a hook event we can act on."""


@dataclass(frozen=True)
class HookPayload:
    host: str
    tool_name: str
    server_name: str | None
    cwd: Path


@dataclass
class Decision:
    code: int
    reason: str = ""
    warnings: list[str] = field(default_factory=list)


def mcp_server_name(tool_name: str) -> str | None:
    """Return the server from Claude Code's ``mcp__<server>__<tool>`` name.

    Returns ``None`` for ordinary built-in tools, which the hook must ignore rather
    than block: a PreToolUse hook fires for every call, not only MCP ones.
    """
    if not tool_name.startswith(MCP_TOOL_PREFIX):
        return None
    remainder = tool_name[len(MCP_TOOL_PREFIX) :]
    server, _, _ = remainder.partition("__")
    return server or None


def _explicit_server_name(payload: dict[str, Any]) -> str | None:
    """Hosts that already resolved the server can say so directly."""
    for key in ("server_name", "serverName", "mcp_server", "mcpServer"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def parse_payload(data: object, *, host: str, root: Path | None = None) -> HookPayload:
    if host not in SUPPORTED_HOSTS:
        raise HookInputError(f"unsupported host {host!r}")
    if not isinstance(data, dict):
        raise HookInputError("payload must be a JSON object")

    tool_name = data.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        raise HookInputError("payload has no 'tool_name' string")

    server_name = _explicit_server_name(data)
    if server_name is None:
        server_name = mcp_server_name(tool_name)

    cwd_value = data.get("cwd")
    if root is not None:
        cwd = root
    elif isinstance(cwd_value, str) and cwd_value:
        cwd = Path(cwd_value).expanduser()
    else:
        cwd = Path.cwd()

    return HookPayload(
        host=host,
        tool_name=tool_name,
        server_name=server_name,
        cwd=cwd,
    )


def parse_text(raw: str, *, host: str, root: Path | None = None) -> HookPayload:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HookInputError(f"stdin is not valid JSON: {exc.msg}") from exc
    return parse_payload(data, host=host, root=root)


def _matching_specs(
    specs: list[ServerSpec], server_name: str, client: str | None
) -> list[ServerSpec]:
    matches = [
        s
        for s in specs
        if s.name == server_name
        and (client is None or client in s.all_clients)
    ]
    return sorted(matches, key=lambda s: s.server_id)


def _describe(finding: Finding) -> str:
    text = f"[{finding.severity.value}] {finding.title}"
    if finding.detail:
        text += f": {finding.detail}"
    return visible(text)


def _format_denial(payload: HookPayload, server_id: str, reasons: list[str]) -> str:
    tool = visible(payload.tool_name)
    server = visible(server_id)
    lines = [
        f"pindrift blocked this tool call: {tool} (server {server})",
        "The server no longer matches the state that was pinned and approved:",
    ]
    lines.extend(f"  - {reason}" for reason in reasons[:8])
    if len(reasons) > 8:
        lines.append(f"  - ... and {len(reasons) - 8} more finding(s)")
    lines.append(
        f"Review with `pindrift check {server}`, then `pindrift approve {server}` "
        "if the change is intended."
    )
    return "\n".join(lines)


def _evaluate_spec(
    spec: ServerSpec,
    fail_on: Severity,
    timeout: float,
    warnings: list[str],
) -> list[str]:
    pin = store.get(spec.server_id)
    if pin is None:
        warnings.append(f"{spec.server_id} has no pin; this call was not verified")
        return []

    # Only pinned servers are probed. An unapproved server is never executed just
    # because a tool call mentioned it.
    current = service.fingerprint_spec(spec, do_probe=True, timeout=timeout)
    result = compare(pin, current)

    if current.tools is None:
        detail = current.probe_error or "probe unavailable"
        if pin.tools is None:
            warnings.append(
                f"{spec.server_id} has no pinned manifest and none could be captured "
                f"({detail}); allowed, but the call was not verified"
            )
        else:
            warnings.append(
                f"{spec.server_id} manifest could not be verified ({detail}); "
                "allowed, but drift in tool definitions cannot be ruled out"
            )

    blocking = [
        finding
        for finding in result.findings
        if finding.kind not in UNVERIFIABLE_KINDS
        and severity_at_least(finding.severity, fail_on)
    ]
    return [_describe(finding) for finding in blocking]


def evaluate(
    payload: HookPayload,
    *,
    fail_on: Severity = Severity.HIGH,
    timeout: float = DEFAULT_TIMEOUT,
    include_project: bool = True,
) -> Decision:
    """Decide one pending tool call.

    ``payload.server_name`` is ``None`` for a non-MCP tool; those calls are allowed
    silently because there is no server definition to compare.
    """
    if not payload.server_name:
        return Decision(EXIT_ALLOW)

    warnings: list[str] = []
    baseline = store.load()
    specs, errors, _ = service.load_specs(
        root=payload.cwd,
        include_project=include_project,
        dedupe=True,
        aliases=store.alias_map(baseline),
    )
    client = HOST_CLIENTS.get(payload.host)
    for error in errors:
        if error.level == "info":
            continue
        if client and error.client not in (client, "sources-registry"):
            continue
        warnings.append(f"config {error.client} {error.path}: {error.message}")

    candidates = _matching_specs(specs, payload.server_name, client)
    if not candidates:
        warnings.append(
            f"no config entry for MCP server '{payload.server_name}' "
            f"({payload.host}); this call was not verified"
        )
        return Decision(EXIT_ALLOW, warnings=warnings)

    reasons: list[str] = []
    for spec in candidates:
        reasons.extend(_evaluate_spec(spec, fail_on, timeout, warnings))

    if reasons:
        server_id = candidates[0].server_id
        return Decision(
            EXIT_DENY,
            reason=_format_denial(payload, server_id, reasons),
            warnings=warnings,
        )
    return Decision(EXIT_ALLOW, warnings=warnings)


def run_hook(
    *,
    host: str,
    stream: TextIO,
    stdout: TextIO,
    stderr: TextIO,
    fail_on: Severity = Severity.HIGH,
    timeout: float = DEFAULT_TIMEOUT,
    root: Path | None = None,
    include_project: bool = True,
) -> int:
    try:
        payload = parse_text(stream.read(), host=host, root=root)
    except HookInputError as exc:
        print(f"pindrift hook: malformed input: {exc}", file=stderr)
        return EXIT_MALFORMED

    decision = evaluate(
        payload,
        fail_on=fail_on,
        timeout=timeout,
        include_project=include_project,
    )
    for warning in decision.warnings:
        print(f"pindrift hook: warning: {warning}", file=stderr)
    if decision.reason:
        print(decision.reason, file=stdout)
    return decision.code
