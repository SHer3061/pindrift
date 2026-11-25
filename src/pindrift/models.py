"""Core data models.

Everything that gets pinned on disk and everything that gets compared lives here.
Serialisation is deliberately explicit rather than ``asdict()`` so that the pin file
format stays stable across refactors.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class State(str, Enum):
    """Verdict for a single server.

    ``UNKNOWN`` is a first-class outcome on purpose. A scanner that reports "clean"
    because it could not reach the server is worse than no scanner at all.
    """

    OK = "ok"
    DRIFT = "drift"
    NEW = "new"
    MISSING = "missing"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

SARIF_LEVEL: dict[Severity, str] = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def severity_at_least(value: Severity, threshold: Severity) -> bool:
    return SEVERITY_RANK[value] >= SEVERITY_RANK[threshold]


@dataclass
class ToolManifest:
    """The part of a tool definition the model actually reads.

    A tool can be redefined without touching a single byte of source code -- the
    description and schema are supplied at runtime by the server. That is why this
    is pinned separately from the artifact hash.
    """

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mcp(cls, payload: dict[str, Any]) -> "ToolManifest":
        schema = payload.get("inputSchema")
        annotations = payload.get("annotations")
        return cls(
            name=str(payload.get("name") or ""),
            description=str(payload.get("description") or ""),
            input_schema=schema if isinstance(schema, dict) else {},
            annotations=annotations if isinstance(annotations, dict) else {},
        )

    def canonical(self) -> str:
        """Stable byte representation used for hashing.

        No normalisation of the description: whitespace and control characters are
        exactly the things an attacker hides payloads in.
        """
        return json.dumps(
            {
                "annotations": self.annotations,
                "description": self.description,
                "inputSchema": self.input_schema,
                "name": self.name,
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def digest(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    def schema_properties(self) -> list[str]:
        props = self.input_schema.get("properties")
        if not isinstance(props, dict):
            return []
        return sorted(str(k) for k in props)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": self.annotations,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ToolManifest":
        return cls(
            name=str(payload.get("name") or ""),
            description=str(payload.get("description") or ""),
            input_schema=payload.get("inputSchema") or {},
            annotations=payload.get("annotations") or {},
        )


@dataclass
class Artifact:
    """Best-effort identification of the code behind a server.

    ``UNKNOWN`` content is honest: for a remote server or an unpinned npm package we
    genuinely cannot tell what will execute.
    """

    kind: str = "unknown"  # local | npx | uvx | remote | unknown
    target: str = ""
    sha256: str | None = None
    files: int = 0
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "sha256": self.sha256,
            "files": self.files,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Artifact":
        return cls(
            kind=str(payload.get("kind") or "unknown"),
            target=str(payload.get("target") or ""),
            sha256=payload.get("sha256"),
            files=int(payload.get("files") or 0),
            note=str(payload.get("note") or ""),
        )


@dataclass
class ServerFingerprint:
    """A three-layer fingerprint of one MCP server."""

    server_id: str
    client: str
    name: str
    transport: str = "unknown"  # stdio | http | sse | unknown
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env_keys: list[str] = field(default_factory=list)
    config_hash: str = ""
    artifact: Artifact = field(default_factory=Artifact)
    tools: list[ToolManifest] | None = None
    tools_hash: str | None = None
    probed_at: str | None = None
    probe_error: str | None = None
    source_config: str = ""

    @property
    def tool_names(self) -> list[str]:
        if self.tools is None:
            return []
        return [t.name for t in self.tools]

    @property
    def manifest_known(self) -> bool:
        return self.tools is not None

    def tool(self, name: str) -> ToolManifest | None:
        for t in self.tools or []:
            if t.name == name:
                return t
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "client": self.client,
            "name": self.name,
            "transport": self.transport,
            "command": self.command,
            "args": list(self.args),
            "env_keys": list(self.env_keys),
            "config_hash": self.config_hash,
            "artifact": self.artifact.to_dict(),
            "tools": [t.to_dict() for t in self.tools] if self.tools is not None else None,
            "tools_hash": self.tools_hash,
            "probed_at": self.probed_at,
            "probe_error": self.probe_error,
            "source_config": self.source_config,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ServerFingerprint":
        tools_payload = payload.get("tools")
        tools = (
            [ToolManifest.from_dict(t) for t in tools_payload]
            if isinstance(tools_payload, list)
            else None
        )
        return cls(
            server_id=str(payload.get("server_id") or ""),
            client=str(payload.get("client") or ""),
            name=str(payload.get("name") or ""),
            transport=str(payload.get("transport") or "unknown"),
            command=payload.get("command"),
            args=[str(a) for a in (payload.get("args") or [])],
            env_keys=[str(k) for k in (payload.get("env_keys") or [])],
            config_hash=str(payload.get("config_hash") or ""),
            artifact=Artifact.from_dict(payload.get("artifact") or {}),
            tools=tools,
            tools_hash=payload.get("tools_hash"),
            probed_at=payload.get("probed_at"),
            probe_error=payload.get("probe_error"),
            source_config=str(payload.get("source_config") or ""),
        )


@dataclass
class Finding:
    """One detected drift, with the evidence that justifies it."""

    server_id: str
    kind: str
    severity: Severity
    title: str
    detail: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "kind": self.kind,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "evidence": list(self.evidence),
        }


@dataclass
class ServerResult:
    fingerprint: ServerFingerprint
    state: State
    findings: list[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_RANK[s])
