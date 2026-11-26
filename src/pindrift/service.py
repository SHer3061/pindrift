"""Shared scan/pin operations used by the CLI, hook and desktop UI.

Keeping this pipeline in one place matters: ``check`` must never probe an unpinned
server, and every caller must agree on what "unknown" means. Callers render the
returned dataclasses; this module does not print or exit.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import store, trust
from .differ import Summary, compare, summarise
from .discover import ConfigSource, ServerSpec, SourceError, collect
from .fingerprint import build
from .models import (
    Finding,
    ServerFingerprint,
    ServerResult,
    Severity,
    State,
    severity_at_least,
)
from .probe import DEFAULT_TIMEOUT, probe_spec


class BaselineError(RuntimeError):
    """A baseline was requested but could not be read or verified."""


class SelectionError(ValueError):
    """A server selector matched nothing, or matched more than one server."""


Progress = Callable[[int, int, str], None]


@dataclass
class ScanOptions:
    root: Path = field(default_factory=Path.cwd)
    include_project: bool = True
    dedupe: bool = False
    probe: str = "auto"  # auto | all | none
    timeout: float = DEFAULT_TIMEOUT
    fail_on: Severity = Severity.HIGH
    baseline_path: Path | None = None
    wanted: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    results: list[ServerResult]
    summary: Summary
    errors: list[SourceError]
    sources: list[ConfigSource]
    baseline_label: str
    pinned_ids: set[str]
    exit_code: int


def load_baseline(path: Path | None = None) -> tuple[dict[str, object], str]:
    """Load the comparison baseline, verifying a named file before use."""
    if path is not None:
        try:
            payload = store.load_path(path)
        except FileNotFoundError as exc:
            raise BaselineError(f"baseline not found: {path}") from exc
        except (OSError, ValueError) as exc:
            raise BaselineError(f"baseline is not a pin file: {path}: {exc}") from exc

        verdict = trust.verify(payload)
        if not verdict.ok:
            raise BaselineError(f"refusing to use baseline {path}: {verdict.detail}")
        stamp = payload.get("updated_at") or "no baseline"
        return payload, f"baseline {stamp} ({path})"

    payload = store.load()
    stamp = payload.get("updated_at") or "no baseline"
    return payload, f"baseline {stamp}"


def load_specs(
    *,
    root: Path | None = None,
    include_project: bool = True,
    dedupe: bool = False,
    aliases: dict[str, str] | None = None,
) -> tuple[list[ServerSpec], list[SourceError], list[ConfigSource]]:
    return collect(
        include_project=include_project,
        root=root or Path.cwd(),
        dedupe=dedupe,
        aliases=aliases,
    )


def fingerprint_spec(
    spec: ServerSpec, *, do_probe: bool, timeout: float
) -> ServerFingerprint:
    if not do_probe:
        return build(spec)
    tools, error = probe_spec(spec, timeout=timeout)
    return build(
        spec,
        tools=tools,
        probe_error=error,
        probed_at=store.utc_now() if tools is not None else None,
    )


def fingerprint_specs(
    specs: list[ServerSpec], *, do_probe: bool, timeout: float
) -> list[ServerFingerprint]:
    return [
        fingerprint_spec(spec, do_probe=do_probe, timeout=timeout) for spec in specs
    ]


def select(specs: list[ServerSpec], wanted: list[str]) -> list[ServerSpec]:
    if not wanted:
        return specs
    selected: list[ServerSpec] = []
    for token in wanted:
        matches = [
            s
            for s in specs
            if token in s.all_aliases or s.server_id == token or s.name == token
        ]
        if not matches:
            matches = [s for s in specs if token.lower() in s.server_id.lower()]
        if not matches:
            raise SelectionError(f"no MCP server matched {token!r}")
        if len(matches) > 1:
            options = ", ".join(s.server_id for s in matches)
            raise SelectionError(f"{token!r} is ambiguous, matched: {options}")
        selected.append(matches[0])
    return selected


def _missing_results(
    payload: dict[str, object], seen: set[str]
) -> list[ServerResult]:
    """Pinned servers that no longer appear in any config."""
    results: list[ServerResult] = []
    for server_id in sorted(set(payload.get("pins") or {}) - seen):
        pin = store.from_payload(payload, server_id)
        if pin is None:
            continue
        results.append(
            ServerResult(
                fingerprint=pin,
                state=State.MISSING,
                findings=[
                    Finding(
                        server_id=server_id,
                        kind="server_missing",
                        severity=Severity.MEDIUM,
                        title="pinned server is no longer configured",
                        detail=(
                            "Either it was uninstalled, or the config entry was removed. "
                            "If that was not you, treat it as tampering."
                        ),
                        evidence=(
                            [f"last seen in {pin.source_config}"]
                            if pin.source_config
                            else []
                        ),
                    )
                ],
            )
        )
    return results


def scan(options: ScanOptions, progress: Progress | None = None) -> ScanReport:
    """Compare current server state against the baseline.

    ``probe`` is ``auto`` (only pinned servers), ``all`` or ``none``. The default
    never executes a server the user has not already approved.

    ``progress`` receives ``(done, total, server_id)`` as each target is completed.
    """
    if options.probe not in ("auto", "all", "none"):
        raise ValueError(f"unknown probe mode {options.probe!r}")

    payload, baseline_label = load_baseline(options.baseline_path)
    aliases = store.alias_map(payload)
    specs, errors, sources = load_specs(
        root=options.root,
        include_project=options.include_project,
        dedupe=options.dedupe,
        aliases=aliases,
    )
    specs = select(specs, options.wanted)

    pinned = set(payload.get("pins") or {})
    fingerprints: list[ServerFingerprint] = []
    total = len(specs)
    for index, spec in enumerate(specs):
        if options.probe == "none":
            do_probe = False
        elif options.probe == "all":
            do_probe = True
        else:
            do_probe = spec.server_id in pinned
        fingerprints.append(
            fingerprint_spec(spec, do_probe=do_probe, timeout=options.timeout)
        )
        if progress is not None:
            progress(index + 1, total, spec.server_id)

    results = [
        compare(store.from_payload(payload, fp.server_id), fp) for fp in fingerprints
    ]
    results.extend(_missing_results(payload, {fp.server_id for fp in fingerprints}))
    results.sort(key=lambda r: (r.state == State.OK, r.fingerprint.server_id))

    summary = summarise(results)
    worst = [
        finding.severity
        for result in results
        for finding in result.findings
        if finding.kind != "unpinned"
    ]
    code = (
        2
        if worst and any(severity_at_least(s, options.fail_on) for s in worst)
        else 0
    )
    return ScanReport(
        results=results,
        summary=summary,
        errors=errors,
        sources=sources,
        baseline_label=baseline_label,
        pinned_ids=pinned,
        exit_code=code,
    )
