"""Command-line interface.

Design notes:

* ``check`` probes only servers that already have a pin. A server you have never
  trusted does not get executed just because you ran a scan.
* ``--no-probe`` degrades gracefully into ``UNKNOWN``, never into ``ok``.
* exit code 2 means "findings at or above the threshold", so CI wiring is a one-liner.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, store, trust
from .capability import FACET_BY_NAME, infer_capabilities, server_capabilities
from .detect import analyse_text
from .differ import compare, summarise
from .discover import ServerSpec, collect
from .fingerprint import build
from .hook import SUPPORTED_HOSTS, run_hook
from .models import (
    SEVERITY_RANK,
    Finding,
    ServerFingerprint,
    ServerResult,
    Severity,
    State,
    severity_at_least,
)
from .probe import DEFAULT_TIMEOUT, probe_spec
from .report import (
    render_inventory,
    render_json,
    render_sarif,
    render_text,
)

EXIT_OK = 0
EXIT_FINDINGS = 2
EXIT_UNTRUSTED = 3
EXIT_USAGE = 64


def _now_label() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


def _load_specs(args: argparse.Namespace) -> list[ServerSpec]:
    specs, errors, _ = collect(
        include_project=not getattr(args, "no_project", False),
        root=Path(getattr(args, "root", None) or Path.cwd()),
        dedupe=getattr(args, "dedupe", False),
    )
    for error in errors:
        print(f"warning: {error.client} {error.path}: {error.message}", file=sys.stderr)
    return specs


def _fingerprint_spec(
    spec: ServerSpec, do_probe: bool, timeout: float
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


def _select(specs: list[ServerSpec], wanted: list[str]) -> list[ServerSpec]:
    if not wanted:
        return specs
    selected: list[ServerSpec] = []
    for token in wanted:
        matches = [s for s in specs if s.server_id == token or s.name == token]
        if not matches:
            matches = [s for s in specs if token.lower() in s.server_id.lower()]
        if not matches:
            raise SystemExit(f"no MCP server matched {token!r}")
        if len(matches) > 1:
            options = ", ".join(s.server_id for s in matches)
            raise SystemExit(f"{token!r} is ambiguous, matched: {options}")
        selected.append(matches[0])
    return selected


def cmd_scan(args: argparse.Namespace) -> int:
    specs = _load_specs(args)
    fingerprints = [
        _fingerprint_spec(spec, do_probe=args.probe, timeout=args.timeout) for spec in specs
    ]
    if args.format == "json":
        print(
            render_json(
                [ServerResult(fingerprint=fp, state=State.NEW, findings=[]) for fp in fingerprints],
                summarise([]),
            )
        )
    else:
        print(render_inventory(fingerprints, store.pinned_ids()))
    return EXIT_OK


def _verified_baseline(path: Path) -> dict[str, object]:
    """Load a repo-committed baseline and refuse to use it unverified.

    A baseline that cannot be verified is worse than no baseline: it looks like a
    statement of approved state while anyone who can edit the file controls the
    comparison. Exit before comparing anything.
    """
    try:
        payload = store.load_path(path)
    except FileNotFoundError:
        print(f"pindrift: baseline not found: {path}", file=sys.stderr)
        raise SystemExit(EXIT_UNTRUSTED)
    except (OSError, ValueError) as exc:
        print(f"pindrift: baseline is not a pin file: {path}: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_UNTRUSTED)

    verdict = trust.verify(payload)
    if not verdict.ok:
        print(f"pindrift: refusing to use baseline {path}: {verdict.detail}", file=sys.stderr)
        raise SystemExit(EXIT_UNTRUSTED)
    return payload


def cmd_pin(args: argparse.Namespace) -> int:
    specs = _load_specs(args)
    if not args.all:
        specs = _select(specs, args.servers)
    if not specs:
        print("no MCP servers found to pin", file=sys.stderr)
        return EXIT_USAGE

    target = Path(args.baseline).expanduser() if args.baseline else None
    if target is not None:
        try:
            if trust.load_key() is None:
                print(
                    "a shared baseline must be signed; run `pindrift trust init` "
                    f"or set {trust.ENV_KEY}",
                    file=sys.stderr,
                )
                return EXIT_USAGE
        except trust.TrustError as exc:
            print(f"cannot sign baseline: {exc}", file=sys.stderr)
            return EXIT_USAGE

        # Refuse to merge into a baseline we cannot verify: re-signing it with our key
        # would launder pins someone else inserted after the last review.
        if target.is_file():
            try:
                existing = store.load_path(target)
            except (OSError, ValueError) as exc:
                print(f"cannot read existing baseline {target}: {exc}", file=sys.stderr)
                return EXIT_USAGE
            verdict = trust.verify(existing)
            if not verdict.ok:
                print(
                    f"refusing to overwrite baseline {target}: {verdict.detail}",
                    file=sys.stderr,
                )
                return EXIT_USAGE

    fingerprints = [
        _fingerprint_spec(spec, do_probe=not args.no_probe, timeout=args.timeout)
        for spec in specs
    ]
    try:
        written = store.put_many(fingerprints, reason="cli-pin", path=target)
    except (OSError, ValueError) as exc:
        print(f"cannot write baseline {target}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    probed = sum(1 for fp in fingerprints if fp.tools is not None)
    print(f"pinned {len(fingerprints)} server(s) to {written}")
    print(f"manifest captured for {probed} of {len(fingerprints)}")
    for fp in fingerprints:
        if fp.tools is None and fp.probe_error:
            print(f"  unverified {fp.server_id}: {fp.probe_error}", file=sys.stderr)
    return EXIT_OK


def _missing_results(payload: dict[str, object], seen: set[str]) -> list[ServerResult]:
    """Pinned servers that no longer appear in any config.

    This is reported rather than ignored: quietly removing a server from the config is
    also how you stop being monitored.
    """
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
                        evidence=[f"last seen in {pin.source_config}"] if pin.source_config else [],
                    )
                ],
            )
        )
    return results


def _run_check(args: argparse.Namespace) -> tuple[list[ServerResult], int]:
    baseline_path = getattr(args, "baseline", None)
    if baseline_path:
        baseline_payload = _verified_baseline(Path(baseline_path).expanduser())
        baseline = baseline_payload.get("updated_at") or "no baseline"
        baseline_label = f"baseline {baseline} ({baseline_path})"
    else:
        baseline_payload = store.load()
        baseline = baseline_payload.get("updated_at") or "no baseline"
        baseline_label = f"baseline {baseline}"

    specs = _load_specs(args)
    if args.servers:
        specs = _select(specs, args.servers)

    pinned = set(baseline_payload.get("pins") or {})
    if not pinned:
        print(
            "no pins yet. Run `pindrift pin --all` after reviewing what is installed.",
            file=sys.stderr,
        )

    fingerprints: list[ServerFingerprint] = []
    for spec in specs:
        if args.no_probe:
            do_probe = False
        elif args.probe_all:
            do_probe = True
        else:
            do_probe = spec.server_id in pinned
        fingerprints.append(_fingerprint_spec(spec, do_probe=do_probe, timeout=args.timeout))

    results = [
        compare(store.from_payload(baseline_payload, fp.server_id), fp) for fp in fingerprints
    ]
    results.extend(_missing_results(baseline_payload, {fp.server_id for fp in fingerprints}))
    results.sort(key=lambda r: (r.state == State.OK, r.fingerprint.server_id))

    summary = summarise(results)
    threshold = Severity(args.fail_on)

    if args.format == "json":
        print(render_json(results, summary))
    elif args.format == "sarif":
        print(render_sarif(results))
    else:
        print(
            render_text(
                results,
                summary,
                baseline_label=f"{baseline_label}  |  {_now_label()}",
                verbose=args.verbose,
            )
        )

    worst = [
        f.severity
        for r in results
        for f in r.findings
        if not (f.kind == "unpinned")
    ]
    if worst and any(severity_at_least(s, threshold) for s in worst):
        return results, EXIT_FINDINGS
    return results, EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    _, code = _run_check(args)
    return code


def cmd_approve(args: argparse.Namespace) -> int:
    specs = _load_specs(args)
    if not args.all:
        specs = _select(specs, args.servers)
    if not specs:
        return EXIT_USAGE

    for spec in specs:
        current = _fingerprint_spec(spec, do_probe=not args.no_probe, timeout=args.timeout)
        pin = store.get(current.server_id)
        if pin is not None:
            result = compare(pin, current)
            print(f"--- {current.server_id}")
            print(
                render_text(
                    [result],
                    summarise([result]),
                    baseline_label="re-pin review",
                    verbose=True,
                )
            )
        store.put(current, reason="cli-approve")
        print(f"approved {current.server_id}\n")
    return EXIT_OK


def cmd_caps(args: argparse.Namespace) -> int:
    specs = _load_specs(args)
    specs = _select(specs, args.servers)
    for spec in specs:
        fp = _fingerprint_spec(spec, do_probe=not args.no_probe, timeout=args.timeout)
        print(f"{fp.server_id}  [{fp.transport}]  artifact={fp.artifact.kind}")
        if fp.tools is None:
            print(f"  manifest unavailable: {fp.probe_error}")
            continue
        capabilities = server_capabilities(fp.tools)
        if capabilities:
            print("  capabilities: " + ", ".join(f"{k} ({FACET_BY_NAME[k].risk.value})" for k in capabilities))
        for tool in fp.tools:
            hits = infer_capabilities(tool)
            risk = analyse_text(tool.description)
            flags = sorted(hits)
            print(f"  - {tool.name}: {', '.join(flags) if flags else 'no capability inferred'}")
            for facet in flags:
                print(f"      {facet}: {'; '.join(hits[facet].evidence[:2])}")
            if not risk.empty:
                print(f"      content risk ({risk.severity().value}): {'; '.join(risk.summary())}")
        print()
    return EXIT_OK


def cmd_watch(args: argparse.Namespace) -> int:
    print(f"watching every {args.interval:g}s, Ctrl-C to stop")
    last_code = EXIT_OK
    try:
        while True:
            print(f"\n[{_now_label()}]")
            _, code = _run_check(args)
            last_code = code
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped")
        return last_code


def cmd_hook(args: argparse.Namespace) -> int:
    return run_hook(
        host=args.host,
        stream=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
        fail_on=Severity(args.fail_on),
        timeout=args.timeout,
        root=Path(args.root) if args.root else None,
        include_project=not args.no_project,
    )


def cmd_trust_init(args: argparse.Namespace) -> int:
    try:
        _, key_file, created = trust.ensure_key(force=args.force)
    except (OSError, trust.TrustError) as exc:
        print(f"cannot create trust key: {exc}", file=sys.stderr)
        return EXIT_USAGE

    payload = store.load()
    if not payload["pins"]:
        print(
            "no pins to sign. Run `pindrift pin --all` after reviewing what is installed.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    target = Path(args.baseline).expanduser() if args.baseline else None
    try:
        store.save(payload)
        if target is not None:
            store.save(payload, target)
    except (OSError, ValueError) as exc:
        print(f"cannot write signed baseline: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if key_file is None:
        print(f"trust key: {trust.ENV_KEY} (from the environment)")
    else:
        label = "created" if created else "existing"
        print(f"trust key: {key_file} ({label})")
    print(f"signed {len(payload['pins'])} server(s) in {store.pins_path()}")
    if target is not None:
        print(f"wrote signed baseline to {target}")
    return EXIT_OK


def cmd_trust_verify(args: argparse.Namespace) -> int:
    path = Path(args.baseline).expanduser() if args.baseline else store.pins_path()
    try:
        payload = store.load_path(path)
    except FileNotFoundError:
        print(f"baseline not found: {path}", file=sys.stderr)
        return EXIT_UNTRUSTED
    except (OSError, ValueError) as exc:
        print(f"cannot read baseline {path}: {exc}", file=sys.stderr)
        return EXIT_UNTRUSTED

    verdict = trust.verify(payload)
    if verdict.ok:
        print(f"{path}: {verdict.detail}")
        return EXIT_OK
    print(f"{path}: {verdict.detail}", file=sys.stderr)
    return EXIT_UNTRUSTED


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pindrift",
        description="Continuous drift monitoring for MCP servers and agent skills.",
    )
    parser.add_argument("--version", action="version", version=f"pindrift {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(
        sub: argparse.ArgumentParser, *, probe_flag: bool = True, dedupe_flag: bool = True
    ) -> None:
        sub.add_argument("--root", help="project root for project-scoped configs")
        sub.add_argument("--no-project", action="store_true", help="ignore project-scoped configs")
        sub.add_argument(
            "--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-server probe timeout in seconds"
        )
        if probe_flag:
            sub.add_argument("--no-probe", action="store_true", help="skip manifest probing")
        if dedupe_flag:
            sub.add_argument(
                "--dedupe",
                action="store_true",
                help="fingerprint one server once when several clients configure it identically",
            )

    scan = subparsers.add_parser("scan", help="inventory MCP servers without comparing")
    add_common(scan)
    scan.add_argument("--probe", action="store_true", help="also capture tool manifests")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.set_defaults(func=cmd_scan)

    pin = subparsers.add_parser("pin", help="record the current state as the trust baseline")
    add_common(pin)
    pin.add_argument("servers", nargs="*", help="server names or ids; omit with --all")
    pin.add_argument("--all", action="store_true", help="pin every discovered server")
    pin.add_argument(
        "--baseline",
        metavar="PATH",
        help="write a signed baseline to PATH instead of the home pin store",
    )
    pin.set_defaults(func=cmd_pin)

    check = subparsers.add_parser("check", help="compare current state against the baseline")
    add_common(check)
    check.add_argument("servers", nargs="*", help="limit to specific servers")
    check.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    check.add_argument(
        "--baseline",
        metavar="PATH",
        help="read and verify this baseline instead of the home pin store",
    )
    check.add_argument(
        "--fail-on",
        choices=("info", "low", "medium", "high", "critical"),
        default="high",
        help="minimum severity that produces a non-zero exit code (default: high)",
    )
    check.add_argument("--probe-all", action="store_true", help="probe servers without a pin too")
    check.add_argument("--verbose", "-v", action="store_true", help="show informational findings")
    check.set_defaults(func=cmd_check)

    approve = subparsers.add_parser("approve", help="review drift and re-pin")
    add_common(approve)
    approve.add_argument("servers", nargs="*", help="server names or ids; omit with --all")
    approve.add_argument("--all", action="store_true")
    approve.set_defaults(func=cmd_approve)

    caps = subparsers.add_parser("caps", help="explain inferred capabilities per tool")
    add_common(caps)
    caps.add_argument("servers", nargs="*", help="server names or ids; omit for all")
    caps.set_defaults(func=cmd_caps)

    watch = subparsers.add_parser("watch", help="poll check() on an interval")
    add_common(watch)
    watch.add_argument("servers", nargs="*")
    watch.add_argument("--interval", type=float, default=300.0, help="seconds between checks")
    watch.add_argument("--format", choices=("text", "json"), default="text")
    watch.add_argument(
        "--fail-on",
        choices=("info", "low", "medium", "high", "critical"),
        default="high",
    )
    watch.add_argument("--probe-all", action="store_true")
    watch.add_argument("--verbose", "-v", action="store_true")
    watch.add_argument(
        "--baseline",
        metavar="PATH",
        help="read and verify this baseline instead of the home pin store",
    )
    watch.set_defaults(func=cmd_watch)

    hook = subparsers.add_parser(
        "hook",
        aliases=["agent-hook"],
        help="check one pending tool call before an agent host runs it",
    )
    add_common(hook, probe_flag=False, dedupe_flag=False)
    hook.add_argument(
        "--host",
        required=True,
        choices=SUPPORTED_HOSTS,
        help="agent host producing the hook payload on stdin",
    )
    hook.add_argument(
        "--fail-on",
        choices=("info", "low", "medium", "high", "critical"),
        default="high",
        help="minimum severity that denies the call (default: high)",
    )
    hook.set_defaults(func=cmd_hook)

    trust_parser = subparsers.add_parser("trust", help="sign and verify shared baselines")
    trust_sub = trust_parser.add_subparsers(dest="trust_command", required=True)

    trust_init = trust_sub.add_parser(
        "init", help="create a signing key and sign the current pins"
    )
    trust_init.add_argument(
        "--baseline",
        metavar="PATH",
        help="also write a signed copy for committing to a repository",
    )
    trust_init.add_argument(
        "--force", action="store_true", help="replace an existing key file"
    )
    trust_init.set_defaults(func=cmd_trust_init)

    trust_verify = trust_sub.add_parser("verify", help="verify a baseline signature")
    trust_verify.add_argument(
        "--baseline",
        metavar="PATH",
        help="baseline file to verify (default: the home pin store)",
    )
    trust_verify.set_defaults(func=cmd_trust_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except trust.TrustError as exc:
        print(f"pindrift: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
