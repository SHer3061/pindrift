# AGENTS.md

Context for any coding agent working in this repository. Read this before the first
edit. It is written to be sufficient on its own: you should not need to ask a human
what the constraints are.

## What this project is

`pindrift` is a CLI that monitors **drift** in MCP servers and agent skills. Scanners
check a server once before install; `pindrift` pins the state a human approved and
compares against that pin on every run.

The single case that justifies the whole project: a server whose config file and code
are byte-identical but whose runtime tool manifest has changed. Everything is built
around being able to see that.

## Hard constraints

These are not preferences. Breaking one is a bug, not a style choice.

1. **Python 3.10 minimum.** `requires-python = ">=3.10"`. No `tomllib` unguarded (it is
   3.11+; `discover.py` already guards it). No `typing.Self`, no `except*`, no 3.12+
   syntax. `X | Y` annotations are fine because every module starts with
   `from __future__ import annotations`.
2. **Zero runtime dependencies.** `dependencies = []` in `pyproject.toml` stays empty.
   The tool is installed with `pipx` by people auditing it; every dependency is a
   reason not to trust it.
3. **No network access at runtime.** Ever. Not for version resolution, not for
   telemetry, not for update checks. This is why npm/PyPI targets are fingerprinted
   without resolving their versions, and why that weakness is documented instead of
   fixed.
4. **Secrets never reach disk.** Environment *values* are excluded from fingerprints;
   only key names are stored. Command-line arguments pass through
   `detect.redact_arg()` before persistence. If you add a code path that writes config
   data, it must go through redaction.
5. **`unknown` is never folded into `ok`.** If the tool could not verify something, the
   state is `State.UNKNOWN`. Collapsing it into success is the one failure mode that
   makes a security monitor actively harmful.
6. **No `shell=True`.** Subprocess calls resolve the executable and build an argv list.
   On Windows, `.cmd`/`.bat` are routed through `cmd.exe /c` explicitly (see
   `probe._wrap_for_windows`).

## Layout

```
src/pindrift/
  models.py       dataclasses: ToolManifest, Artifact, ServerFingerprint, Finding,
                  ServerResult, State, Severity. Serialisation is explicit, not asdict().
  discover.py     find + parse client configs into ServerSpec. Tolerant: an unreadable
                  file is reported, never fatal. Reads with utf-8-sig (BOM tolerance).
  fingerprint.py  three hashes: hash_config, artifact sha256, hash_tools.
  probe.py        stdio JSON-RPC handshake, paged tools/list, bounded by timeout.
  capability.py   Facet table + weighted phrase scoring -> capability facets.
  detect.py       content heuristics (hidden chars, injection phrasing, credential
                  paths, URLs, encoded blobs), diff_lines(), redact_arg().
  differ.py       compare(pin, current) -> ServerResult with graded Findings.
  store.py        ~/.pindrift/pins.json, atomic write via os.replace.
  report.py       text / JSON / SARIF renderers.
  cli.py          argparse subcommands, exit codes.
tests/            71 tests; fixtures/fake_mcp_server.py is a stdio MCP server.
docs/             DESIGN.md (internals), THREAT-MODEL.md (coverage and gaps).
examples/         demo.py reproduces the rug-pull narrative end to end.
```

## Data flow

```
config files -> ServerSpec -> ServerFingerprint -> compare() -> Findings -> report
                                   ^                  ^
                              probe.py           store.py (pin)
```

`discover` produces specs. `fingerprint.build()` turns a spec into a fingerprint,
optionally with a manifest from `probe`. `differ.compare()` takes the pin and the
current fingerprint and returns a `ServerResult`. `report` renders it.

## Design rules worth preserving

- **Capability delta over text diff.** Diff size is a bad proxy for risk. Use
  `capability.infer_capabilities()` on both sides and compare sets.
- **Specificity weighting.** In `capability.py`, a phrase containing a space,
  underscore, or three or more CJK characters is *specific* and scores 2 in a
  description; a generic single word scores 1. Name matches score 3. Threshold is 2.
  Do not flatten this — it is what keeps `overwrite` from firing on unrelated tools.
- **Evidence on every finding.** Any new heuristic must record *what fired* so a human
  can overrule it. Findings without evidence are not acceptable.
- **Escape before display.** `differ.visible()` renders control and invisible
  characters as `\x1b`, `\u200b` etc. Evidence passes through it. Raw ESC sequences in
  terminal output or an issue comment defeat the purpose of reporting them.
- **Probe only what is already trusted.** `check` probes servers that have a pin;
  untrusted servers are never executed just because a check ran. Preserve this.
- **No database.** The pin file is a trust anchor and must stay small enough for a
  human to read during an incident.

## Working standards

- Every new detection heuristic needs a test with a **real** sample of the pattern it
  targets, plus a negative test proving it does not fire on benign input.
- Every new capability facet needs a positive test and access to the risk grading.
- Run the full suite before claiming a change works:

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"    # .venv/bin/python on POSIX
python -m pytest -q
python examples/demo.py                            # must still reproduce the narrative
```

- Line length 100 (`[tool.ruff]`). Stdlib only. Prefer explicit over clever.
- Commit messages: imperative subject, body explains *why*. No `--no-verify`.
- If you change user-visible behaviour, update `README.md`; if you change internals or
  limits, update `docs/DESIGN.md`; if you change what is or is not detected, update
  `docs/THREAT-MODEL.md`. The threat model is a promise — keep it accurate.

## Extension recipes

**Add a capability facet** — append a `Facet` to `capability.FACETS` with `name`,
`risk`, `label`, `phrases`, optional `schema_keys`. Scoring, aggregation and severity
mapping are generic. Add a positive and a negative test in `tests/test_capability.py`.

**Add a client config location** — add a `ConfigSource` in
`discover.user_config_sources()` for the platform, or in `project_config_sources()`
for project scope. Nothing else changes. Add a parse test in `tests/test_discover.py`.

**Add a content heuristic** — extend `HIDDEN_PATTERNS`, `INSTRUCTION_PHRASES` or
`SENSITIVE_PATH_PATTERNS` in `detect.py`, then map it to a severity inside
`ContentRisk.severity()`. Test with a real sample in `tests/test_detect.py`.

**Add an output format** — write a renderer in `report.py`, add a `choices` entry in
the corresponding `cli.py` subparser. Keep the JSON shape stable; SARIF must stay
schema-valid (2.1.0).

## Non-goals

Do not implement these without an explicit new decision, because each one was
considered and deferred for a recorded reason:

- sandboxing or intercepting MCP traffic (that is a different product)
- runtime output-poisoning detection (happens after the last observation)
- installing, updating, or launching servers on the user's behalf
- any hosted service, account, or telemetry
- resolving package versions over the network

See `docs/THREAT-MODEL.md` for why each is out of scope.
