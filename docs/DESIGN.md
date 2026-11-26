# Design

## Data flow

```
  config files            runtime observation               decision
┌────────────────┐      ┌──────────────────────┐      ┌────────────────┐
│ claude_desktop │      │ stdio JSON-RPC       │      │ compare against│
│ .claude.json   │─────▶│ initialize           │─────▶│ the pin        │
│ .cursor/mcp    │      │ tools/list (paged)   │      │                │
│ .vscode/mcp    │      │                      │      │  ok / drift    │
│ codex toml     │      └──────────────────────┘      │  new / missing │
└────────────────┘                                    │  unknown       │
        │                                             └────────────────┘
        ▼                                                     │
┌────────────────┐      ┌──────────────────────┐              ▼
│ ServerSpec     │─────▶│ ServerFingerprint    │      ┌────────────────┐
│ command args   │      │ config_hash          │      │ pins.json      │
│ env keys       │      │ artifact.sha256      │◀────▶│ (trust anchor) │
│ transport      │      │ tools_hash           │      └────────────────┘
└────────────────┘      └──────────────────────┘
```

Modules map one-to-one onto that flow:

| Module | Responsibility |
|---|---|
| `discover` | find and parse config files into `ServerSpec` |
| `jsoncfg` | strip JSONC comments and trailing commas |
| `sources` | additive registry of custom config files |
| `fingerprint` | hash config, identify and hash the artifact |
| `probe` | handshake with a stdio server, capture the manifest |
| `capability` | infer facets from a tool definition |
| `detect` | content heuristics and redaction |
| `differ` | compare a fingerprint against a pin, produce findings |
| `service` | one scan/pin pipeline shared by CLI, hook and UI |
| `store` | read and write the pin file |
| `report` | text, JSON, SARIF |
| `ui` | optional Tkinter desktop interface |

## Discovery and dedupe

Discovery is a list of known config paths plus a few directory scans: VS Code
`globalStorage` for Cline/Roo/Kilo, each installed JetBrains product directory,
`.continue/mcpServers/*.json`, WorkBuddy `project-resources/*/mcp.json`, and the
per-platform userData directories of Electron clients. Product and version directory
names are discovered, not guessed, so an IDE upgrade does not silently drop coverage.

Client formats differ in more than the path. Zed puts servers under `context_servers`
and has historically nested `command` as `{"path", "args", "env"}`. Kilo and OpenCode
write `command` as an array and env under `environment`. `_command_parts()` normalises
all of them to the same `ServerSpec`. `.jsonc` files go through `jsoncfg.strip_jsonc`,
which removes comments and trailing commas without a JSON5/YAML dependency.
`disabled: true` entries are skipped and counted as info, not treated as active
servers.

WorkBuddy's `connectors/` tree is a connector template library (hundreds of entries
with `disabled: true`), not an active configuration. Only `~/.workbuddy/mcp.json`,
its project-resources files, and project `.workbuddy/mcp.json` are registered.
Marketplace caches, credentials and session data are never scanned.

YAML-only clients (Goose, DSH/Cordis) cannot be parsed without a dependency. They are
listed by `sources list` and the UI as `unsupported`, never silently omitted. DSH has
no MCP server config on a stock install; skill fingerprinting is a separate planned
feature.

### Custom sources

`~/.pindrift/sources.json` is an additive registry for clients that are not built in.
`discover()` always loads built-ins first; a custom path that resolves to a built-in
file is ignored, and the registry has no way to hide or disable a built-in source.
A missing custom file is a warning, and a corrupt registry is an error that is
surfaced instead of degrading to an empty scan. Only absolute paths and JSON, JSONC or
TOML files are accepted.

`collect(dedupe=True)` groups specs by a launch key — name, transport, command, args,
env keys, url and header keys. The group's id is the id it was first pinned under;
before the first pin it is the alphabetically first client, as before. Every
`client:name` alias present at pin time is recorded, so a known client can be added or
removed, and a launch can change, without renaming the server or its SARIF
fingerprint. If every recorded alias is gone, an unambiguous pinned name is matched
instead; two pinned servers sharing a name are never guessed between. A group with no
known alias or name match that collides with another group of the same name gets a
short launch-derived suffix, which is persisted with the pin; the suffix is never
re-derived afterwards. `clients` keeps every client so a report can name them all.
Entries with the same name but a different launch are deliberately not merged:
that difference is the drift this tool exists to show.

## SARIF output

SARIF exists so CI can gate on a drift result without a custom parser, which makes
the document a public interface:

* Every finding kind has static metadata in `report.SARIF_RULES`: a rule id, an
  identifier-shaped `name`, descriptions, a `defaultConfiguration` and a `helpUri`
  pointing at a heading in `docs/THREAT-MODEL.md`. Rule metadata is not derived from
  the current run, so a finding graded differently on another machine does not
  rewrite the rule. `tests/test_report.py` checks every anchor against the actual
  headings in the threat model.
* Results carry `ruleId`, `ruleIndex` and a `partialFingerprints["pindrift/v1"]`
  hash of rule, server, title and detail. Evidence is excluded because digests and
  probe errors legitimately change between runs. Code scanning uses the fingerprint
  to dedupe a finding instead of reopening it on every build.
* A deduped server keeps its every-client list in result properties, so collapsing
  three identical configs into one probe does not erase where it was found.
* An unrecognised kind gets a synthesised but schema-valid rule rather than being
  dropped, so a future finding cannot disappear from the report.
* Titles, details and evidence pass through `differ.visible()` before encoding, so a
  hidden character cannot travel through SARIF into a viewer unescaped.

## The three fingerprint layers

They answer different questions and fail independently, which is why all three exist.

| Layer | Question | Blind to |
|---|---|---|
| `config_hash` | did the launch definition change? | anything the server does at runtime |
| `artifact.sha256` | did the bytes on disk change? | remote servers; unpinned package versions |
| `tools_hash` | did the manifest change? | a server that lies about its manifest |

The case that motivates the tool is `config_hash` stable **and** `artifact.sha256`
stable **and** `tools_hash` different. Any design that compares only the first two is
blind to it.

## Capability scoring

For each tool, each facet accumulates a score:

```
score = 3 × (phrase appears in tool name)
      + 2 × (specific phrase appears in description or schema)
      + 1 × (generic single word appears in description or schema)
      + 1 × (facet-specific schema parameter name present)
      + annotation modifiers
```

A phrase is *specific* if it contains a space or underscore, or is a CJK term of three
or more characters. Specificity is the guard against single words like `overwrite`
firing on unrelated descriptions.

A facet activates at `score >= 2`. Annotation modifiers: `destructiveHint=true` adds 2
to `fs.delete`; `readOnlyHint=false` adds 1 to `fs.write` and `db.write`.

Facet risk levels:

| Risk | Facets |
|---|---|
| critical | `exec.shell`, `cred.read`, `cloud.control` |
| high | `fs.write`, `fs.delete`, `db.write`, `repo.push`, `ci.trigger`, `msg.send`, `net.listen` |
| medium | `net.egress`, `browser.control`, `clipboard` |
| low | `fs.read` |

A capability delta takes the highest risk among the gained facets. Losing a facet is
`info`.

## States

| State | Meaning | Exit-code relevant |
|---|---|---|
| `ok` | pinned and unchanged, or only informational findings | no |
| `drift` | at least one finding at `low` or above | yes |
| `new` | discovered but never pinned | no |
| `missing` | pinned but no longer present in any config | no |
| `unknown` | could not be verified — **not** the same as clean | yes |

`unknown` is deliberately a separate state rather than a severity. Collapsing it into
`ok` is the single easiest way to make a monitor useless.

## Persistence

One JSON file at `$PINDRIFT_HOME/pins.json` (`~/.pindrift` by default), written
atomically via a temporary file and `os.replace`.

No database. The reasoning: the pin file is a trust anchor, and a trust anchor should be
small enough for a human to read. A SQLite file would hide the very data an incident
reviewer needs to see.

Pins are keyed by a canonical server id. An `aliases` object maps every `client:name`
observed at pin time to that id; a pin key is also treated as an alias of itself, which
is what keeps pin files written before aliases existed resolving to the same server.
Both objects are part of the signed document, so an alias cannot be added or redirected
without invalidating the signature.

Environment values are never stored — only key names. Command-line arguments pass
through `redact_arg` first.

### Signing and shared baselines

A pin file can be signed with HMAC-SHA256 over the canonicalised document (sorted keys,
compact separators, `signature` excluded). The signature covers the *content*, not the
bytes, so reformatting the JSON does not invalidate it and changing a fingerprint does.

`pindrift trust init` writes a 32-byte key to `$PINDRIFT_HOME/trust.key` (mode 0600) if
`PINDRIFT_TRUST_KEY` is not set. The environment variable always wins, so CI can hold
the key in a secret store and never write it next to the baseline. Every `store.save()`
re-signs the document when a key is available and drops any stale signature otherwise.

`--baseline <path>` on `pin` writes the signed document to a repository file;
`check --baseline` and `trust verify` read it back. A baseline named on the command
line is read strictly (a corrupt file is an error, not an empty pin set) and must
verify before it is used. A failure exits `3`; the home pin store is not signature-
checked, because it may predate signing and `check` would otherwise stop working for
every existing user.

The limit is authorship: a shared secret proves the file was written by someone holding
the key, not *which* teammate. See [THREAT-MODEL.md](THREAT-MODEL.md#threat-model-of-pindrift-itself).

### Desktop UI

`pindrift gui` is a Tkinter process, not a local web server. Opening a socket (even on
loopback) would add an attack surface and conflict with the no-network rule. Tkinter is
part of the Python standard library but is an optional OS package on some Linux
distributions; `ui.app.main()` imports it lazily, so no other command depends on it.

The UI calls `service` for every scan, check, pin and approve; it does not call CLI
handlers, which write to stdout and return exit codes. Probes run in one daemon worker
thread and post results back through a queue to `root.after()`. A generation counter is
not needed because only one task runs at a time.

The UI never probes on load. `Check` uses probe mode `auto`, which executes only
servers that already have a pin. `Pin` and `Approve` probe the selected servers but
require a confirmation dialog first.

## Extension points

* **New client**: add a `ConfigSource` to `discover.user_config_sources()`; nothing
  else changes. Add a parse test in `tests/test_discover.py`.
* **One-off client**: `pindrift sources add` writes to `~/.pindrift/sources.json`;
  no code change.
* **New capability facet**: append a `Facet` to `capability.FACETS`. The scoring,
  aggregation, reporting and severity mapping are all generic.
* **New detection heuristic**: add to `detect.HIDDEN_PATTERNS`,
  `INSTRUCTION_PHRASES` or `SENSITIVE_PATH_PATTERNS`, plus a test with a real sample.
* **New output format**: add a renderer in `report` and a choice in the CLI.

## Known weaknesses

* npm and PyPI targets are not version-resolved, because resolving requires network
  access that the tool deliberately does not use. An `npx` fingerprint is weaker than a
  local one and says so in its artifact note.
* Capability inference has both false positives and false negatives; see
  [THREAT-MODEL.md](THREAT-MODEL.md#limits-of-capability-inference).
* YAML-only clients (Goose, DSH/Cordis, Continue's YAML config) are listed as
  `unsupported` rather than parsed. A YAML parser is not worth a runtime dependency;
  they are not silently treated as absent.
* DSH has no MCP server config. Its tools are Cordis plugins and its agent skills are
  not fingerprinted yet; see the planned skill model.
* Two pinned servers that share a name cannot be told apart by the name fallback.
  Remove the last recorded alias of one and its pin can still be orphaned; re-pin
  after that change, or give distinct servers distinct names.
* Manifest capture requires a working stdio handshake. Servers that require
  authentication before `tools/list` will report `unknown`.
* `watch` polls. The `hook` command is stronger for Claude Code, but a host that has no
  hook API still depends on polling.
* The desktop UI depends on the platform's Tk package. Without it the `gui` command
  fails cleanly; there is no fallback web UI by design.
