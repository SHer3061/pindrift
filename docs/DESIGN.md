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
| `fingerprint` | hash config, identify and hash the artifact |
| `probe` | handshake with a stdio server, capture the manifest |
| `capability` | infer facets from a tool definition |
| `detect` | content heuristics and redaction |
| `differ` | compare a fingerprint against a pin, produce findings |
| `store` | read and write the pin file |
| `report` | text, JSON, SARIF |

## Discovery and dedupe

Discovery is a list of known config paths plus a few directory scans: VS Code
`globalStorage` for Cline, each installed JetBrains product directory, and
`.continue/mcpServers/*.json` for Continue. Product and version directory names are
discovered, not guessed, so an IDE upgrade does not silently drop coverage.

Client formats differ in more than the path. Zed puts servers under `context_servers`
and has historically nested `command` as `{"path", "args", "env"}`; `_command_parts()`
normalises that to the same `ServerSpec` every other client produces.

`collect(dedupe=True)` groups specs by a launch key — name, transport, command, args,
env keys, url and header keys. The first client alphabetically supplies the
`server_id`; `clients` keeps every client so a report can name them all. Entries with
the same name but a different launch are deliberately not merged: that difference is
the drift this tool exists to show.

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

Environment values are never stored — only key names. Command-line arguments pass
through `redact_arg` first.

## Extension points

* **New client**: add a `ConfigSource` to `discover.user_config_sources()`; nothing
  else changes.
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
* Continue's primary config is `~/.continue/config.yaml`. A YAML parser is not worth
  a runtime dependency, so only Continue's JSON forms are discovered; the YAML file is
  ignored rather than reported as broken.
* Manifest capture requires a working stdio handshake. Servers that require
  authentication before `tools/list` will report `unknown`.
* `watch` polls. A host hook that checks immediately before each tool call is stronger
  and is on the roadmap.
