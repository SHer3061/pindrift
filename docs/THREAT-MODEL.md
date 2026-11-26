# Threat model

What `pindrift` defends, what it provably cannot, and where the boundary sits.

Reading this before trusting the tool is the intended use. A monitor that overstates
its coverage is a liability, so the "not detected" section is as important as the
"detected" one.

## The asset

The thing being protected is not a file or a credential. It is **the agent's belief
about what its tools do**.

Every tool definition is text the model treats as instruction: a name, a description,
an input schema. The model has no way to verify that this text still means what it
meant when a human approved it. Nothing in the MCP protocol forces stability, and no
package lockfile covers it, because tool descriptions are not code.

That asymmetry — a human approves once, the model trusts forever — is the vulnerability.

## Assumed attacker capability

| Capability | Assumed |
|---|---|
| Can publish or compromise an MCP server or agent skill | yes |
| Can change what a server advertises after the user approved it | yes |
| Can influence content the agent reads (issues, tickets, docs, telemetry) | yes |
| Can write to the local config directory | yes |
| Has local code execution as the user | no — game over at that point |

## Detected

### Tool poisoning — hidden instructions in a description

The model read a description; the human reviewing it saw something different.

Detected through: ANSI terminal escapes, zero-width characters, bidi control
characters, Unicode tag characters, carriage-return overwrites, and instruction-shaped
phrasing addressed to the model rather than to a human (`do not tell the user`,
`before using this tool`, `忽略前述`).

Severity: **critical** for hidden characters, **high** for instruction phrasing.

### Rug pull — silent redefinition after approval

The server launches identically, runs identical code, and returns a different tool
manifest on the next session.

Detected through: the pinned `tools_hash` and per-tool comparison. This is the case
that a one-shot scanner cannot see by construction.

Severity: graded by what actually changed — see capability escalation below.

### Capability escalation

An existing tool gains a facet, or a new tool appears, that the original approval did
not cover.

Detected through: capability inference over name, description and schema, compared as
a set difference against the pin.

Examples: a `read_file` tool whose description starts mentioning writes; a
`search_issues` server that later advertises `create_issue` with a filesystem
parameter; `readOnlyHint` flipped to `false`.

### Launch definition change

Different command, different arguments, different environment key set, different
transport.

Detected through: `config_hash`, with arguments and environment keys reported
individually so the diff is readable.

Severity: **high** for command and arguments, **medium** for environment keys and
transport.

### Artifact swap

Same launch definition, different bytes on disk.

Detected through: sha256 of the resolved script or source tree.

Severity: **high**.

## Not detected — read this section

### A server that lies about its own manifest

`pindrift` asks the server what tools it has. A server that advertises two tools to
the probe and three to the host defeats it.

There is no protocol-level attestation to bind the manifest to the implementation.
Until MCP has something equivalent to a build provenance attestation, this gap is
architectural. The mitigation available today is pinning the artifact digest, which
catches the *code* changing even when the manifest is consistent.

### Cross-server tool shadowing

A malicious server steering a trusted server, or a tool that changes meaning depending
on another server's presence. Requires reasoning across the whole session, not per
server.

### Output poisoning at runtime

Injection delivered through tool *results* — a poisoned issue body, a malicious
document, telemetry consumed by the agent. This is the dominant real-world vector and
it happens after `pindrift`'s last observation. It is a runtime problem, and solving it
needs interception, not comparison.

### Sampling and resource abuse

Bidirectional sampling exploitation, resource exhaustion, and similar protocol-level
attacks. Out of scope.

### Malicious code that behaves identically

`pindrift` detects change, not malice. A server that was malicious from the start is
pinned as-is, and every subsequent check reports `ok`.

This is why `pindrift check` on a fresh machine is a workflow for *accepted* risk, not
a clean bill of health. Scan before you pin.

## Limits of capability inference

Inference is a weighted phrase model, not analysis of the implementation. Both error
directions are real:

* **False negative.** A tool that deletes files but describes itself as "clean up a
  workspace" carries no facet. The capability delta is then invisible, and only the
  text diff fires at `low`.
* **False positive.** A tool described as "read the file and write the result to
  stdout" triggers `fs.write` because the phrase matches, even though no file write
  occurs.

Every hit carries the phrases that fired so a reviewer can overrule the tool quickly.
Treat the facet as a prompt for review, not as a verdict. `pindrift caps <server>`
exists for exactly this reason.

## Threat model of pindrift itself

**Probing executes third-party code.** Any tool that captures a runtime manifest must
start the server. Mitigations: probing is opt-in for discovery, only runs automatically
for servers that are already pinned, is timeout-bounded, and the child is always
terminated. This is not a sandbox. If a server is untrusted, do not pin it.

**The pin file is a trust anchor.** If an attacker can rewrite `~/.pindrift/pins.json`,
they can approve their own drift. Protect it like any other credential-adjacent file.

A baseline can carry an HMAC-SHA256 signature (`pindrift trust init`). This protects a
copy that leaves the machine — one committed to a repository — from edits by anyone
without the key. It does **not** protect the local pin file from an attacker who can
read `$PINDRIFT_HOME/trust.key` sitting beside it, and it proves possession of a shared
secret rather than the identity of an author. Put the key in `PINDRIFT_TRUST_KEY` from a
secret store wherever the stronger property matters. A `--baseline` file is refused
unless its signature verifies; a missing key is reported as unverifiable, never as
success. A signature also does not prevent replay of an older baseline that was validly
signed: use the repository history (or a review of the diff) to rule that out.

**Secrets must not leak into the pin.** Environment values are excluded from
fingerprints and credential-shaped arguments are redacted before anything is written.
This is tested. If you find a path where a secret reaches disk, that is a security bug.

**No network access.** `pindrift` never calls out. Version pinning for npm and PyPI
packages is therefore not attempted, and the resulting `npx` fingerprints are weaker
than local ones — the package can resolve differently tomorrow. This limitation is
recorded in the artifact note rather than hidden.
