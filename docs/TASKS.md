# Task board

Tasks are cut so that **file ownership is disjoint**. That is deliberate: an agent IDE
that runs several agents in parallel worktrees only helps if the diffs do not collide.
Claim one task per worktree, and respect its file list.

## Ownership map

| Task | Owns these files | New files |
|---|---|---|
| T1 hook | `cli.py`, `tests/test_hook.py` | `src/pindrift/hook.py` |
| T2 trust | `store.py`, `tests/test_trust.py` | `src/pindrift/trust.py` |
| T3 discovery | `discover.py`, `tests/test_discover.py` | — |
| T4 capability | `capability.py`, `tests/test_capability.py` | `tests/fixtures/facet_corpus.jsonl` |
| T5 output | `report.py`, `tests/test_report.py` | `.github/actions/pindrift/action.yml` |
| T6 research | — | `docs/RESEARCH-content-provenance.md` |

Anything not listed (models, fingerprint, probe, detect, differ, docs) is shared. If a
task genuinely needs a shared file, do it as its own small commit first so the others
rebase onto a stable base.

**Merge order:** T3 and T4 first (leaf behaviour, no cross-dependency), then T5, then
T1, then T2. T6 is independent and can land any time.

---

## T1 — `agent-hook` subcommand

**Why.** `watch` polls. A host that calls a check immediately before each tool call is
strictly stronger, because the window between observation and use closes to zero. This
is the single highest-value remaining feature.

**Scope.** `pindrift hook --host claude-code` reads the hook payload from stdin,
resolves which server the pending tool call belongs to, compares its live manifest
against the pin, and exits:

- `0` allow (no findings at or above `--fail-on`)
- `2` deny (findings present), printing an agent-readable reason on stdout
- `1` on malformed input

Must degrade to allow-with-warning when the manifest cannot be fetched, and say so —
never block work because a probe timed out, but never report silence as safety either.

**Files.** `src/pindrift/hook.py` (new), `src/pindrift/cli.py`, `tests/test_hook.py`.

**Acceptance.** A test that feeds a synthetic hook payload for a drifted server and
asserts exit 2 plus a reason string containing the capability that was gained.

---

## T2 — signed shared baseline

**Why.** The pin file is an unsigned trust anchor. An attacker who can rewrite
`~/.pindrift/pins.json` approves their own drift. Teams also need one baseline
committed to the repo.

**Scope.** Ed25519 (or HMAC with a key from env, whichever lands smaller without a
dependency) signature over the canonical pin JSON; `pindrift trust init`,
`trust verify`, and a `--baseline <path>` flag that reads a repo-committed baseline
instead of the home directory.

**Constraint.** Ed25519 from the stdlib does not exist. Either implement HMAC-SHA256
over the canonicalised pin (acceptable: it proves the file was written by someone
holding the key) or argue explicitly in the PR why a dependency is worth it. Do not
silently add `cryptography`.

**Files.** `src/pindrift/trust.py` (new), `src/pindrift/store.py`, `tests/test_trust.py`.

**Acceptance.** Tampering with one byte of a pinned fingerprint makes verification
fail with a specific message.

---

## T3 — discovery coverage and dedupe

**Why.** Every client that appears is a reason for someone to bounce off the tool.

**Scope.** Add config locations as they ship (check Claude Code project scope, Cline,
Zed, JetBrains AI, Continue). Add `--dedupe` so the same server configured in three
clients is fingerprinted and reported once, while the report still names all clients.

**Files.** `src/pindrift/discover.py`, `tests/test_discover.py`.

**Acceptance.** A test with the same server in two client configs collapses to one
result and lists both clients.

---

## T4 — capability rule quality

**Why.** This is the differentiator and the weakest part. Both false positives and
false negatives are real; today neither rate is measured.

**Scope.** Build a small labelled corpus (`tests/fixtures/facet_corpus.jsonl`: one
JSON object per line with `tool`, `expect_facets`, `note`), wire a test that asserts
per-facet precision and recall thresholds, then tune `FACETS` against it. Target:
no facet below 0.85 precision on the corpus. Adding facets is allowed but the corpus
is the contract.

**Files.** `src/pindrift/capability.py`, `tests/test_capability.py`,
`tests/fixtures/facet_corpus.jsonl` (new).

**Acceptance.** The corpus test reports precision/recall per facet and fails below
threshold. Include at least ten benign tools that must produce **no** facet — false
positives are what make users uninstall.

---

## T5 — SARIF fidelity and a reusable Action

**Why.** Gating CI is the adoption path that does not require trusting a new daemon.

**Scope.** Give each finding kind a real SARIF `rule` with `helpUri` pointing at
`docs/THREAT-MODEL.md` anchor, set `partialFingerprints` so results dedupe across
runs, and add `.github/actions/pindrift/action.yml` (composite) that installs the
tool, runs `check --format sarif`, uploads the file, and fails on threshold.

**Files.** `src/pindrift/report.py`, `tests/test_report.py` (new),
`.github/actions/pindrift/action.yml` (new).

**Acceptance.** `tests/test_report.py` validates the document against the SARIF 2.1.0
required fields (no network, no schema download — assert the shape directly).

---

## T6 — research note, no code

**Why.** The second project (AI content-provenance verification) needs its evidence
chain assembled before any code, and that writing is the part hardest to copy.

**Scope.** `docs/RESEARCH-content-provenance.md`: for each verification signal
(C2PA manifest chain, Chinese explicit/implicit labelling fields, statistical text
watermarks, pixel watermarks, metadata-stripped fallback), record what it actually
proves, what defeats it, who currently implements a third-party-runnable detector, and
what the three-state verdict should be. Cite primary sources. Explicitly mark where
detection is impossible rather than weak.

**Files.** `docs/RESEARCH-content-provenance.md` only. Do not touch code in this task.

---

## Working in a worktree

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
python -m pytest -q
```

`pip install -e` inside each worktree is required — the console script and the
editable path are per-environment. Keep `.venv` out of git (already ignored).
