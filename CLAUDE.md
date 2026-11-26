# CLAUDE.md

@AGENTS.md

The import above is the source of truth for architecture, constraints and standards.
Only Claude-specific working notes belong here.

## Verify before claiming done

```bash
python -m pytest -q          # full suite, all must pass
python examples/demo.py      # must still print critical drift in step 4
```

## Things that have already caused bugs here

- A `json.loads` on a UTF-8 BOM crashed config parsing. Read files with
  `encoding="utf-8-sig"`. Windows editors and PowerShell write BOMs.
- Capability scoring was too loose: a single description match scored 1 against a
  threshold of 2, so "description now mentions writing a file" was missed. The
  specificity weighting exists because of this. Do not simplify it away.
- Evidence printed raw ANSI escapes into the terminal. Use `differ.visible()`.
- `pyproject.toml` references `README.md`; deleting or renaming it breaks the build.
- Tkinter is an optional OS package on Linux. Never import it at module import time
  outside `pindrift/ui/`; `pindrift` and `pindrift-gui` must degrade cleanly when Tk
  is missing.

## Tone for this codebase

Comments explain *why*, especially where a heuristic is a guess. Do not write comments
that restate the code. Where the tool has a real limitation, state it in
`docs/THREAT-MODEL.md` rather than hiding it in a code comment.
