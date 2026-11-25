#!/usr/bin/env python3
"""Reproducible end-to-end demo of pindrift.

Runs the whole narrative against a throwaway directory so nothing touches your real
MCP configuration:

  1. a clean server is discovered and pinned
  2. the check passes
  3. the server's tool description is silently rewritten  -> critical drift
  4. the server also gains a write-capable tool           -> escalation

Between steps the config file and the server code are left byte-identical. Only what
the server advertises at runtime changes, which is exactly the case a one-shot scanner
cannot see.

Usage:
    python examples/demo.py [--keep]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parent / "tests" / "fixtures" / "fake_mcp_server.py"


def write_config(workspace: Path, state_file: Path) -> None:
    """Write the MCP config once. It is never rewritten during the demo."""
    payload = {
        "mcpServers": {
            "demo-fs": {
                "command": sys.executable,
                "args": [str(FIXTURE), "--mode-file", str(state_file)],
            }
        }
    }
    (workspace / ".mcp.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def set_mode(state_file: Path, mode: str) -> None:
    """Change what the server advertises without touching any pinned surface."""
    state_file.write_text(mode + "\n", encoding="utf-8")


def run(args: list[str], workspace: Path, home: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PINDRIFT_HOME"] = str(home / "state")
    env["USERPROFILE"] = str(home / "user")
    env["HOME"] = str(home / "user")
    env["APPDATA"] = str(home / "user" / "AppData" / "Roaming")
    env["NO_COLOR"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(
        [sys.executable, "-m", "pindrift", *args],
        cwd=str(workspace),
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    print(f"\n$ pindrift {' '.join(args)}")
    if result.stdout.strip():
        print(result.stdout.rstrip())
    if result.stderr.strip():
        print(result.stderr.rstrip(), file=sys.stderr)
    print(f"[exit {result.returncode}]")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="keep the scratch directory")
    args = parser.parse_args()

    if not FIXTURE.is_file():
        print(f"fixture server not found at {FIXTURE}", file=sys.stderr)
        return 1

    scratch = Path(tempfile.mkdtemp(prefix="pindrift-demo-"))
    workspace = scratch / "workspace"
    home = scratch / "home"
    workspace.mkdir(parents=True)
    (home / "user").mkdir(parents=True)

    state_file = workspace / "demo.mode"
    set_mode(state_file, "clean")
    write_config(workspace, state_file)

    print(f"scratch: {scratch}")
    print("=" * 70)

    print("\n### 1. a clean server appears in the config")
    run(["scan"], workspace, home)

    print("\n### 2. approve it as the baseline")
    run(["pin", "--all"], workspace, home)

    print("\n### 3. nothing has changed")
    run(["check"], workspace, home)

    print("\n### 4. the tool description is rewritten after approval (rug pull)")
    set_mode(state_file, "poisoned")
    run(["check"], workspace, home)

    print("\n### 5. the server also grows a write-capable tool")
    set_mode(state_file, "escalated")
    run(["check"], workspace, home)

    print("\n### 6. machine-readable output for CI")
    result = run(["check", "--format", "sarif"], workspace, home)
    preview = json.loads(result.stdout) if result.stdout.strip() else {}
    runs = preview.get("runs") or [{}]
    print(f"\nSARIF results: {len(runs[0].get('results', []))}")

    print("\n### 7. what the server can do, per tool")
    run(["caps", "demo-fs"], workspace, home)

    if not args.keep:
        import shutil

        shutil.rmtree(scratch, ignore_errors=True)
    else:
        print(f"\nkept: {scratch}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
