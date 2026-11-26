"""Fingerprint construction: hashing, artifact identification, redaction.

Three layers, each answering a different question:

1. ``config_hash`` -- did the launch definition change? (command, args, env *keys*)
2. ``artifact``    -- did the bytes on disk change?
3. ``tools_hash``  -- did the runtime manifest change?

Layers 1 and 3 can diverge from layer 2, and that divergence is the interesting
case: a server whose code is untouched but whose tool descriptions changed after
approval is a classic rug pull.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from .discover import ServerSpec
from .models import Artifact, ServerFingerprint, ToolManifest

MAX_HASH_FILES = 400
MAX_HASH_BYTES = 8 * 1024 * 1024

NODE_RUNNERS = {"npx", "npx.cmd", "bunx", "bunx.exe", "pnpm", "pnpm.cmd", "yarn"}
PYTHON_RUNNERS = {"uvx", "uvx.exe", "uv", "uv.exe", "pipx", "pipx.exe"}
INTERPRETERS = {"python", "python3", "python.exe", "py", "py.exe", "node", "node.exe", "bun", "deno"}


def sha256_file(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def hash_tree(root: Path) -> tuple[str | None, int]:
    """Hash a directory deterministically: relative paths plus file contents."""
    digest = hashlib.sha256()
    count = 0
    total = 0
    try:
        entries = sorted(p for p in root.rglob("*") if p.is_file())
    except OSError:
        return None, 0
    for path in entries:
        if count >= MAX_HASH_FILES:
            break
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if total + size > MAX_HASH_BYTES:
            break
        file_hash = sha256_file(path)
        if file_hash is None:
            continue
        digest.update(str(path.relative_to(root)).replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_hash.encode("ascii"))
        digest.update(b"\n")
        count += 1
        total += size
    if count == 0:
        return None, 0
    return digest.hexdigest(), count


def _first_positional(args: list[str]) -> str | None:
    for arg in args:
        if arg.startswith("-"):
            continue
        return arg
    return None


def _basename(command: str) -> str:
    name = command.replace("\\", "/").rsplit("/", 1)[-1]
    return name.lower()


def identify_artifact(spec: ServerSpec) -> Artifact:
    """Best-effort answer to "what code runs when this server starts?"."""
    if spec.url:
        return Artifact(
            kind="remote",
            target=spec.url,
            note="remote endpoint, content cannot be pinned locally",
        )

    if not spec.command:
        return Artifact(kind="unknown", note="no command or url in config")

    base = _basename(spec.command)

    if base in NODE_RUNNERS:
        target = _first_positional(spec.args) or ""
        return Artifact(
            kind="npx",
            target=target,
            note="package resolved at launch; version not pinned unless args specify one",
        )
    if base in PYTHON_RUNNERS:
        target = _first_positional(spec.args) or ""
        return Artifact(kind="uvx", target=target, note="package resolved at launch")

    if base in INTERPRETERS:
        script = None
        for arg in spec.args:
            if arg.lower().endswith((".py", ".js", ".mjs", ".cjs", ".ts")):
                script = arg
                break
        if not script:
            return Artifact(kind="local", target=spec.command, note="no script argument found")
        path = Path(script).expanduser()
        if not path.is_absolute():
            source_dir = Path(spec.source_path).parent
            candidate = source_dir / path
            path = candidate if candidate.exists() else path.resolve()
        if path.is_file():
            return Artifact(
                kind="local", target=str(path), sha256=sha256_file(path), files=1
            )
        if path.is_dir():
            digest, count = hash_tree(path)
            return Artifact(kind="local", target=str(path), sha256=digest, files=count)
        return Artifact(kind="local", target=str(path), note="path does not exist")

    resolved = shutil.which(spec.command)
    if resolved:
        path = Path(resolved)
        if path.is_file():
            return Artifact(
                kind="local", target=str(path), sha256=sha256_file(path), files=1
            )
        return Artifact(kind="local", target=str(path), note="resolved but not a regular file")

    candidate = Path(spec.command).expanduser()
    if candidate.is_file():
        return Artifact(
            kind="local", target=str(candidate), sha256=sha256_file(candidate), files=1
        )
    return Artifact(kind="unknown", target=spec.command, note="command not resolvable")


def hash_config(spec: ServerSpec) -> str:
    """Hash the launch definition.

    Environment *values* are excluded by design: rotating a token must not look like
    a supply-chain event, and persisting secrets in a pin file would be a worse bug
    than the one this tool exists to catch.
    """
    payload = {
        "args": spec.redacted_args,
        "command": spec.command,
        "env_keys": spec.env_keys,
        "headers_keys": spec.headers_keys,
        "transport": spec.transport,
        "url": spec.url,
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def hash_tools(tools: list[ToolManifest] | None) -> str | None:
    if tools is None:
        return None
    digest = hashlib.sha256()
    for tool in sorted(tools, key=lambda t: t.name):
        digest.update(tool.canonical().encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def build(
    spec: ServerSpec,
    tools: list[ToolManifest] | None = None,
    probe_error: str | None = None,
    probed_at: str | None = None,
) -> ServerFingerprint:
    return ServerFingerprint(
        server_id=spec.server_id,
        client=spec.client,
        name=spec.name,
        clients=spec.all_clients,
        aliases=spec.all_aliases,
        transport=spec.transport,
        command=spec.command,
        args=spec.redacted_args,
        env_keys=list(spec.env_keys),
        config_hash=hash_config(spec),
        artifact=identify_artifact(spec),
        tools=tools,
        tools_hash=hash_tools(tools),
        probed_at=probed_at,
        probe_error=probe_error,
        source_config=spec.source_path,
    )
