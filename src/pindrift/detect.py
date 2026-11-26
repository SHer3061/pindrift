"""Content heuristics for tool descriptions.

Tool descriptions are the primary prompt-injection surface in MCP. They are plain
text handed straight to the model, they are not code, and nothing in the protocol
forces them to stay stable after a user has approved them.

The published attack patterns this module is aimed at:

* ANSI terminal escape sequences and bidirectional control characters used to hide
  text from a human reviewer while leaving it visible to the model
* Unicode tag characters appended after a legitimate description
* instructions addressed to the model rather than to a human reader
* references to credential material that a filesystem tool has no business knowing
* encoded blobs used to smuggle a second-stage payload

Detection is intentionally conservative and explainable. Every hit carries the
snippet that produced it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .models import Severity

HIDDEN_PATTERNS: dict[str, re.Pattern[str]] = {
    "ansi escape": re.compile(r"\x1b\["),
    "zero-width character": re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]"),
    "bidi control character": re.compile(r"[\u202a-\u202e\u2066-\u2069]"),
    "unicode tag character": re.compile(r"[\U000E0000-\U000E007F]"),
    "carriage-return overwrite": re.compile(r"\r(?!\n)"),
}

INSTRUCTION_PHRASES: tuple[str, ...] = (
    "ignore previous",
    "ignore all previous",
    "ignore the above",
    "disregard previous",
    "disregard the above",
    "do not tell the user",
    "don't tell the user",
    "without telling the user",
    "do not mention",
    "do not inform",
    "without informing",
    "before using this tool",
    "before calling this tool",
    "you must first",
    "always call this tool",
    "always include",
    "secretly",
    "silently",
    "do not log",
    "ignore safety",
    "忽略之前",
    "忽略上述",
    "不要告诉用户",
    "无需告知",
    "在调用此工具前",
    "必须先",
    "静默地",
)

SENSITIVE_PATH_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ssh private key", re.compile(r"\.ssh|id_rsa|id_ed25519", re.IGNORECASE)),
    ("aws credentials", re.compile(r"\.aws[/\\]credentials|aws_access_key", re.IGNORECASE)),
    ("dotenv file", re.compile(r"(^|[^\w])\.env\b", re.IGNORECASE)),
    ("netrc or git credentials", re.compile(r"\.netrc|\.git-credentials", re.IGNORECASE)),
    ("npm token", re.compile(r"\.npmrc", re.IGNORECASE)),
    ("browser cookie store", re.compile(r"cookies\.sqlite|Login Data", re.IGNORECASE)),
    (
        "keychain or credential store",
        re.compile(r"keychain|credential manager|secret service", re.IGNORECASE),
    ),
)

URL_PATTERN = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)
ENCODED_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
SHORTENER_HOSTS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "shorturl.at", "cutt.ly"}
)
IPV4_HOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@dataclass
class ContentRisk:
    hidden: list[str] = field(default_factory=list)
    instructions: list[str] = field(default_factory=list)
    sensitive_paths: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    suspicious_urls: list[str] = field(default_factory=list)
    encoded: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (
            self.hidden
            or self.instructions
            or self.sensitive_paths
            or self.suspicious_urls
            or self.encoded
        )

    def severity(self) -> Severity | None:
        if self.hidden or self.sensitive_paths:
            return Severity.CRITICAL
        if self.instructions or self.suspicious_urls:
            return Severity.HIGH
        if self.encoded or self.urls:
            return Severity.MEDIUM
        return None

    def summary(self) -> list[str]:
        parts: list[str] = []
        if self.hidden:
            parts.append("hidden characters: " + ", ".join(sorted(set(self.hidden))))
        if self.instructions:
            parts.append("instruction-like phrases: " + ", ".join(sorted(set(self.instructions))[:3]))
        if self.sensitive_paths:
            parts.append("credential references: " + ", ".join(sorted(set(self.sensitive_paths))))
        if self.suspicious_urls:
            parts.append("suspicious URL: " + ", ".join(sorted(set(self.suspicious_urls))[:3]))
        if self.encoded:
            parts.append(f"{len(self.encoded)} encoded blob(s) >= 80 chars")
        return parts


def _is_suspicious_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return True
    host = (parsed.hostname or "").lower()
    if not host:
        return True
    if parsed.scheme.lower() != "https":
        return True
    if IPV4_HOST.match(host):
        return True
    return host in SHORTENER_HOSTS


def analyse_text(text: str) -> ContentRisk:
    """Run every heuristic against a blob of text."""
    risk = ContentRisk()
    if not text:
        return risk

    for label, pattern in HIDDEN_PATTERNS.items():
        match = pattern.search(text)
        if match:
            snippet = text[max(0, match.start() - 20) : match.end() + 20]
            risk.hidden.append(f"{label} near {snippet!r}")

    lowered = text.lower()
    for phrase in INSTRUCTION_PHRASES:
        if phrase in lowered:
            risk.instructions.append(phrase)

    for label, pattern in SENSITIVE_PATH_PATTERNS:
        if pattern.search(text):
            risk.sensitive_paths.append(label)

    for url in URL_PATTERN.findall(text):
        risk.urls.append(url)
        if _is_suspicious_url(url):
            risk.suspicious_urls.append(url)

    for blob in ENCODED_BLOB_PATTERN.findall(text):
        if not URL_PATTERN.search(blob):
            risk.encoded.append(blob[:24] + "...")

    return risk


def diff_lines(old: str, new: str) -> tuple[list[str], list[str]]:
    """Return (added, removed) lines using a set-free LCS-free comparison.

    Order does not matter for review purposes, so a multiset difference is enough
    and avoids pulling in a diff dependency.
    """
    old_lines = [line for line in old.splitlines() if line.strip()]
    new_lines = [line for line in new.splitlines() if line.strip()]
    old_counts: dict[str, int] = {}
    for line in old_lines:
        old_counts[line] = old_counts.get(line, 0) + 1
    added: list[str] = []
    for line in new_lines:
        if old_counts.get(line, 0) > 0:
            old_counts[line] -= 1
        else:
            added.append(line)
    new_counts: dict[str, int] = {}
    for line in new_lines:
        new_counts[line] = new_counts.get(line, 0) + 1
    removed: list[str] = []
    for line in old_lines:
        if new_counts.get(line, 0) > 0:
            new_counts[line] -= 1
        else:
            removed.append(line)
    return added, removed


def redact_arg(arg: str) -> str:
    """Mask likely secrets in command-line arguments before anything is persisted.

    Client configs routinely carry tokens in ``--api-key=VALUE`` form. Those values
    must never reach the pin file.
    """
    if "=" in arg:
        key, _, value = arg.partition("=")
        sensitive = re.search(
            r"(key|token|secret|passwd|password|credential|auth)", key, re.IGNORECASE
        )
        if sensitive and value:
            return f"{key}=<redacted:{len(value)}>"
    if re.match(r"^(sk-|ghp_|gho_|github_pat_|xox[baprs]-|AKIA|AIza)", arg):
        return f"<redacted:{len(arg)}>"
    if len(arg) >= 32 and re.fullmatch(r"[A-Za-z0-9_\-]+", arg) and arg.isalnum() is False:
        has_digit = any(c.isdigit() for c in arg)
        has_upper = any(c.isupper() for c in arg)
        has_lower = any(c.islower() for c in arg)
        if has_digit and has_upper and has_lower:
            return f"<redacted:{len(arg)}>"
    return arg
