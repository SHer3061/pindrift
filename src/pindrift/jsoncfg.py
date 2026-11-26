"""Minimal JSONC support.

Several MCP clients ship ``.jsonc`` files: JSON plus ``//`` and ``/* */`` comments
and trailing commas. Adding a JSON5 or YAML parser would mean a runtime dependency,
so this module handles only the subset those clients actually use.

Strings are tracked character by character, so ``"https://example"`` and an escaped
quote do not confuse the comment scanner.
"""

from __future__ import annotations


def strip_jsonc(text: str) -> str:
    """Remove comments and trailing commas, preserving newlines.

    Raises ``ValueError`` for an unterminated block comment. Other syntax errors are
    left for ``json.loads`` to report with a useful position.
    """
    without_comments: list[str] = []
    index = 0
    length = len(text)
    in_string = False
    escaped = False

    while index < length:
        char = text[index]
        if in_string:
            without_comments.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue

        if char == '"':
            in_string = True
            without_comments.append(char)
            index += 1
            continue

        if char == "/" and index + 1 < length:
            following = text[index + 1]
            if following == "/":
                index += 2
                while index < length and text[index] not in "\r\n":
                    index += 1
                continue
            if following == "*":
                index += 2
                closed = False
                while index + 1 < length:
                    if text[index] == "*" and text[index + 1] == "/":
                        index += 2
                        closed = True
                        break
                    if text[index] in "\r\n":
                        without_comments.append(text[index])
                    index += 1
                if not closed:
                    raise ValueError("unterminated block comment")
                continue

        without_comments.append(char)
        index += 1

    cleaned = "".join(without_comments)
    return _strip_trailing_commas(cleaned)


def _strip_trailing_commas(text: str) -> str:
    result: list[str] = []
    index = 0
    length = len(text)
    in_string = False
    escaped = False

    while index < length:
        char = text[index]
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue

        if char == '"':
            in_string = True
            result.append(char)
            index += 1
            continue

        if char == ",":
            lookahead = index + 1
            while lookahead < length and text[lookahead] in " \t\r\n":
                lookahead += 1
            if lookahead < length and text[lookahead] in "}]":
                index += 1
                continue

        result.append(char)
        index += 1

    return "".join(result)
