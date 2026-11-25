from __future__ import annotations

from pindrift.differ import visible


def test_plain_text_is_unchanged() -> None:
    assert visible("read a file") == "read a file"


def test_cjk_is_preserved() -> None:
    assert visible("读取文件内容") == "读取文件内容"


def test_escape_sequence_is_rendered() -> None:
    assert visible("a\x1b[2Kb") == "a\\x1b[2Kb"


def test_zero_width_is_rendered() -> None:
    assert visible("a\u200bb") == "a\\u200bb"


def test_bidi_control_is_rendered() -> None:
    assert visible("\u202e") == "\\u202e"


def test_newlines_become_spaces() -> None:
    assert visible("a\nb") == "a b"
