from __future__ import annotations

import json

import pytest

from pindrift.jsoncfg import strip_jsonc


def test_line_and_block_comments_are_removed() -> None:
    text = """
    {
      // a line comment
      "a": 1, /* inline */
      "b": 2
    }
    """
    assert json.loads(strip_jsonc(text)) == {"a": 1, "b": 2}


def test_comment_markers_inside_strings_are_preserved() -> None:
    text = '{"url": "https://example.com/a//b", "note": "/* not a comment */"}'
    assert json.loads(strip_jsonc(text)) == {
        "url": "https://example.com/a//b",
        "note": "/* not a comment */",
    }


def test_escaped_quote_does_not_end_the_string() -> None:
    text = '{"quote": "a \\" // b"}'
    assert json.loads(strip_jsonc(text)) == {"quote": 'a " // b'}


def test_trailing_commas_are_removed_in_objects_and_arrays() -> None:
    text = '{"a": [1, 2,], "b": {"c": 3,},}'
    assert json.loads(strip_jsonc(text)) == {"a": [1, 2], "b": {"c": 3}}


def test_comma_inside_string_is_not_treated_as_trailing() -> None:
    text = '{"a": "x,}", "b": [1, 2,]}'
    assert json.loads(strip_jsonc(text)) == {"a": "x,}", "b": [1, 2]}


def test_newlines_from_block_comments_are_preserved() -> None:
    text = '{\n/* one\ntwo */\n"a": 1\n}'
    assert strip_jsonc(text).count("\n") == text.count("\n")


def test_unterminated_block_comment_is_an_error() -> None:
    with pytest.raises(ValueError, match="unterminated block comment"):
        strip_jsonc('{"a": 1 /* broken')
