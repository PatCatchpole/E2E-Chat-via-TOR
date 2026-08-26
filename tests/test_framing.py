"""Payload framing: priming packets must be invisible, text must round trip."""

from __future__ import annotations

import pytest

from crypto.framing import PRIME, TEXT, FramingError, frame_prime, frame_text, parse


def test_text_round_trip():
    kind, text = parse(frame_text("hello world"))
    assert kind == TEXT
    assert text == "hello world"


def test_unicode_round_trip():
    payload = "héllo wörld 🔐 ünïcode"
    assert parse(frame_text(payload))[1] == payload


def test_empty_text_round_trip():
    assert parse(frame_text(""))[1] == ""


def test_prime_carries_no_text():
    kind, text = parse(frame_prime())
    assert kind == PRIME
    assert text is None


def test_prime_is_indistinguishable_in_length_from_a_short_message():
    """Not a security guarantee, just a check that priming carries no payload."""
    assert len(frame_prime()) == 1


def test_unknown_type_is_rejected_not_guessed():
    with pytest.raises(FramingError, match="unknown payload type"):
        parse(bytes([0x7f]) + b"something")


def test_empty_payload_is_rejected():
    with pytest.raises(FramingError, match="empty"):
        parse(b"")


def test_text_starting_with_a_zero_byte_is_still_text():
    """The type byte is a prefix, so payload content cannot be confused for it."""
    kind, text = parse(frame_text("\x00 leading null"))
    assert kind == TEXT
    assert text == "\x00 leading null"
