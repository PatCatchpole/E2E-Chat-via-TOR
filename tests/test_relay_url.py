"""Relay address parsing, including the .onion forms."""

from __future__ import annotations

import pytest

from client_cli import normalise_onion, resolve_relay


@pytest.mark.parametrize("text,expected_url,expected_tor", [
    ("127.0.0.1:5055", "http://127.0.0.1:5055", False),
    ("192.168.0.169:5055", "http://192.168.0.169:5055", False),
    ("http://192.168.0.169:5055", "http://192.168.0.169:5055", False),
    ("http://192.168.0.169:5055/", "http://192.168.0.169:5055", False),
    ("abc.onion", "http://abc.onion:80", True),
    ("abc", "http://abc", False),
])
def test_resolve_relay(text, expected_url, expected_tor):
    assert resolve_relay(text) == (expected_url, expected_tor)


@pytest.mark.parametrize("text,expected", [
    ("abc", "http://abc.onion:80"),
    ("abc.onion", "http://abc.onion:80"),
    ("http://abc.onion", "http://abc.onion:80"),
    ("https://abc.onion/", "http://abc.onion:80"),
    # The port must be split off before the suffix is stripped, or the address
    # ends up with two ".onion" segments.
    ("abc.onion:80", "http://abc.onion:80"),
    ("abc.onion:8080", "http://abc.onion:8080"),
    ("http://abc.onion:9050/", "http://abc.onion:9050"),
])
def test_normalise_onion(text, expected):
    assert normalise_onion(text) == expected


def test_onion_suffix_is_never_doubled():
    for text in ("abc.onion", "abc.onion:80", "http://abc.onion:9050"):
        assert normalise_onion(text).count(".onion") == 1
