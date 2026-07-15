"""Offline tests for vaultcheck — no network access, no real passwords echoed.

Run with:  python -m pytest tests/ -q
"""

import hashlib

from vaultcheck import analyzer
from vaultcheck import breach as breach_mod


# --------------------------------------------------------------------------
# Analyzer: entropy + heuristics (pure, offline)
# --------------------------------------------------------------------------

def test_empty_password_entropy_zero():
    assert analyzer.shannon_entropy("") == 0.0


def test_uniform_string_entropy_exact():
    # "aaaa" -> 0 bits (single symbol, no surprise).
    assert analyzer.shannon_entropy("aaaa") == 0.0


def test_binary_string_entropy():
    # 4 symbols, one of each -> 2 bits per symbol * 4 = 8 bits.
    assert analyzer.shannon_entropy("abcd") == 8.0


def test_known_password_entropy():
    # "password": 8 chars, s appears twice -> 22.0 bits (verified by hand).
    e = analyzer.shannon_entropy("password")
    assert abs(e - 22.0) < 0.01


def test_len8_lowercase_entropy():
    # 8 distinct chars, each prob 1/8 -> 8 * log2(8) = 24.0 bits.
    e = analyzer.shannon_entropy("abcdefgh")
    assert abs(e - 24.0) < 0.01


def test_short_password_flags():
    r = analyzer.analyze("ab")
    assert r["score"] == 0
    assert any("Too short" in w for w in r["warnings"])


def test_common_password_flagged():
    r = analyzer.analyze("password123")
    assert r["score"] == 0
    assert any("common" in w.lower() for w in r["warnings"])


def test_repeat_run_flagged():
    r = analyzer.analyze("aaaaaaaA1!")
    assert any("repeated" in w.lower() for w in r["warnings"])


def test_sequence_flagged():
    r = analyzer.analyze("Abcd12345!")
    assert any("sequential" in w.lower() for w in r["warnings"])


def test_variety_warning():
    r = analyzer.analyze("aaaaaaaa")
    assert any("variety" in w.lower() for w in r["warnings"])


def test_strong_password_clean():
    r = analyzer.analyze("T7#mK9$pQ2!wLxR4")
    assert r["warnings"] == []
    assert r["score"] >= 3


def test_crack_time_drops_with_entropy():
    fast = analyzer.estimate_crack_time(20.0)
    slow = analyzer.estimate_crack_time(60.0)
    assert slow > fast
    assert slow > 1e8  # ~18 years at 1e9 gps — far longer than the 20-bit case


def test_human_duration_formatting():
    assert analyzer.human_duration(0) == "instantly"
    assert "seconds" in analyzer.human_duration(42)
    assert "year" in analyzer.human_duration(1e12)
    assert analyzer.human_duration(float("inf")) == "effectively forever"


# --------------------------------------------------------------------------
# Breach: hash formatting + matching logic (HTTP mocked, offline)
# --------------------------------------------------------------------------

def test_hash_prefix_format():
    prefix, suffix = breach_mod.hash_prefix("password")
    digest = hashlib.sha1(b"password").hexdigest().upper()
    assert len(digest) == 40
    assert len(prefix) == 5
    assert len(suffix) == 35
    assert prefix == digest[:5]
    assert suffix == digest[5:]


def test_hash_prefix_case_insensitive_match():
    # The suffix we look for must match a HIBP-style uppercase body line.
    prefix, suffix = breach_mod.hash_prefix("Password123")
    # HIBP returns uppercase; our matcher uppercases internally.
    body = f"{suffix.upper()}:12345\n{('F' * 35)}:1\n"
    with _patch_fetch(body):
        found, count = breach_mod.check_breach("Password123")
    assert found is True
    assert count == 12345


def test_check_breach_found():
    prefix, suffix = breach_mod.hash_prefix("hunter2")
    # Build a body that INCLUDES our suffix.
    body = (
        f"{suffix.upper()}:4242\n"           # the target
        f"{'A' * 35}:100\n"
        f"{'B' * 35}:7\n"
    )
    with _patch_fetch(body):
        found, count = breach_mod.check_breach("hunter2")
    assert found is True
    assert count == 4242


def test_check_breach_not_found():
    prefix, suffix = breach_mod.hash_prefix("hunter2")
    # Body that does NOT contain our suffix at all.
    body = (
        f"{'C' * 35}:12\n"
        f"{'D' * 35}:3\n"
    )
    with _patch_fetch(body):
        found, count = breach_mod.check_breach("hunter2")
    assert found is False
    assert count == 0


def test_check_breach_network_error_safe():
    def _boom(prefix):
        raise RuntimeError("simulated network failure")
    breach_mod._fetch_range = _boom
    # Must not raise; returns (False, 0) and the password is never sent.
    found, count = breach_mod.check_breach("anything")
    assert found is False
    assert count == 0


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

class _patch_fetch:
    """Context manager that monkeypatches breach._fetch_range to return a
    crafted body without touching the network."""

    def __init__(self, body):
        self.body = body
        self._orig = None

    def __enter__(self):
        self._orig = breach_mod._fetch_range
        breach_mod._fetch_range = lambda prefix: self.body
        return self

    def __exit__(self, *exc):
        breach_mod._fetch_range = self._orig
        return False
