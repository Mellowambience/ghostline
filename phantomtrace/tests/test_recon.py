"""Offline tests for phantomtrace — no network required."""

from phantomtrace.recon import _hostname, ReconResult


def test_hostname_strips_scheme():
    assert _hostname("https://example.com/path") == "example.com"
    assert _hostname("http://example.org") == "example.org"
    assert _hostname("example.net") == "example.net"


def test_recon_result_defaults():
    r = ReconResult(target="example.com")
    assert r.target == "example.com"
    assert r.domain is None  # domain is populated by recon(), not the bare dataclass
    assert r.dns == {}
    assert r.notes == []


def test_recon_result_serializes():
    r = ReconResult(target="example.com", domain="example.com", dns={"A": ["1.2.3.4"]})
    d = r.__dict__
    assert d["domain"] == "example.com"
    assert d["dns"]["A"] == ["1.2.3.4"]
