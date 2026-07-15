"""Offline tests for ghostdns — no network access required."""

import re

import pytest

from ghostdns import leak, resolver


class _FakeAnswer:
    """Mimics a single dnspython RR (str(x) -> address)."""

    def __init__(self, value):
        self._value = value

    def __str__(self):
        return self._value


class _FakeResolver:
    """A monkeypatch stand-in for ``dns.resolver.Resolver``.

    Returns canned answers keyed by the nameserver IP set on the instance,
    so :func:`resolver.query_one` (which sets ``.nameservers``) gets
    deterministic, network-free results.
    """

    def __init__(self, canned):
        self.nameservers = []
        self.timeout = 5.0
        self.lifetime = 5.0
        self._canned = canned

    def resolve(self, domain, record):
        ns = self.nameservers[0]
        values = self._canned.get(ns, [])
        return [_FakeAnswer(v) for v in values]


def _patch(monkeypatch, canned):
    """Patch ``dns.resolver.Resolver`` to return ``canned`` answers."""

    def _factory():
        return _FakeResolver(canned)

    # query_one (used by both resolver and leak via compare_resolvers) builds
    # dns.resolver.Resolver from the resolver module's namespace.
    monkeypatch.setattr(resolver.dns.resolver, "Resolver", _factory)


def test_compare_resolvers_consistent(monkeypatch):
    canned = {
        "1.1.1.1": ["93.184.216.34"],
        "8.8.8.8": ["93.184.216.34"],
    }
    _patch(monkeypatch, canned)
    spec = list(canned.keys())
    results = resolver.compare_resolvers("example.com", "A", spec)
    assert results["1.1.1.1"]["answers"] == ["93.184.216.34"]
    assert results["8.8.8.8"]["answers"] == ["93.184.216.34"]
    inc = resolver.analyze_inconsistency(results)
    assert inc["inconsistent"] is False
    assert inc["majority"] == ["93.184.216.34"]


def test_compare_resolvers_inconsistent(monkeypatch):
    canned = {
        "1.1.1.1": ["93.184.216.34"],
        "8.8.8.8": ["6.6.6.6"],  # different answer => poisoning/cache issue
    }
    _patch(monkeypatch, canned)
    spec = list(canned.keys())
    results = resolver.compare_resolvers("example.com", "A", spec)
    inc = resolver.analyze_inconsistency(results)
    assert inc["inconsistent"] is True
    assert "8.8.8.8" in inc["outliers"]
    assert inc["majority"] == ["93.184.216.34"]


def test_detect_default_resolver_returns_string():
    out = leak.detect_default_resolver()
    assert isinstance(out, str)
    assert out.startswith("system")


def test_generate_unique_subdomain_format():
    sub = leak.generate_unique_subdomain("example.com")
    # form: <16 lowercase-alnum chars>.example.com
    assert sub.endswith(".example.com")
    label = sub[: -len(".example.com")]
    assert re.fullmatch(r"[a-z0-9]{16}", label)


def test_generate_unique_subdomain_is_random():
    a = leak.generate_unique_subdomain("example.com")
    b = leak.generate_unique_subdomain("example.com")
    assert a != b


def test_analyze_no_leak_offline(monkeypatch):
    # Unique subdomain should resolve to nothing on every resolver (NXDOMAIN).
    canned = {
        "1.1.1.1": [],
        "8.8.8.8": [],
        "9.9.9.9": [],
        "208.67.222.222": [],
        "127.0.0.1": [],
    }
    _patch(monkeypatch, canned)
    report = leak.analyze("example.com")
    assert report["leak_suspected"] is False
    assert "unique_subdomain" in report
    assert isinstance(report["comparison"], dict)


def test_normalize_resolvers_system_and_known():
    resolved = resolver.normalize_resolvers("cloudflare,system,1.0.0.1")
    assert resolved["cloudflare"] == "1.1.1.1"
    assert "system" in resolved
    assert resolved["1.0.0.1"] == "1.0.0.1"
