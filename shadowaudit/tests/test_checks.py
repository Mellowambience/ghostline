"""Offline tests for shadowaudit — no network required."""

from shadowaudit import checks


class _FakeResp:
    def __init__(self, headers, url):
        self.headers = headers
        self.url = url


def test_score_uses_pass_warn_fail_weights(monkeypatch):
    # Force a deterministic probe result
    monkeypatch.setattr(checks, "_probe", lambda *a, **k: (
        {
            "strict-transport-security": "max-age=63072000",
            "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        },
        "https://secure.example.com",
        "https",
    ))
    report = checks.run_audit("secure.example.com")
    assert report.transport == "https"
    assert report.score == report.max_score  # all pass
    assert all(c.state == "pass" for c in report.checks)


def test_csp_missing_directive_is_warn(monkeypatch):
    monkeypatch.setattr(checks, "_probe", lambda *a, **k: (
        {"content-security-policy": "default-src 'self'"},  # missing script-src/object-src
        "https://weak.example.com",
        "https",
    ))
    report = checks.run_audit("weak.example.com")
    csp_check = [c for c in report.checks if c.id == "header.content-security-policy"][0]
    assert csp_check.state == "warn"


def test_missing_headers_fail(monkeypatch):
    monkeypatch.setattr(checks, "_probe", lambda *a, **k: ({}, "http://plain.example.com", "http"))
    report = checks.run_audit("plain.example.com")
    assert report.transport == "http"
    failed = [c for c in report.checks if c.state == "fail"]
    assert len(failed) >= 6  # 1 transport + 5+ missing headers
