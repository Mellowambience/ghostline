"""shadowaudit checklist engine.

Generates a security checklist for a web target by probing ONLY safe,
non-destructive signals: HTTP security headers, TLS configuration, and
redirect/transport behavior. It does NOT perform intrusive testing
(injection, fuzzing, auth bypass). Each check yields a pass/warn/fail state,
a human note, and a remediation hint.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None

# Header -> (why it matters, remediation)
SECURITY_HEADERS = {
    "strict-transport-security": (
        "Forces HTTPS, mitigates downgrade/SSL-strip.",
        "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.",
    ),
    "content-security-policy": (
        "Reduces XSS and data-injection risk.",
        "Define a CSP allowing only trusted sources; avoid 'unsafe-inline'.",
    ),
    "x-content-type-options": (
        "Stops MIME sniffing.",
        "Set `X-Content-Type-Options: nosniff`.",
    ),
    "x-frame-options": (
        "Clickjacking protection.",
        "Set `X-Frame-Options: DENY` (or use CSP frame-ancestors).",
    ),
    "referrer-policy": (
        "Limits referrer leakage.",
        "Set `Referrer-Policy: no-referrer` or `strict-origin-when-cross-origin`.",
    ),
    "permissions-policy": (
        "Restricts powerful browser features.",
        "Set a Permissions-Policy scoping camera/mic/location etc.",
    ),
}

CSP_DIRECTIVES_RECOMMENDED = ["default-src", "script-src", "object-src"]


@dataclass
class Check:
    id: str
    title: str
    state: str  # pass | warn | fail
    note: str
    remediation: str = ""


@dataclass
class AuditReport:
    target: str
    transport: str = ""
    checks: list[Check] = field(default_factory=list)
    score: int = 0
    max_score: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def _probe(target: str, timeout: int, user_agent: str) -> tuple[dict, str, str]:
    """Return (headers, final_url, transport). Safe GET only."""
    if httpx is None:  # pragma: no cover
        raise RuntimeError("httpx is required for shadowaudit")
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True,
                         headers={"User-Agent": user_agent})
    except Exception as exc:  # noqa: BLE001
        try:
            resp = httpx.get(url.replace("https://", "http://"), timeout=timeout,
                             follow_redirects=True, headers={"User-Agent": user_agent})
        except Exception as exc2:  # noqa: BLE001
            return {}, url, f"<error: {exc} / {exc2}>"
    headers = {k.lower(): v for k, v in resp.headers.items()}
    return headers, str(resp.url), urlparse(str(resp.url)).scheme


def run_audit(target: str, timeout: int = 10, user_agent: str = "ghostline") -> AuditReport:
    headers, final_url, transport = _probe(target, timeout, user_agent)
    report = AuditReport(target=target, transport=transport)
    checks: list[Check] = []

    # Transport / TLS
    if transport == "https":
        checks.append(Check("transport.tls", "Served over HTTPS",
                            "pass", f"Final URL scheme: {transport} ({final_url})"))
    else:
        checks.append(Check("transport.tls", "Served over HTTPS",
                            "fail", f"Not HTTPS (scheme: {transport}).",
                            "Obtain a TLS cert (e.g. Let's Encrypt) and redirect HTTP->HTTPS."))

    # Redirect hygiene
    if transport == "http":
        checks.append(Check("transport.redirect", "HTTP->HTTPS redirect",
                            "fail", "Site answers on plain HTTP.",
                            "Redirect all HTTP traffic to HTTPS (301)."))
    elif "https://" in target or transport == "https":
        checks.append(Check("transport.redirect", "HTTP->HTTPS redirect",
                            "pass", "Target reached over HTTPS."))

    # Security headers
    for hname, (why, remediation) in SECURITY_HEADERS.items():
        if hname in headers:
            extra = ""
            if hname == "content-security-policy":
                csp = headers[hname].lower()
                missing = [d for d in CSP_DIRECTIVES_RECOMMENDED if d not in csp]
                if missing:
                    extra = f" (CSP present but missing recommended directives: {', '.join(missing)})"
                    checks.append(Check(f"header.{hname}", f"Header: {hname}",
                                        "warn", why + extra, remediation))
                    continue
            checks.append(Check(f"header.{hname}", f"Header: {hname}", "pass", why))
        else:
            checks.append(Check(f"header.{hname}", f"Header: {hname}", "fail",
                                f"Missing `{hname}`. {why}", remediation))

    report.checks = checks
    report.max_score = len(checks) * 2
    report.score = sum(2 if c.state == "pass" else 1 if c.state == "warn" else 0 for c in checks)
    return report
