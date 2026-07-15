"""phantomtrace recon primitives — PUBLIC DATA ONLY.

Every function here touches only data that is legitimately public:
DNS records, TLS certificate metadata, and HTTP response headers. It does
NOT perform enumeration of private assets, brute-force, or scraping of
authenticated content. Operators are responsible for having authorization
to investigate the target.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlparse

import whois  # python-whois

try:  # httpx is preferred; requests is a fallback
    import httpx
except ImportError:  # pragma: no cover
    httpx = None


@dataclass
class ReconResult:
    target: str
    domain: str | None = None
    dns: dict[str, list[str]] = field(default_factory=dict)
    http_headers: dict[str, str] = field(default_factory=dict)
    tls: dict[str, object] = field(default_factory=dict)
    whois: dict[str, object] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _hostname(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return urlparse(target).hostname or target
    return target


def dns_lookup(host: str, record_types: tuple[str, ...] = ("A", "AAAA", "MX", "TXT", "NS")) -> dict:
    import dns.resolver  # dnspython

    out: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    for rtype in record_types:
        try:
            answers = resolver.resolve(host, rtype, lifetime=5)
            out[rtype] = [r.to_text().rstrip(".") for r in answers]
        except Exception as exc:  # noqa: BLE001 - report and continue
            out[rtype] = [f"<error: {exc}>"]
    return out


def http_headers(target: str, timeout: int = 10, user_agent: str = "ghostline") -> dict:
    if httpx is None:  # pragma: no cover
        raise RuntimeError("httpx is required for HTTP header recon")
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True, headers={"User-Agent": user_agent})
        return {k: v for k, v in resp.headers.items()}
    except Exception as exc:  # noqa: BLE001
        # Try plaintext fallback
        try:
            resp = httpx.get(url.replace("https://", "http://"), timeout=timeout,
                             follow_redirects=True, headers={"User-Agent": user_agent})
            return {k: v for k, v in resp.headers.items()}
        except Exception as exc2:  # noqa: BLE001
            return {"<error>": f"{exc} / {exc2}"}


def tls_info(target: str, port: int = 443, timeout: int = 10) -> dict:
    host = _hostname(target)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        return {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": cert.get("subjectAltName"),
            "version": cert.get("version"),
        }
    except Exception as exc:  # noqa: BLE001
        return {"<error>": str(exc)}


def whois_lookup(target: str) -> dict:
    host = _hostname(target)
    try:
        w = whois.whois(host)
        data = {}
        for k, v in w.items():
            if isinstance(v, (list, tuple)):
                data[k] = [str(x) for x in v]
            else:
                data[k] = str(v)
        return data
    except Exception as exc:  # noqa: BLE001
        return {"<error>": str(exc)}


def recon(target: str, config: dict | None = None) -> ReconResult:
    config = config or {}
    host = _hostname(target)
    res = ReconResult(target=target, domain=host)
    res.dns = dns_lookup(host)
    res.http_headers = http_headers(target, timeout=config.get("timeout", 10),
                                    user_agent=config.get("user_agent", "ghostline"))
    res.tls = tls_info(target, timeout=config.get("timeout", 10))
    res.whois = whois_lookup(target)
    if not res.dns.get("A") and not res.dns.get("AAAA"):
        res.notes.append("No A/AAAA records resolved — target may not be publicly hosted.")
    return res
