"""ghostdns leak — client-side DNS leak / resolver-hijack detection.

What is a DNS leak?
-------------------
A *DNS leak* happens when your DNS queries reach a resolver you did **not**
intend — e.g. your ISP's resolver instead of the VPN / tunnel you believed
you were using, or a resolver that injects or rewrites answers. Anything that
can see your DNS queries (your ISP, a captive portal, a malicious network)
can build a near-complete profile of the sites you visit, even if the
traffic itself is encrypted.

The gold-standard leak test needs an **authoritative DNS server you control**:
you issue a query for a unique subdomain of a domain you own, then watch your
authoritative logs to see *which* resolver actually shows up. If it isn't the
resolver you expected, you leaked.

This module implements the **client-side heuristic** only: it generates a
random, unique, never-cached subdomain and compares what your default (OS)
resolver returns against what public resolvers return. If the default resolver
serves answers nothing else does — for a name that should not exist — that is
a strong hint it is doing something unexpected (hijack / sinkhole / injected
NXDOMAIN). The authoritative server-side test is documented as a future
extension below.

IMPORTANT: use only on networks and domains you are authorized to test.
"""

import secrets

from ghostdns.resolver import (
    PUBLIC_RESOLVERS,
    SYSTEM_RESOLVER,
    analyze_inconsistency,
    compare_resolvers,
    detect_system_nameserver,
)

SUBDOMAIN_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"


def detect_default_resolver():
    """Return a human-readable string naming the OS default resolver.

    e.g. ``"system (8.8.8.8)"`` or ``"system (unknown)"``.
    """
    ns = detect_system_nameserver()
    if ns and ns != SYSTEM_RESOLVER:
        return f"{SYSTEM_RESOLVER} ({ns})"
    return f"{SYSTEM_RESOLVER} (unknown)"


def generate_unique_subdomain(tld="example.com"):
    """Generate a random, unique subdomain such as ``"a1b2c3.example.com"``.

    Uses crypto-strong randomness so the label is effectively unguessable and
    has never been cached by any resolver.
    """
    label = "".join(secrets.choice(SUBDOMAIN_CHARS) for _ in range(16))
    tld = tld.strip().lstrip(".")
    return f"{label}.{tld}"


def analyze(domain="example.com", timeout=5.0):
    """Client-side leak analysis for ``domain``.

    Returns a report dict with ``leak_suspected`` (bool), the per-resolver
    comparison, and human-readable ``notes``. See the module docstring for the
    server-side authoritative caveat.
    """
    sub = generate_unique_subdomain(domain)
    report = {
        "domain": domain,
        "unique_subdomain": sub,
        "default_resolver": detect_default_resolver(),
        "method": "client-side comparison (no authoritative server)",
        "leak_suspected": False,
        "notes": [],
        "comparison": None,
    }

    target = dict(PUBLIC_RESOLVERS)
    sys_ns = detect_system_nameserver()
    target[SYSTEM_RESOLVER] = sys_ns if sys_ns != SYSTEM_RESOLVER else "127.0.0.1"

    try:
        comparison = compare_resolvers(sub, "A", target, timeout)
    except Exception as exc:  # noqa: BLE001
        report["notes"].append(f"Query error: {exc}")
        return report

    report["comparison"] = comparison

    system_answers = comparison.get(SYSTEM_RESOLVER, {}).get("answers", [])

    # A unique subdomain that has never existed should resolve to nothing.
    # If the *default* resolver returns live answers, it is serving data that
    # public resolvers do not — a classic sign of DNS hijacking / sinkholing.
    if system_answers:
        report["leak_suspected"] = True
        report["notes"].append(
            "Default resolver returned answers for a subdomain that should not "
            "exist (possible DNS hijacking / sinkhole / injected NXDOMAIN)."
        )

    # Inconsistency between the default resolver and public resolvers.
    inc = analyze_inconsistency(comparison)
    if inc["inconsistent"] and SYSTEM_RESOLVER in inc["outliers"]:
        report["leak_suspected"] = True
        report["notes"].append(
            "Default resolver disagrees with public resolvers for the same unique "
            "subdomain — possible DNS leak to an unexpected resolver."
        )

    if not report["leak_suspected"]:
        report["notes"].append(
            "No client-side anomaly detected. Server-side authoritative testing is "
            "required for definitive leak confirmation (see README)."
        )
    return report
