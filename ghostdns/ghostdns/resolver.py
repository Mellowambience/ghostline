"""ghostdns resolver — multi-resolver DNS querying via dnspython.

Compares the answers returned by different DNS resolvers for the *same*
query, flagging inconsistencies that may indicate cache poisoning,
split-horizon DNS, a hijacked resolver, or a misconfigured one.

Design note for testing
------------------------
:func:`query_one` constructs ``dns.resolver.Resolver`` directly and sets
``.nameservers``. That means the offline test-suite can monkeypatch
``dns.resolver.Resolver`` with a fake that returns canned answers keyed by
the nameserver IP, exercising the comparison/inconsistency logic with zero
network access.
"""

import os
import re
import subprocess
from collections import Counter

import dns.resolver

# Built-in public resolvers (name -> IP).
PUBLIC_RESOLVERS = {
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8",
    "quad9": "9.9.9.9",
    "opendns": "208.67.222.222",
}

# Sentinel entry representing the OS / system default resolver.
SYSTEM_RESOLVER = "system"

# Record types exposed through the CLI.
SUPPORTED_RECORDS = ("A", "AAAA", "TXT", "MX", "CNAME", "NS")


def detect_system_nameserver():
    """Best-effort detection of the OS default resolver IP.

    * Linux / WSL / macOS: first ``nameserver`` line in ``/etc/resolv.conf``.
    * Windows: ``DNS Servers`` line from ``ipconfig /all``.
    * macOS: ``scutil --dns`` (best effort).

    Returns the IP string, or ``SYSTEM_RESOLVER`` (``"system"``) if unknown.
    """
    # Linux / WSL / macOS resolv.conf
    resolv = "/etc/resolv.conf"
    if os.path.exists(resolv):
        try:
            with open(resolv, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
        except OSError:
            pass

    # Windows
    if os.name == "nt" or os.environ.get("OS", "").lower().startswith("windows"):
        try:
            out = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
            m = re.search(r"DNS Servers[^\n]*:\s*([\d.]+)", out)
            if m:
                return m.group(1)
        except (OSError, subprocess.SubprocessError):
            pass

    return SYSTEM_RESOLVER


def normalize_resolvers(spec):
    """Turn a resolver spec into an ordered ``{name: ip}`` mapping.

    Accepts:

    * a ``dict`` (name -> ip) — returned unchanged
    * a ``list``/``tuple`` of IPs or names
    * a comma-separated string of IPs/names; ``"system"`` maps to the OS resolver
    """
    if isinstance(spec, dict):
        return dict(spec)
    if isinstance(spec, (list, tuple)):
        tokens = list(spec)
    else:
        tokens = str(spec).split(",")

    resolvers = {}
    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue
        if tok == SYSTEM_RESOLVER:
            resolvers[SYSTEM_RESOLVER] = detect_system_nameserver()
            continue
        if tok in PUBLIC_RESOLVERS:
            resolvers[tok] = PUBLIC_RESOLVERS[tok]
        else:
            resolvers[tok] = tok  # treat as a raw IP / hostname
    return resolvers


def query_one(resolver_ip, domain, record="A", timeout=5.0):
    """Query a single resolver IP for ``domain``/``record``.

    Returns a sorted list of answer strings. Raises on resolution failure
    (NXDOMAIN, timeout, etc.). Uses dnspython directly so tests can
    monkeypatch ``dns.resolver.Resolver``.
    """
    r = dns.resolver.Resolver()
    r.nameservers = [resolver_ip]
    r.timeout = timeout
    r.lifetime = timeout
    answer = r.resolve(domain, record)
    return sorted(str(rr) for rr in answer)


def compare_resolvers(domain, record="A", resolvers=None, timeout=5.0):
    """Query every resolver for the same ``(domain, record)`` tuple.

    Parameters
    ----------
    domain : str
    record : str
        One of ``A``, ``AAAA``, ``TXT``, ``MX``, ``CNAME``, ``NS``.
    resolvers : dict | list | str | None
        ``None`` uses the built-in :data:`PUBLIC_RESOLVERS` set.

    Returns
    -------
    dict
        ``name -> {"ip": str, "answers": [str], "error": str | None}``
    """
    if resolvers is None:
        resolvers = PUBLIC_RESOLVERS
    resolvers = normalize_resolvers(resolvers)

    results = {}
    for name, ip in resolvers.items():
        entry = {"ip": ip, "answers": [], "error": None}
        try:
            entry["answers"] = query_one(ip, domain, record, timeout)
        except Exception as exc:  # noqa: BLE001 - surface any resolution error
            entry["error"] = str(exc)
        results[name] = entry
    return results


def analyze_inconsistency(results):
    """Flag resolvers whose answer set differs from the majority.

    Returns
    -------
    dict
        ``{
            "inconsistent": bool,
            "majority": [str],            # most common answer set
            "outliers":   {name: [str]},  # resolvers disagreeing with majority
            "distinct_sets": int,
        }``
    """
    clean = {n: d["answers"] for n, d in results.items() if not d.get("error")}
    if len(clean) < 2:
        return {
            "inconsistent": False,
            "majority": next(iter(clean.values()), []),
            "outliers": {},
            "distinct_sets": len(clean),
        }

    counter = Counter(tuple(v) for v in clean.values())
    majority_set, _ = counter.most_common(1)[0]
    outliers = {n: a for n, a in clean.items() if tuple(a) != majority_set}
    return {
        "inconsistent": len(outliers) > 0,
        "majority": list(majority_set),
        "outliers": outliers,
        "distinct_sets": len(counter),
    }
