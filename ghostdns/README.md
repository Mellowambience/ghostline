# ghostdns

> **DNS resolver comparison + leak test.** Part of the [Ghostline](https://github.com/Mellowambience/ghostline) cybersecurity suite.

*Invisible. Inevitable.*

---

## Why this exists

DNS is the quietest surveillance channel most people never think about. Every website, app, and API you open starts with a DNS lookup — and the resolver that answers that lookup sees *where you're going*, even when the traffic itself is encrypted. If your queries don't reach the resolver you think they do (your VPN's, your chosen privacy resolver), that's a **DNS leak**: your ISP, a captive portal, or a malicious network can log a near-complete map of your activity.

`ghostdns` gives you two things:

1. **Resolver comparison** — ask Cloudflare, Google, Quad9, OpenDNS *and* your system resolver the same question and see if they disagree. Disagreement can reveal cache poisoning, a hijacked resolver, split-horizon DNS, or a simple misconfiguration.
2. **Client-side leak detection** — generate a random, never-cached subdomain, ask your default resolver for it, and compare against public resolvers to spot a resolver that is doing something it shouldn't.

---

## What it does

- Queries multiple resolvers for the same `(domain, record)` pair via [dnspython](https://dnspython.readthedocs.io/) and collects answers
- Flags **inconsistencies** (different answer sets across resolvers = possible poisoning / cache / split-horizon issue)
- Runs a **client-side DNS leak check** against the OS default resolver
- Detects the system resolver from `/etc/resolv.conf` (Linux/WSL/macOS) or `ipconfig /all` (Windows)
- Supports `--json` output for scripting
- Zero network required for the test suite

### Authorized / educational use only

`ghostdns` is a defensive, read-only reconnaissance tool. Use it **only** on networks and domains you are authorized to test. It performs standard DNS lookups; it does not spoof, forge, or intercept traffic. Be aware of the privacy implications below before pointing it at anything that isn't yours.

---

## Install

```bash
# Clone Ghostline and install ghostdns
git clone https://github.com/Mellowambience/ghostline.git
cd ghostline/ghostdns
pip install -e .
```

---

## Quick start

```bash
# Compare resolvers for a domain (defaults: all built-in public resolvers)
ghostdns compare example.com
ghostdns compare example.com --record AAAA
ghostdns compare example.com --resolvers 1.1.1.1,8.8.8.8

# Client-side DNS leak check
ghostdns leak
ghostdns leak --domain example.com

# Helpers
ghostdns default-resolver     # show detected OS resolver
ghostdns gen-subdomain        # print a fresh unique test subdomain
ghostdns list-resolvers       # show built-in public resolver set

# Machine-readable output
ghostdns compare example.com --json
ghostdns leak --json
```

---

## CLI reference

```bash
ghostdns compare <domain> [--record A|AAAA|TXT|MX|CNAME|NS] [--resolvers ip,ip] [--timeout 5.0] [--json]
ghostdns leak [--domain example.com] [--timeout 5.0] [--json]
ghostdns default-resolver
ghostdns gen-subdomain [--domain example.com]
ghostdns list-resolvers
```

---

## What is a DNS leak? (and what this tool can/can't prove)

A **DNS leak** is when your DNS queries reach a resolver other than the one you intended — typically because the operating system, a misconfigured VPN, or a captive portal routes queries around your tunnel. Anything observing those queries can profile your browsing.

**The definitive test needs an authoritative server you control:** you issue a query for a unique subdomain of a domain you own, then watch your authoritative logs to see *which* resolver actually shows up. If it isn't the resolver you expected, you leaked.

**This tool implements the client-side heuristic only.** It generates a random, unique, never-cached subdomain and compares what your default resolver returns against what public resolvers return:

- If your default resolver serves a live answer for a name that should not exist, that's a strong hint of DNS hijacking / sinkholing / injected NXDOMAIN.
- If your default resolver disagrees with public resolvers for the same unique subdomain, that hints at a leak to an unexpected resolver.

> **Server-side authoritative confirmation is a documented future extension** (see Roadmap). The client-side result is a *suspicion*, not proof.

### Privacy implications

Running `ghostdns` itself generates DNS queries from your machine to whatever resolvers you configure — including your real, default resolver. Those queries are observable by your network operator, exactly as normal browsing is. The tool never exfiltrates your results; any sharing is up to you. Point it only at infrastructure you're authorized to probe, and understand that the act of testing is itself visible on the wire.

---

## Architecture

```
ghostdns/
├── cli.py               # Click CLI entrypoint (compare / leak / helpers)
├── resolver.py          # Public resolver list, query logic, inconsistency flag
├── leak.py              # Client-side leak detection + educational notes
├── config.py            # YAML config loader + ${ENV} expansion
├── config.example.yaml  # Example config
└── tests/
    └── test_offline.py  # Network-free tests (monkeypatched dns.resolver)
```

---

## Roadmap

- **Now**: multi-resolver comparison, inconsistency flagging, client-side leak heuristic, system-resolver detection (Linux / Windows), `--json`
- **Next**: DNSSEC validation check, DNS-over-HTTPS (DoH) resolver support
- **Future**: server-side authoritative leak confirmation (unique-subdomain callback to a resolver you control), historical comparison/diff, configurable alerting

---

## Contributing

PRs welcome. See [Ghostline CONTRIBUTING.md](../CONTRIBUTING.md).

---

*Ghostline — Invisible. Inevitable.*
