# phantomtrace

> **Public-data OSINT recon toolkit.** Part of the [Ghostline](https://github.com/Mellowambience/ghostline) cybersecurity suite.

*Invisible. Inevitable.*

---

## ⚠ Authorized use only

`phantomtrace` queries **only data that is already public** — DNS records, TLS
certificate metadata, HTTP response headers, and WHOIS registration data. It
performs **no** enumeration of private assets, no brute-forcing, no scraping of
authenticated content.

**You must only investigate targets you are authorized to assess.** Misuse
against systems you do not own or have permission to test may violate computer
misuse, privacy, and other laws. The operators bear sole responsibility.

---

## What it does

`phantomtrace recon` runs a single, read-only recon pass over public signals and
reports:

- **DNS** — A / AAAA / MX / TXT / NS records
- **TLS certificate** — subject, issuer, validity window, SAN
- **HTTP headers** — as returned by the server (redirects followed)
- **WHOIS** — registrar, creation/expiry, name servers (where published)

---

## Install

```bash
git clone https://github.com/Mellowambience/ghostline.git
cd ghostline/phantomtrace
pip install -e .
```

---

## Quick start

```bash
# Copy and fill in config (optional — sane defaults are used)
cp phantomtrace/config.example.yaml ~/.ghostline/phantomtrace/config.yaml

# Run a public-data recon pass
phantomtrace recon example.com
phantomtrace recon https://example.com --json
```

The `--json` flag emits the full structured result for piping into other tools.

---

## CLI reference

```bash
phantomtrace recon <target> [--json]   # target = domain or URL
```

---

## Architecture

```
phantomtrace/
├── cli.py          # Click CLI entrypoint
├── config.py       # YAML config loader + ${ENV} expansion
├── recon.py        # DNS / TLS / HTTP / WHOIS primitives (public data only)
└── tests/          # Offline pytest suite (no network)
```

All network access lives in `recon.py` behind small functions (`dns_lookup`,
`tls_info`, `http_headers`, `whois_lookup`) so behavior is easy to audit and to
mock in tests.

---

## Notes

- `python-whois`, `dnspython`, and `httpx` are required at runtime.
- Rate limiting is configurable via `rate_limit_seconds` to be a good citizen
  when querying public infrastructure.

---

*Ghostline — Invisible. Inevitable.*
