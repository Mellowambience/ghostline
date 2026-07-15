# Ghostline

> **Modular cybersecurity suite.** CLI-first. Privacy-native. Dark by design.
> *Invisible. Inevitable.*

Ghostline is a collection of small, focused, open-source security tools. Each
module is installed independently and wrapped by a single `ghostline` dispatcher.

## Modules

| Dispatcher | Module | What it does | Status |
|------------|--------|--------------|--------|
| `ghostline scan` | `ghost-scan` | TCP connect port scanner + service fingerprinter | ✅ |
| `ghostline vault` | `vaultcheck` | Password strength + HIBP breach check | ✅ |
| `ghostline dns` | `ghostdns` | DNS resolver comparison + leak test | ✅ |
| `ghostline trace` | `phantomtrace` | Public-data OSINT recon (DNS/TLS/HTTP/WHOIS) | ✅ |
| `ghostline audit` | `shadowaudit` | Non-destructive web-app security checklist | ✅ |
| `ghostline account` | `accountwatch` | Recovery-contact backdoor detector | ✅ |
| `ghostline bookmarks` | `bookmark-audit` | Dual-use bookmark export auditor (Firefox HTML + Chromium JSON) | ✅ |

## Install

```bash
git clone https://github.com/Mellowambience/ghostline.git
cd ghostline

# Install the dispatcher (optional convenience wrapper)
pip install -e .

# Install whichever modules you want
pip install -e ./ghost-scan
pip install -e ./vaultcheck
pip install -e ./ghostdns
pip install -e ./phantomtrace
pip install -e ./shadowaudit
pip install -e ./accountwatch
pip install -e ./bookmark-audit
```

## Use

```bash
ghostline modules          # list modules + install status
ghostline scan 127.0.0.1 --top 1000
ghostline vault check
ghostline dns compare example.com
ghostline trace recon example.com
ghostline audit example.com
ghostline account check
ghostline bookmarks "C:/Users/you/AppData/Roaming/Opera Software/Opera GX Stable/Default/Bookmarks"


Each module also has its own console script (`ghost-scan`, `vaultcheck`, …) if
you prefer to call it directly.

## ⚠ Authorized use only

Every Ghostline tool is built for **defensive, authorized security work** —
your own systems, or targets you have explicit permission to test. Scanning,
recon, or auditing networks you do not own or are not authorized to test may
violate computer-misuse, privacy, and other laws. You are solely responsible
for how you use these tools.

## Color palette

Void Black `#0a0a0f` · Electric Mint `#00ffcc` · Ghost White `#f0f0f0` · Phantom Purple `#6e3fa3`

## License

MIT — do what you want, just don't be evil.

*Ghostline — Invisible. Inevitable.*
