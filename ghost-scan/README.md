# ghost-scan

> **TCP connect port scanner + service fingerprinter.** Part of the
> [Ghostline](https://github.com/Mellowambience/ghostline) cybersecurity suite.

*Invisible. Inevitable.*

---

## ⚠ Authorized use only

**Only scan hosts and networks you own or are explicitly authorized to test.**
Scanning networks without permission can violate computer-misuse and other
laws. By default, `ghost-scan` targets **localhost (127.0.0.1)** and will only
scan a remote host when you pass one explicitly.

---

## What it does

- **TCP connect scanning** — built on the standard-library `socket`, no raw
  sockets, **no root required**.
- **Service fingerprinting** — classifies ~8,000 well-known ports to service
  names (nmap-services derived).
- **Banner grabbing** — optionally reads the first bytes a service sends.
- **Fast, parallel** — bounded thread pool (default 200 workers).
- **JSON + file export** — pipe-friendly output for automation.

> Note: connect scanning (not SYN/half-open) is intentionally the only mode —
> it is safer, privilege-free, and far less likely to be mistaken for an attack.

---

## Install

```bash
git clone https://github.com/Mellowambience/ghostline.git
cd ghostline/ghost-scan
pip install -e .
```

---

## Quick start

```bash
# Safest: scan your own machine
ghost-scan

# Scan a specific host (only if you have authorization)
ghost-scan 192.168.1.1 --ports 1-1024 --json

# Top 1000 common ports, no banners
ghost-scan example.com --top 1000 --no-banner

# Save a report
ghost-scan 127.0.0.1 --ports 1-1000 --output report.txt
```

---

## CLI reference

```bash
ghost-scan [TARGET] [--ports SPEC] [--top N] [--timeout S] [--threads N]
           [--banner | --no-banner] [--json] [--output FILE]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `TARGET` | `127.0.0.1` | Host to scan (omit = localhost) |
| `--ports` | — | Port spec, e.g. `1-1024` or `22,80,443` |
| `--top N` | `1000` | Scan the N most common ports |
| `--timeout` | `0.5` | Per-port connect timeout (seconds) |
| `--threads` | `200` | Max concurrent probes |
| `--banner/--no-banner` | banner | Grab service banners |
| `--json` | off | Emit JSON |
| `--output` | stdout | Write report to a file |

---

## Architecture

```
ghost-scan/
├── cli.py          # Click CLI entrypoint
├── config.py       # YAML config loader + ${ENV} expansion
├── ghost_scan/
│   ├── scanner.py      # TCP connect scanner + port-spec parser
│   └── fingerprint.py  # Port→service map + banner grab
└── tests/          # Offline pytest suite (dummy socket server)
```

---

## Limitations

- Connect scanning is slower and noisier than SYN scanning, and is easier for
  an IDS to observe. That is a deliberate trade-off for safety.
- No UDP scanning (would require raw sockets / root).
- Service *version* detection beyond banners is out of scope here; pair with
  `phantomtrace` for richer recon.

---

*Ghostline — Invisible. Inevitable.*
