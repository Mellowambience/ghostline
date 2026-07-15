# bookmark-audit

> **Browser bookmark dual-use auditor.** Part of the [Ghostline](https://github.com/Mellowambience/ghostline) cybersecurity suite.

*Invisible. Inevitable.*

---

## What it does

A browser bookmarks HTML export (Firefox / Netscape format) is a plain-text
inventory of everywhere you've pointed your browser. This tool parses it and
**shows you the dual-use security surface** in your own collection — disposable
identity services, default-credential lookups, hash crackers, wifi audit tools,
and recovery utilities.

- Parses every link + its folder path from **two formats**:
  - Netscape/Firefox HTML exports (`bookmarks.html`)
  - Chromium JSON bookmarks (Chrome / Edge / Opera GX / Brave — `Bookmarks` file)
  - Format is auto-detected — just point it at either file
- Classifies each link into a dual-use category (or benign)
- Emits a categorized inventory: **markdown / csv / json**
- Optionally writes a **CLEAN** export (favicon base64 stripped → tiny file)
- Optionally writes a **RISK-SPLIT** export (dual-use links routed to a separate
  `DUAL-USE (authorized audit only)` folder)

**Possession is legal. The line is *whose* network/account you point the tool at.**
This tool only helps you *see* your own collection so you can decide what to keep.

---

## Install

No dependencies — standard library only (Python 3.11+).

```bash
git clone https://github.com/Mellowambience/ghostline.git
cd ghostline/bookmark-audit
# that's it — no pip install required
```

---

## Quick start

```bash
# Human-readable report to stdout (auto-detects HTML or Chromium-JSON)
python audit.py bookmarks.html
python audit.py "C:/Users/you/AppData/Roaming/Opera Software/Opera GX Stable/Default/Bookmarks"

# Machine-readable (pipeline composable — Ghostline standard)
python audit.py bookmarks.html --json

# Full deliverables
python audit.py bookmarks.html \
  --md report.md \
  --csv report.csv \
  --clean clean.html \
  --risk risk.html
```

### Flags

| Flag | Purpose |
|------|---------|
| `--json` | Print JSON to stdout (summary + every link w/ category + dual_use bool) |
| `--md OUT.md` | Write markdown report |
| `--csv OUT.csv` | Write CSV of all links (folder, title, url, dates, category, dual_use) |
| `--clean OUT.html` | Write icon-stripped clean export (much smaller) |
| `--risk OUT.html` | Write risk-split export (dual-use in its own folder) |

---

## Categories

| Category | Examples caught |
|----------|-----------------|
| Disposable Identity (burner email/SMS) | freesmsreceive, receive-sms, temp-mail, emailnator |
| Default Credentials / Router | routerpasswords, defaultpassword.us, cirt.net |
| Hash Cracking / Decryption | crackstation, md5decrypt, dcode.fr, weakpass |
| WiFi Audit / Cracking | pyrit, cowpatty, airbase-ng, fern-wifi, oswa |
| Password Recovery Tools | nirsoft |
| Hacking Resources / Blog | anonhacktivism, exploit/payload blogs |
| Vendor / Help (browser default) | support.mozilla.org |

Add or tune patterns in the `CATEGORIES` dict in `audit.py`.

---

### Examples

| File | What it is |
|------|-----------|
| `examples/sample_bookmarks.html` | Small reconstructed Netscape export (dual-use links) — `python audit.py examples/sample_bookmarks.html --json` |
| `examples/live_opera_audit.md` | Real audit output of a live Opera GX `Bookmarks` JSON — 12 benign links, 0 dual-use |

---

## Legal / ethical note

This tool reads a file **you already have**. It makes no network requests, sends
no telemetry, and never touches anything but the local file you point it at.
Dual-use bookmarks are flagged for *your* review — using audit tools against
networks or accounts you don't own permission for is outside this tool's scope
and outside the law.

---

*Ghostline — Invisible. Inevitable.*
