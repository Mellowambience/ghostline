# accountwatch

> **Recovery contact backdoor detector.** Part of the [Ghostline](https://github.com/Mellowambience/ghostline) cybersecurity suite.

*Invisible. Inevitable.*

---

## Why this exists

On March 2, 2026, an unauthorized third party silently added `nsh11@myyahoo.com` to a Meta Accounts Center as a recovery contact — without notifying the account owner, without requiring approval from existing verified contacts, and without any detection mechanism on Meta's end.

The attacker now had a permanent backdoor: password resets, 2FA intercepts, account lockout. Meta's platform did nothing. `accountwatch` does.

> *This is the exact attack it detects. It happened to the person who built it.*

---

## What it does

`accountwatch` monitors your platform accounts for unauthorized recovery contact additions — emails and phone numbers — and alerts you the moment anything changes, before the attacker can use it.

- Polls connected platform APIs on a configurable schedule
- Compares live contacts against a **locally-stored, HMAC-signed baseline** (never uploaded)
- Alerts via terminal, desktop notification, Discord/Slack/Telegram webhook, or SMTP
- Writes an **immutable append-only audit log** exportable as JSON, CSV, or legal-filing format

---

## Platform support

| Platform | Method | Status |
|----------|--------|--------|
| Meta (Facebook/Instagram) | Graph API + IMAP notification parse | ✅ Phase 1 |
| GitHub | REST API `/user/emails` | ✅ Phase 1 |
| Google Account | People API | 🔨 Phase 2 |
| Twitter/X | v2 account settings | 🔨 Phase 2 |
| Apple ID | iCloud notification email parse | 🔨 Phase 2 |
| Generic (any platform) | IMAP notification email parser | 🔨 Phase 2 |

---

## Install

```bash
# Clone Ghostline and install accountwatch
git clone https://github.com/Mellowambience/ghostline.git
cd ghostline/accountwatch
pip install -e .
```

---

## Quick start

```bash
# 1. Set your signing key (keep this secret)
export GHOSTLINE_HMAC_KEY=$(openssl rand -hex 32)

# 2. Copy and fill in your config
cp accountwatch/config.example.yaml ~/.ghostline/accountwatch/config.yaml
# edit config.yaml — add your API tokens

# 3. Capture trusted baseline
accountwatch init

# 4. Run a check
accountwatch check

# 5. Run as daemon (polls every 15 minutes)
accountwatch watch --interval=15m
```

---

## CLI reference

```bash
accountwatch init                          # Capture trusted baseline
accountwatch check                         # One-time check (all platforms)
accountwatch check --platform=meta         # Check one platform
accountwatch show --platform=all           # View current contacts (read-only)
accountwatch watch --interval=30m          # Daemon mode
accountwatch baseline update --platform=meta  # Update after legitimate change
accountwatch report export --format=json   # Export audit log
accountwatch report export --format=legal  # Legal-filing formatted export
```

---

## Architecture

```
accountwatch/
├── cli.py               # Click CLI entrypoint
├── config.py            # YAML config loader + env var expansion
├── baseline.py          # Snapshot capture, HMAC signing, diff engine
├── alerter.py           # Multi-channel alert dispatcher + audit log
├── scheduler.py         # APScheduler daemon mode
├── report.py            # Audit log reader + export engine
└── platforms/
    ├── meta.py          # Meta Graph API adapter
    ├── github.py        # GitHub REST API adapter
    └── ...              # Phase 2: google, twitter, apple, imap
```

---

## Audit log export formats

- `--format=json` — machine-readable, full event detail
- `--format=csv` — spreadsheet-compatible
- `--format=legal` — human-readable, timestamped, signed — **designed for legal filing attachment**

---

## Roadmap

- **Phase 1** (now): Meta + GitHub adapters, baseline engine, multi-channel alerting, audit log
- **Phase 2**: Google, Twitter, Apple ID, generic IMAP parser, daemon scheduler
- **Phase 3**: Legal export, GitHub Actions CI, full test suite
- **Phase 4**: Web dashboard ($9/mo), cross-platform correlation, opt-in threat intel feed

---

## Contributing

PRs welcome. See [Ghostline CONTRIBUTING.md](../CONTRIBUTING.md).

If you've experienced an unauthorized recovery contact addition on any platform, open an issue — your case may reveal a new attack vector worth building an adapter for.

---

*Ghostline — Invisible. Inevitable.*
