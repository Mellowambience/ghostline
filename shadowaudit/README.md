# shadowaudit

> **Non-destructive web-app security checklist generator.** Part of the
> [Ghostline](https://github.com/Mellowambience/ghostline) cybersecurity suite.

*Invisible. Inevitable.*

---

## ⚠ Authorized use only

`shadowaudit` performs **non-destructive** checks only: it reads publicly
visible HTTP security headers, TLS/transport behavior, and redirect hygiene. It
does **not** perform injection testing, fuzzing, auth bypass, or any action that
writes to or mutates the target.

**Only audit targets you are authorized to assess.** Unauthorized scanning or
testing of systems you do not own may violate computer-misuse and other laws.

---

## What it does

`shadowaudit audit <target>` probes a URL and scores it against a checklist of
safe, observable security signals:

- Served over **HTTPS**
- **HTTP → HTTPS** redirect
- Presence of key **security headers**:
  - `Strict-Transport-Security`
  - `Content-Security-Policy` (also checks for recommended directives)
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`

Each check returns **pass / warn / fail** with a remediation hint. The run ends
with a hardening score (`score / max_score`).

---

## Install

```bash
git clone https://github.com/Mellowambience/ghostline.git
cd ghostline/shadowaudit
pip install -e .
```

---

## Quick start

```bash
shadowaudit audit example.com
shadowaudit audit https://example.com --json
```

---

## CLI reference

```bash
shadowaudit audit <target> [--json] [--timeout 10]
```

---

## Architecture

```
shadowaudit/
├── cli.py       # Click CLI entrypoint
├── config.py    # YAML config loader + ${ENV} expansion
├── checks.py    # Header/transport checklist engine (safe GET only)
└── tests/       # Offline pytest suite (monkeypatched probe)
```

The probe (`checks._probe`) is the single network touchpoint and is fully
mocked in tests, so the suite runs with zero network access.

---

## Limitations

This is a **first-pass hygiene checklist**, not a full penetration test. It
cannot detect business-logic flaws, injection vulnerabilities, or
authentication weaknesses — those require dedicated, authorized testing
tooling. Use `shadowaudit` as a fast pre-flight before deeper work.

---

*Ghostline — Invisible. Inevitable.*
