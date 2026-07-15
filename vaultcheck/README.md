# vaultcheck

> **Password strength analyzer + HIBP breach checker.** Part of the [Ghostline](https://github.com/Mellowambience/ghostline) cybersecurity suite.

*Invisible. Inevitable.*

---

## ⚠️ Read this first

- **Do not run `vaultcheck` with your real passwords on a shared, multi-user, or compromised machine.** Anyone with access to that machine (or its shell history, process list, or a keylogger) could capture what you type. Use it on a machine you control and trust.
- The breach check uses **k-anonymity**: only the **first 5 hex characters of the SHA-1 hash** of your password are ever sent to HaveIBeenPwned. **The password itself and the full hash never leave your machine.** That is by design — do not "improve" this by sending more.
- This is a **defensive / authorized-use** tool only. Run it against your own passwords.

---

## Why this exists

Most "password strength meters" are games of vibes — they reward `P@ssw0rd1!` because it hits character-class checkboxes while being trivially crackable. `vaultcheck` does two concrete things instead:

1. **Measures real entropy** (Shannon bits) and converts it to a pessimistic crack-time estimate.
2. **Checks your password against the HIBP breach corpus** so you know if it has already been leaked — without ever transmitting it.

---

## What it does

- Computes **Shannon entropy** (bits) of a password
- Estimates **crack time** from a simple keyspace model (`2^(entropy-1) / guesses-per-second`, default 1e9 gps)
- Runs **lightweight weakness heuristics** (no heavy ML deps):
  - length < 8
  - repeated characters (e.g. `aaa`)
  - sequential patterns (e.g. `1234`, `abcd`)
  - common-password / dictionary substring hits (~50 worst offenders)
  - lack of character-class variety
- Returns a **structured result** `{ length, entropy, crack_time_human, char_classes, score 0-4, warnings[] }`
- Performs a **HIBP k-anonymity breach lookup** — never sends the password

---

## Install

```bash
# Clone Ghostline and install vaultcheck
git clone https://github.com/Mellowambience/ghostline.git
cd ghostline/vaultcheck
pip install -e .
```

Config is optional — vaultcheck uses safe built-in defaults. To customize:

```bash
mkdir -p ~/.ghostline/vaultcheck
cp vaultcheck/config.example.yaml ~/.ghostline/vaultcheck/config.yaml
# edit as needed
```

---

## Quick start

```bash
# Full check (entropy + heuristics + breach), prompted password (never echoed)
vaultcheck check

# Batch-check a file, one password per line
vaultcheck check --file passwords.txt

# Breach-only check (no heuristics)
vaultcheck breach

# Machine-readable output
vaultcheck check --json
vaultcheck breach --file list.txt --json
```

---

## CLI reference

```bash
vaultcheck check              # entropy + weakness heuristics + HIBP breach lookup
vaultcheck check --file F     # read one password per line from F
vaultcheck check --json       # JSON output
vaultcheck breach             # HIBP k-anonymity lookup only
vaultcheck breach --file F    # read one password per line from F
vaultcheck breach --json      # JSON output
```

Both commands read a password from a **hidden prompt** (`hide_input=True`) unless
`--file` is given. **The password is never echoed to stdout, logs, or the terminal.**

---

## Architecture

```
vaultcheck/
├── cli.py               # Click CLI entrypoint (check / breach)
├── analyzer.py          # Shannon entropy, crack-time estimate, weakness heuristics
├── breach.py            # HIBP k-anonymity range lookup (sha1 -> prefix/suffix)
├── config.py            # Optional YAML config loader + ${ENV} expansion
├── config.example.yaml  # Example config (optional)
└── tests/
    └── test_analyzer.py # Offline tests (entropy, hash format, breach matching)
```

### How the breach check stays private

```
password ──SHA1──▶ ABCDEF1234... (40 hex, UPPER)
                       ├── prefix  = first 5  → "ABCDEF"  ──▶ sent to HIBP
                       └── suffix  = last 35  → matched LOCALLY against response
```

HIBP returns every suffix that shares your prefix. We match locally. The
password and the full hash never leave your machine.

---

## Scoring

| Score | Meaning |
|-------|---------|
| 0 | Very weak (common password, too short, or low entropy) |
| 1 | Weak |
| 2 | Fair |
| 3 | Strong |
| 4 | Very strong (high entropy + varied) |

Score starts from an entropy bucket and is penalized for each detected weakness.

---

## Roadmap

- **Phase 1** (now): entropy scoring, crack-time estimate, weakness heuristics, HIBP k-anonymity lookup, JSON/batch modes
- **Phase 2**: leetspeak normalization, keyboard-walk detection, zxcvbn-style guess estimation
- **Phase 3**: GitHub Actions CI, config-driven thresholds, optional local breach corpus

---

## Contributing

PRs welcome. See [Ghostline CONTRIBUTING.md](../CONTRIBUTING.md).

---

*Ghostline — Invisible. Inevitable.*
