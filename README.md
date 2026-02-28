# 👻 Ghostline

> *Invisible. Inevitable.*

**Ghostline** is a modular, open-source cybersecurity suite built for people who don't explain themselves.

CLI-first. Privacy-native. Dark by design.

---

## Modules

| Module | Status | Description |
|--------|--------|-------------|
| `ghost-scan` | 🚧 In Progress | Port scanner + service fingerprinter |
| `vaultcheck` | 🚧 In Progress | Password entropy analyzer + HIBP breach lookup |
| `phantomtrace` | 📋 Planned | OSINT recon — domain, IP, social footprint |
| `shadowaudit` | 📋 Planned | Automated security checklist for web apps |
| `ghostdns` | 📋 Planned | DNS leak tester + resolver comparison |

---

## Architecture

```
ghost-scan/        # Port scan + fingerprint CLI
vaultcheck/        # Password strength + breach API
phantomtrace/      # OSINT recon toolkit
shadowaudit/       # Web app security audit generator
ghostdns/          # DNS leak + resolver audit
web/               # Dashboard (Next.js) — premium layer
merch/             # Ghostline merch store (Printful + Stripe)
docs/              # Documentation site
```

---

## Color Palette

| Name | Hex |
|------|-----|
| Void Black | `#0a0a0f` |
| Electric Mint | `#00ffcc` |
| Ghost White | `#f0f0f0` |
| Phantom Purple | `#6e3fa3` |

---

## Roadmap

- [ ] `vaultcheck` CLI v0.1
- [ ] `ghostdns` CLI v0.1  
- [ ] Merch store live (Printful + Stripe)
- [ ] `ghost-scan` + `phantomtrace` CLI beta
- [ ] Web dashboard (Next.js dark theme)
- [ ] `shadowaudit` + API access tier
- [ ] Ko-fi / sponsorship integration

---

## Revenue Model

| Stream | Details |
|--------|---------|
| Merch | Print-on-demand via Printful, zero inventory |
| CLI tools | Free + open source (trust + GitHub stars) |
| Dashboard | $9/mo — unlimited scans, history, exports |
| Pro tier | $29/mo — API access, team seats, custom reports |

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). We welcome security researchers, designers, and weirdos.

---

*Built by [@1Aether1Rose1](https://twitter.com/1Aether1Rose1)*  
*Licensed MIT — do what you want, just don't be evil.*
