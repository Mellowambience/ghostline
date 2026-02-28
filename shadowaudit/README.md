# shadowaudit

> Automated security checklist for web apps

Given a target URL, generates a structured security audit checklist based on OWASP Top 10 and common misconfigurations.

## Planned Features

- HTTP header security analysis (CSP, HSTS, X-Frame-Options)
- Cookie flag audit (Secure, HttpOnly, SameSite)
- TLS/SSL grade check
- Open redirect detection
- Exposed sensitive file detection
- JSON + Markdown report output

## Status

📋 Planned — contributions welcome

```bash
# Target usage
shadowaudit https://example.com --full --json
```
