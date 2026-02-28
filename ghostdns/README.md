# ghostdns

> DNS leak tester + resolver comparison

Verify your DNS isn't betraying you. Compare resolvers. Detect leaks.

## Planned Features

- DNS leak detection
- Multi-resolver comparison (Cloudflare, Google, Quad9, custom)
- DNSSEC validation check
- DNS-over-HTTPS (DoH) support
- JSON output mode

## Status

📋 Planned — contributions welcome

```bash
# Target usage
ghostdns --leak-test
ghostdns --compare 1.1.1.1 8.8.8.8 9.9.9.9
```
