# vaultcheck

> Password entropy analyzer + breach lookup

Checks password strength using entropy scoring and cross-references against the HaveIBeenPwned (HIBP) k-anonymity API — no full password ever leaves your machine.

## Planned Features

- Entropy scoring (bits)
- HIBP k-anonymity breach lookup
- Common pattern detection (keyboard walks, dates, leetspeak)
- JSON output mode
- Batch mode from file

## Status

🚧 In development

```bash
# Target usage
vaultcheck --check "mypassword123" --hibp
vaultcheck --batch passwords.txt --json
```
