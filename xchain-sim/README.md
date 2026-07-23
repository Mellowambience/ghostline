# xchain-sim

## Why this exists
Cross-chain bridges are the highest-value DeFi attack surface. This module encodes the
**four canonical cross-chain attack classes** and checks a contract's declared verification
gates against them — predicting whether each attack reverts (SAFE), is not applicable (N/A),
or would succeed because a defending gate is missing (VULN).

It is a **static** analyzer: it maps a contract descriptor (its gates) to attack outcomes.
It does NOT execute on-chain and does NOT discover novel bugs. It is a research/audit aid for
quickly checking a new bridge against defense patterns proven correct in audited code
(Wormhole, Arbitrum token bridge, Chainlink CCIP). It flags MISSING defenses — the fastest
way to spot an unhardened contract before deeper review.

## What it does
Simulates four scenarios against a gate descriptor:
- **a1 forged_message** — forged cross-chain message without valid proof
- **a2 replay** — double-execution / replay of the same transfer
- **a3 mint_without_burn** — supply inflation without burn
- **a4 curse_bypass** — RMN/guardian pause/curse bypass (only for bridges with a curse mechanism)

Built-in profiles: `wormhole-core`, `wormhole-token-bridge`, `arbitrum-token-bridge`,
`ccip-solana-offramp`. Or pass your own descriptor JSON via `--contract`.

## Install
```bash
# stdlib only — no dependencies. Python 3.11+.
python simulate.py --profile ccip-solana-offramp --json
```

## Quick start
```bash
# Simulate a built-in profile
python simulate.py --profile ccip-solana-offramp --json

# Simulate a custom contract descriptor
python simulate.py --contract examples/sample.json --scenario a4 --json

# Simulate all scenarios
python simulate.py --profile wormhole-core --json
```

## CLI reference
| Flag | Required | Description |
|---|---|---|
| `--profile` | one of `--profile`/`--contract` | built-in gate profile name |
| `--contract` | one of `--profile`/`--contract` | path to JSON descriptor (`message_auth`, `replay_protection`, `mint_gated`, `curse_gate`, optional `has_curse`) |
| `--scenario` | no | `a1`/`a2`/`a3`/`a4`/`all` (default `all`) |
| `--json` | **yes** | emit JSON (Ghostline mandate) |

## Architecture
- `simulate.py` — stdlib-only CLI. `PROFILES` holds verified gate patterns; `SCENARIOS`
  maps each attack to its defending gate key; `simulate()` returns per-scenario outcomes.
- `examples/sample.json` — runnable descriptor sample.
- `requirements.txt` — declares stdlib-only.

## Roadmap
- Add `ccip-evm-offramp` profile once the EVM OffRamp source is retrieved.
- Optional: parse Solidity/Rust gate annotations from source (out of scope for v1).

## Contributing
Match Ghostline conventions: stdlib-only, `--json` on every CLI, no telemetry.
Run `python simulate.py --profile ccip-solana-offramp --json` and confirm exit 0 + valid JSON.

## Legal / ethical note
xchain-sim is a defensive audit aid. It analyzes contract *descriptors* you provide; it does
not interact with any chain, does not submit transactions, and does not perform unauthorized
testing. Use only against contracts you are authorized to review (your own, public source,
or in-scope bug-bounty programs per their rules — private net only, never mainnet/public
testnets). The authors are not liable for misuse. *Invisible. Inevitable.*
