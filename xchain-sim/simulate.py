#!/usr/bin/env python3
"""xchain-sim - cross-chain bridge attack simulator (static, symbolic).

Encodes the four cross-chain attack classes against known-good verification
gate patterns derived from source review of Wormhole / Arbitrum / CCIP.
Given a contract descriptor (its verification gates), it predicts whether each
attack reverts (SAFE) or would succeed (VULN).

This is a STATIC analyzer. It does NOT execute on-chain. It maps a contract's
declared gates to the attack classes and reports the predicted outcome. It is a
research/audit aid for checking a NEW contract against patterns proven correct
in audited code. It does not discover novel bugs; it flags MISSING defenses.

Ghostline module. Stdlib-only. --json required (pipeline composability).
No telemetry. No network. Authorized-use boundary in README.

Usage:
  python simulate.py --profile ccip-solana-offramp --json
  python simulate.py --contract descriptor.json --scenario a4 --json
"""
import argparse
import json
import sys

# Built-in verified gate profiles from this session's source review.
# Each profile lists the verification gates present in the real audited contract.
PROFILES = {
    "wormhole-core": {
        "message_auth": ["guardian_quorum_2of3", "body_integrity_hash", "verify_derivation"],
        "replay_protection": ["claim_consume"],
        "mint_gated": ["pda_mint_authority"],
        "curse_gate": [],
        "has_curse": False,
    },
    "wormhole-token-bridge": {
        "message_auth": ["guardian_quorum_2of3", "body_integrity_hash"],
        "replay_protection": ["claim_consume"],
        "mint_gated": ["pda_mint_authority"],
        "curse_gate": [],
        "has_curse": False,
    },
    "arbitrum-token-bridge": {
        "message_auth": ["bridge_sender", "l1_to_l2_alias", "only_counterpart_gateway"],
        "replay_protection": ["outbox_merkle_proof"],
        "mint_gated": ["only_gateway_bridge_init"],
        "curse_gate": [],
        "has_curse": False,
    },
    "ccip-solana-offramp": {
        "message_auth": ["ocr3_quorum_fplus1", "merkle_root", "transmitter_registered"],
        "replay_protection": ["exec_state_success_skip"],
        "mint_gated": ["pool_signer_pda", "balance_postcheck"],
        "curse_gate": ["verify_uncursed_cpi_before_release"],
        "has_curse": True,
    },
    # CCIP EVM OffRamp: in-scope Solidity asset. Source retrieved via @chainlink/contracts-ccip@2.0.0
    # (npm). Verified 2026-07-23: RMN curse checked FIRST (line 199), onRamp allowlist +
    # destChainSelector + CCV quorum (_ensureCCVQuorumIsReached), replay via executionState
    # (UNTOUCHED/FAILURE only), mint via registered pool + balance pre/post. All four gates present.
    "ccip-evm-offramp": {
        "message_auth": ["onRamp_allowlist", "ccv_quorum", "dest_chain_selector"],
        "replay_protection": ["execution_state_untouched_failure"],
        "mint_gated": ["token_admin_registry_pool", "balance_pre_post"],
        "curse_gate": ["isCursed_first"],
        "has_curse": True,
        "verified": True,
    },
}

# Attack class -> (human name, which gate key defends it)
SCENARIOS = {
    "a1": ("forged_message", "message_auth"),
    "a2": ("replay", "replay_protection"),
    "a3": ("mint_without_burn", "mint_gated"),
    "a4": ("curse_bypass", "curse_gate"),
}

# Attacks that are not applicable to a contract without a curse mechanism.
CURSE_RELEVANT = {"wormhole-core": False, "wormhole-token-bridge": False,
                  "arbitrum-token-bridge": False, "ccip-solana-offramp": True}


def simulate(gates):
    """Predict outcome per scenario from a gates dict."""
    has_curse = gates.get("has_curse", True)  # default: assume curse mechanism exists
    if not gates.get("verified", True):
        # Source not retrieved — never claim SAFE on unread code.
        return {sid: {
            "scenario": name,
            "outcome": "UNVERIFIED",
            "detail": "contract source not retrieved; outcome unknown",
        } for sid, (name, _) in SCENARIOS.items()}
    results = {}
    for sid, (name, gate_key) in SCENARIOS.items():
        present = gates.get(gate_key, [])
        if sid == "a4" and not has_curse:
            # Curse bypass is only meaningful for bridges with an RMN-like
            # pause/curse mechanism. Bridges using pure guardian/quorum trust
            # (Wormhole, Arbitrum token bridge) are N/A, not vulnerable.
            results[sid] = {
                "scenario": name,
                "outcome": "N/A",
                "detail": "no curse/pause mechanism in this bridge; scenario not applicable",
            }
            continue
        if present:
            results[sid] = {
                "scenario": name,
                "outcome": "SAFE",
                "detail": "reverts; gate '%s' present: [%s]" % (gate_key, ", ".join(present)),
            }
        else:
            results[sid] = {
                "scenario": name,
                "outcome": "VULN",
                "detail": "MISSING defending gate '%s' -> attack may succeed" % gate_key,
            }
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="simulate.py",
        description="Static cross-chain bridge attack simulator (Ghostline module).",
    )
    ap.add_argument("--profile", help="built-in profile: " + ", ".join(sorted(PROFILES)))
    ap.add_argument("--contract", help="path to a JSON contract-descriptor file")
    ap.add_argument("--scenario", default="all",
                    choices=["a1", "a2", "a3", "a4", "all"],
                    help="attack scenario to simulate (default: all)")
    ap.add_argument("--json", action="store_true", required=True,
                    help="emit JSON (required by Ghostline convention)")
    args = ap.parse_args(argv)

    gates = None
    profile_name = args.profile
    if args.profile:
        gates = PROFILES.get(args.profile)
        if gates is None:
            sys.stderr.write("unknown profile: %s\n" % args.profile)
            return 2
    elif args.contract:
        try:
            with open(args.contract, "r", encoding="utf-8") as fh:
                gates = json.load(fh)
            profile_name = args.contract
        except (OSError, ValueError) as exc:
            sys.stderr.write("cannot read contract descriptor: %s\n" % exc)
            return 2
    else:
        sys.stderr.write("need --profile or --contract\n")
        return 2

    res = simulate(gates)
    if args.scenario != "all":
        res = {args.scenario: res[args.scenario]}

    # Summarize: any VULN -> flag
    any_vuln = any(r["outcome"] == "VULN" for r in res.values())
    out = {
        "tool": "xchain-sim",
        "target": profile_name,
        "predicted_findings": any_vuln,
        "results": res,
    }
    sys.stdout.write(json.dumps(out, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
