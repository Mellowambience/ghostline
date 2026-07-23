#!/usr/bin/env python3
"""Smoke test for xchain-sim (run from repo root: python xchain-sim/tests/test_sim.py)."""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SIM = HERE.parent / "simulate.py"


def run(args):
    return subprocess.run(
        [sys.executable, str(SIM), *args],
        capture_output=True, text=True,
    )


def main():
    # ccip-solana-offramp -> all SAFE, no findings
    r = run(["--profile", "ccip-solana-offramp", "--json"])
    assert r.returncode == 0, "ccip profile failed: " + r.stderr
    out = json.loads(r.stdout)
    assert out["predicted_findings"] is False, "ccip should be clean"
    assert all(v["outcome"] == "SAFE" for v in out["results"].values()), out

    # wormhole-core -> a4 N/A (no curse mechanism)
    r = run(["--profile", "wormhole-core", "--json"])
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["results"]["a4"]["outcome"] == "N/A", out

    # missing curse gate with has_curse=true -> a4 VULN
    desc = {
        "has_curse": True,
        "message_auth": ["x"], "replay_protection": ["y"],
        "mint_gated": ["z"], "curse_gate": [],
    }
    dpath = HERE / "g_test.json"
    dpath.write_text(json.dumps(desc))
    try:
        r = run(["--contract", str(dpath), "--json"])
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["results"]["a4"]["outcome"] == "VULN", out
    finally:
        dpath.unlink(missing_ok=True)

    print("xchain-sim tests: PASS")


if __name__ == "__main__":
    main()
