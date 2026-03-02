"""accountwatch baseline engine.

Captures, stores, and diffs recovery contact snapshots.
All baselines are HMAC-SHA256 signed using a local key — never uploaded.
"""

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict

BASELINE_DIR = Path.home() / ".ghostline" / "accountwatch" / "baselines"


def _get_hmac_key() -> bytes:
    key_env = os.environ.get("GHOSTLINE_HMAC_KEY")
    if not key_env:
        raise EnvironmentError(
            "GHOSTLINE_HMAC_KEY environment variable not set.\n"
            "Set it to a random secret string: export GHOSTLINE_HMAC_KEY=$(openssl rand -hex 32)"
        )
    return key_env.encode("utf-8")


def _sign(data: str) -> str:
    key = _get_hmac_key()
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()


def capture_baseline(platform: str, contacts: List[str]) -> None:
    """Capture and sign a trusted baseline snapshot for a platform."""
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "platform": platform,
        "contacts": sorted(contacts),
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }
    serialized = json.dumps(payload, sort_keys=True)
    signature = _sign(serialized)
    envelope = {"payload": payload, "signature": signature}
    path = BASELINE_DIR / f"{platform}.json"
    with open(path, "w") as f:
        json.dump(envelope, f, indent=2)


def load_baseline(platform: str) -> List[str]:
    """Load and verify the baseline for a platform. Returns contact list."""
    path = BASELINE_DIR / f"{platform}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"No baseline found for '{platform}'. Run 'accountwatch init' first."
        )
    with open(path, "r") as f:
        envelope = json.load(f)
    payload = envelope["payload"]
    stored_sig = envelope["signature"]
    serialized = json.dumps(payload, sort_keys=True)
    expected_sig = _sign(serialized)
    if not hmac.compare_digest(stored_sig, expected_sig):
        raise ValueError(
            f"Baseline signature verification FAILED for '{platform}'.\n"
            "The baseline file may have been tampered with."
        )
    return payload["contacts"]


def diff_contacts(baseline: List[str], current: List[str]) -> Dict[str, List[str]]:
    """Return added, removed, and modified contacts between baseline and current."""
    baseline_set = set(baseline)
    current_set = set(current)
    return {
        "added": sorted(current_set - baseline_set),
        "removed": sorted(baseline_set - current_set),
        "modified": [],  # Phase 2: deep field-level comparison
    }
