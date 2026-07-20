"""ghostline_doctor.py -- install + reachability sanity check.

Signals maturity: one command tells a new user what's missing and whether
HIBP (the only network dependency) is reachable. No telemetry, ever.
"""
from __future__ import annotations

import shutil
import socket
import sys

MODULES = {
    "scan": "ghost-scan",
    "vault": "vaultcheck",
    "dns": "ghostdns",
    "trace": "phantomtrace",
    "audit": "shadowaudit",
    "account": "accountwatch",
    "bookmarks": "bookmark-audit",
}

HIBP_HOST = "api.pwnedpasswords.com"
HIBP_PORT = 443


def check_python() -> tuple[bool, str]:
    v = sys.version_info
    ok = (v.major, v.minor) >= (3, 11)
    return ok, f"{v.major}.{v.minor}.{v.micro}"


def check_modules() -> list[tuple[str, bool]]:
    return [(name, shutil.which(exe) is not None) for name, exe in MODULES.items()]


def check_hibp() -> tuple[bool, str]:
    try:
        sock = socket.create_connection((HIBP_HOST, HIBP_PORT), timeout=5)
        sock.close()
        return True, "reachable"
    except OSError as e:
        return False, f"unreachable: {e}"


def run() -> int:
    print("Ghostline doctor\n===============")
    ok_py, ver = check_python()
    print(f"python: {ver} {'OK' if ok_py else 'NEEDS 3.11+'}")
    print("modules:")
    any_missing = False
    for name, ok in check_modules():
        print(f"  {name:<8} {'installed' if ok else 'MISSING'}")
        any_missing = any_missing or not ok
    hibp_ok, hibp_msg = check_hibp()
    print(f"HIBP (vaultcheck breach check): {hibp_msg}")
    total_ok = ok_py and not any_missing and hibp_ok
    print("\nverdict:", "healthy" if total_ok else "needs attention")
    return 0 if total_ok else 1


if __name__ == "__main__":
    sys.exit(run())
