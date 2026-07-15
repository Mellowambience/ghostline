"""vaultcheck HIBP k-anonymity breach lookup.

Privacy model (k-anonymity):
    Only the FIRST 5 HEX CHARACTERS of the uppercase SHA-1 hash of a
    password are sent to the HIBP range API. The password and the full hash
    never leave your machine. The server returns every suffix that shares
    your prefix; we match locally.

    NEVER send the full hash or the plaintext password.
"""

import hashlib
import logging

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:  # pragma: no cover - exercised only without httpx
    httpx = None
    _HAS_HTTPX = False

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:  # pragma: no cover - exercised only without requests
    requests = None
    _HAS_REQUESTS = False

logger = logging.getLogger(__name__)

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
DEFAULT_HEADERS = {
    "User-Agent": "ghostline-vaultcheck",
    "Add-Padding": "true",
}


def hash_prefix(password: str) -> tuple[str, str]:
    """Return ``(prefix, suffix)`` of the UPPERCASE SHA-1 hex digest.

    ``prefix`` is the first 5 hex chars; ``suffix`` is the remaining 35.
    The full digest is always 40 hex chars.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def _fetch_range(prefix: str) -> str:
    """GET the HIBP range body for a 5-char prefix. Returns raw text."""
    url = HIBP_RANGE_URL.format(prefix=prefix)
    headers = dict(DEFAULT_HEADERS)
    if _HAS_HTTPX:
        resp = httpx.get(url, headers=headers, timeout=10.0, follow_redirects=True)
        resp.raise_for_status()
        return resp.text
    if _HAS_REQUESTS:
        resp = requests.get(url, headers=headers, timeout=10.0)
        resp.raise_for_status()
        return resp.text
    raise RuntimeError("Neither httpx nor requests is installed.")


def check_breach(password: str) -> tuple[bool, int]:
    """Return ``(found, count)`` using the HIBP k-anonymity range API.

    On any network/HTTP error, returns ``(False, 0)`` and logs the error.
    The password is NEVER transmitted — only its 5-char hash prefix is sent.
    """
    prefix, suffix = hash_prefix(password)
    try:
        body = _fetch_range(prefix)
    except Exception as exc:  # noqa: BLE001 - we never want to leak a traceback
        logger.warning("HIBP breach check failed (password NOT transmitted): %s", exc)
        return False, 0

    suffix_upper = suffix.upper()
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        sfx, _, cnt = line.partition(":")
        if sfx.strip().upper() == suffix_upper:
            try:
                return True, int(cnt)
            except ValueError:
                continue
    return False, 0
