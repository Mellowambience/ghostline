"""vaultcheck password strength analyzer.

Lightweight, dependency-free heuristics:

* Shannon entropy (bits) of the full password string
* A simple crack-time estimate:  2 ** (entropy_bits - 1) / guesses_per_second
* Weakness detection without heavy ML/deps:
    - length < 8
    - repeated characters (e.g. ``aaa``)
    - sequential patterns (e.g. ``1234``, ``abcd``, reversed)
    - common-password / dictionary substring hits
    - lack of character-class variety

Returns a structured result:
    {length, entropy, crack_time_seconds, crack_time_human,
     char_classes, score (0-4), warnings[]}
"""

import math

# ~50 of the most commonly-breached passwords (RockYou / NIST worst-list).
# Used ONLY for substring / exact-match weakness detection — never transmitted.
COMMON_PASSWORDS = [
    "password", "123456", "12345678", "123456789", "1234567", "12345",
    "1234567890", "qwerty", "abc123", "letmein", "monkey", "dragon",
    "iloveyou", "sunshine", "princess", "football", "baseball", "welcome",
    "admin", "login", "passw0rd", "password1", "password123", "qwerty123",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsx", "1q2w3e4r", "1qaz2wsx",
    "111111", "000000", "123123", "666666", "trustno1", "superman",
    "batman", "mustang", "michael", "shadow", "master", "jordan",
    "harley", "ranger", "iamgod", "changeme", "admin123", "root",
    "toor", "administrator", "access", "flower", "hello", "freedom",
    "whatever", "qwerty1", "passwort", "azerty",
]

# Offline hash rate ballpark (guesses/sec). Real crackers are faster; this is
# intentionally conservative so estimates err toward "stronger than claimed".
GUESSES_PER_SECOND = 1_000_000_000  # 1e9


def shannon_entropy(password: str) -> float:
    """Total Shannon entropy (bits) of the whole password string."""
    if not password:
        return 0.0
    freq: dict[str, int] = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(password)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy * n


def _has_repeat_run(password: str, run: int = 3) -> bool:
    """True if the password contains >= ``run`` identical consecutive chars."""
    if len(password) < run:
        return False
    same = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            same += 1
            if same >= run:
                return True
        else:
            same = 1
    return False


def _has_sequence(password: str, length: int = 3) -> bool:
    """Detect ascending/descending runs of [length] consecutive codepoints."""
    if len(password) < length:
        return False
    for i in range(len(password) - length + 1):
        window = password[i : i + length]
        asc = all(ord(window[j]) - ord(window[j - 1]) == 1 for j in range(1, length))
        desc = all(ord(window[j - 1]) - ord(window[j]) == 1 for j in range(1, length))
        if asc or desc:
            return True
    return False


def _char_classes(password: str) -> list[str]:
    classes = {
        "lower": any(c.islower() for c in password),
        "upper": any(c.isupper() for c in password),
        "digit": any(c.isdigit() for c in password),
        "symbol": any(not c.isalnum() for c in password),
    }
    return [name for name, present in classes.items() if present]


def _matches_common(password: str):
    """Return the matched common password (str) or None."""
    low = password.lower()
    for word in COMMON_PASSWORDS:
        if low == word:
            return word
        if len(word) >= 4 and word in low:
            return word
    return None


def estimate_crack_time(entropy_bits: float,
                         guesses_per_second: float = GUESSES_PER_SECOND) -> float:
    """Average crack time (seconds) = 2 ** (entropy_bits - 1) / gps.

    Computed in log space to avoid float overflow for high entropies.
    """
    if entropy_bits <= 1:
        return 0.5 / guesses_per_second
    exponent = entropy_bits - 1
    log10_seconds = exponent * math.log10(2) - math.log10(guesses_per_second)
    if log10_seconds > 308:
        return float("inf")
    return 10 ** log10_seconds


def human_duration(seconds: float) -> str:
    """Render a seconds value as a human-readable duration string."""
    if seconds == 0:
        return "instantly"
    if math.isinf(seconds):
        return "effectively forever"
    if seconds < 1:
        return f"{seconds * 1000:.0f} milliseconds"
    units = [
        ("year", 31_536_000),
        ("day", 86_400),
        ("hour", 3_600),
        ("minute", 60),
        ("second", 1),
    ]
    for name, sec in units:
        if seconds >= sec:
            value = seconds / sec
            # Step up to a larger unit when the current one is unwieldy.
            if value >= 100 and name != "year":
                continue
            label = name if value == 1 else name + "s"
            return f"{value:,.1f} {label}"
    return f"{seconds:.2f} seconds"


def analyze(password: str,
            guesses_per_second: float = GUESSES_PER_SECOND) -> dict:
    """Analyze a password and return a structured strength result."""
    length = len(password)
    entropy = shannon_entropy(password)
    crack_seconds = estimate_crack_time(entropy, guesses_per_second)

    warnings: list[str] = []
    if length < 8:
        warnings.append(f"Too short ({length} chars) — use at least 8, ideally 12+")
    if _has_repeat_run(password):
        warnings.append("Contains repeated characters (e.g. 'aaa')")
    if _has_sequence(password):
        warnings.append("Contains a sequential pattern (e.g. '1234', 'abcd')")
    common = _matches_common(password)
    if common:
        warnings.append(f"Matches a common/dictionary password ('{common}')")
    classes = _char_classes(password)
    if length > 0 and len(classes) < 2:
        warnings.append("Lacks character variety — mix upper/lower/digits/symbols")

    # Entropy-bucket base score.
    if entropy >= 80:
        score = 4
    elif entropy >= 60:
        score = 3
    elif entropy >= 40:
        score = 2
    elif entropy >= 28:
        score = 1
    else:
        score = 0

    # Floor for obviously weak passwords, then apply warning penalties.
    if length < 8:
        score = min(score, 1)
    if common:
        score = 0
    score = max(0, score - len(warnings))

    return {
        "length": length,
        "entropy": round(entropy, 2),
        "crack_time_seconds": crack_seconds,
        "crack_time_human": human_duration(crack_seconds),
        "char_classes": classes,
        "score": score,
        "warnings": warnings,
    }
