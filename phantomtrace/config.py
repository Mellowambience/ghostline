"""Config loader for phantomtrace with ${ENV} expansion."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

DEFAULT_PATH = Path(os.path.expanduser("~/.ghostline/phantomtrace/config.yaml"))

_VAR = re.compile(r"\$\{([^}]+)\}")


def _expand(raw: object) -> object:
    if isinstance(raw, str):
        return _VAR.sub(lambda m: os.environ.get(m.group(1), ""), raw)
    if isinstance(raw, dict):
        return {k: _expand(v) for k, v in raw.items()}
    if isinstance(raw, list):
        return [_expand(v) for v in raw]
    return raw


def load_config(path: str | os.PathLike | None = None) -> dict:
    """Load config from ``path`` (default ~/.ghostline/phantomtrace/config.yaml).

    Falls back to sane defaults if the file does not exist.
    """
    p = Path(path) if path else DEFAULT_PATH
    if not p.exists():
        return {
            "user_agent": "ghostline-phantomtrace/0.1 (+https://github.com/Mellowambience/ghostline)",
            "timeout": 10,
            "rate_limit_seconds": 1.5,
        }
    with open(p, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return _expand(data)
