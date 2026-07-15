"""Config loader for shadowaudit with ${ENV} expansion."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

DEFAULT_PATH = Path(os.path.expanduser("~/.ghostline/shadowaudit/config.yaml"))
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
    p = Path(path) if path else DEFAULT_PATH
    if not p.exists():
        return {"user_agent": "ghostline-shadowaudit/0.1", "timeout": 10}
    with open(p, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return _expand(data)
