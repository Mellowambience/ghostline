"""accountwatch config loader.

Loads configuration from ~/.ghostline/accountwatch/config.yaml,
substituting environment variables for any ${VAR} placeholders.
"""

import os
import re
import yaml
from pathlib import Path

DEFAULT_CONFIG_PATH = Path.home() / ".ghostline" / "accountwatch" / "config.yaml"


def _expand_env(value: str) -> str:
    """Substitute ${VAR} placeholders with environment variable values."""
    return re.sub(r"\$\{([^}]+)\}", lambda m: os.environ.get(m.group(1), m.group(0)), value)


def _expand_all(obj):
    """Recursively expand env vars in a config dict."""
    if isinstance(obj, dict):
        return {k: _expand_all(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_all(i) for i in obj]
    if isinstance(obj, str):
        return _expand_env(obj)
    return obj


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> dict:
    """Load and return the accountwatch config."""
    if not path.exists():
        raise FileNotFoundError(
            f"Config not found at {path}.\n"
            "Run 'accountwatch init' or copy config.example.yaml to get started."
        )
    with open(path, "r") as f:
        raw = yaml.safe_load(f)
    return _expand_all(raw)
