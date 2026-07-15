"""vaultcheck config loader.

Loads configuration from ~/.ghostline/vaultcheck/config.yaml,
substituting environment variables for any ${VAR} placeholders.

Config is OPTIONAL — vaultcheck falls back to safe built-in defaults
when no config file is present.
"""

import os
import re
from pathlib import Path

DEFAULT_CONFIG_PATH = Path.home() / ".ghostline" / "vaultcheck" / "config.yaml"


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
    """Load and return the vaultcheck config.

    Raises FileNotFoundError if the config file is absent. Callers that treat
    config as optional should catch this and use built-in defaults.
    """
    import yaml  # imported lazily so the module works without PyYAML at import time

    if not path.exists():
        raise FileNotFoundError(
            f"Config not found at {path}.\n"
            "Copy config.example.yaml to get started (optional — vaultcheck "
            "uses safe defaults when no config is present)."
        )
    with open(path, "r") as f:
        raw = yaml.safe_load(f)
    return _expand_all(raw)
