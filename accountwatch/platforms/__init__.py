"""accountwatch platform adapters registry."""

from accountwatch.platforms.meta import MetaAdapter
from accountwatch.platforms.github import GitHubAdapter

_REGISTRY = {
    "meta": MetaAdapter,
    "github": GitHubAdapter,
    # Phase 2: google, twitter, apple_watch, generic_imap
}


def get_adapter(platform_name: str, config: dict):
    """Return an initialized adapter for the given platform."""
    cls = _REGISTRY.get(platform_name)
    if not cls:
        raise ValueError(
            f"No adapter registered for platform '{platform_name}'.\n"
            f"Available: {list(_REGISTRY.keys())}"
        )
    return cls(config)
