"""GitHub platform adapter.

Fetches all email addresses associated with a GitHub account,
including primary, backup, and recovery addresses.
"""

import httpx
from typing import List


class GitHubAdapter:
    """Adapter for GitHub account recovery emails."""

    API_BASE = "https://api.github.com"

    def __init__(self, config: dict):
        self.token = config.get("token")
        if not self.token:
            raise ValueError("GitHub adapter requires 'token' in config.")

    def fetch_contacts(self) -> List[str]:
        """Fetch all emails associated with the authenticated GitHub account."""
        contacts = []
        try:
            with httpx.Client(timeout=10) as client:
                headers = {
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
                resp = client.get(f"{self.API_BASE}/user/emails", headers=headers)
                resp.raise_for_status()
                for entry in resp.json():
                    email = entry.get("email")
                    primary = entry.get("primary", False)
                    verified = entry.get("verified", False)
                    tag = "primary" if primary else ("verified" if verified else "unverified")
                    contacts.append(f"email:{email}:{tag}")
        except httpx.HTTPStatusError as e:
            raise RuntimeError(f"GitHub API error: {e.response.status_code} — {e.response.text}")
        except Exception as e:
            raise RuntimeError(f"GitHub adapter failed: {e}")
        return contacts
