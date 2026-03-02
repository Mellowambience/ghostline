"""Meta (Facebook/Instagram) platform adapter.

Fetches recovery contact emails and phones from Meta Accounts Center
via the Facebook Graph API.

Origin story:
  This adapter was built because Meta's own platform failed to detect
  an unauthorized recovery email (nsh11@myyahoo.com) being silently added
  to an account. accountwatch does what Meta wouldn't.
"""

import httpx
from typing import List


class MetaAdapter:
    """Adapter for Meta Accounts Center recovery contacts."""

    GRAPH_API_BASE = "https://graph.facebook.com/v19.0"

    def __init__(self, config: dict):
        self.access_token = config.get("access_token")
        if not self.access_token:
            raise ValueError("Meta adapter requires 'access_token' in config.")

    def fetch_contacts(self) -> List[str]:
        """
        Fetch recovery emails and phone numbers from Meta Accounts Center.

        Note: The Graph API exposes limited recovery contact data via /me?fields=email.
        For full Accounts Center monitoring, supplement with iCloud/Gmail notification
        email parsing (see generic_imap adapter in Phase 2).
        """
        contacts = []
        try:
            with httpx.Client(timeout=10) as client:
                # Primary email on the account
                resp = client.get(
                    f"{self.GRAPH_API_BASE}/me",
                    params={"fields": "email,name", "access_token": self.access_token},
                )
                resp.raise_for_status()
                data = resp.json()
                if email := data.get("email"):
                    contacts.append(f"email:{email}")

                # TODO Phase 2: parse security notification emails from Gmail/IMAP
                # to detect Accounts Center contact additions that Graph API doesn't expose
        except httpx.HTTPStatusError as e:
            raise RuntimeError(f"Meta API error: {e.response.status_code} — {e.response.text}")
        except Exception as e:
            raise RuntimeError(f"Meta adapter failed: {e}")

        return contacts
