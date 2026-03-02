"""accountwatch alerter — multi-channel alert dispatcher."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

AUDIT_LOG_PATH = Path.home() / ".ghostline" / "accountwatch" / "audit.log"

logger = logging.getLogger(__name__)


def alert(platform: str, diff: Dict[str, List[str]], alert_config: dict) -> None:
    """Dispatch alerts across all configured channels and append to audit log."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": platform,
        "added": diff.get("added", []),
        "removed": diff.get("removed", []),
        "modified": diff.get("modified", []),
    }

    # Always write to audit log
    _append_audit_log(event)

    # Terminal (always on)
    _alert_terminal(platform, diff)

    # Desktop notification
    if alert_config.get("desktop_notification", False):
        _alert_desktop(platform, diff)

    # Webhooks (Discord, Slack, Telegram, custom)
    for webhook in alert_config.get("webhook", []):
        _alert_webhook(platform, diff, webhook)

    # SMTP (optional)
    smtp_cfg = alert_config.get("smtp", {})
    if smtp_cfg.get("enabled", False):
        _alert_smtp(platform, diff, smtp_cfg)


def _append_audit_log(event: dict) -> None:
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")


def _alert_terminal(platform: str, diff: dict) -> None:
    print(f"\n{'='*60}")
    print(f"[accountwatch] ⚠️  RECOVERY CONTACT CHANGE DETECTED")
    print(f"Platform : {platform}")
    print(f"Time     : {datetime.now(timezone.utc).isoformat()}")
    if diff.get("added"):
        print(f"ADDED    : {', '.join(diff['added'])}")
    if diff.get("removed"):
        print(f"REMOVED  : {', '.join(diff['removed'])}")
    print(f"{'='*60}\n")


def _alert_desktop(platform: str, diff: dict) -> None:
    try:
        from plyer import notification
        added = ", ".join(diff.get("added", []))
        notification.notify(
            title=f"accountwatch: Change on {platform}",
            message=f"Unauthorized contact added: {added}" if added else "Contact removed",
            app_name="Ghostline accountwatch",
            timeout=10,
        )
    except Exception as e:
        logger.warning(f"Desktop notification failed: {e}")


def _alert_webhook(platform: str, diff: dict, webhook_cfg: dict) -> None:
    try:
        import requests
        url = webhook_cfg.get("url")
        if not url:
            return
        webhook_type = webhook_cfg.get("type", "generic")
        added = diff.get("added", [])
        removed = diff.get("removed", [])
        if webhook_type == "discord":
            payload = {
                "embeds": [{
                    "title": f"⚠️ accountwatch: Recovery contact change on {platform}",
                    "color": 16711680,  # red
                    "fields": [
                        {"name": "Added", "value": "\n".join(added) or "none", "inline": True},
                        {"name": "Removed", "value": "\n".join(removed) or "none", "inline": True},
                    ],
                    "footer": {"text": "Ghostline accountwatch — Invisible. Inevitable."},
                }]
            }
        else:
            payload = {
                "text": f"[accountwatch] ⚠️ Contact change on {platform}: added={added} removed={removed}"
            }
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        logger.warning(f"Webhook alert failed: {e}")


def _alert_smtp(platform: str, diff: dict, smtp_cfg: dict) -> None:
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(
            f"accountwatch detected a recovery contact change on {platform}.\n\n"
            f"Added: {diff.get('added', [])}\n"
            f"Removed: {diff.get('removed', [])}\n"
        )
        msg["Subject"] = f"[accountwatch] ⚠️ Contact change detected on {platform}"
        msg["From"] = smtp_cfg["from"]
        msg["To"] = smtp_cfg["to"]
        with smtplib.SMTP_SSL(smtp_cfg["host"], smtp_cfg.get("port", 465)) as server:
            server.login(smtp_cfg["username"], smtp_cfg["password"])
            server.send_message(msg)
    except Exception as e:
        logger.warning(f"SMTP alert failed: {e}")
