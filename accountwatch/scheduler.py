"""accountwatch scheduler — APScheduler-based daemon mode."""

import re
from apscheduler.schedulers.blocking import BlockingScheduler
from accountwatch.config import load_config
from accountwatch.baseline import load_baseline, diff_contacts
from accountwatch.alerter import alert
from accountwatch import platforms


def _parse_interval(interval: str) -> dict:
    """Parse interval string like '15m', '1h', '30s' into APScheduler kwargs."""
    match = re.fullmatch(r"(\d+)(m|h|s)", interval.strip())
    if not match:
        raise ValueError(f"Invalid interval: '{interval}'. Use format like '15m', '1h'.")
    value, unit = int(match.group(1)), match.group(2)
    return {"minutes": value} if unit == "m" else ({"hours": value} if unit == "h" else {"seconds": value})


def _run_check():
    config = load_config()
    for platform_name, platform_cfg in config["platforms"].items():
        if not platform_cfg.get("enabled", True):
            continue
        try:
            adapter = platforms.get_adapter(platform_name, platform_cfg)
            current = adapter.fetch_contacts()
            baseline = load_baseline(platform_name)
            diff = diff_contacts(baseline, current)
            if diff["added"] or diff["removed"] or diff["modified"]:
                alert(platform_name, diff, config.get("alerts", {}))
        except Exception as e:
            print(f"[accountwatch] Error checking {platform_name}: {e}")


def start_scheduler(interval: str) -> None:
    kwargs = _parse_interval(interval)
    scheduler = BlockingScheduler()
    scheduler.add_job(_run_check, "interval", **kwargs)
    print(f"[accountwatch] Daemon running. Ctrl+C to stop.")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        print("[accountwatch] Stopped.")
