"""accountwatch CLI — Click-based entrypoint."""

import click
from accountwatch.config import load_config
from accountwatch.baseline import capture_baseline, load_baseline, diff_contacts
from accountwatch.alerter import alert
from accountwatch import platforms


@click.group()
@click.version_option()
def cli():
    """accountwatch — Recovery contact backdoor detector.

    Monitors your platform accounts for unauthorized recovery email/phone
    additions and alerts you before the attacker uses them.
    """
    pass


@cli.command()
def init():
    """Initialize accountwatch and capture trusted baseline snapshot."""
    config = load_config()
    click.echo("[accountwatch] Capturing baseline...")
    for platform_name, platform_cfg in config["platforms"].items():
        if not platform_cfg.get("enabled", True):
            continue
        adapter = platforms.get_adapter(platform_name, platform_cfg)
        contacts = adapter.fetch_contacts()
        capture_baseline(platform_name, contacts)
        click.echo(f"  ✓ {platform_name}: {len(contacts)} contact(s) saved to baseline")
    click.echo("[accountwatch] Baseline initialized. Run 'accountwatch watch' to start monitoring.")


@cli.command()
@click.option("--platform", default="all", help="Platform to check (default: all)")
def check(platform):
    """Run a one-time check against current baseline."""
    config = load_config()
    targets = (
        {k: v for k, v in config["platforms"].items() if k == platform}
        if platform != "all"
        else config["platforms"]
    )
    any_change = False
    for platform_name, platform_cfg in targets.items():
        if not platform_cfg.get("enabled", True):
            continue
        adapter = platforms.get_adapter(platform_name, platform_cfg)
        current = adapter.fetch_contacts()
        baseline = load_baseline(platform_name)
        diff = diff_contacts(baseline, current)
        if diff["added"] or diff["removed"] or diff["modified"]:
            any_change = True
            click.echo(f"[!] CHANGE DETECTED on {platform_name}")
            for c in diff["added"]:
                click.echo(f"    + ADDED:    {c}")
            for c in diff["removed"]:
                click.echo(f"    - REMOVED:  {c}")
            for c in diff["modified"]:
                click.echo(f"    ~ MODIFIED: {c}")
            alert(platform_name, diff, config.get("alerts", {}))
        else:
            click.echo(f"  ✓ {platform_name}: clean")
    if not any_change:
        click.echo("[accountwatch] All platforms clean.")


@cli.command()
@click.option("--interval", default="30m", help="Poll interval (e.g. 15m, 1h)")
def watch(interval):
    """Run in daemon mode, continuously polling all platforms."""
    from accountwatch.scheduler import start_scheduler
    click.echo(f"[accountwatch] Starting daemon (interval: {interval})...")
    start_scheduler(interval)


@cli.command()
@click.option("--platform", default="all", help="Platform to show (default: all)")
def show(platform):
    """Display current recovery contacts for a platform (read-only)."""
    config = load_config()
    targets = (
        {k: v for k, v in config["platforms"].items() if k == platform}
        if platform != "all"
        else config["platforms"]
    )
    for platform_name, platform_cfg in targets.items():
        if not platform_cfg.get("enabled", True):
            continue
        adapter = platforms.get_adapter(platform_name, platform_cfg)
        contacts = adapter.fetch_contacts()
        click.echo(f"\n[{platform_name}]")
        for c in contacts:
            click.echo(f"  {c}")


@cli.group()
def baseline():
    """Baseline management commands."""
    pass


@baseline.command("update")
@click.option("--platform", required=True, help="Platform to update baseline for")
def baseline_update(platform):
    """Update baseline after a legitimate contact change."""
    config = load_config()
    platform_cfg = config["platforms"].get(platform)
    if not platform_cfg:
        click.echo(f"[!] Platform '{platform}' not found in config.")
        return
    adapter = platforms.get_adapter(platform, platform_cfg)
    contacts = adapter.fetch_contacts()
    capture_baseline(platform, contacts)
    click.echo(f"  ✓ Baseline updated for {platform}: {len(contacts)} contact(s)")


@cli.group()
def report():
    """Audit log and report commands."""
    pass


@report.command("export")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "csv", "legal"]), help="Output format")
@click.option("--output", default=None, help="Output file path (default: stdout)")
def report_export(fmt, output):
    """Export the audit log."""
    from accountwatch.report import export_audit_log
    export_audit_log(fmt, output)


if __name__ == "__main__":
    cli()
