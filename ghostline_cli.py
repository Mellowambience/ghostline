"""ghostline — top-level dispatcher for the Ghostline cybersecurity suite.

Routes subcommands to each module's CLI. Modules are installed independently
(ghost-scan, vaultcheck, ghostdns, phantomtrace, shadowaudit, accountwatch, bookmark-audit);
this launcher finds them on PATH and forwards arguments.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import click

from ghostline_profiles import (
    list_profiles,
    run_profile,
    render_markdown,
    render_html,
    list_reports,
)
from ghostline_doctor import run as doctor_run

MODULES = {
    "scan": "ghost-scan",
    "vault": "vaultcheck",
    "dns": "ghostdns",
    "trace": "phantomtrace",
    "audit": "shadowaudit",
    "account": "accountwatch",
    "bookmarks": "bookmark-audit",
}


@click.group()
@click.version_option()
def cli():
    """ghostline — modular cybersecurity suite. Invisible. Inevitable."""


def _dispatch(entry: str, args: list[str]):
    exe = shutil.which(entry)
    if exe is None:
        click.echo(f"[ghostline] '{entry}' is not installed. Run: pip install -e ./<module>")
        sys.exit(2)
    # Forward to the module CLI, preserving the remaining args
    return subprocess.run([exe, *args])


for _name, _entry in MODULES.items():
    def _make(name: str, entry: str):
        @cli.command(name, help=f"Run the '{entry}' module.")
        @click.argument("args", nargs=-1, type=click.UNPROCESSED)
        def _cmd(args, entry=entry):
            _dispatch(entry, list(args))
        return _cmd
    _make(_name, _entry)


@cli.command()
def modules():
    """List available modules and their install status."""
    click.echo("Ghostline modules:")
    for name, entry in MODULES.items():
        status = "installed" if shutil.which(entry) else "not installed"
        click.echo(f"  ghostline {name:<7} → {entry:<14} [{status}]")


@cli.command()
@click.argument("name", required=False)
@click.option("--html", is_flag=True, help="also write an HTML report")
def profile(name, html):
    """Run a composed workflow profile. With no name, list available profiles."""
    if not name:
        click.echo("Available profiles:")
        for p in list_profiles():
            click.echo(f"  ghostline profile {p}")
        return
    try:
        report = run_profile(name)
    except FileNotFoundError as e:
        click.echo(f"[ghostline] {e}")
        sys.exit(2)
    md = render_markdown(report)
    click.echo(md)
    if html:
        out = render_html(report)
        path = os.path.expanduser(f"~/.ghostline/reports/{name}_last.html")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
        click.echo(f"\n[ghostline] HTML report: {path}")


@cli.command()
@click.option("--last", "days", default=30, type=int, help="show reports from last N days")
def report(days):
    """Show stored run history from ~/.ghostline/reports/."""
    reps = list_reports(days)
    if not reps:
        click.echo(f"No reports in the last {days} days.")
        return
    click.echo(f"Ghostline reports (last {days}d):")
    for r in reps:
        status = "OK" if r["ok"] else "DEGRADED"
        click.echo(f"  {r['ran_at'][:19]}  {r['profile']:<16} [{status}]")


@cli.command()
def doctor():
    """Check install status, module availability, and HIBP reachability."""
    sys.exit(doctor_run())


if __name__ == "__main__":
    cli()
