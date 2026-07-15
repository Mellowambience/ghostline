"""shadowaudit CLI — Click entrypoint.

Generates a non-destructive web-app security checklist for a target URL.
Does NOT perform intrusive testing. Authorized targets only.
"""

from __future__ import annotations

import json

import click

from shadowaudit import checks
from shadowaudit.config import load_config


@click.group()
@click.version_option()
def cli():
    """shadowaudit — automated web-app security checklist (non-destructive)."""


@cli.command()
@click.argument("target")
@click.option("--json", "as_json", is_flag=True, help="Emit raw JSON.")
@click.option("--timeout", default=10, help="Request timeout (seconds).")
def audit(target, as_json, timeout):
    """Run the security checklist against TARGET (domain or URL)."""
    click.echo("⚠ shadowaudit performs NON-DESTRUCTIVE checks only (headers/TLS/transport).")
    click.echo("⚠ Only audit targets you are authorized to assess.")
    config = load_config()
    report = checks.run_audit(target, timeout=timeout,
                              user_agent=config.get("user_agent", "ghostline"))
    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2))
        return
    click.echo(f"\n=== shadowaudit: {report.target} ===")
    click.echo(f"Transport: {report.transport}")
    click.echo(f"Score: {report.score}/{report.max_score}\n")
    for c in report.checks:
        icon = {"pass": "✓", "warn": "~", "fail": "✗"}[c.state]
        click.echo(f"  [{icon}] {c.title}")
        click.echo(f"        {c.note}")
        if c.remediation:
            click.echo(f"        → fix: {c.remediation}")
    pct = round(100 * report.score / report.max_score) if report.max_score else 0
    click.echo(f"\n  Summary: {pct}% hardened. Review failed/warn items above.")


if __name__ == "__main__":
    cli()
