"""phantomtrace CLI — Click entrypoint.

OSINT recon over PUBLIC data only (DNS, TLS cert, HTTP headers, WHOIS).
Operators must have authorization to investigate the target.
"""

from __future__ import annotations

import json

import click

from phantomtrace.config import load_config
from phantomtrace import recon as reconmod


@click.group()
@click.version_option()
def cli():
    """phantomtrace — public-data OSINT recon for authorized investigations."""


@cli.command()
@click.argument("target")
@click.option("--json", "as_json", is_flag=True, help="Emit raw JSON.")
def recon(target, as_json):
    """Run a public-data recon pass on TARGET (domain or URL)."""
    click.echo("⚠ phantomtrace queries only PUBLIC data (DNS/TLS/HTTP/WHOIS).")
    click.echo("⚠ Only investigate targets you are authorized to assess.")
    config = load_config()
    result = reconmod.recon(target, config)
    if as_json:
        click.echo(json.dumps(result.__dict__, indent=2, default=str))
        return
    click.echo(f"\n=== Recon: {result.target} (host: {result.domain}) ===")
    click.echo("\n[DNS]")
    for rtype, vals in result.dns.items():
        click.echo(f"  {rtype}: {', '.join(vals)}")
    click.echo("\n[TLS certificate]")
    for k, v in result.tls.items():
        click.echo(f"  {k}: {v}")
    click.echo("\n[HTTP headers]")
    for k, v in result.http_headers.items():
        click.echo(f"  {k}: {v}")
    click.echo("\n[WHOIS]")
    for k, v in result.whois.items():
        click.echo(f"  {k}: {v}")
    if result.notes:
        click.echo("\n[notes]")
        for n in result.notes:
            click.echo(f"  - {n}")


if __name__ == "__main__":
    cli()
