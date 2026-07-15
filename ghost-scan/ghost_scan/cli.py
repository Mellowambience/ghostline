"""ghost-scan CLI — Click entrypoint.

Connect-scan-only port scanner + service fingerprinter.
Defaults to localhost; only scans a remote host if explicitly given one.
Authorized networks only.
"""

from __future__ import annotations

import json

import click

from ghost_scan import scanner
from ghost_scan.config import load_config


@click.group()
@click.version_option()
def cli():
    """ghost-scan — TCP connect port scanner + service fingerprinter."""


@cli.command()
@click.argument("target", default=None, required=False)
@click.option("--ports", default=None, help="Port spec e.g. '1-1024' or '22,80,443'")
@click.option("--top", "top_n", default=1000, type=int, help="Scan the top N common ports")
@click.option("--timeout", default=None, type=float, help="Per-port timeout (s)")
@click.option("--threads", "max_threads", default=None, type=int, help="Max concurrency")
@click.option("--banner/--no-banner", default=True, help="Grab service banners")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON")
@click.option("--output", default=None, help="Write report to file")
def scan(target, ports, top_n, timeout, max_threads, banner, as_json, output):
    """Scan TARGET (defaults to localhost 127.0.0.1)."""
    config = load_config()
    host = target or config.get("default_target", "127.0.0.1")
    if target is None:
        click.echo("⚠ No target given — scanning localhost (127.0.0.1).")
        click.echo("⚠ Only scan networks you own or are authorized to test.")
    to = timeout if timeout is not None else config.get("timeout", 0.5)
    mt = max_threads if max_threads is not None else config.get("max_threads", 200)

    if ports:
        port_list = scanner.parse_ports(ports)
    else:
        port_list = None

    results = scanner.scan_target(
        host=host, ports=port_list, top_n=top_n, timeout=to,
        max_threads=mt, grab_banners=banner,
    )

    open_ports = [r for r in results if r["state"] == "open"]

    if as_json:
        out = {"target": host, "open_count": len(open_ports), "results": results}
        text = json.dumps(out, indent=2)
    else:
        lines = [f"ghost-scan → {host}  ({len(open_ports)} open)"]
        lines.append(f"{'PORT':<8}{'STATE':<9}{'SERVICE':<20}{'BANNER'}")
        for r in results:
            if r["state"] != "open" and not banner:
                continue
            lines.append(f"{r['port']:<8}{r['state']:<9}{r['service']:<20}{r['banner'][:60]}")
        text = "\n".join(lines)

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        click.echo(f"[ghost-scan] report written to {output}")
    else:
        click.echo(text)


if __name__ == "__main__":
    cli()
