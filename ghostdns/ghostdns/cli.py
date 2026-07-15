"""ghostdns CLI — Click-based entrypoint.

Compare what different resolvers say about the same domain, and run a
client-side DNS leak check.
"""

import json

import click

from ghostdns import __version__
from ghostdns.leak import analyze, detect_default_resolver, generate_unique_subdomain
from ghostdns.resolver import (
    PUBLIC_RESOLVERS,
    SUPPORTED_RECORDS,
    analyze_inconsistency,
    compare_resolvers,
)


def _emit(data, json_mode):
    """Print ``data`` as JSON (``--json``) or plaintext otherwise."""
    if json_mode:
        click.echo(json.dumps(data, indent=2))
    else:
        return False
    return True


@click.group()
@click.version_option(version=__version__)
def cli():
    """ghostdns — DNS resolver comparison + leak test.

    Compare resolvers for the same query and run a client-side DNS leak check.
    Use only on networks/domains you are authorized to test.
    """
    pass


@cli.command()
@click.argument("domain")
@click.option("--record", "record", default="A", type=click.Choice(SUPPORTED_RECORDS),
              help="DNS record type to query (default: A)")
@click.option("--resolvers", "resolvers", default=None,
              help="Comma-separated resolver IPs/names (default: built-in public set)")
@click.option("--timeout", default=5.0, type=float, help="Per-query timeout in seconds")
@click.option("--json", "json_mode", is_flag=True, help="Emit JSON instead of text")
def compare(domain, record, resolvers, timeout, json_mode):
    """Query each resolver for DOMAIN and report answers + inconsistencies."""
    spec = resolvers.split(",") if resolvers else None
    results = compare_resolvers(domain, record, spec, timeout)
    inc = analyze_inconsistency(results)

    if json_mode:
        click.echo(json.dumps({
            "domain": domain,
            "record": record,
            "results": results,
            "inconsistency": inc,
        }, indent=2))
        return

    click.echo(f"ghostdns compare — {domain} ({record})")
    click.echo("=" * 48)
    for name, entry in results.items():
        ip = entry["ip"]
        click.echo(f"\n[{name}] {ip}")
        if entry["error"]:
            click.echo(f"  ! error: {entry['error']}")
        elif entry["answers"]:
            for a in entry["answers"]:
                click.echo(f"  - {a}")
        else:
            click.echo("  (no answers)")

    click.echo("\n" + "-" * 48)
    if inc["inconsistent"]:
        click.echo("[!] INCONSISTENCY: resolvers disagree.")
        click.echo(f"    majority ({len(inc['majority'])}): {inc['majority'] or '(empty)'}")
        for name, ans in inc["outliers"].items():
            click.echo(f"    outlier {name}: {ans or '(empty)'}")
        click.echo("    Possible poisoning / cache / split-horizon issue.")
    else:
        click.echo("[✓] All resolvers agree.")


@cli.command()
@click.option("--domain", "domain", default="example.com",
              help="Base domain used to build a unique test subdomain")
@click.option("--timeout", default=5.0, type=float, help="Per-query timeout in seconds")
@click.option("--json", "json_mode", is_flag=True, help="Emit JSON instead of text")
def leak(domain, timeout, json_mode):
    """Client-side DNS leak check against the OS default resolver."""
    report = analyze(domain, timeout)

    if json_mode:
        click.echo(json.dumps(report, indent=2))
        return

    click.echo("ghostdns leak (client-side heuristic)")
    click.echo("=" * 48)
    click.echo(f"default resolver   : {report['default_resolver']}")
    click.echo(f"unique subdomain   : {report['unique_subdomain']}")
    click.echo(f"method             : {report['method']}")

    comp = report.get("comparison")
    if comp:
        click.echo("-" * 48)
        for name, entry in comp.items():
            ip = entry["ip"]
            if entry["error"]:
                click.echo(f"  [{name}] {ip}: ! {entry['error']}")
            else:
                click.echo(f"  [{name}] {ip}: {entry['answers'] or '(empty-NXDOMAIN)'}")

    click.echo("-" * 48)
    if report["leak_suspected"]:
        click.echo("[!] POSSIBLE LEAK / RESOLVER HIJACK DETECTED")
    else:
        click.echo("[✓] No client-side anomaly detected")
    for note in report["notes"]:
        click.echo(f"  • {note}")


@cli.command(name="default-resolver")
def default_resolver_cmd():
    """Print the detected OS default resolver (debug helper)."""
    click.echo(detect_default_resolver())


@cli.command(name="gen-subdomain")
@click.option("--domain", "domain", default="example.com", help="Base domain")
def gen_subdomain_cmd(domain):
    """Print a freshly generated unique test subdomain."""
    click.echo(generate_unique_subdomain(domain))


@cli.command(name="list-resolvers")
def list_resolvers_cmd():
    """Print the built-in public resolver set."""
    for name, ip in PUBLIC_RESOLVERS.items():
        click.echo(f"{name}\t{ip}")


if __name__ == "__main__":
    cli()
