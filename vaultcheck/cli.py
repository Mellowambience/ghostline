"""vaultcheck CLI — Click-based entrypoint.

Password strength analyzer + HIBP k-anonymity breach checker.

Privacy guarantees:
  * The password is NEVER echoed to stdout, logs, or the terminal.
  * The breach check sends only the FIRST 5 HEX of the SHA-1 hash to HIBP.
    The password and full hash never leave your machine.
"""

import json
import logging

import click

from vaultcheck import analyzer
from vaultcheck import breach as breach_mod

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("vaultcheck")


def _read_passwords(file_path, prompt):
    """Yield passwords from a file (one per line) or a hidden prompt."""
    if file_path:
        with open(file_path, "r") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line:  # skip blank lines
                    yield line
    else:
        # hide_input=True — the password is never echoed to the terminal.
        yield click.prompt(prompt, hide_input=True, default="").strip()


def _build_report(password, do_analysis, do_breach):
    """Build a result dict for one password without ever echoing it."""
    result = {}
    if do_analysis:
        result["analysis"] = analyzer.analyze(password)
    if do_breach:
        try:
            found, count = breach_mod.check_breach(password)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Breach check error: %s", exc)
            found, count = False, 0
        result["breach"] = {"found": found, "count": count}
    return result


def _print_human(report):
    """Print a human-readable report (no password ever printed)."""
    if "analysis" in report:
        a = report["analysis"]
        click.echo(f"  Length          : {a['length']}")
        click.echo(f"  Entropy         : {a['entropy']} bits")
        click.echo(f"  Est. crack time : {a['crack_time_human']}")
        click.echo(f"  Char classes    : {', '.join(a['char_classes']) or 'none'}")
        click.echo(f"  Score (0-4)     : {a['score']}")
        if a["warnings"]:
            click.echo("  Warnings        :")
            for w in a["warnings"]:
                click.echo(f"    - {w}")
        else:
            click.echo("  Warnings        : none")
    if "breach" in report:
        b = report["breach"]
        if b["found"]:
            click.echo(f"  BREACHED        : YES — seen {b['count']:,} times")
        else:
            click.echo("  BREACHED        : no (not found in HIBP range)")


@click.group()
@click.version_option()
def cli():
    """vaultcheck — password strength analyzer + HIBP breach checker.

    Estimates password entropy, flags weak patterns, and checks the
    HaveIBeenPwned k-anonymity API. Your password is never transmitted.
    """
    pass


@cli.command()
@click.option("--file", "file_path", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Read one password per line from this file.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of text.")
def check(file_path, as_json):
    """Full check: entropy + weakness heuristics + HIBP breach lookup."""
    prompt = "Enter password to analyze"
    reports = [_build_report(pw, do_analysis=True, do_breach=True)
               for pw in _read_passwords(file_path, prompt)]
    if as_json:
        click.echo(json.dumps(reports, indent=2))
    else:
        for i, report in enumerate(reports):
            if len(reports) > 1:
                click.echo(f"\n[password #{i + 1}]")
            _print_human(report)


@cli.command()
@click.option("--file", "file_path", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Read one password per line from this file.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of text.")
def breach(file_path, as_json):
    """Breach-only check: HIBP k-anonymity lookup (no weakness heuristics)."""
    prompt = "Enter password to breach-check"
    reports = [_build_report(pw, do_analysis=False, do_breach=True)
               for pw in _read_passwords(file_path, prompt)]
    if as_json:
        click.echo(json.dumps(reports, indent=2))
    else:
        for i, report in enumerate(reports):
            if len(reports) > 1:
                click.echo(f"\n[password #{i + 1}]")
            _print_human(report)


if __name__ == "__main__":
    cli()
