"""ghostline — top-level dispatcher for the Ghostline cybersecurity suite.

Routes subcommands to each module's CLI. Modules are installed independently
(ghost-scan, vaultcheck, ghostdns, phantomtrace, shadowaudit, accountwatch, bookmark-audit);
this launcher finds them on PATH and forwards arguments.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

import click

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


if __name__ == "__main__":
    cli()
