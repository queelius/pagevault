"""inspect command."""

import click

from ..shared import _print_info, _verify_password


@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-p", "--password", help="Password to verify (prompts if --check)")
@click.option("-u", "--username", help="Username for multi-user content")
@click.option(
    "--check",
    "do_check",
    is_flag=True,
    help="Also verify password (requires -p or prompts)",
)
def inspect(path, password, username, do_check):
    """Inspect an encrypted HTML file.

    Shows encryption metadata, viewer info, and runtime details
    without requiring a password. With --check, also verifies the password.

    \b
    Examples:
      pagevault inspect encrypted.html
      pagevault inspect _locked/index.html
      pagevault inspect file.html --check -p "my-password"
      pagevault inspect file.html -u alice --check
    """
    _print_info(path)

    if do_check:
        if not password:
            password = click.prompt("Password", hide_input=True)

        ok, err = _verify_password(path, password, username=username)
        if ok:
            click.echo("Password: correct")
        else:
            click.echo(f"Password: incorrect ({err})")
            raise SystemExit(1)
