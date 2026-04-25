"""sync command."""

from pathlib import Path

import click

from pagevault.config import load_config
from pagevault.crypto import PagevaultError
from pagevault.parser import has_pagevault_elements, sync_html_keys

from ..shared import _collect_files, _relative_path, _resolve_managed_html_files


@click.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("-r", "--recursive", is_flag=True, help="Process directories recursively")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
@click.option("--dry-run", is_flag=True, help="Show what would be done without changes")
@click.option("--rekey", is_flag=True, help="Generate new content encryption key")
def sync(paths, recursive, config_path, dry_run, rekey):
    """Re-wrap encryption keys for current users.

    Updates encrypted files so that the current set of users in the config
    can decrypt them. Use after adding or removing users.

    If no paths are given, uses the 'managed' globs from the config file.

    \b
    Examples:
      pagevault sync encrypted/ -r
      pagevault sync encrypted/ -r --rekey
      pagevault sync -c .pagevault.yaml --dry-run
    """
    # Load configuration
    try:
        config = load_config(
            config_path=Path(config_path) if config_path else None,
            start_path=Path(paths[0]) if paths else None,
        )
    except PagevaultError as e:
        raise click.ClickException(str(e))

    if not config.users:
        raise click.ClickException(
            "No 'users' defined in config. sync requires multi-user configuration."
        )

    # Determine files to process
    if paths:
        files = _collect_files(paths, recursive)
    elif config.managed and config.config_path:
        files = _resolve_managed_html_files(config.config_path.parent, config.managed)
    else:
        raise click.ClickException(
            "No paths specified and no 'managed' globs in config."
        )

    if not files:
        click.echo("No HTML files found")
        return

    processed = 0
    skipped = 0

    for input_path in files:
        try:
            content = input_path.read_text(encoding="utf-8")
        except OSError as e:
            click.echo(f"Warning: Cannot read {input_path}: {e}", err=True)
            continue

        if not has_pagevault_elements(content):
            skipped += 1
            continue

        rel_path = _relative_path(input_path)

        if dry_run:
            click.echo(f"Would sync: {rel_path}")
            processed += 1
            continue

        try:
            result = sync_html_keys(
                content,
                old_users=config.users,  # Use current users to recover CEK
                new_users=config.users,
                rekey=rekey,
            )

            if result != content:
                input_path.write_text(result, encoding="utf-8")
                click.echo(f"Synced: {rel_path}")
                processed += 1
            else:
                skipped += 1
        except PagevaultError as e:
            click.echo(f"Error syncing {rel_path}: {e}", err=True)

    click.echo(f"\n{processed} file(s) synced, {skipped} skipped")
