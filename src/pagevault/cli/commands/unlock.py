"""unlock command."""

from pathlib import Path

import click

from pagevault._fs import atomic_write
from pagevault.config import load_config
from pagevault.crypto import PagevaultError
from pagevault.parser import has_pagevault_elements, process_file, unlock_html
from pagevault.wrap import WrapDocument, WrapKind

from ..shared import (
    BatchTally,
    _collect_files,
    _default_output_dir,
    _get_output_path,
    _read_html,
    _relative_path,
)


def _unlock_wrapped(
    doc: WrapDocument,
    output_path: Path,
    password: str,
    username: str | None,
    dry_run: bool,
) -> Path:
    """Decrypt a wrapped file or site; returns where its contents go.

    ``output_path`` is where the wrapper HTML would be mirrored. A file is
    restored under its original name beside it; a site is extracted into a
    directory named after the wrapper (``site.html`` -> ``site/``).
    """
    payload = doc.decrypt(password, username=username)
    if payload.kind is WrapKind.FILE:
        dest = output_path.with_name(payload.filename)
        if not dry_run:
            atomic_write(dest, payload.data)
    else:
        dest = output_path.with_suffix("")
        if not dry_run:
            payload.extract_site(dest)
    return dest


@click.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("-r", "--recursive", is_flag=True, help="Process directories recursively")
@click.option(
    "-d",
    "--directory",
    "output_dir",
    type=click.Path(),
    help="Output directory (default: _unlocked/)",
)
@click.option("-p", "--password", help="Decryption password (or use config/env)")
@click.option("-u", "--username", help="Username for multi-user encrypted content")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
@click.option("--dry-run", is_flag=True, help="Show what would be done without changes")
@click.option(
    "--stdout",
    "to_stdout",
    is_flag=True,
    help="Output decrypted content to stdout (for piping)",
)
def unlock(
    paths,
    recursive,
    output_dir,
    password,
    config_path,
    dry_run,
    username,
    to_stdout,
):
    """Unlock (decrypt) encrypted HTML files.

    Pages with encrypted <pagevault> regions return to "marked" state
    (plaintext inside <pagevault> wrappers). Wrapped files are restored
    under their original name; wrapped sites are extracted to a directory.
    With --stdout, a wrapped file's raw bytes (a site's zip archive) are
    written to stdout.

    \b
    Examples:
      pagevault unlock _locked/index.html
      pagevault unlock _locked/ -r
      pagevault unlock _locked/ -r -d _unlocked/
      pagevault unlock _locked/file.html -u alice -p "alice-pw"
      pagevault unlock report.pdf.html --stdout -p "$SECRET" > report.pdf
    """
    if not paths:
        raise click.UsageError("No files or directories specified")

    if to_stdout and output_dir:
        raise click.UsageError("--stdout and -d/--directory are mutually exclusive")

    if to_stdout and dry_run:
        raise click.UsageError("--stdout and --dry-run are mutually exclusive")

    if to_stdout and recursive:
        raise click.UsageError("--stdout requires a single file, not -r")

    # Load configuration
    try:
        config = load_config(
            config_path=Path(config_path) if config_path else None,
            start_path=Path(paths[0]) if paths else None,
            password_override=password,
        )
    except PagevaultError as e:
        raise click.ClickException(str(e))

    # Determine username (explicit or default from config)
    user = username or config.user

    # Get password: auto-lookup from config if user specified, else prompt
    if user and config.users and user in config.users:
        # Auto-lookup password from config when user is specified
        pwd = password or config.users[user]
    elif password:
        pwd = password
    elif config.password:
        pwd = config.password
    else:
        pwd = click.prompt("Enter decryption password", hide_input=True)

    # --stdout mode: decrypt and write to stdout
    if to_stdout:
        if len(paths) != 1 or not Path(paths[0]).is_file():
            raise click.UsageError("--stdout requires exactly one file")

        input_path = Path(paths[0])
        try:
            content = input_path.read_text(encoding="utf-8")
        except OSError as e:
            raise click.ClickException(f"Cannot read {input_path}: {e}") from e

        try:
            doc = WrapDocument.parse(content)
            if doc is not None:
                payload = doc.decrypt(pwd, username=user)
                click.echo(payload.data, nl=False)  # bytes go out unencoded
                return
            decrypted = unlock_html(content, pwd, username=user)
        except PagevaultError as e:
            raise click.ClickException(str(e)) from e

        if decrypted == content:
            raise click.ClickException("File has no encrypted pagevault content")
        click.echo(decrypted, nl=False)
        return

    output_base = _default_output_dir(output_dir, "_unlocked")

    # Collect files to process
    files = _collect_files(paths, recursive)

    if not files:
        click.echo("No HTML files found")
        return

    tally = BatchTally()

    for input_path in files:
        output_path = _get_output_path(input_path, paths, output_base)
        content = _read_html(input_path, tally)
        if content is None:
            continue

        if not has_pagevault_elements(content):
            tally.skipped += 1
            continue

        rel_input = _relative_path(input_path)
        rel_output = _relative_path(output_path)

        try:
            doc = WrapDocument.parse(content)
            if doc is not None:
                dest = _unlock_wrapped(doc, output_path, pwd, user, dry_run)
                verb = "Would unlock" if dry_run else "Unlocked"
                click.echo(f"{verb}: {rel_input} -> {_relative_path(dest)}")
                tally.done += 1
                continue
        except (PagevaultError, OSError) as e:
            tally.fail(f"Error processing {rel_input}: {e}")
            continue

        if dry_run:
            click.echo(f"Would unlock: {rel_input} -> {rel_output}")
            tally.done += 1
            continue

        try:
            changed = process_file(
                input_path,
                output_path,
                password=pwd,
                config=config,
                mode="unlock",
                username=user,
            )
            if changed:
                click.echo(f"Unlocked: {rel_input} -> {rel_output}")
                tally.done += 1
            else:
                tally.skipped += 1
        except PagevaultError as e:
            tally.fail(f"Error processing {rel_input}: {e}")

    tally.finish("unlocked")
