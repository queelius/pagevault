"""mark command."""

import click

from pagevault.parser import has_pagevault_elements, mark_body, mark_elements

from ..shared import _collect_files, _relative_path


@click.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("-r", "--recursive", is_flag=True, help="Process directories recursively")
@click.option(
    "-s",
    "--selector",
    "selectors",
    multiple=True,
    help="CSS selector(s) to mark (can specify multiple)",
)
@click.option(
    "--hint",
    "selector_hint",
    help="Password hint for marked elements",
)
@click.option(
    "--remember",
    "selector_remember",
    type=click.Choice(["none", "session", "local", "ask"]),
    help="Remember mode for marked elements",
)
@click.option(
    "--title",
    "selector_title",
    help="Title for encrypted region (replaces default 'Protected Content')",
)
def mark(
    paths,
    recursive,
    selectors,
    selector_hint,
    selector_remember,
    selector_title,
):
    """Tag elements for encryption (in-place).

    With --selector, wraps matching elements in <pagevault> tags.
    Without --selector, wraps all <body> innerHTML in a single <pagevault>.

    Files are modified in-place. Content stays readable plaintext until locked.

    \b
    Examples:
      pagevault mark index.html -s "#secret"
      pagevault mark site/ -r -s ".private"
      pagevault mark page.html --hint "Contact admin" --title "Members Only"
      pagevault mark page.html  # wraps entire body
    """
    if not paths:
        raise click.UsageError("No files or directories specified")

    # Collect files to process
    files = _collect_files(paths, recursive)

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

        # Skip files already having pagevault elements (unless using selectors)
        if not selectors and has_pagevault_elements(content):
            skipped += 1
            continue

        if selectors:
            modified = mark_elements(
                content,
                list(selectors),
                hint=selector_hint,
                remember=selector_remember,
                title=selector_title,
            )
        else:
            modified = mark_body(
                content,
                hint=selector_hint,
                remember=selector_remember,
                title=selector_title,
            )

        if modified == content or not has_pagevault_elements(modified):
            skipped += 1
            continue

        rel_path = _relative_path(input_path)

        # Write in-place
        try:
            input_path.write_text(modified, encoding="utf-8")
            click.echo(f"Marked: {rel_path}")
            processed += 1
        except OSError as e:
            click.echo(f"Error writing {rel_path}: {e}", err=True)

    click.echo(f"\n{processed} file(s) marked, {skipped} skipped")
