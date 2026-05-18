"""lock command."""

from pathlib import Path

import click

from pagevault.config import load_config
from pagevault.crypto import PagevaultError

from ..shared import (
    _collect_files,
    _default_output_dir,
    _determine_operation_mode,
    _exclude_under_output_dir,
    _is_html,
    _lock_html_files,
    _resolve_password_and_users,
    _validate_flags_for_mode,
    _wrap_single_file,
    _wrap_site_directory,
)


@click.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("-r", "--recursive", is_flag=True, help="Process directories recursively")
@click.option(
    "-d",
    "--directory",
    "output_dir",
    type=click.Path(),
    help="Output directory (default: _locked/)",
)
@click.option("-p", "--password", help="Encryption password (or use config/env)")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
@click.option("--dry-run", is_flag=True, help="Show what would be done without changes")
@click.option(
    "--css",
    "css_path",
    type=click.Path(exists=True),
    help="Custom CSS file for pagevault elements (replaces default styles)",
)
@click.option(
    "-s",
    "--selector",
    "selectors",
    multiple=True,
    help="CSS selector(s) to encrypt (can specify multiple)",
)
@click.option(
    "--hint",
    "selector_hint",
    help="Password hint for elements matched by selectors",
)
@click.option(
    "--remember",
    "selector_remember",
    type=click.Choice(["none", "session", "local", "ask"]),
    help="Remember mode for elements matched by selectors",
)
@click.option(
    "--title",
    "selector_title",
    help="Title for encrypted region (replaces default 'Protected Content')",
)
@click.option(
    "-u",
    "--username",
    help="Username for single-user encryption (requires -p)",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(),
    help="Output file for --site or single non-HTML file (default: <name>.html)",
)
@click.option(
    "--site",
    is_flag=True,
    help="Bundle directory as encrypted site",
)
@click.option(
    "--entry",
    default="index.html",
    help="Entry point HTML file for --site mode (default: index.html)",
)
@click.option(
    "--pad",
    is_flag=True,
    help="Pad content to power-of-2 boundary before encryption (prevents size leakage)",
)
@click.option(
    "--wrap",
    is_flag=True,
    help="Force file-wrapping mode (encrypts entire file, including HTML head/title)",
)
@click.option(
    "--users",
    "user_filter",
    default=None,
    help="Comma-separated usernames to encrypt for (subset of configured users)",
)
def lock(
    paths,
    recursive,
    output_dir,
    password,
    config_path,
    dry_run,
    css_path,
    selectors,
    selector_hint,
    selector_remember,
    selector_title,
    username,
    output_path,
    site,
    entry,
    pad,
    wrap,
    user_filter,
):
    """Encrypt files into password-protected HTML.

    For HTML files: encrypts <pagevault> regions (or entire body if none marked).
    For other files: wraps the entire file into self-contained encrypted HTML.
    For directories: processes all supported files individually.
    With --site: bundles entire directory into a single encrypted HTML site.
    With --wrap: forces file-wrapping for HTML (encrypts everything).

    \b
    Examples:
      pagevault lock page.html                    # Encrypt HTML file
      pagevault lock report.pdf                   # Wrap PDF as encrypted HTML
      pagevault lock mysite/ -r                   # Encrypt all files recursively
      pagevault lock mysite/ --site               # Bundle as encrypted site
      pagevault lock page.html -s "#secret"       # Encrypt only #secret element
      pagevault lock file.html -s "#admin" --title "Admin Panel" -p "admin-pw"
      pagevault lock page.html --wrap             # Wrap entire HTML as opaque file
    """
    if not paths:
        raise click.UsageError("No files or directories specified")

    # 1. Determine operation mode
    mode, target_paths = _determine_operation_mode(paths, site, recursive, wrap)

    # 2. Validate flags for mode
    _validate_flags_for_mode(
        mode,
        selectors,
        css_path,
        selector_hint,
        selector_remember,
        selector_title,
        output_dir,
        output_path,
        recursive,
        wrap_flag=wrap,
    )

    # 3. Load configuration
    try:
        config = load_config(
            config_path=Path(config_path) if config_path else None,
            start_path=Path(paths[0]) if paths else None,
            password_override=password,
        )
    except PagevaultError as e:
        raise click.ClickException(str(e)) from e

    # 4. Resolve password and users
    users, pwd = _resolve_password_and_users(config, password, username)

    # 4b. Apply --users filter if specified
    if user_filter:
        if not users:
            raise click.UsageError(
                "--users requires multi-user config (users: section in config)"
            )
        requested = [u.strip() for u in user_filter.split(",")]
        unknown = [u for u in requested if u not in users]
        if unknown:
            raise click.UsageError(f"Unknown user(s): {', '.join(unknown)}")
        users = {u: users[u] for u in requested}

    # 5. Route to appropriate handler
    effective_pad = pad or config.pad
    out_opt = Path(output_path) if output_path else None

    if mode == "lock_html":
        output_base = _default_output_dir(output_dir, "_locked")
        files = _collect_files(tuple(str(p) for p in target_paths), recursive)
        files = _exclude_under_output_dir(
            files, output_base, tuple(str(p) for p in target_paths)
        )

        if not files:
            click.echo("No HTML files found")
            return

        processed, skipped = _lock_html_files(
            files,
            config,
            users,
            pwd,
            output_base,
            dry_run,
            css_path,
            selectors,
            selector_hint,
            selector_remember,
            selector_title,
            paths,
            pad=effective_pad,
        )

        click.echo(f"\n{processed} file(s) locked, {skipped} skipped")

    elif mode == "wrap_file":
        # File wrapping (non-HTML, or HTML with --wrap)
        if wrap and not output_path:
            # --wrap mode: use -d directory logic (like lock_html)
            output_base = _default_output_dir(output_dir, "_locked")
            output_base.mkdir(parents=True, exist_ok=True)
            for path in target_paths:
                # HTML files keep their name; non-HTML get .html suffix
                dest_name = path.name if _is_html(path) else f"{path.name}.html"
                _wrap_single_file(
                    path,
                    config,
                    users,
                    pwd,
                    output_base / dest_name,
                    dry_run,
                    pad=effective_pad,
                )
        else:
            for path in target_paths:
                _wrap_single_file(
                    path, config, users, pwd, out_opt, dry_run, pad=effective_pad
                )

    elif mode == "wrap_site":
        for path in target_paths:
            _wrap_site_directory(
                path, config, users, pwd, out_opt, entry, dry_run, pad=effective_pad
            )
