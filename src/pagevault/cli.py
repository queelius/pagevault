"""Command-line interface for pagevault."""

import sys
from pathlib import Path

import click
import yaml

from . import __version__
from .config import (
    CONFIG_FILENAME,
    config_to_dict,
    create_default_config,
    create_global_config,
    find_config_file,
    get_global_config_path,
    load_config,
    load_global_config,
    update_config_users,
)
from .crypto import PagevaultError, salt_to_hex
from .parser import (
    has_pagevault_elements,
    mark_body,
    mark_elements,
    process_file,
    sync_html_keys,
)


@click.group()
@click.version_option(version=__version__, prog_name="pagevault")
def main():
    """Password-protect content in HTML and encrypt arbitrary files.

    pagevault encrypts <pagevault> regions in HTML files for mixed public/private
    content on static sites, and wraps arbitrary files into encrypted HTML.

    \b
    Quick start:
      pagevault config init               # Create .pagevault.yaml
      pagevault mark index.html           # Tag elements for encryption
      pagevault lock index.html           # Encrypt marked HTML regions
      pagevault lock paper.pdf            # Wrap file as encrypted HTML
      pagevault lock mysite/ --site       # Bundle directory as encrypted site
      pagevault unlock _locked/           # Restore original content
      pagevault sync _locked/ -r          # Re-wrap keys for current users
    """
    pass


@main.command()
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


# Helper functions for unified lock command
def _determine_operation_mode(
    paths: tuple, site_flag: bool, recursive: bool, wrap_flag: bool = False
) -> tuple[str, list[Path]]:
    """Determine operation mode: 'lock_html', 'wrap_file', or 'wrap_site'.

    Returns:
        Tuple of (mode, target_paths)

    Raises:
        click.UsageError: For invalid path/flag combinations
    """
    if site_flag:
        # --site mode: must be directory
        for path_str in paths:
            path = Path(path_str)
            if not path.is_dir():
                raise click.UsageError("--site requires directory path(s), not files")
        return ("wrap_site", [Path(p) for p in paths])

    if wrap_flag:
        # --wrap: force file-wrapping for all files (including HTML)
        all_files = []
        for path_str in paths:
            path = Path(path_str)
            if path.is_file():
                all_files.append(path)
            elif path.is_dir():
                raise click.UsageError(
                    "--wrap requires files, not directories. "
                    "Use --site for directories."
                )
        if not all_files:
            raise click.UsageError("No files found to wrap")
        return ("wrap_file", all_files)

    # Check file types
    html_files = []
    non_html_files = []

    for path_str in paths:
        path = Path(path_str)
        if path.is_file():
            if path.suffix.lower() in {".html", ".htm"}:
                html_files.append(path)
            else:
                non_html_files.append(path)
        elif path.is_dir():
            html_files.append(path)  # Will be handled by recursive logic

    # Can't mix HTML and non-HTML
    if html_files and non_html_files:
        raise click.UsageError(
            "Cannot mix HTML and non-HTML files. Process separately or use --site."
        )

    if html_files:
        return ("lock_html", html_files)
    elif non_html_files:
        return ("wrap_file", non_html_files)
    else:
        return ("lock_html", [Path(p) for p in paths])


def _validate_flags_for_mode(
    mode: str,
    selectors: tuple,
    css_path: str | None,
    hint: str | None,
    remember: str | None,
    title: str | None,
    output_dir: str | None,
    output_path: str | None,
    entry: str,
    recursive: bool,
    wrap_flag: bool = False,
) -> None:
    """Validate flag compatibility with operation mode.

    Raises:
        click.UsageError: For incompatible flag combinations
    """
    if mode == "wrap_site":
        if selectors or css_path or hint or remember or title:
            raise click.UsageError(
                "--site incompatible with "
                "--selector/--css/--hint/--remember/--title flags"
            )
        if recursive:
            raise click.UsageError("--site already includes all files, -r not needed")
        if output_dir:
            raise click.UsageError("--site uses -o/--output, not -d/--directory")

    elif mode == "wrap_file":
        if selectors or css_path or hint or remember or title:
            raise click.UsageError(
                "Selector/CSS flags only work with HTML files, not non-HTML files"
            )
        if not wrap_flag and output_dir:
            raise click.UsageError("Non-HTML wrap uses -o/--output, not -d/--directory")

    elif mode == "lock_html":
        if output_path:
            raise click.UsageError("HTML lock uses -d/--directory, not -o/--output")


def _resolve_password_and_users(
    config, password: str | None, username: str | None
) -> tuple[dict | None, str | None]:
    """Resolve password and users configuration.

    Returns:
        Tuple of (users_dict, password_str)
        - users_dict: dict of {username: password} for multi-user, or None
        - password_str: single password for single-user, or None
    """
    users = config.users
    if username and password:
        # Ad-hoc single-user encryption with -u and -p
        users = {username: password}
        pwd = None
    elif username and not password:
        raise click.UsageError("-u/--username requires -p/--password")
    elif password and users:
        # CLI -p flag wins, single-user mode
        users = None
        pwd = password
    elif users:
        pwd = None  # Not needed, users dict has passwords
    else:
        pwd = config.password
        if not pwd:
            pwd = click.prompt("Enter encryption password", hide_input=True)

    return users, pwd


def _lock_html_files(
    files: list[Path],
    config,
    users: dict | None,
    password: str | None,
    output_base: Path,
    dry_run: bool,
    css_path: str | None,
    selectors: tuple,
    selector_hint: str | None,
    selector_remember: str | None,
    selector_title: str | None,
    source_paths: tuple,
    pad: bool = False,
) -> tuple[int, int]:
    """Lock HTML files. Returns (processed, skipped)."""

    # Load custom CSS if provided
    custom_css = None
    if css_path:
        try:
            custom_css = Path(css_path).read_text(encoding="utf-8")
        except OSError as e:
            raise click.ClickException(f"Cannot read CSS file: {e}")

    processed = 0
    skipped = 0

    for input_path in files:
        # Determine output path
        output_path = _get_output_path(input_path, source_paths, output_base)

        # Read file content
        try:
            content = input_path.read_text(encoding="utf-8")
        except OSError as e:
            click.echo(f"Warning: Cannot read {input_path}: {e}", err=True)
            continue

        # Apply wrapping
        content_was_wrapped = False
        if selectors:
            content = mark_elements(
                content,
                list(selectors),
                hint=selector_hint,
                remember=selector_remember,
                title=selector_title,
            )
            content_was_wrapped = has_pagevault_elements(content)
        elif not has_pagevault_elements(content):
            # Default: wrap all body content
            content = mark_body(
                content,
                hint=selector_hint,
                remember=selector_remember,
                title=selector_title,
            )
            content_was_wrapped = has_pagevault_elements(content)

        # Check for pagevault elements (including newly wrapped ones)
        if not has_pagevault_elements(content):
            skipped += 1
            continue

        rel_input = _relative_path(input_path)
        rel_output = _relative_path(output_path)

        if dry_run:
            click.echo(f"Would lock: {rel_input} -> {rel_output}")
            processed += 1
            continue

        try:
            # If content was wrapped (selector or body), write modified content
            # to output first, then encrypt from output
            if content_was_wrapped or selectors:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(content, encoding="utf-8")
                changed = process_file(
                    output_path,
                    output_path,
                    password=password,
                    config=config,
                    mode="lock",
                    custom_css=custom_css,
                    users=users,
                    pad=pad,
                )
            else:
                changed = process_file(
                    input_path,
                    output_path,
                    password=password,
                    config=config,
                    mode="lock",
                    custom_css=custom_css,
                    users=users,
                    pad=pad,
                )
            if changed:
                click.echo(f"Locked: {rel_input} -> {rel_output}")
                processed += 1
            else:
                skipped += 1
        except PagevaultError as e:
            click.echo(f"Error processing {rel_input}: {e}", err=True)

    return processed, skipped


def _wrap_single_file(
    path: Path,
    config,
    users: dict | None,
    password: str | None,
    output_path: Path | None,
    dry_run: bool,
    pad: bool = False,
) -> Path:
    """Wrap a single non-HTML file into encrypted HTML.

    Returns:
        Path to output file
    """
    from .wrap import wrap_file

    # Determine output path
    if output_path:
        result_path = output_path
    else:
        result_path = path.with_suffix(".html")

    if dry_run:
        rel_in = _relative_path(path)
        rel_out = _relative_path(result_path)
        click.echo(f"Would wrap: {rel_in} -> {rel_out}")
        return result_path

    try:
        result = wrap_file(
            path,
            password=password,
            config=config,
            output_path=result_path,
            users=users,
            pad=pad,
        )
        click.echo(f"Wrapped: {_relative_path(path)} -> {_relative_path(result)}")
        return result
    except PagevaultError as e:
        raise click.ClickException(str(e))


def _wrap_site_directory(
    path: Path,
    config,
    users: dict | None,
    password: str | None,
    output_path: Path | None,
    entry: str,
    dry_run: bool,
    pad: bool = False,
) -> Path:
    """Wrap a directory into encrypted site HTML.

    Returns:
        Path to output file
    """
    from .wrap import wrap_site

    # Determine output path
    if output_path:
        result_path = output_path
    else:
        # Default: place <dirname>.html in parent directory
        result_path = path.parent / f"{path.name}.html"

    if dry_run:
        rel_in = _relative_path(path)
        rel_out = _relative_path(result_path)
        click.echo(f"Would wrap site: {rel_in} -> {rel_out}")
        return result_path

    try:
        result = wrap_site(
            path,
            password=password,
            config=config,
            output_path=result_path,
            users=users,
            entry=entry,
            pad=pad,
        )
        click.echo(f"Wrapped site: {_relative_path(path)} -> {_relative_path(result)}")
        return result
    except PagevaultError as e:
        raise click.ClickException(str(e))


@main.command()
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
    try:
        mode, target_paths = _determine_operation_mode(paths, site, recursive, wrap)
    except click.UsageError:
        raise

    # 2. Validate flags for mode
    try:
        _validate_flags_for_mode(
            mode,
            selectors,
            css_path,
            selector_hint,
            selector_remember,
            selector_title,
            output_dir,
            output_path,
            entry,
            recursive,
            wrap_flag=wrap,
        )
    except click.UsageError:
        raise

    # 3. Load configuration
    try:
        config = load_config(
            config_path=Path(config_path) if config_path else None,
            start_path=Path(paths[0]) if paths else None,
            password_override=password,
        )
    except PagevaultError as e:
        raise click.ClickException(str(e))

    # 4. Resolve password and users
    try:
        users, pwd = _resolve_password_and_users(config, password, username)
    except click.UsageError:
        raise

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
    if mode == "lock_html":
        # HTML locking: set default output directory
        if output_dir is None:
            output_dir = "_locked"
            click.echo(f"Writing to {output_dir}/ (use -d to change)")
        output_base = Path(output_dir)

        # Collect HTML files
        files = _collect_files(tuple(str(p) for p in target_paths), recursive)

        if not files:
            click.echo("No HTML files found")
            return

        # Process HTML files
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
            pad=pad or config.pad,
        )

        click.echo(f"\n{processed} file(s) locked, {skipped} skipped")

    elif mode == "wrap_file":
        # File wrapping (non-HTML, or HTML with --wrap)
        if wrap and not output_path:
            # --wrap mode: use -d directory logic (like lock_html)
            if output_dir is None:
                output_dir = "_locked"
                click.echo(f"Writing to {output_dir}/ (use -d to change)")
            output_base = Path(output_dir)
            output_base.mkdir(parents=True, exist_ok=True)
            for path in target_paths:
                # HTML files keep their name; non-HTML get .html suffix
                if path.suffix.lower() in {".html", ".htm"}:
                    dest = output_base / path.name
                else:
                    dest = output_base / f"{path.name}.html"
                _wrap_single_file(
                    path, config, users, pwd, dest, dry_run, pad=pad or config.pad
                )
        else:
            for path in target_paths:
                _wrap_single_file(
                    path,
                    config,
                    users,
                    pwd,
                    Path(output_path) if output_path else None,
                    dry_run,
                    pad=pad or config.pad,
                )

    elif mode == "wrap_site":
        # Site wrapping
        for path in target_paths:
            _wrap_site_directory(
                path,
                config,
                users,
                pwd,
                Path(output_path) if output_path else None,
                entry,
                dry_run,
                pad=pad or config.pad,
            )


@main.command()
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
    """Unlock (decrypt) HTML files with encrypted <pagevault> regions.

    Returns files to "marked" state (plaintext inside <pagevault> wrappers).

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
        from .parser import unlock_html

        if len(paths) != 1 or not Path(paths[0]).is_file():
            raise click.UsageError("--stdout requires exactly one file")

        input_path = Path(paths[0])
        try:
            content = input_path.read_text(encoding="utf-8")
        except OSError as e:
            raise click.ClickException(f"Cannot read {input_path}: {e}")

        if not has_pagevault_elements(content):
            raise click.ClickException("File has no encrypted pagevault elements")

        try:
            decrypted = unlock_html(content, pwd, username=user)
        except PagevaultError as e:
            raise click.ClickException(str(e))

        click.echo(decrypted, nl=False)
        return

    # Set default output directory
    if output_dir is None:
        output_dir = "_unlocked"
        click.echo(f"Writing to {output_dir}/ (use -d to change)")
    output_base = Path(output_dir)

    # Collect files to process
    files = _collect_files(paths, recursive)

    if not files:
        click.echo("No HTML files found")
        return

    # Process files
    processed = 0
    skipped = 0

    for input_path in files:
        output_path = _get_output_path(input_path, paths, output_base)

        # Quick check for pagevault elements
        try:
            content = input_path.read_text(encoding="utf-8")
        except OSError as e:
            click.echo(f"Warning: Cannot read {input_path}: {e}", err=True)
            continue

        if not has_pagevault_elements(content):
            skipped += 1
            continue

        rel_input = _relative_path(input_path)
        rel_output = _relative_path(output_path)

        if dry_run:
            click.echo(f"Would unlock: {rel_input} -> {rel_output}")
            processed += 1
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
                processed += 1
            else:
                skipped += 1
        except PagevaultError as e:
            click.echo(f"Error processing {rel_input}: {e}", err=True)

    click.echo(f"\n{processed} file(s) unlocked, {skipped} skipped")


@main.command()
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
        # Resolve managed globs relative to config file location
        config_dir = config.config_path.parent
        files = []
        for pattern in config.managed:
            matched = sorted(config_dir.glob(pattern))
            files.extend(
                f
                for f in matched
                if f.is_file() and f.suffix.lower() in {".html", ".htm"}
            )
        files = sorted(set(files))
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


@main.command()
@click.argument("path", type=click.Path(exists=True))
def info(path):
    """Inspect an encrypted HTML file.

    Shows encryption metadata, viewer info, and runtime details
    without requiring a password.

    \b
    Examples:
      pagevault info encrypted.html
      pagevault info _locked/index.html
    """
    import re

    from .crypto import inspect_payload

    file_path = Path(path)
    if not file_path.is_file():
        raise click.ClickException(f"Not a file: {file_path}")

    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError as e:
        raise click.ClickException(f"Cannot read {file_path}: {e}")

    if not has_pagevault_elements(content):
        raise click.ClickException("File has no pagevault elements")

    # Parse HTML to extract encrypted regions
    from bs4 import BeautifulSoup

    try:
        soup = BeautifulSoup(content, "lxml")
    except Exception:
        soup = BeautifulSoup(content, "html.parser")

    # Check for v3 chunked format (pv-meta script tag)
    pv_meta_el = soup.find("script", {"id": "pv-meta"})
    if pv_meta_el:
        import json

        from .crypto import inspect_payload_v3

        try:
            envelope = json.loads(pv_meta_el.string)
        except (json.JSONDecodeError, TypeError) as e:
            raise click.ClickException(f"Invalid pv-meta JSON: {e}")

        info_data = inspect_payload_v3(envelope)

        click.echo(f"File: {_relative_path(file_path)}")
        click.echo("Format:         v3 chunked")
        click.echo(f"Version:        v{info_data['version']}")
        click.echo(f"Algorithm:      {info_data['algorithm']}")
        click.echo(f"KDF:            {info_data['kdf']}")
        click.echo(f"Iterations:     {info_data['iterations']:,}")
        click.echo(f"Key blobs:      {info_data['key_count']}")
        click.echo(f"Chunk size:     {_format_size(info_data['chunk_size'])}")
        click.echo(f"Chunks:         {info_data['chunk_count']}")
        click.echo(f"Total size:     {_format_size(info_data['total_size'])}")

        if "content_hash" in envelope:
            click.echo(f"Content hash:   {envelope['content_hash']}")

        # Count chunk script tags
        chunk_count = 0
        while soup.find("script", {"id": f"pv-{chunk_count}"}):
            chunk_count += 1
        click.echo(f"Chunk tags:     {chunk_count}")

        # Check pagevault element for mode
        pv_el = soup.find("pagevault")
        if pv_el:
            mode = pv_el.get("data-mode", "single")
            click.echo(f"Mode:           {mode}")

        # Runtime info (same as v2)
        runtime_scripts = soup.find_all("script", {"data-pagevault-runtime": True})
        runtime_styles = soup.find_all("style", {"data-pagevault-runtime": True})
        click.echo(f"Runtime scripts: {len(runtime_scripts)}")
        click.echo(f"Runtime styles:  {len(runtime_styles)}")

        # Check for viewer dispatch table
        viewer_re = r"'([a-z]+/[a-z0-9*+\-.]+)':\s*__pv_"
        for script in runtime_scripts:
            script_text = script.string or ""
            viewer_matches = re.findall(viewer_re, script_text)
            if viewer_matches:
                click.echo(f"Viewers:         {', '.join(viewer_matches)}")

        # Check for JSZip (site mode indicator)
        jszip_present = any("ZipReader" in (s.string or "") for s in runtime_scripts)
        if jszip_present:
            click.echo("JSZip shim:      yes")

        click.echo(f"pagevault:       v{__version__}")
        return

    # --- v2 region-encrypted format ---
    elements = soup.find_all("pagevault")
    encrypted_regions = [el for el in elements if el.has_attr("data-encrypted")]

    if not encrypted_regions:
        raise click.ClickException("No encrypted regions found")

    click.echo(f"File: {_relative_path(file_path)}")
    click.echo(f"Encrypted regions: {len(encrypted_regions)}")
    click.echo()

    for i, el in enumerate(encrypted_regions):
        payload = el.get("data-encrypted", "")
        content_hash_val = el.get("data-content-hash", "")
        mode = el.get("data-mode", "single")
        hint = el.get("data-hint", "")
        title = el.get("data-title", "")
        remember = el.get("data-remember", "")

        click.echo(f"--- Region {i + 1} ---")

        try:
            info_data = inspect_payload(payload)
            click.echo(f"  Version:      v{info_data['version']}")
            click.echo(f"  Algorithm:    {info_data['algorithm']}")
            click.echo(f"  KDF:          {info_data['kdf']}")
            click.echo(f"  Iterations:   {info_data['iterations']:,}")
            click.echo(f"  Key blobs:    {info_data['key_count']}")
            if "salt_length" in info_data:
                click.echo(f"  Salt:         {info_data['salt_length']} bytes")
            if "iv_length" in info_data:
                click.echo(f"  IV:           {info_data['iv_length']} bytes")
            if "ciphertext_length" in info_data:
                ct_len = info_data["ciphertext_length"]
                if ct_len < 1024:
                    click.echo(f"  Ciphertext:   {ct_len} B")
                elif ct_len < 1048576:
                    click.echo(f"  Ciphertext:   {ct_len / 1024:.1f} KB")
                else:
                    click.echo(f"  Ciphertext:   {ct_len / 1048576:.1f} MB")
        except PagevaultError as e:
            click.echo(f"  Error parsing payload: {e}")

        click.echo(f"  Mode:         {mode}")
        if content_hash_val:
            click.echo(f"  Content hash: {content_hash_val}")
        if hint:
            click.echo(f"  Hint:         {hint}")
        if title:
            click.echo(f"  Title:        {title}")
        if remember:
            click.echo(f"  Remember:     {remember}")
        click.echo()

    # Viewer info: check for embedded viewer scripts
    runtime_scripts = soup.find_all("script", {"data-pagevault-runtime": True})
    runtime_styles = soup.find_all("style", {"data-pagevault-runtime": True})
    click.echo(f"Runtime scripts: {len(runtime_scripts)}")
    click.echo(f"Runtime styles:  {len(runtime_styles)}")

    # Check for viewer dispatch table
    for script in runtime_scripts:
        script_text = script.string or ""
        viewer_matches = re.findall(r"'([a-z]+/[a-z0-9*+\-.]+)':\s*__pv_", script_text)
        if viewer_matches:
            click.echo(f"Viewers:         {', '.join(viewer_matches)}")

    # Check for wrap type
    wrap_el = soup.find("pagevault", {"data-wrap-type": True})
    if wrap_el:
        click.echo(f"Wrap type:       {wrap_el.get('data-wrap-type')}")
        if wrap_el.get("data-filename"):
            click.echo(f"Filename:        {wrap_el.get('data-filename')}")
        if wrap_el.get("data-entry"):
            click.echo(f"Entry point:     {wrap_el.get('data-entry')}")

    # Check for JSZip (site mode indicator)
    jszip_present = any("ZipReader" in (s.string or "") for s in runtime_scripts)
    if jszip_present:
        click.echo("JSZip shim:      yes")

    click.echo(f"pagevault:       v{__version__}")


@main.command()
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
def audit(config_path):
    """Run comprehensive health checks on configuration and encrypted files.

    Checks password strength, salt quality, config hygiene, and file integrity.

    \b
    Examples:
      pagevault audit
      pagevault audit -c .pagevault.yaml
    """
    import math
    import os

    # Load configuration
    try:
        cfg = load_config(config_path=Path(config_path) if config_path else None)
    except PagevaultError as e:
        raise click.ClickException(str(e))

    issues = []
    warnings = []
    passed = []

    # --- Password strength ---
    passwords_to_check = []
    if cfg.password:
        passwords_to_check.append(("password", cfg.password))
    if cfg.users:
        for uname, upwd in cfg.users.items():
            passwords_to_check.append((f"user '{uname}'", upwd))

    for label, pwd in passwords_to_check:
        length = len(pwd)
        if length < 8:
            issues.append(f"WEAK: {label} password is only {length} chars (minimum 8)")
        elif length < 12:
            warnings.append(f"{label} password is {length} chars (12+ recommended)")
        else:
            passed.append(f"{label} password length OK ({length} chars)")

        # Character class analysis
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_special = any(not c.isalnum() for c in pwd)
        classes = sum([has_lower, has_upper, has_digit, has_special])

        if classes == 1:
            if has_lower:
                issues.append(f"WEAK: {label} password is all lowercase")
            elif has_digit:
                issues.append(f"WEAK: {label} password is all numeric")
        elif classes == 2:
            warnings.append(f"{label} password uses only {classes} character classes")

        # Entropy estimate (bits per char * length)
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32
        if charset_size > 0:
            entropy = length * math.log2(charset_size)
            if entropy < 40:
                issues.append(
                    f"WEAK: {label} password entropy ~{entropy:.0f} bits (<40)"
                )
            elif entropy < 60:
                warnings.append(
                    f"{label} password entropy ~{entropy:.0f} bits (60+ recommended)"
                )
            else:
                passed.append(f"{label} password entropy ~{entropy:.0f} bits")

    if not passwords_to_check:
        warnings.append("No passwords configured")

    # --- Salt quality ---
    if cfg.salt:
        if len(cfg.salt) < 16:
            issues.append(f"Salt is only {len(cfg.salt)} bytes (minimum 16)")
        elif cfg.salt == b"\x00" * len(cfg.salt):
            issues.append("Salt is all zeros")
        else:
            passed.append(f"Salt OK ({len(cfg.salt)} bytes)")
    else:
        warnings.append("No salt configured (random salt will be used per encryption)")

    # --- Config hygiene ---
    if cfg.config_path:
        config_dir = cfg.config_path.parent
        gitignore = config_dir / ".gitignore"
        if gitignore.is_file():
            gitignore_content = gitignore.read_text(encoding="utf-8", errors="replace")
            config_name = cfg.config_path.name
            yaml_in_gitignore = ".pagevault.yaml" in gitignore_content
            if config_name in gitignore_content or yaml_in_gitignore:
                passed.append(f"{config_name} is in .gitignore")
            else:
                issues.append(
                    f"{config_name} is NOT in .gitignore — passwords may be committed"
                )
        else:
            warnings.append("No .gitignore found in config directory")

    # Check environment variable
    if os.environ.get("PAGEVAULT_PASSWORD"):
        warnings.append(
            "PAGEVAULT_PASSWORD is set in environment — "
            "visible to other processes and shell history"
        )

    # --- File integrity (check managed files if available) ---
    managed_files = []
    if cfg.managed and cfg.config_path:
        config_dir = cfg.config_path.parent
        for pattern in cfg.managed:
            matched = sorted(config_dir.glob(pattern))
            managed_files.extend(
                f
                for f in matched
                if f.is_file() and f.suffix.lower() in {".html", ".htm"}
            )
        managed_files = sorted(set(managed_files))

    if managed_files:
        from bs4 import BeautifulSoup

        checked = 0
        for file_path in managed_files:
            try:
                html = file_path.read_text(encoding="utf-8")
            except OSError:
                warnings.append(f"Cannot read managed file: {file_path.name}")
                continue

            if not has_pagevault_elements(html):
                continue

            try:
                soup = BeautifulSoup(html, "lxml")
            except Exception:
                soup = BeautifulSoup(html, "html.parser")

            for el in soup.find_all("pagevault", {"data-encrypted": True}):
                if el.get("data-content-hash"):
                    checked += 1

        if checked > 0:
            passed.append(f"Found {checked} encrypted region(s) with content hashes")
    else:
        warnings.append("No managed files configured for integrity checks")

    # --- Output results ---
    click.echo("pagevault audit")
    click.echo("=" * 40)

    if issues:
        click.echo(f"\nISSUES ({len(issues)}):")
        for issue in issues:
            click.echo(f"  [!] {issue}")

    if warnings:
        click.echo(f"\nWARNINGS ({len(warnings)}):")
        for warning in warnings:
            click.echo(f"  [?] {warning}")

    if passed:
        click.echo(f"\nPASSED ({len(passed)}):")
        for p in passed:
            click.echo(f"  [+] {p}")

    click.echo()
    if issues:
        click.echo(f"Result: {len(issues)} issue(s) found")
        raise SystemExit(1)
    elif warnings:
        click.echo(f"Result: OK with {len(warnings)} warning(s)")
    else:
        click.echo("Result: All checks passed")


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-p", "--password", help="Password to verify (prompts if omitted)")
@click.option("-u", "--username", help="Username for multi-user content")
def check(path, password, username):
    """Verify a password against an encrypted file.

    Performs fast key verification (one PBKDF2 + one AES-GCM unwrap).
    Does NOT decrypt content.

    Exit code 0 = password correct, 1 = incorrect.

    \b
    Examples:
      pagevault check encrypted.html -p "test-password"
      pagevault check _locked/file.html -p "pw" -u alice
      pagevault check encrypted.html              # prompts for password
    """
    if not password:
        password = click.prompt("Password", hide_input=True)
    from .crypto import verify_password

    file_path = Path(path)
    if not file_path.is_file():
        raise click.ClickException(f"Not a file: {file_path}")

    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError as e:
        raise click.ClickException(f"Cannot read {file_path}: {e}")

    if not has_pagevault_elements(content):
        raise click.ClickException("File has no pagevault elements")

    # Parse to find first encrypted region
    from bs4 import BeautifulSoup

    try:
        soup = BeautifulSoup(content, "lxml")
    except Exception:
        soup = BeautifulSoup(content, "html.parser")

    # Check for v3 chunked format first
    pv_meta_el = soup.find("script", {"id": "pv-meta"})
    if pv_meta_el:
        import json

        from .crypto import verify_password_v3

        try:
            envelope = json.loads(pv_meta_el.string)
        except (json.JSONDecodeError, TypeError) as e:
            raise click.ClickException(f"Invalid pv-meta JSON: {e}")

        try:
            result = verify_password_v3(envelope, password, username=username)
        except PagevaultError as e:
            raise click.ClickException(str(e))

        if result:
            click.echo("Password correct")
            raise SystemExit(0)
        else:
            click.echo("Password incorrect")
            raise SystemExit(1)

    # Fall through to v2 region-encrypted check
    encrypted_el = soup.find("pagevault", {"data-encrypted": True})
    if not encrypted_el:
        raise click.ClickException("No encrypted regions found")

    payload = encrypted_el.get("data-encrypted", "")
    if not payload:
        raise click.ClickException("Empty encrypted payload")

    try:
        result = verify_password(payload, password, username=username)
    except PagevaultError as e:
        raise click.ClickException(str(e))

    if result:
        click.echo("Password correct")
        raise SystemExit(0)
    else:
        click.echo("Password incorrect")
        raise SystemExit(1)


@main.group()
def config():
    """Manage pagevault configuration."""
    pass


@config.command("init")
@click.option(
    "-d",
    "--directory",
    type=click.Path(),
    default=".",
    help="Directory to create config in",
)
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="Create global user config (~/.config/pagevault/config.yaml)",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing config file",
)
def config_init(directory, is_global, force):
    """Create a new pagevault configuration file.

    Generates a .pagevault.yaml config file with a random salt and example settings.
    Remember to add .pagevault.yaml to your .gitignore!

    With --global, creates ~/.config/pagevault/config.yaml with your personal
    credentials that are automatically merged into every project's config.
    """
    if is_global:
        _init_global(force=force)
        return

    try:
        config_path = create_default_config(Path(directory))
        click.echo(f"Created: {config_path}")
        click.echo("\nNext steps:")
        click.echo("  1. Edit the password in .pagevault.yaml")
        click.echo("  2. Add .pagevault.yaml to .gitignore")
        click.echo("  3. Run: pagevault lock <file.html>")
    except PagevaultError as e:
        raise click.ClickException(str(e))


def _init_global(force: bool) -> None:
    """Create a global user configuration."""
    # Prompt for user credentials
    username = click.prompt("Username")
    if not username:
        raise click.ClickException("Username cannot be empty.")
    if ":" in username:
        raise click.ClickException(
            f"Username '{username}' cannot contain ':' (used as delimiter)."
        )

    user_password = click.prompt(
        "Password", hide_input=True, confirmation_prompt=True
    )
    if not user_password:
        raise click.ClickException("Password cannot be empty.")

    try:
        global_path = create_global_config(
            users={username: user_password},
            default_user=username,
            force=force,
        )
        click.echo(f"Created: {global_path}")
        click.echo(f"  User: {username}")
        click.echo()
        click.echo("Your credentials will be merged into every project's config.")
    except PagevaultError as e:
        raise click.ClickException(str(e))


@config.command("show")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(),
    help="Config file path",
)
@click.option(
    "--show-passwords",
    is_flag=True,
    help="Show passwords in plaintext (masked by default)",
)
def config_show(config_path, show_passwords):
    """Display effective configuration with source annotations.

    Shows where each value comes from: local config, global config,
    or merged from both. Passwords are masked by default.
    """
    # Resolve local config path
    if config_path:
        local_path = Path(config_path).resolve()
    else:
        local_path = find_config_file()

    has_local = local_path is not None and local_path.exists()
    global_data = load_global_config()
    has_global = bool(global_data)
    global_path = get_global_config_path()

    if not has_local and not has_global:
        click.echo("No config found (no local .pagevault.yaml and no global config).", err=True)
        click.echo("Run 'pagevault config init' to create a local config.", err=True)
        click.echo("Run 'pagevault config init --global' to create a global config.", err=True)
        sys.exit(1)

    local_data: dict = {}
    if has_local:
        try:
            local_data = yaml.safe_load(local_path.read_text(encoding="utf-8")) or {}
        except OSError as e:
            click.echo(f"Error reading config file: {e}", err=True)
            sys.exit(1)

    def _mask(password: str) -> str:
        if show_passwords:
            return password
        return password[:2] + "***" if len(password) > 2 else "***"

    # Header: show config file paths
    if has_local:
        click.echo(f"Local:  {local_path}")
    if has_global:
        click.echo(f"Global: {global_path}")
    click.echo()

    # Password — show source
    local_pw = local_data.get("password")
    global_pw = global_data.get("password")
    if local_pw:
        source = "local (overrides global)" if global_pw else "local"
        click.echo(f"password: {_mask(str(local_pw))}  # {source}")
    elif global_pw:
        click.echo(f"password: {_mask(str(global_pw))}  # global")

    # Salt — show source
    local_salt = local_data.get("salt")
    global_salt = global_data.get("salt")
    if local_salt:
        source = "local (overrides global)" if global_salt else "local"
        click.echo(f"salt: {local_salt}  # {source}")
    elif global_salt:
        click.echo(f"salt: {global_salt}  # global")

    # Users — show source for each
    global_users = global_data.get("users", {})
    local_users = local_data.get("users", {})
    merged_users = {**global_users, **local_users}

    if merged_users:
        click.echo("users:")
        for username, password in merged_users.items():
            masked = _mask(str(password))
            if username in local_users and username in global_users:
                source = "local (overrides global)"
            elif username in local_users:
                source = "local"
            else:
                source = "global"
            click.echo(f"  {username}: {masked}  # {source}")

    # Default user — show source
    local_user = local_data.get("user")
    global_user = global_data.get("user")
    if local_user:
        source = "local (overrides global)" if global_user else "local"
        click.echo(f"user: {local_user}  # {source}")
    elif global_user:
        click.echo(f"user: {global_user}  # global")

    # Defaults — show source
    local_defaults = local_data.get("defaults", {})
    global_defaults = global_data.get("defaults", {})
    if local_defaults or global_defaults:
        click.echo("defaults:")
        for key in ["remember", "remember_days", "auto_prompt"]:
            l_val = local_defaults.get(key) if isinstance(local_defaults, dict) else None
            g_val = global_defaults.get(key) if isinstance(global_defaults, dict) else None
            if l_val is not None:
                source = "local (overrides global)" if g_val is not None else "local"
                click.echo(f"  {key}: {l_val}  # {source}")
            elif g_val is not None:
                click.echo(f"  {key}: {g_val}  # global")


@config.command("where")
@click.option(
    "-d",
    "--directory",
    type=click.Path(exists=True),
    help="Directory to search from",
)
def config_where(directory):
    """Show which config files would be used.

    Shows both the global config and the local project config found
    by searching up the directory tree.
    """
    # Global config
    global_path = get_global_config_path()
    if global_path.exists():
        global_data = load_global_config()
        global_users = list(global_data.get("users", {}).keys())
        click.echo(f"Global config: {global_path}")
        if global_users:
            click.echo(f"  Users: {', '.join(global_users)}")
    else:
        click.echo(f"Global config: {global_path} (not found)")

    # Local config
    start = Path(directory) if directory else Path.cwd()
    config_path = find_config_file(start)

    if config_path:
        click.echo(f"Local config:  {config_path}")
    else:
        click.echo(f"Local config:  No {CONFIG_FILENAME} found (searched from {start})")


@config.command("set")
@click.argument("key")
@click.argument("value", required=False)
@click.option("--global", "is_global", is_flag=True, help="Update global config")
@click.option("--unset", is_flag=True, help="Remove the key entirely")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
def config_set(key, value, is_global, unset, config_path):
    """Set or unset a config value.

    \b
    Examples:
        pagevault config set user alex          # Set default user
        pagevault config set user --unset       # Clear default user
        pagevault config set --global user alex  # Set in global config
    """
    ALLOWED_KEYS = {"user", "password", "pad"}

    if key not in ALLOWED_KEYS:
        raise click.ClickException(
            f"Cannot set '{key}'. Allowed keys: {', '.join(sorted(ALLOWED_KEYS))}"
        )

    if unset and value is not None:
        raise click.ClickException("Cannot specify both a value and --unset.")
    if not unset and value is None:
        raise click.ClickException(f"Provide a value or use --unset to remove '{key}'.")

    try:
        if is_global:
            raw = _load_raw_global()
            use_global = True
        else:
            resolved, use_global = _resolve_config_path(config_path, fallback_global=True)
            with open(resolved) as f:
                raw = yaml.safe_load(f) or {}
    except FileNotFoundError as e:
        raise click.ClickException(str(e))

    if unset:
        if key in raw:
            del raw[key]
        target = "global" if (is_global or use_global) else "local"
        click.echo(f"Unset '{key}' ({target}).")
    else:
        # Type coerce for known keys
        if key == "pad":
            value = value.lower() in ("true", "1", "yes")
        if key == "password":
            click.echo(
                "Warning: This stores the password as plaintext in .pagevault.yaml."
            )
            click.echo("Consider using -p on the command line instead.")
        raw[key] = value
        target = "global" if (is_global or use_global) else "local"
        display_value = str(value).lower() if isinstance(value, bool) else value
        click.echo(f"Set '{key}' = '{display_value}' ({target}).")

    try:
        if is_global or use_global:
            _save_global(raw)
        else:
            _save_local(resolved, raw)
    except (PagevaultError, OSError) as e:
        raise click.ClickException(str(e))


@config.group()
def user():
    """Manage users for multi-user encryption."""
    pass


def _resolve_config_path(config_path: str | None, fallback_global: bool = False) -> tuple[Path, bool]:
    """Find config file from explicit path, directory traversal, or global fallback.

    Args:
        config_path: Explicit path from -c flag, or None.
        fallback_global: If True, fall back to global config when no local found.

    Returns:
        Tuple of (resolved Path, is_global).

    Raises:
        click.ClickException: If no config file found.
    """
    if config_path:
        return Path(config_path), False
    found = find_config_file()
    if found:
        return found, False
    if fallback_global:
        global_path = get_global_config_path()
        if global_path.exists():
            return global_path, True
    raise click.ClickException(
        f"No {CONFIG_FILENAME} found. Run 'pagevault config init' first."
    )


def _load_raw_global() -> dict:
    """Load raw YAML from global config, raising if missing."""
    path = get_global_config_path()
    if not path.exists():
        raise FileNotFoundError(f"Global config not found: {path}")
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _save_local(path: Path, data: dict) -> None:
    """Write data back to a local config file."""
    content = "# pagevault configuration\n"
    content += "# WARNING: Add this file to .gitignore - it contains passwords!\n\n"
    content += yaml.dump(data, default_flow_style=False, sort_keys=False)
    path.write_text(content, encoding="utf-8")


def _save_global(data: dict) -> None:
    """Write data back to global config."""
    path = get_global_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "# pagevault global configuration\n"
    content += "# Personal credentials merged into every project's config.\n\n"
    content += yaml.dump(data, default_flow_style=False, sort_keys=False)
    path.write_text(content, encoding="utf-8")


@user.command("add")
@click.argument("username")
@click.option("-p", "--password", "user_password", help="Password (prompts if omitted)")
@click.option("--global", "is_global", is_flag=True, help="Add to global config")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
def user_add(username, user_password, is_global, config_path):
    """Add a new user to the config.

    Prompts for password interactively unless -p is given.
    Use --global to add the user to your global config instead.
    """
    # Validate username
    if not username:
        raise click.ClickException("Username cannot be empty.")
    if ":" in username:
        raise click.ClickException(
            f"Username '{username}' cannot contain ':' (used as delimiter)."
        )

    # Load config
    try:
        if is_global:
            raw = _load_raw_global()
            use_global = True
        else:
            resolved, use_global = _resolve_config_path(config_path, fallback_global=True)
            with open(resolved) as f:
                raw = yaml.safe_load(f) or {}
    except FileNotFoundError as e:
        raise click.ClickException(str(e))

    users = raw.get("users", {}) or {}

    if username in users:
        raise click.ClickException(
            f"User '{username}' already exists. "
            "Use 'pagevault config user passwd' to change their password."
        )

    # Get password
    if not user_password:
        user_password = click.prompt(
            "Password", hide_input=True, confirmation_prompt=True
        )
    if not user_password:
        raise click.ClickException("Password cannot be empty.")

    users[username] = user_password
    raw["users"] = users

    target = "global" if (is_global or use_global) else "local"
    try:
        if is_global or use_global:
            _save_global(raw)
        else:
            update_config_users(resolved, users)
    except PagevaultError as e:
        raise click.ClickException(str(e))

    click.echo(f"Added user '{username}' ({target}).")
    click.echo("Run 'pagevault sync' to update encrypted files for the new user.")


@user.command("rm")
@click.argument("username")
@click.option("--global", "is_global", is_flag=True, help="Remove from global config")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
def user_rm(username, is_global, config_path):
    """Remove a user from the config.

    Use --global to remove from your global config instead.
    """
    try:
        if is_global:
            raw = _load_raw_global()
            use_global = True
        else:
            resolved, use_global = _resolve_config_path(config_path, fallback_global=True)
            with open(resolved) as f:
                raw = yaml.safe_load(f) or {}
    except FileNotFoundError as e:
        raise click.ClickException(str(e))

    users = raw.get("users", {}) or {}

    if username not in users:
        # Check if user exists in the other tier
        if not (is_global or use_global):
            global_users = load_global_config().get("users", {})
            if username in global_users:
                raise click.ClickException(
                    f"User '{username}' is not in local config "
                    f"(exists in global; use --global to remove)"
                )
        raise click.ClickException(f"User '{username}' not found.")

    del users[username]
    if users:
        raw["users"] = users
    elif "users" in raw:
        del raw["users"]

    # Clear default user if it was the one we just removed
    cleared_default = False
    if raw.get("user") == username:
        del raw["user"]
        cleared_default = True

    target = "global" if (is_global or use_global) else "local"
    try:
        if is_global or use_global:
            _save_global(raw)
        else:
            _save_local(resolved, raw)
    except PagevaultError as e:
        raise click.ClickException(str(e))

    click.echo(f"Removed user '{username}' ({target}).")
    if cleared_default:
        click.echo(f"Cleared default user (was '{username}').")
    click.echo("Run 'pagevault sync' to update encrypted files.")


@user.command("list")
@click.option("--global", "is_global", is_flag=True, help="List only global config users")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
def user_list(is_global, config_path):
    """List configured users.

    Use --global to list only users from the global config.
    """
    if is_global:
        try:
            raw = _load_raw_global()
        except FileNotFoundError as e:
            raise click.ClickException(str(e))
        users = raw.get("users", {}) or {}
        if not users:
            click.echo("(no users in global config)")
            return
        for name in users:
            click.echo(name)
        return

    resolved, _ = _resolve_config_path(config_path, fallback_global=True)

    try:
        cfg = load_config(config_path=resolved)
    except PagevaultError as e:
        raise click.ClickException(str(e))

    if not cfg.users:
        click.echo("(no users configured)")
        return

    for name in cfg.users:
        click.echo(name)


@user.command("passwd")
@click.argument("username")
@click.option(
    "-p",
    "--password",
    "user_password",
    help="New password (prompts if omitted)",
)
@click.option("--global", "is_global", is_flag=True, help="Update in global config")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
def user_passwd(username, user_password, is_global, config_path):
    """Change a user's password.

    Use --global to update the password in your global config instead.
    """
    try:
        if is_global:
            raw = _load_raw_global()
            use_global = True
        else:
            resolved, use_global = _resolve_config_path(config_path, fallback_global=True)
            with open(resolved) as f:
                raw = yaml.safe_load(f) or {}
    except FileNotFoundError as e:
        raise click.ClickException(str(e))

    users = raw.get("users", {}) or {}

    if username not in users:
        raise click.ClickException(f"User '{username}' not found.")

    if not user_password:
        user_password = click.prompt(
            "New password", hide_input=True, confirmation_prompt=True
        )
    if not user_password:
        raise click.ClickException("Password cannot be empty.")

    users[username] = user_password
    raw["users"] = users

    target = "global" if (is_global or use_global) else "local"
    try:
        if is_global or use_global:
            _save_global(raw)
        else:
            update_config_users(resolved, users)
    except PagevaultError as e:
        raise click.ClickException(str(e))

    click.echo(f"Password updated for '{username}' ({target}).")
    click.echo("Run 'pagevault sync' to update encrypted files.")


def _collect_files(paths: tuple, recursive: bool) -> list[Path]:
    """Collect HTML files from paths.

    Args:
        paths: Tuple of file/directory paths.
        recursive: Whether to search directories recursively.

    Returns:
        List of HTML file paths.
    """
    files = []
    html_extensions = {".html", ".htm"}

    for path_str in paths:
        path = Path(path_str)

        if path.is_file():
            if path.suffix.lower() in html_extensions:
                files.append(path)
        elif path.is_dir():
            if recursive:
                for ext in html_extensions:
                    files.extend(path.rglob(f"*{ext}"))
            else:
                for ext in html_extensions:
                    files.extend(path.glob(f"*{ext}"))

    return sorted(set(files))


def _get_output_path(input_path: Path, source_paths: tuple, output_base: Path) -> Path:
    """Determine output path for a file.

    Args:
        input_path: Original file path.
        source_paths: Original source paths from command.
        output_base: Base output directory.

    Returns:
        Output file path.
    """
    # Find which source path contains this file
    input_resolved = input_path.resolve()

    for source in source_paths:
        source_path = Path(source).resolve()

        if source_path.is_file():
            if input_resolved == source_path:
                return output_base / input_path.name
        elif source_path.is_dir():
            try:
                rel = input_resolved.relative_to(source_path)
                return output_base / rel
            except ValueError:
                continue

    # Fallback: just use filename
    return output_base / input_path.name


def _format_size(n: int) -> str:
    """Format byte size for display."""
    if n < 1024:
        return f"{n} B"
    elif n < 1048576:
        return f"{n / 1024:.1f} KB"
    else:
        return f"{n / 1048576:.1f} MB"


def _relative_path(path: Path) -> str:
    """Get a relative path for display."""
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


@main.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option("-P", "--port", default=8765, type=int, help="Port number (default: 8765)")
@click.option("-o", "--open", "open_browser", is_flag=True, help="Open browser automatically")
def serve(directory, port, open_browser):
    """Serve directory over local HTTP for previewing encrypted files.

    Useful for testing encrypted HTML files that need HTTP (not file://) to work
    correctly with Web Crypto API and blob URLs.

    \b
    Examples:
      pagevault serve                     # Serve current directory on :8765
      pagevault serve _locked/ -P 9000    # Serve _locked/ on port 9000
      pagevault serve _locked/ --open     # Serve and open browser
    """
    import functools
    import http.server
    import webbrowser

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
    try:
        with http.server.HTTPServer(("", port), handler) as httpd:
            url = f"http://localhost:{port}"
            click.echo(f"Serving {directory} at {url}")
            click.echo("Press Ctrl+C to stop.")
            if open_browser:
                webbrowser.open(url)
            httpd.serve_forever()
    except KeyboardInterrupt:
        click.echo("\nStopped.")
    except OSError as e:
        raise click.ClickException(f"Cannot start server: {e}")


if __name__ == "__main__":
    main()
