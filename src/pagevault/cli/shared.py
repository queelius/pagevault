"""Shared helpers for pagevault CLI commands."""

import json
import re
from pathlib import Path

import click
import yaml

from pagevault.config import (
    find_config_file,
    get_global_config_path,
)
from pagevault.crypto import PagevaultError
from pagevault.parser import (
    _parse_html,
    has_pagevault_elements,
    mark_body,
    mark_elements,
    process_file,
)

HTML_EXTENSIONS = frozenset({".html", ".htm"})


def _is_html(path: Path) -> bool:
    """True if path has an HTML file extension."""
    return path.suffix.lower() in HTML_EXTENSIONS


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


def _collect_files(paths: tuple, recursive: bool) -> list[Path]:
    """Collect HTML files from paths.

    Args:
        paths: Tuple of file/directory paths.
        recursive: Whether to search directories recursively.

    Returns:
        List of HTML file paths.
    """
    files: list[Path] = []
    glob = Path.rglob if recursive else Path.glob

    for path_str in paths:
        path = Path(path_str)
        if path.is_file() and _is_html(path):
            files.append(path)
        elif path.is_dir():
            for ext in HTML_EXTENSIONS:
                files.extend(glob(path, f"*{ext}"))

    return sorted(set(files))


def _resolve_managed_html_files(
    config_dir: Path, patterns: list[str]
) -> list[Path]:
    """Expand managed glob patterns (relative to config_dir) to HTML files."""
    files: list[Path] = []
    for pattern in patterns:
        files.extend(
            f
            for f in sorted(config_dir.glob(pattern))
            if f.is_file() and _is_html(f)
        )
    return sorted(set(files))


def _default_output_dir(output_dir: str | None, default: str) -> Path:
    """Return output_dir as Path, or default after informing the user."""
    if output_dir is None:
        output_dir = default
        click.echo(f"Writing to {output_dir}/ (use -d to change)")
    return Path(output_dir)


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
            if _is_html(path):
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
            # If content was wrapped (selector or body), the modified
            # plaintext lives only in `content` — write it to output first
            # so process_file can read+encrypt from there. Otherwise read
            # straight from the input path.
            if content_was_wrapped or selectors:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(content, encoding="utf-8")
                source_path = output_path
            else:
                source_path = input_path
            changed = process_file(
                source_path,
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
    from pagevault.wrap import wrap_file

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
    from pagevault.wrap import wrap_site

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


def _find_first_envelope(soup) -> dict | None:
    """Locate and parse the first v4 envelope JSON in a parsed document.

    Detects format via the pagevault element marker (not by script id),
    so a region-encrypted page that happens to contain plaintext
    referencing ``pv-meta`` won't be misclassified as wrap.

    Wrap format: ``<pagevault data-pv-chunked>`` + document-level
    ``<script id="pv-meta">``.

    Region format: ``<pagevault data-pv-v4>`` containing
    ``<script data-pv-meta>`` as a direct child.

    Returns the parsed envelope dict or ``None`` when neither is present.

    Raises:
        click.ClickException: If a meta script exists but its JSON is invalid.
    """
    # Wrap format: identified by data-pv-chunked on the <pagevault> element
    if soup.find("pagevault", attrs={"data-pv-chunked": True}):
        pv_meta_el = soup.find("script", {"id": "pv-meta"})
        if pv_meta_el:
            try:
                return json.loads(pv_meta_el.string)
            except (json.JSONDecodeError, TypeError) as e:
                raise click.ClickException(f"Invalid pv-meta JSON: {e}") from e
        return None

    # Region format: <pagevault data-pv-v4> with child <script data-pv-meta>
    encrypted_el = soup.find("pagevault", attrs={"data-pv-v4": True})
    if encrypted_el is None:
        return None

    for child in encrypted_el.find_all("script", recursive=False):
        if child.has_attr("data-pv-meta") and child.string:
            try:
                return json.loads(child.string)
            except json.JSONDecodeError as e:
                raise click.ClickException(
                    f"Invalid region envelope JSON: {e}"
                ) from e
    return None


def _print_runtime_info(soup) -> None:
    """Print runtime-script/style/viewer/jszip info for the inspect command."""
    runtime_scripts = soup.find_all("script", {"data-pagevault-runtime": True})
    runtime_styles = soup.find_all("style", {"data-pagevault-runtime": True})
    click.echo(f"Runtime scripts: {len(runtime_scripts)}")
    click.echo(f"Runtime styles:  {len(runtime_styles)}")

    # v4 viewer dispatch shape: window.__pv_viewers['image/*'] = viewer;
    viewer_re = r"window\.__pv_viewers\[\s*'([a-z]+/[a-z0-9*+\-.]+)'\s*\]"
    for script in runtime_scripts:
        viewer_matches = re.findall(viewer_re, script.string or "")
        if viewer_matches:
            click.echo(f"Viewers:         {', '.join(viewer_matches)}")

    if any("ZipReader" in (s.string or "") for s in runtime_scripts):
        click.echo("JSZip shim:      yes")


def _print_info(file_path: str) -> None:
    """Print metadata for an encrypted file (used by inspect command)."""
    from pagevault import __version__
    from pagevault.crypto import inspect_payload_v4

    path = Path(file_path)
    if not path.is_file():
        raise click.ClickException(f"Not a file: {path}")

    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        raise click.ClickException(f"Cannot read {path}: {e}")

    if not has_pagevault_elements(content):
        raise click.ClickException("File has no pagevault elements")

    soup = _parse_html(content)

    # Wrap format: identified by <pagevault data-pv-chunked>, not by script id
    # (a region-encrypted page with plaintext referencing pv-meta would
    # otherwise be misclassified as wrap).
    if soup.find("pagevault", attrs={"data-pv-chunked": True}):
        pv_meta_el = soup.find("script", {"id": "pv-meta"})
        if pv_meta_el is None:
            raise click.ClickException(
                "data-pv-chunked element found but no <script id='pv-meta'>"
            )
        try:
            envelope = json.loads(pv_meta_el.string)
        except (json.JSONDecodeError, TypeError) as e:
            raise click.ClickException(f"Invalid pv-meta JSON: {e}") from e

        info_data = inspect_payload_v4(envelope)

        click.echo(f"File: {_relative_path(path)}")
        click.echo("Format:         v4 chunked (wrap)")
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

        # Count chunk script tags in a single DOM pass (previously O(N²)
        # via while soup.find). If it disagrees with the envelope, surface
        # the mismatch — that's an integrity signal worth showing.
        chunk_id_re = re.compile(r"^pv-\d+$")
        chunk_tags_found = len(soup.find_all("script", {"id": chunk_id_re}))
        envelope_count = info_data["chunk_count"]
        if chunk_tags_found == envelope_count:
            click.echo(f"Chunk tags:     {chunk_tags_found}")
        else:
            click.echo(
                f"Chunk tags:     {chunk_tags_found} "
                f"(WARNING: envelope says {envelope_count})"
            )

        # Check pagevault element for mode
        pv_el = soup.find("pagevault")
        if pv_el:
            mode = pv_el.get("data-mode", "single")
            click.echo(f"Mode:           {mode}")

        _print_runtime_info(soup)
        click.echo(f"pagevault:       v{__version__}")
        return

    # --- v4 region-encrypted format: envelopes inside <pagevault data-pv-v4> ---
    elements = soup.find_all("pagevault")
    encrypted_regions = [el for el in elements if el.has_attr("data-pv-v4")]

    if not encrypted_regions:
        raise click.ClickException("No encrypted regions found")

    click.echo(f"File: {_relative_path(path)}")
    click.echo(f"Encrypted regions: {len(encrypted_regions)}")
    click.echo()

    for i, el in enumerate(encrypted_regions):
        mode = el.get("data-mode", "single")
        hint = el.get("data-hint", "")
        title = el.get("data-title", "")
        remember = el.get("data-remember", "")

        click.echo(f"--- Region {i + 1} ---")

        meta_script = None
        for child in el.find_all("script", recursive=False):
            if child.has_attr("data-pv-meta"):
                meta_script = child
                break

        if meta_script is None or not meta_script.string:
            click.echo("  Error: missing pv-meta script")
        else:
            try:
                envelope = json.loads(meta_script.string)
                info_data = inspect_payload_v4(envelope)
                click.echo(f"  Version:      v{info_data['version']}")
                click.echo(f"  Algorithm:    {info_data['algorithm']}")
                click.echo(f"  KDF:          {info_data['kdf']}")
                click.echo(f"  Iterations:   {info_data['iterations']:,}")
                click.echo(f"  Key blobs:    {info_data['key_count']}")
                click.echo(f"  Chunk size:   {_format_size(info_data['chunk_size'])}")
                click.echo(f"  Chunks:       {info_data['chunk_count']}")
                click.echo(f"  Total size:   {_format_size(info_data['total_size'])}")
            except (json.JSONDecodeError, PagevaultError) as e:
                click.echo(f"  Error parsing envelope: {e}")

        click.echo(f"  Mode:         {mode}")
        if hint:
            click.echo(f"  Hint:         {hint}")
        if title:
            click.echo(f"  Title:        {title}")
        if remember:
            click.echo(f"  Remember:     {remember}")
        click.echo()

    _print_runtime_info(soup)
    click.echo(f"pagevault:       v{__version__}")


def _verify_password(
    file_path: str, password: str, username: str | None = None
) -> tuple[bool, str | None]:
    """Verify a password against an encrypted file.

    Returns:
        (True, None) on success, (False, error_message) on failure.
    """
    from pagevault.crypto import verify_password_v4

    path = Path(file_path)
    if not path.is_file():
        raise click.ClickException(f"Not a file: {path}")

    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        raise click.ClickException(f"Cannot read {path}: {e}")

    if not has_pagevault_elements(content):
        raise click.ClickException("File has no pagevault elements")

    soup = _parse_html(content)

    # Check wrap-level v4 envelope first (document-level pv-meta script),
    # then fall back to the first <pagevault data-pv-v4> region.
    envelope = _find_first_envelope(soup)
    if envelope is None:
        raise click.ClickException("No encrypted regions found")

    try:
        result = verify_password_v4(envelope, password, username=username)
    except PagevaultError as e:
        return False, str(e)

    if result:
        return True, None
    else:
        return False, "password did not match"


def _resolve_config_path(
    config_path: str | None, fallback_global: bool = False
) -> tuple[Path, bool]:
    """Find config file from explicit path, directory traversal, or global fallback.

    Args:
        config_path: Explicit path from -c flag, or None.
        fallback_global: If True, fall back to global config when no local found.

    Returns:
        Tuple of (resolved Path, is_global).

    Raises:
        click.ClickException: If no config file found.
    """
    from pagevault.config import CONFIG_FILENAME

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


def _load_raw_config(
    is_global: bool, config_path: str | None
) -> tuple[dict, Path | None, bool]:
    """Load raw YAML from the target config (global or local).

    Returns (data, resolved_path, use_global). ``resolved_path`` is None
    when ``is_global`` was explicitly requested. ``use_global`` is True
    whenever the loaded file is the global config (explicit or fallback).

    Raises click.ClickException if no config file can be located.
    """
    try:
        if is_global:
            return _load_raw_global(), None, True
        resolved, use_global = _resolve_config_path(config_path, fallback_global=True)
        with open(resolved) as f:
            return yaml.safe_load(f) or {}, resolved, use_global
    except FileNotFoundError as e:
        raise click.ClickException(str(e)) from e


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


def _init_global(force: bool) -> None:
    """Create a global user configuration."""
    from pagevault.config import create_global_config

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
