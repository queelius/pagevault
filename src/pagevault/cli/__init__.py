"""Command-line interface for pagevault."""

import re
import sys
from pathlib import Path

import click
import yaml

from pagevault import __version__
from pagevault.config import (
    CONFIG_FILENAME,
    create_default_config,
    find_config_file,
    get_global_config_path,
    load_config,
    load_global_config,
    update_config_users,
)
from pagevault.crypto import PagevaultError
from pagevault.parser import (
    _parse_html,
    has_pagevault_elements,
)

from .commands.audit import audit as _audit
from .commands.lock import lock as _lock
from .commands.mark import mark as _mark
from .commands.sync import sync as _sync
from .commands.unlock import unlock as _unlock
from .shared import (
    _format_size,
    _init_global,
    _load_raw_config,
    _load_raw_global,
    _print_runtime_info,
    _relative_path,
    _resolve_config_path,
    _save_global,
    _save_local,
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


main.add_command(_mark, name="mark")
main.add_command(_lock, name="lock")
main.add_command(_unlock, name="unlock")
main.add_command(_sync, name="sync")
main.add_command(_audit, name="audit")



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
    file_path = Path(path)
    if not file_path.is_file():
        raise click.ClickException(f"Not a file: {file_path}")

    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError as e:
        raise click.ClickException(f"Cannot read {file_path}: {e}")

    if not has_pagevault_elements(content):
        raise click.ClickException("File has no pagevault elements")

    soup = _parse_html(content)

    # Check for wrap-level v4 envelope (pv-meta script tag at document level)
    pv_meta_el = soup.find("script", {"id": "pv-meta"})
    if pv_meta_el:
        import json

        from pagevault.crypto import inspect_payload_v4

        try:
            envelope = json.loads(pv_meta_el.string)
        except (json.JSONDecodeError, TypeError) as e:
            raise click.ClickException(f"Invalid pv-meta JSON: {e}") from e

        info_data = inspect_payload_v4(envelope)

        click.echo(f"File: {_relative_path(file_path)}")
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
    import json

    from pagevault.crypto import inspect_payload_v4

    elements = soup.find_all("pagevault")
    encrypted_regions = [el for el in elements if el.has_attr("data-pv-v4")]

    if not encrypted_regions:
        raise click.ClickException("No encrypted regions found")

    click.echo(f"File: {_relative_path(file_path)}")
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

    # Check for wrap type
    wrap_el = soup.find("pagevault", {"data-wrap-type": True})
    if wrap_el:
        click.echo(f"Wrap type:       {wrap_el.get('data-wrap-type')}")
        if wrap_el.get("data-filename"):
            click.echo(f"Filename:        {wrap_el.get('data-filename')}")
        if wrap_el.get("data-entry"):
            click.echo(f"Entry point:     {wrap_el.get('data-entry')}")

    click.echo(f"pagevault:       v{__version__}")


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

    file_path = Path(path)
    if not file_path.is_file():
        raise click.ClickException(f"Not a file: {file_path}")

    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError as e:
        raise click.ClickException(f"Cannot read {file_path}: {e}")

    if not has_pagevault_elements(content):
        raise click.ClickException("File has no pagevault elements")

    soup = _parse_html(content)

    import json

    from pagevault.crypto import verify_password_v4

    # Check wrap-level v4 envelope first (document-level pv-meta script)
    pv_meta_el = soup.find("script", {"id": "pv-meta"})
    envelope = None
    if pv_meta_el:
        try:
            envelope = json.loads(pv_meta_el.string)
        except (json.JSONDecodeError, TypeError) as e:
            raise click.ClickException(f"Invalid pv-meta JSON: {e}") from e
    else:
        # Fall through to region-level v4: find the first <pagevault data-pv-v4>
        # and grab its child <script data-pv-meta>.
        encrypted_el = soup.find("pagevault", attrs={"data-pv-v4": True})
        if not encrypted_el:
            raise click.ClickException("No encrypted regions found")
        meta_script = None
        for child in encrypted_el.find_all("script", recursive=False):
            if child.has_attr("data-pv-meta"):
                meta_script = child
                break
        if meta_script is None or not meta_script.string:
            raise click.ClickException("Missing pv-meta script in region")
        try:
            envelope = json.loads(meta_script.string)
        except json.JSONDecodeError as e:
            raise click.ClickException(f"Invalid region envelope JSON: {e}") from e

    try:
        result = verify_password_v4(envelope, password, username=username)
    except PagevaultError as e:
        raise click.ClickException(str(e)) from e

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
        click.echo(
            "No config found (no local .pagevault.yaml and no global config).",
            err=True,
        )
        click.echo("Run 'pagevault config init' to create a local config.", err=True)
        click.echo(
            "Run 'pagevault config init --global' to create a global config.",
            err=True,
        )
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
        local_d = local_defaults if isinstance(local_defaults, dict) else {}
        global_d = global_defaults if isinstance(global_defaults, dict) else {}
        for key in ["remember", "remember_days", "auto_prompt"]:
            l_val = local_d.get(key)
            g_val = global_d.get(key)
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

    raw, resolved, use_global = _load_raw_config(is_global, config_path)
    target = "global" if (is_global or use_global) else "local"

    if unset:
        if key in raw:
            del raw[key]
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
        display_value = str(value).lower() if isinstance(value, bool) else value
        click.echo(f"Set '{key}' = '{display_value}' ({target}).")

    try:
        if is_global or use_global:
            _save_global(raw)
        else:
            _save_local(resolved, raw)
    except (PagevaultError, OSError) as e:
        raise click.ClickException(str(e)) from e


@config.group()
def user():
    """Manage users for multi-user encryption."""
    pass


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

    raw, resolved, use_global = _load_raw_config(is_global, config_path)
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
        raise click.ClickException(str(e)) from e

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
    raw, resolved, use_global = _load_raw_config(is_global, config_path)
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
        raise click.ClickException(str(e)) from e

    click.echo(f"Removed user '{username}' ({target}).")
    if cleared_default:
        click.echo(f"Cleared default user (was '{username}').")
    click.echo("Run 'pagevault sync' to update encrypted files.")


@user.command("list")
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="List only global config users",
)
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
    raw, resolved, use_global = _load_raw_config(is_global, config_path)
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
        raise click.ClickException(str(e)) from e

    click.echo(f"Password updated for '{username}' ({target}).")
    click.echo("Run 'pagevault sync' to update encrypted files.")


@main.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option(
    "-P",
    "--port",
    default=8765,
    type=int,
    help="Port number (default: 8765)",
)
@click.option(
    "-o",
    "--open",
    "open_browser",
    is_flag=True,
    help="Open browser automatically",
)
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

    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=directory
    )
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
