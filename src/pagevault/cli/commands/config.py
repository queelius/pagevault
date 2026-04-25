"""config command group."""

import sys
from pathlib import Path

import click
import yaml

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

from ..shared import (
    _init_global,
    _load_raw_config,
    _load_raw_global,
    _resolve_config_path,
    _save_global,
    _save_local,
)


@click.group()
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
