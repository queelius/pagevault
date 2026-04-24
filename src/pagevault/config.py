"""Configuration management for pagevault.

Handles loading .pagevault.yaml files with directory traversal,
environment variable overrides, and default values.
"""

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .crypto import PagevaultError, generate_salt, hex_to_salt, salt_to_hex

CONFIG_FILENAME = ".pagevault.yaml"
GLOBAL_CONFIG_DIR = "pagevault"
GLOBAL_CONFIG_FILE = "config.yaml"
ENV_PASSWORD = "PAGEVAULT_PASSWORD"
ENV_SALT = "PAGEVAULT_SALT"


@dataclass
class TemplateConfig:
    """Template customization settings."""

    title: str = "Protected Content"
    button_text: str = "Unlock"
    error_text: str = "Incorrect password"
    placeholder: str = "Enter password"
    username_placeholder: str = "Enter username"
    color_primary: str = "#4CAF50"
    color_secondary: str = "#76B852"


@dataclass
class DefaultsConfig:
    """Default behavior settings."""

    remember: str = "ask"  # "none", "session", "local", "ask"
    remember_days: int = 0  # 0 = no expiration
    auto_prompt: bool = True  # Show password prompt on load if locked


@dataclass
class PagevaultConfig:
    """Complete pagevault configuration."""

    password: str | None = None
    salt: bytes | None = None
    users: dict[str, str] | None = None  # {username: password} for multi-user
    user: str | None = None  # Default username for unlock
    managed: list[str] | None = None  # Glob patterns for sync command
    pad: bool = False  # Pad content to power-of-2 before encryption
    defaults: DefaultsConfig = field(default_factory=DefaultsConfig)
    template: TemplateConfig = field(default_factory=TemplateConfig)
    viewers: dict[str, bool] | None = None  # Viewer overrides {name: enabled}
    viewers_dir: Path | None = None  # Directory with custom viewer .py files
    custom_css: str | None = None  # Custom CSS content (replaces default styles)
    config_path: Path | None = None  # Path where config was loaded from

    def validate(self) -> None:
        """Validate configuration.

        Raises:
            PagevaultError: If configuration is invalid.
        """
        valid_remember = {"none", "session", "local", "ask"}
        if self.defaults.remember not in valid_remember:
            raise PagevaultError(
                f"Invalid remember value: {self.defaults.remember}. "
                f"Must be one of: {', '.join(valid_remember)}"
            )

        if self.defaults.remember_days < 0:
            raise PagevaultError("remember_days must be non-negative")

        # Validate users dict
        if self.users is not None:
            if not isinstance(self.users, dict) or not self.users:
                raise PagevaultError("'users' must be a non-empty dictionary")
            for username, user_password in self.users.items():
                if not username:
                    raise PagevaultError("Username cannot be empty")
                if ":" in username:
                    raise PagevaultError(
                        f"Username '{username}' cannot contain ':' (used as delimiter)"
                    )
                if not user_password:
                    raise PagevaultError(
                        f"Password for user '{username}' cannot be empty"
                    )

        # Validate default user exists in users dict
        if self.user is not None:
            if self.users is None:
                raise PagevaultError(
                    f"Default user '{self.user}' specified but no 'users' dict defined"
                )
            if self.user not in self.users:
                raise PagevaultError(
                    f"Default user '{self.user}' not found in 'users' dict"
                )


def get_global_config_path() -> Path:
    """Return the global config file path.

    Uses $XDG_CONFIG_HOME/pagevault/config.yaml if XDG_CONFIG_HOME is set,
    otherwise ~/.config/pagevault/config.yaml.
    """
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        base = Path(xdg)
    else:
        base = Path.home() / ".config"
    return base / GLOBAL_CONFIG_DIR / GLOBAL_CONFIG_FILE


def load_global_config() -> dict[str, Any]:
    """Load global config if it exists, otherwise return empty dict.

    The global config has the same structure as the local config, just lower
    priority. Any field is valid in the global config; local values override
    global values.

    Returns:
        Raw config dict from global file, or empty dict if not found.
    """
    path = get_global_config_path()
    if not path.exists():
        return {}

    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError):
        return {}

    # Basic validation of global users
    users = data.get("users")
    if users and isinstance(users, dict):
        for username, password in users.items():
            if ":" in str(username):
                raise PagevaultError(
                    f"Global config: username '{username}' cannot contain ':'"
                )
            if not password:
                raise PagevaultError(
                    f"Global config: password for user '{username}' cannot be empty"
                )
        data["users"] = {str(k): str(v) for k, v in users.items()}

    return data


def find_config_file(start_path: Path | None = None) -> Path | None:
    """Find .pagevault.yaml by traversing up from start_path.

    Args:
        start_path: Directory to start searching from. Defaults to cwd.

    Returns:
        Path to config file if found, None otherwise.
    """
    if start_path is None:
        start_path = Path.cwd()
    else:
        start_path = Path(start_path).resolve()

    # If start_path is a file, use its parent directory
    if start_path.is_file():
        start_path = start_path.parent

    current = start_path
    while True:
        config_path = current / CONFIG_FILENAME
        if config_path.is_file():
            return config_path

        parent = current.parent
        if parent == current:
            # Reached root, no config found
            return None
        current = parent


def load_config(
    config_path: Path | None = None,
    start_path: Path | None = None,
    password_override: str | None = None,
) -> PagevaultConfig:
    """Load configuration from file, environment, and overrides.

    Priority (highest to lowest):
    1. Function arguments (password_override)
    2. Environment variables (PAGEVAULT_PASSWORD, PAGEVAULT_SALT)
    3. Local config file (.pagevault.yaml)
    4. Global config (~/.config/pagevault/config.yaml)
    5. Defaults

    Global config provides personal credentials (users, password) that are
    merged into every project. Local users override global users on conflict.

    Args:
        config_path: Explicit path to config file. If None, searches.
        start_path: Directory to start config file search from.
        password_override: Override password from CLI argument.

    Returns:
        Loaded and validated configuration.
    """
    config = PagevaultConfig()

    # Find or use explicit config file
    if config_path is not None:
        config_path = Path(config_path)
        if not config_path.is_file():
            raise PagevaultError(f"Config file not found: {config_path}")
    else:
        config_path = find_config_file(start_path)

    # Load config file if found
    if config_path is not None:
        config = _load_config_file(config_path)
        config.config_path = config_path

    # Merge global config (global provides defaults, local overrides)
    global_data = load_global_config()
    if global_data:
        # Merge users: global first, local overrides
        global_users = global_data.get("users", {})
        if global_users:
            if config.users:
                # Warn about password conflicts
                for username in global_users:
                    if username in config.users and str(global_users[username]) != str(
                        config.users[username]
                    ):
                        print(
                            f"Note: user '{username}' has different passwords in "
                            f"global and local config (using local)",
                            file=sys.stderr,
                        )
                config.users = {**global_users, **config.users}
            else:
                config.users = dict(global_users)

        # Global password as fallback
        if config.password is None and "password" in global_data:
            config.password = str(global_data["password"])

        # Global default user as fallback
        if config.user is None and "user" in global_data:
            config.user = str(global_data["user"])

        # Global salt as fallback
        if config.salt is None and "salt" in global_data:
            config.salt = hex_to_salt(str(global_data["salt"]))

    # Override with environment variables
    env_password = os.environ.get(ENV_PASSWORD)
    if env_password:
        config.password = env_password

    env_salt = os.environ.get(ENV_SALT)
    if env_salt:
        config.salt = hex_to_salt(env_salt)

    # Override with function argument
    if password_override is not None:
        config.password = password_override

    config.validate()
    return config


def _load_config_file(config_path: Path) -> PagevaultConfig:
    """Load configuration from a YAML file.

    Args:
        config_path: Path to .pagevault.yaml file.

    Returns:
        Configuration loaded from file.

    Raises:
        PagevaultError: If file cannot be read or parsed.
    """
    try:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise PagevaultError(f"Invalid YAML in {config_path}: {e}") from e
    except OSError as e:
        raise PagevaultError(f"Cannot read config file {config_path}: {e}") from e

    config = PagevaultConfig(config_path=config_path)

    # Load password
    if "password" in data:
        config.password = str(data["password"])

    # Load salt
    if "salt" in data:
        config.salt = hex_to_salt(str(data["salt"]))

    # Load defaults
    if "defaults" in data and isinstance(data["defaults"], dict):
        defaults_data = data["defaults"]
        config.defaults = DefaultsConfig(
            remember=defaults_data.get("remember", config.defaults.remember),
            remember_days=defaults_data.get(
                "remember_days", config.defaults.remember_days
            ),
            auto_prompt=defaults_data.get("auto_prompt", config.defaults.auto_prompt),
        )

    # Load template
    if "template" in data and isinstance(data["template"], dict):
        template_data = data["template"]
        config.template = TemplateConfig(
            title=template_data.get("title", config.template.title),
            button_text=template_data.get("button_text", config.template.button_text),
            error_text=template_data.get("error_text", config.template.error_text),
            placeholder=template_data.get("placeholder", config.template.placeholder),
            username_placeholder=template_data.get(
                "username_placeholder", config.template.username_placeholder
            ),
            color_primary=template_data.get(
                "color_primary", config.template.color_primary
            ),
            color_secondary=template_data.get(
                "color_secondary", config.template.color_secondary
            ),
        )

    # Load users
    if "users" in data and isinstance(data["users"], dict):
        config.users = {str(k): str(v) for k, v in data["users"].items()}

    # Load default user
    if "user" in data and data["user"]:
        config.user = str(data["user"])

    # Load managed glob patterns
    if "managed" in data and isinstance(data["managed"], list):
        config.managed = [str(p) for p in data["managed"]]

    # Load pad setting
    if "pad" in data:
        config.pad = bool(data["pad"])

    # Load viewer overrides
    if "viewers" in data and isinstance(data["viewers"], dict):
        config.viewers = {str(k): bool(v) for k, v in data["viewers"].items()}

    # Load custom viewers directory
    if "viewers_dir" in data:
        viewers_dir_path = Path(data["viewers_dir"])
        # Resolve relative paths against config file directory
        if not viewers_dir_path.is_absolute():
            viewers_dir_path = config_path.parent / viewers_dir_path
        config.viewers_dir = viewers_dir_path

    # Load custom CSS from file
    if "css_file" in data:
        css_file_path = Path(data["css_file"])
        # Resolve relative paths against config file directory
        if not css_file_path.is_absolute():
            css_file_path = config_path.parent / css_file_path
        try:
            config.custom_css = css_file_path.read_text(encoding="utf-8")
        except OSError as e:
            raise PagevaultError(f"Cannot read CSS file {css_file_path}: {e}") from e

    return config


def create_default_config(path: Path | None = None) -> Path:
    """Create a default .pagevault.yaml config file.

    Args:
        path: Directory to create config in. Defaults to cwd.

    Returns:
        Path to created config file.

    Raises:
        PagevaultError: If file already exists or cannot be written.
    """
    if path is None:
        path = Path.cwd()
    else:
        path = Path(path)

    config_path = path / CONFIG_FILENAME

    if config_path.exists():
        raise PagevaultError(f"Config file already exists: {config_path}")

    # Generate random salt
    salt = generate_salt()

    config_content = f'''# pagevault configuration
# WARNING: Add this file to .gitignore - it contains your password!

# Password for encryption (or use PAGEVAULT_PASSWORD env var)
password: "your-strong-passphrase"

# Salt for consistent password hashing (auto-generated)
# Needed for remember-me and share links to work across re-encryptions
salt: "{salt_to_hex(salt)}"

# Multi-user access (uncomment to enable)
# users:
#   alice: "alice-password"
#   bob: "bob-password"

# Files managed by 'pagevault sync' (uncomment to enable)
# managed:
#   - "encrypted/**/*.html"
#   - "site/admin/*.html"

# Default behavior
defaults:
  remember: "ask"        # "none", "session", "local", "ask"
  remember_days: 0       # 0 = no expiration
  auto_prompt: true      # Show password prompt on load if locked

# Template customization
template:
  title: "Protected Content"
  button_text: "Unlock"
  error_text: "Incorrect password"
  placeholder: "Enter password"
  # username_placeholder: "Enter username"  # For multi-user mode
  color_primary: "#4CAF50"
  color_secondary: "#76B852"
'''

    try:
        config_path.write_text(config_content)
    except OSError as e:
        raise PagevaultError(f"Cannot write config file: {e}") from e

    return config_path


def create_global_config(
    users: dict[str, str],
    password: str | None = None,
    default_user: str | None = None,
    force: bool = False,
) -> Path:
    """Create a global pagevault config file.

    Args:
        users: Dict of {username: password} for personal credentials.
        password: Optional single-user password.
        default_user: Optional default username.
        force: If True, overwrite existing global config.

    Returns:
        Path to created config file.

    Raises:
        PagevaultError: If file already exists (without force) or cannot be written.
    """
    global_path = get_global_config_path()

    if global_path.exists() and not force:
        raise PagevaultError(f"Global config already exists: {global_path}")

    data: dict[str, Any] = {}
    if password:
        data["password"] = password
    if users:
        data["users"] = users
    if default_user:
        data["user"] = default_user

    global_path.parent.mkdir(parents=True, exist_ok=True)

    content = "# pagevault global configuration\n"
    content += "# Personal credentials merged into every project's config.\n\n"
    content += yaml.dump(data, default_flow_style=False, sort_keys=False)

    try:
        global_path.write_text(content, encoding="utf-8")
    except OSError as e:
        raise PagevaultError(f"Cannot write global config: {e}") from e

    return global_path


def update_config_users(config_path: Path, users: dict[str, str] | None) -> None:
    """Update the users section in a config file.

    Loads the existing YAML, modifies the 'users' key, writes back.
    Note: comments in the original file are not preserved.

    Args:
        config_path: Path to .pagevault.yaml file.
        users: New users dict, or None to remove the users section.

    Raises:
        PagevaultError: If file cannot be read or written.
    """
    try:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise PagevaultError(f"Invalid YAML in {config_path}: {e}") from e
    except OSError as e:
        raise PagevaultError(f"Cannot read config file {config_path}: {e}") from e

    if users:
        data["users"] = users
    elif "users" in data:
        del data["users"]

    content = "# pagevault configuration\n"
    content += "# WARNING: Add this file to .gitignore - it contains passwords!\n\n"
    content += yaml.dump(data, default_flow_style=False, sort_keys=False)

    try:
        config_path.write_text(content)
    except OSError as e:
        raise PagevaultError(f"Cannot write config file {config_path}: {e}") from e


def config_to_dict(
    config: PagevaultConfig, show_passwords: bool = False
) -> dict[str, Any]:
    """Convert config to dictionary for display.

    Args:
        config: Configuration to convert.
        show_passwords: If True, show passwords in plaintext.
            If False, mask with first 2 chars + "***".
    """

    def _mask(password: str) -> str:
        if show_passwords:
            return password
        return password[:2] + "***" if len(password) > 2 else "***"

    result: dict[str, Any] = {
        "password": _mask(config.password) if config.password else None,
        "salt": salt_to_hex(config.salt) if config.salt else None,
    }

    if config.users:
        result["users"] = {k: _mask(v) for k, v in config.users.items()}
    else:
        result["users"] = None

    result["user"] = config.user

    if config.managed:
        result["managed"] = config.managed
    else:
        result["managed"] = None

    result["pad"] = config.pad

    result["defaults"] = {
        "remember": config.defaults.remember,
        "remember_days": config.defaults.remember_days,
        "auto_prompt": config.defaults.auto_prompt,
    }
    result["template"] = {
        "title": config.template.title,
        "button_text": config.template.button_text,
        "error_text": config.template.error_text,
        "placeholder": config.template.placeholder,
        "username_placeholder": config.template.username_placeholder,
        "color_primary": config.template.color_primary,
        "color_secondary": config.template.color_secondary,
    }
    result["viewers"] = config.viewers
    result["viewers_dir"] = str(config.viewers_dir) if config.viewers_dir else None
    result["config_path"] = str(config.config_path) if config.config_path else None
    return result
