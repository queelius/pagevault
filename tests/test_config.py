"""Tests for pagevault.config module."""

import pytest
import yaml

from pagevault.config import (
    CONFIG_FILENAME,
    DefaultsConfig,
    PagevaultConfig,
    TemplateConfig,
    config_to_dict,
    create_default_config,
    create_global_config,
    find_config_file,
    get_global_config_path,
    load_config,
    load_global_config,
    update_config_users,
)
from pagevault.crypto import PagevaultError, generate_salt, salt_to_hex


class TestFindConfigFile:
    """Tests for find_config_file function."""

    def test_finds_config_in_current_dir(self, tmp_path):
        """Test finding config in current directory."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("password: test")

        found = find_config_file(tmp_path)
        assert found == config_path

    def test_finds_config_in_parent_dir(self, tmp_path):
        """Test finding config by traversing up."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("password: test")

        subdir = tmp_path / "sub" / "deep"
        subdir.mkdir(parents=True)

        found = find_config_file(subdir)
        assert found == config_path

    def test_returns_none_when_not_found(self, tmp_path):
        """Test returns None when no config found."""
        found = find_config_file(tmp_path)
        assert found is None

    def test_starts_from_file_path(self, tmp_path):
        """Test starting from a file path uses parent directory."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("password: test")

        file_path = tmp_path / "index.html"
        file_path.write_text("<html></html>")

        found = find_config_file(file_path)
        assert found == config_path


class TestLoadConfig:
    """Tests for load_config function."""

    def test_loads_from_file(self, tmp_path):
        """Test loading config from file."""
        salt = generate_salt()
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(f"""
password: "secret123"
salt: "{salt_to_hex(salt)}"
defaults:
  remember: "local"
  remember_days: 30
  auto_prompt: false
template:
  title: "Custom Title"
  button_text: "Open"
""")

        config = load_config(config_path=config_path)

        assert config.password == "secret123"
        assert config.salt == salt
        assert config.defaults.remember == "local"
        assert config.defaults.remember_days == 30
        assert config.defaults.auto_prompt is False
        assert config.template.title == "Custom Title"
        assert config.template.button_text == "Open"
        assert config.config_path == config_path

    def test_password_override(self, tmp_path):
        """Test password can be overridden."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text('password: "from-file"')

        config = load_config(config_path=config_path, password_override="from-arg")
        assert config.password == "from-arg"

    def test_env_override(self, tmp_path, monkeypatch):
        """Test environment variables override config file."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text('password: "from-file"')

        monkeypatch.setenv("PAGEVAULT_PASSWORD", "from-env")

        config = load_config(config_path=config_path)
        assert config.password == "from-env"

    def test_arg_overrides_env(self, tmp_path, monkeypatch):
        """Test function argument overrides environment."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text('password: "from-file"')

        monkeypatch.setenv("PAGEVAULT_PASSWORD", "from-env")

        config = load_config(config_path=config_path, password_override="from-arg")
        assert config.password == "from-arg"

    def test_missing_explicit_config_fails(self, tmp_path):
        """Test explicit config path that doesn't exist fails."""
        with pytest.raises(PagevaultError, match="not found"):
            load_config(config_path=tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_fails(self, tmp_path):
        """Test invalid YAML fails."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("invalid: yaml: syntax:")

        with pytest.raises(PagevaultError, match="Invalid YAML"):
            load_config(config_path=config_path)

    def test_invalid_remember_value_fails(self, tmp_path):
        """Test invalid remember value fails validation."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
defaults:
  remember: "invalid"
""")

        with pytest.raises(PagevaultError, match="Invalid remember value"):
            load_config(config_path=config_path)

    def test_negative_remember_days_fails(self, tmp_path):
        """Test negative remember_days fails validation."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
defaults:
  remember_days: -1
""")

        with pytest.raises(PagevaultError, match="non-negative"):
            load_config(config_path=config_path)

    def test_defaults_without_file(self):
        """Test loading defaults when no config file exists."""
        config = load_config(start_path="/nonexistent/path")

        assert config.password is None
        assert config.salt is None
        assert config.defaults.remember == "ask"
        assert config.defaults.remember_days == 0
        assert config.defaults.auto_prompt is True
        assert config.config_path is None


class TestCreateDefaultConfig:
    """Tests for create_default_config function."""

    def test_creates_config_file(self, tmp_path):
        """Test creating a new config file."""
        config_path = create_default_config(tmp_path)

        assert config_path.exists()
        assert config_path.name == CONFIG_FILENAME

        content = config_path.read_text()
        assert "password:" in content
        assert "salt:" in content
        assert "defaults:" in content
        assert "template:" in content

    def test_generated_salt_is_valid(self, tmp_path):
        """Test generated salt can be loaded."""
        create_default_config(tmp_path)

        # Should be able to load without error
        config = load_config(config_path=tmp_path / CONFIG_FILENAME)
        assert config.salt is not None
        assert len(config.salt) == 16

    def test_fails_if_exists(self, tmp_path):
        """Test fails if config already exists."""
        (tmp_path / CONFIG_FILENAME).write_text("existing")

        with pytest.raises(PagevaultError, match="already exists"):
            create_default_config(tmp_path)


class TestConfigToDict:
    """Tests for config_to_dict function."""

    def test_masks_password(self):
        """Test password is masked in output (first 2 chars + ***)."""
        config = PagevaultConfig(password="secret")
        data = config_to_dict(config)

        assert data["password"] == "se***"

    def test_none_password(self):
        """Test None password shows as None."""
        config = PagevaultConfig()
        data = config_to_dict(config)

        assert data["password"] is None

    def test_includes_all_fields(self):
        """Test all fields are included."""
        salt = generate_salt()
        config = PagevaultConfig(
            password="test",
            salt=salt,
            defaults=DefaultsConfig(remember="local", remember_days=7),
            template=TemplateConfig(title="Test"),
        )
        data = config_to_dict(config)

        assert "password" in data
        assert "salt" in data
        assert "defaults" in data
        assert "template" in data
        assert data["salt"] == salt_to_hex(salt)
        assert data["defaults"]["remember"] == "local"
        assert data["template"]["title"] == "Test"


class TestUsersConfig:
    """Tests for v2 multi-user, managed, and related config features."""

    def test_loads_users_from_yaml(self, tmp_path):
        """Test loading users dict from config file."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
users:
  alice: "pw-a"
  bob: "pw-b"
""")
        config = load_config(config_path=config_path)
        assert config.users == {"alice": "pw-a", "bob": "pw-b"}

    def test_loads_managed_from_yaml(self, tmp_path):
        """Test loading managed glob patterns from config file."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
managed:
  - "encrypted/**/*.html"
""")
        config = load_config(config_path=config_path)
        assert config.managed == ["encrypted/**/*.html"]

    def test_username_with_colon_fails(self, tmp_path):
        """Test that a username containing ':' fails validation."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
users:
  "alice:admin": "pw"
""")
        with pytest.raises(PagevaultError, match="cannot contain ':'"):
            load_config(config_path=config_path)

    def test_empty_username_fails(self, tmp_path):
        """Test that an empty username fails validation."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
users:
  "": "pw"
""")
        with pytest.raises(PagevaultError, match="cannot be empty"):
            load_config(config_path=config_path)

    def test_empty_password_fails(self, tmp_path):
        """Test that an empty password for a user fails validation."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
users:
  alice: ""
""")
        with pytest.raises(PagevaultError, match="cannot be empty"):
            load_config(config_path=config_path)

    def test_users_empty_dict_fails(self, tmp_path):
        """Test that an empty users dict fails validation."""
        config = PagevaultConfig(users={})
        with pytest.raises(PagevaultError, match="non-empty dictionary"):
            config.validate()

    def test_config_to_dict_masks_user_passwords(self):
        """Test that config_to_dict masks all user passwords."""
        config = PagevaultConfig(users={"alice": "pw"})
        data = config_to_dict(config)
        assert data["users"] == {"alice": "***"}  # short password fully masked

    def test_config_to_dict_includes_managed(self):
        """Test that config_to_dict includes managed patterns."""
        config = PagevaultConfig(managed=["*.html"])
        data = config_to_dict(config)
        assert data["managed"] == ["*.html"]

    def test_users_and_password_coexist(self, tmp_path):
        """Test that both password and users can be set simultaneously."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "main-pw"
users:
  alice: "pw-a"
  bob: "pw-b"
""")
        config = load_config(config_path=config_path)
        assert config.password == "main-pw"
        assert config.users == {"alice": "pw-a", "bob": "pw-b"}

    def test_username_placeholder_loaded(self, tmp_path):
        """Test that template.username_placeholder is loaded from config."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
template:
  username_placeholder: "Who are you?"
""")
        config = load_config(config_path=config_path)
        assert config.template.username_placeholder == "Who are you?"

    def test_create_default_config_has_users_section(self, tmp_path):
        """Test that created default config contains commented-out users section."""
        config_path = create_default_config(tmp_path)
        content = config_path.read_text()
        assert "# users:" in content
        assert "#   alice:" in content


class TestDefaultUserConfig:
    """Tests for default user configuration."""

    def test_loads_user_from_yaml(self, tmp_path):
        """Test loading user field from config file."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
user: alice
users:
  alice: "pw-a"
  bob: "pw-b"
""")
        config = load_config(config_path=config_path)
        assert config.user == "alice"
        assert config.users == {"alice": "pw-a", "bob": "pw-b"}

    def test_user_must_exist_in_users(self, tmp_path):
        """Test that user field must reference an existing user in users dict."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
user: charlie
users:
  alice: "pw-a"
  bob: "pw-b"
""")
        with pytest.raises(PagevaultError, match="not found in 'users' dict"):
            load_config(config_path=config_path)

    def test_user_without_users_dict_fails(self, tmp_path):
        """Test that user field without users dict fails validation."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
user: alice
password: "single-pw"
""")
        with pytest.raises(PagevaultError, match="no 'users' dict defined"):
            load_config(config_path=config_path)

    def test_user_none_by_default(self, tmp_path):
        """Test user is None when not specified in config."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
users:
  alice: "pw-a"
""")
        config = load_config(config_path=config_path)
        assert config.user is None

    def test_config_to_dict_includes_user(self):
        """Test that config_to_dict includes user field."""
        config = PagevaultConfig(user="alice", users={"alice": "pw-a"})
        data = config_to_dict(config)
        assert data["user"] == "alice"

    def test_config_to_dict_user_none(self):
        """Test that config_to_dict handles None user."""
        config = PagevaultConfig()
        data = config_to_dict(config)
        assert data["user"] is None


class TestUpdateConfigUsers:
    """Tests for update_config_users function."""

    def test_add_users_to_empty_config(self, tmp_path):
        """Test adding users to a config with no users section."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text('password: "test-pw"\n')

        update_config_users(config_path, {"alice": "pw-a", "bob": "pw-b"})

        config = load_config(config_path=config_path)
        assert config.users == {"alice": "pw-a", "bob": "pw-b"}
        assert config.password == "test-pw"

    def test_update_existing_users(self, tmp_path):
        """Test updating an existing users section."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-pw"
users:
  alice: "old-pw"
""")

        update_config_users(config_path, {"alice": "new-pw", "bob": "pw-b"})

        config = load_config(config_path=config_path)
        assert config.users == {"alice": "new-pw", "bob": "pw-b"}

    def test_remove_last_user_removes_key(self, tmp_path):
        """Test removing the last user removes the users key entirely."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-pw"
users:
  alice: "pw-a"
""")

        update_config_users(config_path, None)

        config = load_config(config_path=config_path)
        assert config.users is None
        assert config.password == "test-pw"

    def test_preserves_other_config_keys(self, tmp_path):
        """Test that other config keys are preserved after update."""
        salt = generate_salt()
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(f"""
password: "test-pw"
salt: "{salt_to_hex(salt)}"
defaults:
  remember: "local"
  remember_days: 7
template:
  title: "Custom Title"
managed:
  - "site/**/*.html"
""")

        update_config_users(config_path, {"alice": "pw-a"})

        config = load_config(config_path=config_path)
        assert config.users == {"alice": "pw-a"}
        assert config.password == "test-pw"
        assert config.salt == salt
        assert config.defaults.remember == "local"
        assert config.defaults.remember_days == 7
        assert config.template.title == "Custom Title"
        assert config.managed == ["site/**/*.html"]

    def test_writes_header_comment(self, tmp_path):
        """Test that the output file has the warning header."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text('password: "test-pw"\n')

        update_config_users(config_path, {"alice": "pw-a"})

        content = config_path.read_text()
        assert content.startswith("# pagevault configuration\n")
        assert "WARNING" in content
        assert ".gitignore" in content

    def test_empty_dict_removes_users(self, tmp_path):
        """Test that an empty dict removes the users section (falsy)."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-pw"
users:
  alice: "pw-a"
""")

        update_config_users(config_path, {})

        content = config_path.read_text()
        assert "users:" not in content

    def test_nonexistent_file_raises(self, tmp_path):
        """Test that a nonexistent file raises PagevaultError."""
        with pytest.raises(PagevaultError, match="Cannot read"):
            update_config_users(tmp_path / "nonexistent.yaml", {"alice": "pw"})


# =============================================================================
# Global config tests
# =============================================================================


class TestGlobalConfig:
    """Tests for global config loading and merging."""

    def _setup_global(
        self, tmp_path, monkeypatch, users=None, password=None, user=None, extra=None
    ):
        """Create global config and point XDG_CONFIG_HOME at tmp_path."""
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        global_dir = config_home / "pagevault"
        global_dir.mkdir()
        global_path = global_dir / "config.yaml"

        data = {}
        if users:
            data["users"] = users
        if password:
            data["password"] = password
        if user:
            data["user"] = user
        if extra:
            data.update(extra)

        global_path.write_text(
            yaml.dump(data, default_flow_style=False), encoding="utf-8"
        )
        return global_path

    def _create_local(self, tmp_path, **kwargs):
        """Create local .pagevault.yaml."""
        config_path = tmp_path / CONFIG_FILENAME
        data = {"salt": "0123456789abcdef0123456789abcdef"}
        data.update(kwargs)
        config_path.write_text(
            yaml.dump(data, default_flow_style=False), encoding="utf-8"
        )
        return config_path

    def test_no_global_config(self, tmp_path, monkeypatch):
        """load_config works fine without global config."""
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        local = self._create_local(tmp_path, password="test")
        config = load_config(config_path=local)
        assert config.password == "test"

    def test_global_users_merged(self, tmp_path, monkeypatch):
        """Global users are merged into local config."""
        self._setup_global(tmp_path, monkeypatch, users={"carol": "carol-global"})
        local = self._create_local(
            tmp_path, password="test", users={"alice": "alice-local"}
        )

        config = load_config(config_path=local)
        assert "alice" in config.users
        assert "carol" in config.users
        assert config.users["carol"] == "carol-global"

    def test_local_user_overrides_global(self, tmp_path, monkeypatch):
        """When same username in both, local password wins."""
        self._setup_global(
            tmp_path, monkeypatch, users={"alice": "global-password"}
        )
        local = self._create_local(
            tmp_path, password="test", users={"alice": "local-password"}
        )

        config = load_config(config_path=local)
        assert config.users["alice"] == "local-password"

    def test_global_password_as_fallback(self, tmp_path, monkeypatch):
        """Global password used when local doesn't have one."""
        self._setup_global(tmp_path, monkeypatch, password="global-pass")
        local = self._create_local(tmp_path)  # no password

        config = load_config(config_path=local)
        assert config.password == "global-pass"

    def test_local_password_overrides_global(self, tmp_path, monkeypatch):
        """Local password takes precedence over global."""
        self._setup_global(tmp_path, monkeypatch, password="global-pass")
        local = self._create_local(tmp_path, password="local-pass")

        config = load_config(config_path=local)
        assert config.password == "local-pass"

    def test_global_default_user(self, tmp_path, monkeypatch):
        """Global default user is used as fallback."""
        self._setup_global(
            tmp_path, monkeypatch,
            users={"alice": "pass"},
            user="alice",
        )
        local = self._create_local(tmp_path, password="test")

        config = load_config(config_path=local)
        assert config.user == "alice"

    def test_load_global_config_returns_empty(self, tmp_path, monkeypatch):
        """load_global_config returns {} when no global config exists."""
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = load_global_config()
        assert result == {}

    def test_global_invalid_username_rejected(self, tmp_path, monkeypatch):
        """Global config with ':' in username raises error."""
        self._setup_global(tmp_path, monkeypatch, users={"bad:name": "pass"})

        with pytest.raises(PagevaultError, match="cannot contain ':'"):
            load_global_config()

    def test_password_conflict_warning(self, tmp_path, monkeypatch, capsys):
        """Warns when same user has different passwords in global and local."""
        self._setup_global(
            tmp_path, monkeypatch, users={"alice": "global-pw"}
        )
        local = self._create_local(
            tmp_path, password="test", users={"alice": "local-pw"}
        )

        config = load_config(config_path=local)
        assert config.users["alice"] == "local-pw"  # local wins
        captured = capsys.readouterr()
        assert "different passwords" in captured.err

    def test_no_warning_same_password(self, tmp_path, monkeypatch, capsys):
        """No warning when same user has same password in both."""
        self._setup_global(
            tmp_path, monkeypatch, users={"alice": "same-pw"}
        )
        local = self._create_local(
            tmp_path, password="test", users={"alice": "same-pw"}
        )

        load_config(config_path=local)
        captured = capsys.readouterr()
        assert "different passwords" not in captured.err

    def test_global_salt_as_fallback(self, tmp_path, monkeypatch):
        """Global salt is used when local config has no salt."""
        salt_hex = "0123456789abcdef0123456789abcdef"
        self._setup_global(
            tmp_path, monkeypatch,
            password="test",
            extra={"salt": salt_hex},
        )
        # Local config without salt
        local = self._create_local(tmp_path)
        # Remove salt from local (it was added by _create_local)
        data = yaml.safe_load(local.read_text())
        del data["salt"]
        local.write_text(yaml.dump(data, default_flow_style=False))

        config = load_config(config_path=local)
        assert config.salt is not None
        assert salt_to_hex(config.salt) == salt_hex

    def test_local_salt_overrides_global(self, tmp_path, monkeypatch):
        """Local salt takes precedence over global salt."""
        global_salt = "abcdef0123456789abcdef0123456789"
        local_salt = "0123456789abcdef0123456789abcdef"
        self._setup_global(
            tmp_path, monkeypatch,
            password="test",
            extra={"salt": global_salt},
        )
        local = self._create_local(tmp_path, salt=local_salt)

        config = load_config(config_path=local)
        assert salt_to_hex(config.salt) == local_salt

    def test_global_config_full_structure(self, tmp_path, monkeypatch):
        """Global config can have full structure (same as local)."""
        self._setup_global(
            tmp_path, monkeypatch,
            password="global-pass",
            users={"alice": "pw"},
            extra={
                "salt": "0123456789abcdef0123456789abcdef",
                "defaults": {"remember": "local", "remember_days": 30},
            },
        )
        # No local config, load via search (won't find one)
        config = load_config(start_path=tmp_path)
        assert config.password == "global-pass"
        assert config.users == {"alice": "pw"}


class TestCreateGlobalConfig:
    """Tests for create_global_config function."""

    def test_creates_global_config(self, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        path = create_global_config(users={"alice": "pass"})
        assert path.exists()

        data = yaml.safe_load(path.read_text())
        assert data["users"]["alice"] == "pass"

    def test_refuses_overwrite(self, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        (pv_dir / "config.yaml").write_text("password: old\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        with pytest.raises(PagevaultError, match="already exists"):
            create_global_config(users={"alice": "pass"})

    def test_force_overwrites(self, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        (pv_dir / "config.yaml").write_text("password: old\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        path = create_global_config(users={"alice": "new"}, force=True)
        data = yaml.safe_load(path.read_text())
        assert data["users"]["alice"] == "new"

    def test_with_default_user(self, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        create_global_config(
            users={"alice": "pass"}, default_user="alice"
        )
        data = yaml.safe_load(get_global_config_path().read_text())
        assert data["user"] == "alice"


class TestConfigToDictShowPasswords:
    """Tests for config_to_dict show_passwords parameter."""

    def test_show_passwords_reveals_all(self):
        config = PagevaultConfig(
            password="secret", users={"alice": "alice-pass"}
        )
        data = config_to_dict(config, show_passwords=True)
        assert data["password"] == "secret"
        assert data["users"]["alice"] == "alice-pass"

    def test_default_masks_passwords(self):
        config = PagevaultConfig(
            password="secret", users={"alice": "alice-pass"}
        )
        data = config_to_dict(config)
        assert data["password"] == "se***"
        assert data["users"]["alice"] == "al***"
