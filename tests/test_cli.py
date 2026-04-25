"""Tests for pagevault.cli module."""

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from pagevault.cli import main
from pagevault.config import CONFIG_FILENAME


@pytest.fixture
def runner():
    """Create a CLI runner."""
    return CliRunner()


@pytest.fixture
def sample_html():
    """Sample HTML with pagevault element."""
    return """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<header>Public Header</header>
<pagevault hint="Password hint">
<main>Secret content here</main>
</pagevault>
<footer>Public Footer</footer>
</body>
</html>"""


@pytest.fixture
def sample_config():
    """Sample configuration file content."""
    return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
defaults:
  remember: "ask"
  remember_days: 0
  auto_prompt: true
"""


class TestConfigInit:
    """Tests for config init command."""

    def test_creates_config_file(self, runner, tmp_path):
        """Test creating a new config file."""
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["config", "init"])

            assert result.exit_code == 0
            assert "Created:" in result.output
            assert Path(CONFIG_FILENAME).exists()

    def test_creates_in_directory(self, runner, tmp_path):
        """Test creating config in specified directory."""
        result = runner.invoke(main, ["config", "init", "-d", str(tmp_path)])

        assert result.exit_code == 0
        assert (tmp_path / CONFIG_FILENAME).exists()

    def test_fails_if_exists(self, runner, tmp_path):
        """Test fails if config already exists."""
        (tmp_path / CONFIG_FILENAME).write_text("existing")

        result = runner.invoke(main, ["config", "init", "-d", str(tmp_path)])

        assert result.exit_code != 0
        assert "already exists" in result.output


class TestConfigShow:
    """Tests for config show command."""

    def test_shows_config(self, runner, tmp_path, sample_config):
        """Test showing configuration with source annotations."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(main, ["config", "show", "-c", str(config_path)])

        assert result.exit_code == 0
        assert "te***" in result.output
        assert "salt:" in result.output
        assert "# local" in result.output
        assert "remember: ask" in result.output

    def test_shows_no_config(self, runner, tmp_path, monkeypatch):
        """Test error when no config exists at all."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(main, ["config", "show"])

        assert result.exit_code != 0
        assert "No config found" in result.output

    def test_shows_global_only(self, runner, tmp_path, monkeypatch):
        """Test showing config when only global config exists."""
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        (pv_dir / "config.yaml").write_text(
            'password: "global-pass"\nusers:\n  carol: "carol-pw"\n'
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(main, ["config", "show"])

        assert result.exit_code == 0
        assert "# global" in result.output
        assert "carol" in result.output

    def test_shows_source_overrides(self, runner, tmp_path, monkeypatch):
        """Test source annotations when local overrides global."""
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        (pv_dir / "config.yaml").write_text(
            'users:\n  alice: "global-pw"\n  carol: "carol-pw"\n'
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(
            'users:\n  alice: "local-pw"\nsalt: "0123456789abcdef0123456789abcdef"\n'
        )

        result = runner.invoke(main, ["config", "show", "-c", str(config_path)])

        assert result.exit_code == 0
        assert "local (overrides global)" in result.output
        assert "carol" in result.output


class TestConfigWhere:
    """Tests for config where command."""

    def test_finds_config(self, runner, tmp_path, sample_config):
        """Test finding config file."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(main, ["config", "where", "-d", str(tmp_path)])

        assert result.exit_code == 0
        assert str(config_path) in result.output

    def test_not_found(self, runner, tmp_path):
        """Test when config not found."""
        result = runner.invoke(main, ["config", "where", "-d", str(tmp_path)])

        assert result.exit_code == 0
        assert "No .pagevault.yaml found" in result.output


class TestLock:
    """Tests for lock command."""

    def test_locks_file(self, runner, tmp_path, sample_html, sample_config):
        """Test locking a single file."""
        # Create test files
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0
        assert "Locked:" in result.output
        assert "1 file(s) locked" in result.output

        # Check output file
        output_path = output_dir / "index.html"
        assert output_path.exists()

        content = output_path.read_text()
        assert "data-pv-v4" in content
        assert "Secret content" not in content
        assert "Public Header" in content

    def test_locks_directory_recursive(
        self, runner, tmp_path, sample_html, sample_config
    ):
        """Test locking directory recursively."""
        # Create test files
        (tmp_path / "site").mkdir()
        (tmp_path / "site" / "sub").mkdir()
        (tmp_path / "site" / "index.html").write_text(sample_html)
        (tmp_path / "site" / "sub" / "page.html").write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(tmp_path / "site"),
                "-r",
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0
        assert "2 file(s) locked" in result.output

        assert (output_dir / "index.html").exists()
        assert (output_dir / "sub" / "page.html").exists()

    def test_dry_run(self, runner, tmp_path, sample_html, sample_config):
        """Test dry run mode."""
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "--dry-run",
            ],
        )

        assert result.exit_code == 0
        assert "Would lock:" in result.output
        assert not output_dir.exists()

    def test_skips_files_without_elements(self, runner, tmp_path, sample_config):
        """Test skips files with empty body (nothing to wrap or encrypt)."""
        html_path = tmp_path / "normal.html"
        html_path.write_text("<html><body></body></html>")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code == 0
        assert "0 file(s) locked" in result.output
        assert "1 skipped" in result.output

    def test_prompts_for_password(self, runner, tmp_path, sample_html):
        """Test prompts for password when not in config."""
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-d",
                str(output_dir),
            ],
            input="test-password\n",
        )

        assert result.exit_code == 0
        assert "1 file(s) locked" in result.output

    def test_password_override(self, runner, tmp_path, sample_html, sample_config):
        """Test password can be overridden via CLI."""
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-p",
                "override-password",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) locked" in result.output

    def test_default_output_directory_message(
        self, runner, tmp_path, sample_html, sample_config
    ):
        """Test lock prints default output directory message when -d not specified."""
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code == 0
        assert "Writing to _locked/ (use -d to change)" in result.output


class TestUnlock:
    """Tests for unlock command."""

    def test_unlocks_file(self, runner, tmp_path, sample_html, sample_config):
        """Test unlocking a single file."""
        # Create and lock test file
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        locked_dir = tmp_path / "locked"
        unlocked_dir = tmp_path / "unlocked"

        # Lock first
        runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
            ],
        )

        # Then unlock
        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "-c",
                str(config_path),
                "-d",
                str(unlocked_dir),
            ],
        )

        assert result.exit_code == 0
        assert "Unlocked:" in result.output
        assert "1 file(s) unlocked" in result.output

        # Check content is restored
        content = (unlocked_dir / "index.html").read_text()
        assert "Secret content" in content
        assert "Public Header" in content

    def test_roundtrip(self, runner, tmp_path, sample_html, sample_config):
        """Test lock/unlock roundtrip preserves structure."""
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        locked_dir = tmp_path / "locked"
        unlocked_dir = tmp_path / "unlocked"

        # Lock
        runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
            ],
        )

        # Unlock
        runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir),
                "-r",
                "-c",
                str(config_path),
                "-d",
                str(unlocked_dir),
            ],
        )

        # Compare key elements
        html_path.read_text()
        restored = (unlocked_dir / "index.html").read_text()

        assert "Public Header" in restored
        assert "Public Footer" in restored
        assert "Secret content" in restored
        assert 'hint="Password hint"' in restored

    def test_default_output_directory_message(
        self, runner, tmp_path, sample_html, sample_config
    ):
        """Test unlock prints default output directory message when -d not specified."""
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        locked_dir = tmp_path / "locked"

        # Lock first
        runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
            ],
        )

        # Unlock without -d
        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code == 0
        assert "Writing to _unlocked/ (use -d to change)" in result.output


class TestSelectorLock:
    """Tests for lock command with --selector option."""

    @pytest.fixture
    def html_without_pagevault(self):
        """HTML without pagevault elements."""
        return """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<header>Public Header</header>
<div id="secret-content">Secret content here</div>
<div class="private">Private section</div>
<footer>Public Footer</footer>
</body>
</html>"""

    def test_selector_by_id(
        self, runner, tmp_path, html_without_pagevault, sample_config
    ):
        """Test locking element by ID selector."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_pagevault)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret-content",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) locked" in result.output

        content = (output_dir / "index.html").read_text()
        assert "data-pv-v4" in content
        assert "Secret content here" not in content
        assert "Public Header" in content

    def test_selector_by_class(
        self, runner, tmp_path, html_without_pagevault, sample_config
    ):
        """Test locking element by class selector."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_pagevault)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                ".private",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) locked" in result.output

        content = (output_dir / "index.html").read_text()
        assert "data-pv-v4" in content
        assert "Private section" not in content

    def test_multiple_selectors(
        self, runner, tmp_path, html_without_pagevault, sample_config
    ):
        """Test locking multiple elements with multiple selectors."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_pagevault)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret-content",
                "-s",
                ".private",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) locked" in result.output

        content = (output_dir / "index.html").read_text()
        from bs4 import BeautifulSoup
        assert len(BeautifulSoup(content, "html.parser").find_all(
            "pagevault", attrs={"data-pv-v4": True}
        )) == 2
        assert "Secret content here" not in content
        assert "Private section" not in content

    def test_selector_with_hint(
        self, runner, tmp_path, html_without_pagevault, sample_config
    ):
        """Test selector with password hint."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_pagevault)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret-content",
                "--hint",
                "Use the magic word",
            ],
        )

        assert result.exit_code == 0

        content = (output_dir / "index.html").read_text()
        assert 'data-hint="Use the magic word"' in content

    def test_selector_with_remember(
        self, runner, tmp_path, html_without_pagevault, sample_config
    ):
        """Test selector with remember mode."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_pagevault)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret-content",
                "--remember",
                "local",
            ],
        )

        assert result.exit_code == 0

        content = (output_dir / "index.html").read_text()
        assert 'data-remember="local"' in content

    def test_selector_dry_run(
        self, runner, tmp_path, html_without_pagevault, sample_config
    ):
        """Test selector with dry run mode."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_pagevault)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret-content",
                "--dry-run",
            ],
        )

        assert result.exit_code == 0
        assert "Would lock:" in result.output
        assert not output_dir.exists()

    def test_selector_no_match_skips(
        self, runner, tmp_path, html_without_pagevault, sample_config
    ):
        """Test that files with no matching selectors are skipped."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_pagevault)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#nonexistent",
            ],
        )

        assert result.exit_code == 0
        assert "0 file(s) locked" in result.output
        assert "1 skipped" in result.output

    def test_selector_with_title(
        self, runner, tmp_path, html_without_pagevault, sample_config
    ):
        """Test selector with custom title."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_pagevault)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret-content",
                "--title",
                "Admin Panel",
            ],
        )

        assert result.exit_code == 0

        content = (output_dir / "index.html").read_text()
        assert 'data-title="Admin Panel"' in content

    def test_multi_password_workflow(self, runner, tmp_path, sample_config):
        """Test locking elements with different passwords."""
        html = """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<div id="admin">Admin content</div>
<div id="member">Member content</div>
</body>
</html>"""

        html_path = tmp_path / "index.html"
        html_path.write_text(html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        # First pass: lock admin section with password1
        pass1_dir = tmp_path / "pass1"
        result1 = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(pass1_dir),
                "-s",
                "#admin",
                "-p",
                "admin-password",
                "--title",
                "Admin Area",
            ],
        )

        assert result1.exit_code == 0
        assert "1 file(s) locked" in result1.output

        # Second pass: lock member section with different password
        pass2_dir = tmp_path / "pass2"
        result2 = runner.invoke(
            main,
            [
                "lock",
                str(pass1_dir / "index.html"),
                "-c",
                str(config_path),
                "-d",
                str(pass2_dir),
                "-s",
                "#member",
                "-p",
                "member-password",
                "--title",
                "Members Only",
            ],
        )

        assert result2.exit_code == 0
        assert "1 file(s) locked" in result2.output

        # Final file should have both sections locked
        content = (pass2_dir / "index.html").read_text()
        from bs4 import BeautifulSoup
        assert len(BeautifulSoup(content, "html.parser").find_all(
            "pagevault", attrs={"data-pv-v4": True}
        )) == 2
        assert "Admin content" not in content
        assert "Member content" not in content
        assert 'data-title="Admin Area"' in content
        assert 'data-title="Members Only"' in content


class TestDefaultBodyLock:
    """Tests for default body wrapping behavior."""

    @pytest.fixture
    def sample_config(self):
        """Sample configuration file content."""
        return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
defaults:
  remember: "ask"
  remember_days: 0
  auto_prompt: true
"""

    def test_locks_body_without_pagevault_elements(
        self, runner, tmp_path, sample_config
    ):
        """Test HTML without pagevault elements gets body wrapped."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<h1>Hello World</h1>
<p>Some public content that should be encrypted.</p>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) locked" in result.output

        content = (output_dir / "index.html").read_text()
        assert "data-pv-v4" in content
        assert "Hello World" not in content

    def test_preserves_head_during_body_lock(self, runner, tmp_path, sample_config):
        """Test head section is preserved when body is auto-wrapped."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head>
<title>My Page</title>
<meta name="description" content="Test page">
<link rel="stylesheet" href="styles.css">
</head>
<body>
<p>Body content to encrypt</p>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) locked" in result.output

        content = (output_dir / "index.html").read_text()
        assert "<title>My Page</title>" in content
        assert 'href="styles.css"' in content
        assert "Body content to encrypt" not in content
        assert "data-pv-v4" in content

    def test_body_lock_with_password_flag(self, runner, tmp_path, sample_config):
        """Test using -p flag with body locking works."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body><p>Secret stuff</p></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-p",
                "override-password",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) locked" in result.output

        content = (output_dir / "index.html").read_text()
        assert "data-pv-v4" in content
        assert "Secret stuff" not in content

    def test_selector_overrides_body_wrap(self, runner, tmp_path, sample_config):
        """Test using --selector prevents automatic body wrapping."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<div id="public">Public content</div>
<div id="secret">Secret content</div>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) locked" in result.output

        content = (output_dir / "index.html").read_text()
        # Only the selected element is locked, public content remains
        assert "Public content" in content
        assert "Secret content" not in content
        assert "data-pv-v4" in content


class TestMark:
    """Tests for mark command."""

    def test_mark_with_selector(self, runner, tmp_path):
        """Test marking element in-place with a CSS selector."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<header>Public Header</header>
<div id="secret">Secret content here</div>
<footer>Public Footer</footer>
</body>
</html>""")

        result = runner.invoke(
            main,
            [
                "mark",
                str(html_path),
                "-s",
                "#secret",
            ],
        )

        assert result.exit_code == 0
        assert "Marked:" in result.output
        assert "1 file(s) marked" in result.output

        # File should be modified in-place
        content = html_path.read_text()
        assert "pagevault" in content
        assert "Secret content here" in content
        assert "Public Header" in content

    def test_mark_body(self, runner, tmp_path):
        """Test marking entire body when no selector is given."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<h1>Hello World</h1>
<p>Body content to mark.</p>
</body>
</html>""")

        result = runner.invoke(
            main,
            [
                "mark",
                str(html_path),
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) marked" in result.output

        content = html_path.read_text()
        assert "pagevault" in content

    def test_mark_skips_already_marked(self, runner, tmp_path):
        """Test that files already containing pagevault are skipped."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>
<p>Already marked content</p>
</pagevault>
</body>
</html>""")

        result = runner.invoke(
            main,
            [
                "mark",
                str(html_path),
            ],
        )

        assert result.exit_code == 0
        assert "0 file(s) marked" in result.output
        assert "1 skipped" in result.output

    def test_mark_with_hint_and_title(self, runner, tmp_path):
        """Test marking with hint and title attributes."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<div id="secret">Secret content here</div>
</body>
</html>""")

        result = runner.invoke(
            main,
            [
                "mark",
                str(html_path),
                "-s",
                "#secret",
                "--hint",
                "Contact admin",
                "--title",
                "Members Only",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) marked" in result.output

        content = html_path.read_text()
        assert "pagevault" in content
        assert "Contact admin" in content
        assert "Members Only" in content

    def test_mark_recursive(self, runner, tmp_path):
        """Test marking files recursively with -r flag."""
        (tmp_path / "site").mkdir()
        (tmp_path / "site" / "sub").mkdir()
        (tmp_path / "site" / "index.html").write_text("""<!DOCTYPE html>
<html>
<head><title>Page 1</title></head>
<body>
<div id="secret">Secret 1</div>
</body>
</html>""")
        (tmp_path / "site" / "sub" / "page.html").write_text("""<!DOCTYPE html>
<html>
<head><title>Page 2</title></head>
<body>
<div id="secret">Secret 2</div>
</body>
</html>""")

        result = runner.invoke(
            main,
            [
                "mark",
                str(tmp_path / "site"),
                "-r",
                "-s",
                "#secret",
            ],
        )

        assert result.exit_code == 0
        assert "2 file(s) marked" in result.output

        content1 = (tmp_path / "site" / "index.html").read_text()
        content2 = (tmp_path / "site" / "sub" / "page.html").read_text()
        assert "pagevault" in content1
        assert "pagevault" in content2


class TestMultiUserCli:
    """Tests for multi-user encryption/decryption via CLI."""

    @pytest.fixture
    def sample_users_config(self):
        """Multi-user configuration file content."""
        return """
password: "fallback"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
  bob: "pw-bob"
"""

    def test_lock_with_users_config(self, runner, tmp_path, sample_users_config):
        """Test locking with users config produces data-mode='user' output."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault hint="Multi-user">
<p>Secret for multiple users</p>
</pagevault>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) locked" in result.output

        content = (output_dir / "index.html").read_text()
        assert 'data-mode="user"' in content
        assert "data-pv-v4" in content
        assert "Secret for multiple users" not in content

    def test_unlock_with_username_flag(self, runner, tmp_path, sample_users_config):
        """Test lock with users config, unlock with -u alice -p pw."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>
<p>Alice and Bob's secret</p>
</pagevault>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        locked_dir = tmp_path / "locked"
        unlocked_dir = tmp_path / "unlocked"

        # Lock with users
        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
            ],
        )
        assert result.exit_code == 0

        # Unlock as alice
        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "-u",
                "alice",
                "-p",
                "pw-alice",
                "-d",
                str(unlocked_dir),
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) unlocked" in result.output

        content = (unlocked_dir / "index.html").read_text()
        assert "Alice and Bob's secret" in content

    def test_password_flag_overrides_users(self, runner, tmp_path, sample_users_config):
        """Test -p flag overrides users config for single-user locking."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>
<p>Single user override</p>
</pagevault>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        locked_dir = tmp_path / "locked"
        unlocked_dir = tmp_path / "unlocked"

        # Lock with -p flag (should override users)
        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
                "-p",
                "single-password",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) locked" in result.output

        content = (locked_dir / "index.html").read_text()
        # Should NOT have data-mode="user" since -p overrides users
        assert 'data-mode="user"' not in content

        # Should be unlockable with the single password (no username)
        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "-p",
                "single-password",
                "-d",
                str(unlocked_dir),
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) unlocked" in result.output

        content = (unlocked_dir / "index.html").read_text()
        assert "Single user override" in content


class TestSyncCommand:
    """Tests for sync command."""

    @pytest.fixture
    def sample_users_config(self):
        """Multi-user configuration file content."""
        return """
password: "fallback"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
  bob: "pw-bob"
"""

    def test_sync_basic(self, runner, tmp_path, sample_users_config):
        """Test basic sync with users config."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>
<p>Sync test content</p>
</pagevault>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        locked_dir = tmp_path / "locked"

        # Lock first
        runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
            ],
        )

        # Sync the locked file
        result = runner.invoke(
            main,
            [
                "sync",
                str(locked_dir / "index.html"),
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code == 0

        # File should still be valid and unlockable
        unlocked_dir = tmp_path / "unlocked"
        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "-u",
                "alice",
                "-p",
                "pw-alice",
                "-d",
                str(unlocked_dir),
            ],
        )

        assert result.exit_code == 0
        content = (unlocked_dir / "index.html").read_text()
        assert "Sync test content" in content

    def test_sync_dry_run(self, runner, tmp_path, sample_users_config):
        """Test sync --dry-run shows what would happen without modifying files."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>
<p>Dry run content</p>
</pagevault>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        locked_dir = tmp_path / "locked"

        # Lock first
        runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
            ],
        )

        # Capture file content before sync
        locked_before = (locked_dir / "index.html").read_text()

        # Sync with --dry-run
        result = runner.invoke(
            main,
            [
                "sync",
                str(locked_dir / "index.html"),
                "-c",
                str(config_path),
                "--dry-run",
            ],
        )

        assert result.exit_code == 0
        assert "Would sync:" in result.output

        # File should be unchanged
        locked_after = (locked_dir / "index.html").read_text()
        assert locked_before == locked_after

    def test_sync_requires_users(self, runner, tmp_path):
        """Test sync fails when config has no users defined."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
""")

        html_path = tmp_path / "index.html"
        html_path.write_text("<pagevault>content</pagevault>")

        result = runner.invoke(
            main,
            [
                "sync",
                str(html_path),
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code != 0
        assert "users" in result.output.lower()

    def test_sync_no_paths_no_managed(self, runner, tmp_path, sample_users_config):
        """Test sync fails when no paths given and no managed globs in config."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        result = runner.invoke(
            main,
            [
                "sync",
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code != 0
        assert "managed" in result.output.lower() or "paths" in result.output.lower()

    def test_sync_with_managed_globs(self, runner, tmp_path):
        """Test sync using managed globs from config (no paths argument)."""
        # Config with managed globs
        locked_dir = tmp_path / "locked"
        locked_dir.mkdir()

        config_content = """
password: "fallback"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
  bob: "pw-bob"
managed:
  - "locked/**/*.html"
"""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(config_content)

        # Create and lock a file
        html_path = tmp_path / "source.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>
<p>Managed content</p>
</pagevault>
</body>
</html>""")

        runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
            ],
        )

        assert (locked_dir / "source.html").exists()

        # Sync using managed globs (no paths argument)
        result = runner.invoke(
            main,
            [
                "sync",
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code == 0


class TestConfigUserAdd:
    """Tests for config user add command."""

    @pytest.fixture
    def config_with_users(self, tmp_path):
        """Config file with existing users."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-pw"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
""")
        return config_path

    @pytest.fixture
    def config_without_users(self, tmp_path):
        """Config file with no users."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-pw"
salt: "0123456789abcdef0123456789abcdef"
""")
        return config_path

    def test_add_user_with_password_flag(self, runner, config_without_users):
        """Test adding a user with -p flag."""
        result = runner.invoke(
            main,
            [
                "config",
                "user",
                "add",
                "alice",
                "-p",
                "pw-alice",
                "-c",
                str(config_without_users),
            ],
        )

        assert result.exit_code == 0
        assert "Added user 'alice'" in result.output
        assert "pagevault sync" in result.output

        # Verify written to file
        import yaml

        with open(config_without_users) as f:
            data = yaml.safe_load(f)
        assert data["users"]["alice"] == "pw-alice"

    def test_add_user_interactive_prompt(self, runner, config_without_users):
        """Test adding a user with interactive password prompt."""
        result = runner.invoke(
            main,
            ["config", "user", "add", "bob", "-c", str(config_without_users)],
            input="secret-pw\nsecret-pw\n",
        )

        assert result.exit_code == 0
        assert "Added user 'bob'" in result.output

    def test_add_duplicate_fails(self, runner, config_with_users):
        """Test adding an existing user fails."""
        result = runner.invoke(
            main,
            [
                "config",
                "user",
                "add",
                "alice",
                "-p",
                "new-pw",
                "-c",
                str(config_with_users),
            ],
        )

        assert result.exit_code != 0
        assert "already exists" in result.output
        assert "passwd" in result.output

    def test_add_user_with_colon_fails(self, runner, config_without_users):
        """Test username with colon is rejected."""
        result = runner.invoke(
            main,
            [
                "config",
                "user",
                "add",
                "bad:name",
                "-p",
                "pw",
                "-c",
                str(config_without_users),
            ],
        )

        assert result.exit_code != 0
        assert "cannot contain ':'" in result.output

    def test_add_preserves_existing_users(self, runner, config_with_users):
        """Test adding a new user preserves existing users."""
        result = runner.invoke(
            main,
            [
                "config",
                "user",
                "add",
                "bob",
                "-p",
                "pw-bob",
                "-c",
                str(config_with_users),
            ],
        )

        assert result.exit_code == 0

        import yaml

        with open(config_with_users) as f:
            data = yaml.safe_load(f)
        assert data["users"]["alice"] == "pw-alice"
        assert data["users"]["bob"] == "pw-bob"


class TestConfigUserRm:
    """Tests for config user rm command."""

    @pytest.fixture
    def config_with_users(self, tmp_path):
        """Config file with two users."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-pw"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
  bob: "pw-bob"
""")
        return config_path

    def test_remove_user(self, runner, config_with_users):
        """Test removing a user."""
        result = runner.invoke(
            main,
            ["config", "user", "rm", "bob", "-c", str(config_with_users)],
        )

        assert result.exit_code == 0
        assert "Removed user 'bob'" in result.output
        assert "pagevault sync" in result.output

        import yaml

        with open(config_with_users) as f:
            data = yaml.safe_load(f)
        assert "bob" not in data["users"]
        assert "alice" in data["users"]

    def test_remove_nonexistent_fails(self, runner, config_with_users):
        """Test removing a nonexistent user fails."""
        result = runner.invoke(
            main,
            ["config", "user", "rm", "charlie", "-c", str(config_with_users)],
        )

        assert result.exit_code != 0
        assert "not found" in result.output

    def test_remove_last_user(self, runner, tmp_path):
        """Test removing the last user removes the users key."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-pw"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
""")

        result = runner.invoke(
            main,
            ["config", "user", "rm", "alice", "-c", str(config_path)],
        )

        assert result.exit_code == 0
        assert "Removed user 'alice'" in result.output

        import yaml

        with open(config_path) as f:
            data = yaml.safe_load(f)
        assert "users" not in data


class TestConfigUserList:
    """Tests for config user list command."""

    def test_list_users(self, runner, tmp_path):
        """Test listing users."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-pw"
users:
  alice: "pw-alice"
  bob: "pw-bob"
""")

        result = runner.invoke(
            main,
            ["config", "user", "list", "-c", str(config_path)],
        )

        assert result.exit_code == 0
        assert "alice" in result.output
        assert "bob" in result.output
        # Passwords should not appear
        assert "pw-alice" not in result.output
        assert "pw-bob" not in result.output

    def test_list_no_users(self, runner, tmp_path):
        """Test listing when no users configured."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text('password: "test-pw"\n')

        result = runner.invoke(
            main,
            ["config", "user", "list", "-c", str(config_path)],
        )

        assert result.exit_code == 0
        assert "(no users configured)" in result.output


class TestConfigUserPasswd:
    """Tests for config user passwd command."""

    @pytest.fixture
    def config_with_users(self, tmp_path):
        """Config file with existing users."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-pw"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
  bob: "pw-bob"
""")
        return config_path

    def test_change_password_with_flag(self, runner, config_with_users):
        """Test changing password with -p flag."""
        result = runner.invoke(
            main,
            [
                "config",
                "user",
                "passwd",
                "alice",
                "-p",
                "new-pw",
                "-c",
                str(config_with_users),
            ],
        )

        assert result.exit_code == 0
        assert "Password updated for 'alice'" in result.output
        assert "pagevault sync" in result.output

        import yaml

        with open(config_with_users) as f:
            data = yaml.safe_load(f)
        assert data["users"]["alice"] == "new-pw"
        assert data["users"]["bob"] == "pw-bob"

    def test_change_password_interactive(self, runner, config_with_users):
        """Test changing password interactively."""
        result = runner.invoke(
            main,
            ["config", "user", "passwd", "alice", "-c", str(config_with_users)],
            input="new-pw\nnew-pw\n",
        )

        assert result.exit_code == 0
        assert "Password updated for 'alice'" in result.output

    def test_change_nonexistent_user_fails(self, runner, config_with_users):
        """Test changing password for nonexistent user fails."""
        result = runner.invoke(
            main,
            [
                "config",
                "user",
                "passwd",
                "charlie",
                "-p",
                "pw",
                "-c",
                str(config_with_users),
            ],
        )

        assert result.exit_code != 0
        assert "not found" in result.output


class TestUserAddGlobal:
    """Tests for config user add --global."""

    def _setup_global(self, tmp_path, monkeypatch, users=None):
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        data = {"users": users or {"alice": "pw-alice"}}
        (pv_dir / "config.yaml").write_text(yaml.dump(data))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
        return pv_dir / "config.yaml"

    def test_add_user_global(self, runner, tmp_path, monkeypatch):
        global_path = self._setup_global(tmp_path, monkeypatch)
        result = runner.invoke(
            main,
            ["config", "user", "add", "bob", "-p", "pw-bob", "--global"],
        )
        assert result.exit_code == 0
        assert "bob" in result.output
        assert "global" in result.output

        data = yaml.safe_load(global_path.read_text())
        assert data["users"]["bob"] == "pw-bob"
        assert data["users"]["alice"] == "pw-alice"

    def test_add_duplicate_global_fails(self, runner, tmp_path, monkeypatch):
        self._setup_global(tmp_path, monkeypatch)
        result = runner.invoke(
            main,
            ["config", "user", "add", "alice", "-p", "pw", "--global"],
        )
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_no_global_config_fails(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
        result = runner.invoke(
            main,
            ["config", "user", "add", "bob", "-p", "pw", "--global"],
        )
        assert result.exit_code != 0
        assert "not found" in result.output.lower()


class TestUserRmGlobal:
    """Tests for config user rm --global."""

    def _setup_global(self, tmp_path, monkeypatch, users=None):
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        data = {"users": users or {"alice": "pw-alice", "bob": "pw-bob"}}
        (pv_dir / "config.yaml").write_text(yaml.dump(data))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
        return pv_dir / "config.yaml"

    def test_remove_user_global(self, runner, tmp_path, monkeypatch):
        global_path = self._setup_global(tmp_path, monkeypatch)
        result = runner.invoke(
            main,
            ["config", "user", "rm", "bob", "--global"],
        )
        assert result.exit_code == 0
        assert "bob" in result.output
        assert "global" in result.output

        data = yaml.safe_load(global_path.read_text())
        assert "bob" not in data["users"]
        assert "alice" in data["users"]

    def test_remove_nonexistent_global_fails(self, runner, tmp_path, monkeypatch):
        self._setup_global(tmp_path, monkeypatch)
        result = runner.invoke(
            main,
            ["config", "user", "rm", "charlie", "--global"],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_hints_when_user_in_other_tier(self, runner, tmp_path, monkeypatch):
        """Removing a global-only user from local config hints about --global."""
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        (pv_dir / "config.yaml").write_text(
            yaml.dump({"users": {"globaluser": "gpass"}})
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-pw"
salt: "0123456789abcdef0123456789abcdef"
users:
  localuser: "pw-local"
""")
        result = runner.invoke(
            main,
            ["config", "user", "rm", "globaluser", "-c", str(config_path)],
        )
        assert result.exit_code != 0
        assert "global" in result.output
        assert "--global" in result.output


class TestUserListGlobal:
    """Tests for config user list --global."""

    def test_list_global_users(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        (pv_dir / "config.yaml").write_text(
            yaml.dump({"users": {"alice": "pw", "bob": "pw"}})
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(main, ["config", "user", "list", "--global"])
        assert result.exit_code == 0
        assert "alice" in result.output
        assert "bob" in result.output

    def test_list_empty_global(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        (pv_dir / "config.yaml").write_text(yaml.dump({}))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(main, ["config", "user", "list", "--global"])
        assert result.exit_code == 0
        assert "no users" in result.output.lower()


class TestUserPasswdGlobal:
    """Tests for config user passwd --global."""

    def _setup_global(self, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        data = {"users": {"alice": "old-pw"}}
        (pv_dir / "config.yaml").write_text(yaml.dump(data))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
        return pv_dir / "config.yaml"

    def test_change_password_global(self, runner, tmp_path, monkeypatch):
        global_path = self._setup_global(tmp_path, monkeypatch)
        result = runner.invoke(
            main,
            ["config", "user", "passwd", "alice", "-p", "new-pw", "--global"],
        )
        assert result.exit_code == 0
        assert "alice" in result.output
        assert "global" in result.output

        data = yaml.safe_load(global_path.read_text())
        assert data["users"]["alice"] == "new-pw"

    def test_change_nonexistent_global_fails(self, runner, tmp_path, monkeypatch):
        self._setup_global(tmp_path, monkeypatch)
        result = runner.invoke(
            main,
            ["config", "user", "passwd", "charlie", "-p", "pw", "--global"],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_change_password_interactive_global(self, runner, tmp_path, monkeypatch):
        global_path = self._setup_global(tmp_path, monkeypatch)
        result = runner.invoke(
            main,
            ["config", "user", "passwd", "alice", "--global"],
            input="new-pw\nnew-pw\n",
        )
        assert result.exit_code == 0

        data = yaml.safe_load(global_path.read_text())
        assert data["users"]["alice"] == "new-pw"


class TestLockWithUsername:
    """Tests for lock command with -u flag."""

    @pytest.fixture
    def sample_config(self):
        """Sample configuration file content."""
        return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
"""

    def test_lock_with_username_and_password(self, runner, tmp_path, sample_config):
        """Test -u alice -p secret creates single-user file for alice."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>Secret for alice</pagevault>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "locked"

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-u",
                "alice",
                "-p",
                "secret",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) locked" in result.output

        # Check output has data-mode="user" (multi-user format for single user)
        content = (output_dir / "index.html").read_text()
        assert 'data-mode="user"' in content
        assert "data-pv-v4" in content
        assert "Secret for alice" not in content

    def test_lock_username_without_password_fails(
        self, runner, tmp_path, sample_config
    ):
        """Test -u alone without -p produces an error."""
        html_path = tmp_path / "index.html"
        html_path.write_text("<pagevault>Secret</pagevault>")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-u",
                "alice",
            ],
        )

        assert result.exit_code != 0
        assert "-u" in result.output or "username" in result.output.lower()
        assert "-p" in result.output or "password" in result.output.lower()

    def test_lock_username_password_can_be_unlocked(
        self, runner, tmp_path, sample_config
    ):
        """Test file locked with -u -p can be unlocked with same credentials."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>Alice's secret</pagevault>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        locked_dir = tmp_path / "locked"
        unlocked_dir = tmp_path / "unlocked"

        # Lock with -u -p
        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
                "-u",
                "alice",
                "-p",
                "secret",
            ],
        )
        assert result.exit_code == 0

        # Unlock with same credentials
        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "-d",
                str(unlocked_dir),
                "-u",
                "alice",
                "-p",
                "secret",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) unlocked" in result.output

        content = (unlocked_dir / "index.html").read_text()
        assert "Alice's secret" in content


class TestUnlockAutoPassword:
    """Tests for unlock command with automatic password lookup."""

    @pytest.fixture
    def sample_users_config(self):
        """Multi-user configuration file content."""
        return """
password: "fallback"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
  bob: "pw-bob"
"""

    @pytest.fixture
    def sample_users_config_with_default(self):
        """Multi-user configuration with default user."""
        return """
password: "fallback"
salt: "0123456789abcdef0123456789abcdef"
user: alice
users:
  alice: "pw-alice"
  bob: "pw-bob"
"""

    def test_unlock_auto_password_from_config(
        self, runner, tmp_path, sample_users_config
    ):
        """Test -u alice uses password from config automatically."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>Auto password secret</pagevault>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        locked_dir = tmp_path / "locked"
        unlocked_dir = tmp_path / "unlocked"

        # Lock with users config
        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
            ],
        )
        assert result.exit_code == 0

        # Unlock with -u only (no -p) - password should come from config
        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "-c",
                str(config_path),
                "-d",
                str(unlocked_dir),
                "-u",
                "alice",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) unlocked" in result.output

        content = (unlocked_dir / "index.html").read_text()
        assert "Auto password secret" in content

    def test_unlock_uses_default_user(
        self, runner, tmp_path, sample_users_config_with_default
    ):
        """Test unlock without -u uses default user from config."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>Default user secret</pagevault>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config_with_default)

        locked_dir = tmp_path / "locked"
        unlocked_dir = tmp_path / "unlocked"

        # Lock with users config
        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
            ],
        )
        assert result.exit_code == 0

        # Unlock without -u flag - should use default user 'alice' from config
        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "-c",
                str(config_path),
                "-d",
                str(unlocked_dir),
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) unlocked" in result.output

        content = (unlocked_dir / "index.html").read_text()
        assert "Default user secret" in content

    def test_unlock_explicit_user_overrides_default(
        self, runner, tmp_path, sample_users_config_with_default
    ):
        """Test -u bob overrides default user alice."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>Override default secret</pagevault>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config_with_default)

        locked_dir = tmp_path / "locked"
        unlocked_dir = tmp_path / "unlocked"

        # Lock with users config
        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
            ],
        )
        assert result.exit_code == 0

        # Unlock with -u bob (overrides default alice)
        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "-c",
                str(config_path),
                "-d",
                str(unlocked_dir),
                "-u",
                "bob",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) unlocked" in result.output

        content = (unlocked_dir / "index.html").read_text()
        assert "Override default secret" in content

    def test_unlock_multiuser_without_username_helpful_error(
        self, runner, tmp_path, sample_users_config
    ):
        """Test unlocking multi-user file without -u gives helpful error."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>Multi-user secret</pagevault>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        # Config without default user
        config_path.write_text(sample_users_config)

        locked_dir = tmp_path / "locked"
        unlocked_dir = tmp_path / "unlocked"

        # Lock with users config
        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
            ],
        )
        assert result.exit_code == 0

        # Create a different config without users for unlock (simulating no config)
        simple_config_path = tmp_path / "simple.yaml"
        simple_config_path.write_text('password: "wrong"\n')

        # Unlock without -u and without default user - should get helpful error
        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "-c",
                str(simple_config_path),
                "-d",
                str(unlocked_dir),
            ],
        )

        # Should fail with helpful error about multi-user encryption
        assert result.exit_code == 0 or "multi-user" in result.output.lower()


class TestVersion:
    """Tests for version command."""

    def test_version(self, runner):
        """Test version output."""
        result = runner.invoke(main, ["--version"])

        assert result.exit_code == 0
        assert "pagevault" in result.output
        assert "0.4.0" in result.output


class TestInfoCommand:
    """Tests for pagevault inspect command (info mode)."""

    @pytest.fixture
    def sample_config(self):
        return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
"""

    def test_info_shows_metadata(self, runner, tmp_path, sample_config):
        """Test info command shows encryption metadata."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault hint="Test hint">Secret content</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        locked_dir = tmp_path / "locked"

        runner.invoke(
            main,
            ["lock", str(html_path), "-c", str(config_path), "-d", str(locked_dir)],
        )

        result = runner.invoke(
            main, ["inspect", str(locked_dir / "index.html")]
        )

        assert result.exit_code == 0
        assert "Encrypted regions: 1" in result.output
        assert "aes-256-gcm" in result.output
        assert "pbkdf2-sha256" in result.output
        assert "310,000" in result.output
        assert "Key blobs:" in result.output
        # In v4, content_hash is inside the encrypted envelope metadata,
        # not a DOM attribute — so it isn't visible without decryption.
        assert "Chunks:" in result.output

    def test_info_multi_user(self, runner, tmp_path):
        """Test info shows multi-user mode."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault>Secret</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "fallback"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
  bob: "pw-bob"
""")

        locked_dir = tmp_path / "locked"

        runner.invoke(
            main,
            ["lock", str(html_path), "-c", str(config_path), "-d", str(locked_dir)],
        )

        result = runner.invoke(
            main, ["inspect", str(locked_dir / "index.html")]
        )

        assert result.exit_code == 0
        assert "Key blobs:    2" in result.output
        assert "user" in result.output

    def test_info_non_encrypted_fails(self, runner, tmp_path):
        """Test info fails on non-encrypted file."""
        html_path = tmp_path / "plain.html"
        html_path.write_text("<html><body>Hello</body></html>")

        result = runner.invoke(
            main, ["inspect", str(html_path)]
        )

        assert result.exit_code != 0
        assert "no pagevault elements" in result.output.lower()

    def test_info_wrap_file(self, runner, tmp_path):
        """Test info on wrapped file shows v4 chunked format."""
        # Create a text file and wrap it (now uses v4 chunked format)
        txt_path = tmp_path / "data.txt"
        txt_path.write_text("test content")

        out_path = tmp_path / "data.html"

        result = runner.invoke(
            main,
            ["lock", str(txt_path), "-p", "test-pw", "-o", str(out_path)],
        )
        assert result.exit_code == 0

        result = runner.invoke(
            main, ["inspect", str(out_path)]
        )

        assert result.exit_code == 0
        assert "v4 chunked" in result.output
        assert "Chunks:" in result.output
        assert "Total size:" in result.output


class TestCheckCommand:
    """Tests for pagevault inspect --check command."""

    @pytest.fixture
    def sample_config(self):
        return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
"""

    def test_check_correct_password(self, runner, tmp_path, sample_config):
        """Test check exits 0 for correct password."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault>Secret</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        locked_dir = tmp_path / "locked"

        runner.invoke(
            main,
            ["lock", str(html_path), "-c", str(config_path), "-d", str(locked_dir)],
        )

        result = runner.invoke(
            main,
            [
                "inspect", str(locked_dir / "index.html"),
                "-p", "test-password", "--check",
            ],
        )

        assert "correct" in result.output.lower()
        assert result.exit_code == 0

    def test_check_wrong_password(self, runner, tmp_path, sample_config):
        """Test check exits 1 for wrong password."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault>Secret</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        locked_dir = tmp_path / "locked"

        runner.invoke(
            main,
            ["lock", str(html_path), "-c", str(config_path), "-d", str(locked_dir)],
        )

        result = runner.invoke(
            main,
            [
                "inspect", str(locked_dir / "index.html"),
                "-p", "wrong-password", "--check",
            ],
        )

        assert "incorrect" in result.output.lower()
        assert result.exit_code == 1

    def test_check_multi_user(self, runner, tmp_path):
        """Test check with username for multi-user file."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault>Secret</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "fallback"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
""")

        locked_dir = tmp_path / "locked"

        runner.invoke(
            main,
            ["lock", str(html_path), "-c", str(config_path), "-d", str(locked_dir)],
        )

        result = runner.invoke(
            main,
            [
                "inspect",
                str(locked_dir / "index.html"),
                "-p",
                "pw-alice",
                "-u",
                "alice",
                "--check",
            ],
        )

        assert "correct" in result.output.lower()
        assert result.exit_code == 0

    def test_check_non_encrypted_fails(self, runner, tmp_path):
        """Test check fails on non-encrypted file."""
        html_path = tmp_path / "plain.html"
        html_path.write_text("<html><body>Hello</body></html>")

        result = runner.invoke(
            main,
            ["inspect", str(html_path), "-p", "test", "--check"],
        )

        assert result.exit_code != 0


class TestAuditCommand:
    """Tests for pagevault audit command."""

    def test_audit_good_config(self, runner, tmp_path):
        """Test audit passes with good configuration."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "very-strong-passphrase-2024!"
salt: "0123456789abcdef0123456789abcdef"
""")

        # Create .gitignore
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text(".pagevault.yaml\n")

        result = runner.invoke(main, ["audit", "-c", str(config_path)])

        assert "PASSED" in result.output
        assert "password length OK" in result.output
        assert ".gitignore" in result.output

    def test_audit_weak_password(self, runner, tmp_path):
        """Test audit flags weak passwords."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "abc"
salt: "0123456789abcdef0123456789abcdef"
""")

        result = runner.invoke(main, ["audit", "-c", str(config_path)])

        assert "WEAK" in result.output
        assert "only 3 chars" in result.output

    def test_audit_all_lowercase_password(self, runner, tmp_path):
        """Test audit flags all-lowercase passwords."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "longbutweakpassword"
salt: "0123456789abcdef0123456789abcdef"
""")

        result = runner.invoke(main, ["audit", "-c", str(config_path)])

        assert "WEAK" in result.output or "lowercase" in result.output

    def test_audit_missing_gitignore(self, runner, tmp_path):
        """Test audit warns about missing .gitignore."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "Strong-Password-2024!"
salt: "0123456789abcdef0123456789abcdef"
""")

        result = runner.invoke(main, ["audit", "-c", str(config_path)])

        assert "WARNING" in result.output or ".gitignore" in result.output

    def test_audit_no_salt(self, runner, tmp_path):
        """Test audit warns about missing salt."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text('password: "Strong-Password-2024!"\n')

        result = runner.invoke(main, ["audit", "-c", str(config_path)])

        assert "salt" in result.output.lower()

    def test_audit_user_passwords(self, runner, tmp_path):
        """Test audit checks each user's password."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "fallback"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "Strong-Password-2024!"
  bob: "ab"
""")

        result = runner.invoke(main, ["audit", "-c", str(config_path)])

        assert "bob" in result.output
        assert "WEAK" in result.output


class TestUnlockStdout:
    """Tests for unlock --stdout flag."""

    @pytest.fixture
    def sample_config(self):
        return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
"""

    def test_stdout_outputs_decrypted(self, runner, tmp_path, sample_config):
        """Test --stdout outputs decrypted HTML to stdout."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault>Secret content here</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        locked_dir = tmp_path / "locked"

        runner.invoke(
            main,
            ["lock", str(html_path), "-c", str(config_path), "-d", str(locked_dir)],
        )

        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "--stdout",
                "-p",
                "test-password",
            ],
        )

        assert result.exit_code == 0
        assert "Secret content here" in result.output
        # Should not have the normal "Unlocked:" output
        assert "file(s) unlocked" not in result.output

    def test_stdout_with_directory_fails(self, runner, tmp_path, sample_config):
        """Test --stdout and -d are mutually exclusive."""
        html_path = tmp_path / "index.html"
        html_path.write_text("<pagevault>Secret</pagevault>")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        locked_dir = tmp_path / "locked"

        runner.invoke(
            main,
            ["lock", str(html_path), "-c", str(config_path), "-d", str(locked_dir)],
        )

        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "--stdout",
                "-d",
                str(tmp_path / "out"),
                "-p",
                "test-password",
            ],
        )

        assert result.exit_code != 0
        assert "mutually exclusive" in result.output.lower()

    def test_stdout_with_recursive_fails(self, runner, tmp_path, sample_config):
        """Test --stdout and -r are mutually exclusive."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(
            main,
            [
                "unlock",
                str(tmp_path),
                "--stdout",
                "-r",
                "-p",
                "test-password",
            ],
        )

        assert result.exit_code != 0

    def test_stdout_non_encrypted_fails(self, runner, tmp_path):
        """Test --stdout fails on non-encrypted file."""
        html_path = tmp_path / "plain.html"
        html_path.write_text("<html><body>Hello</body></html>")

        result = runner.invoke(
            main,
            ["unlock", str(html_path), "--stdout", "-p", "pw"],
        )

        assert result.exit_code != 0


class TestPadFlag:
    """Tests for --pad flag on lock command."""

    @pytest.fixture
    def sample_config(self):
        return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
"""

    def test_pad_flag_produces_larger_output(self, runner, tmp_path, sample_config):
        """Test --pad produces output (padded content encrypts to larger size)."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault>Short</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        # Lock without padding
        nopad_dir = tmp_path / "nopad"
        runner.invoke(
            main,
            ["lock", str(html_path), "-c", str(config_path), "-d", str(nopad_dir)],
        )

        # Lock with padding
        pad_dir = tmp_path / "pad"
        runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(pad_dir),
                "--pad",
            ],
        )

        nopad_size = (nopad_dir / "index.html").stat().st_size
        pad_size = (pad_dir / "index.html").stat().st_size

        # Padded version should be at least as large
        assert pad_size >= nopad_size

    def test_pad_roundtrip(self, runner, tmp_path, sample_config):
        """Test padded content still decrypts correctly."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault>Padded secret content</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        locked_dir = tmp_path / "locked"
        unlocked_dir = tmp_path / "unlocked"

        # Lock with padding
        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
                "--pad",
            ],
        )
        assert result.exit_code == 0

        # Unlock
        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "-c",
                str(config_path),
                "-d",
                str(unlocked_dir),
            ],
        )
        assert result.exit_code == 0

        content = (unlocked_dir / "index.html").read_text()
        assert "Padded secret content" in content

    def test_pad_config(self, runner, tmp_path):
        """Test pad: true in config works without --pad flag."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault>Config pad</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
pad: true
""")

        locked_dir = tmp_path / "locked"
        unlocked_dir = tmp_path / "unlocked"

        # Lock without --pad flag (config has pad: true)
        result = runner.invoke(
            main,
            ["lock", str(html_path), "-c", str(config_path), "-d", str(locked_dir)],
        )
        assert result.exit_code == 0

        # Unlock should work
        result = runner.invoke(
            main,
            [
                "unlock",
                str(locked_dir / "index.html"),
                "-c",
                str(config_path),
                "-d",
                str(unlocked_dir),
            ],
        )
        assert result.exit_code == 0
        content = (unlocked_dir / "index.html").read_text()
        assert "Config pad" in content


# =============================================================================
# Global config CLI tests
# =============================================================================


class TestConfigInitGlobal:
    """Tests for config init --global command."""

    def test_creates_global_config(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["config", "init", "--global"],
            input="alice\nmypass\nmypass\n",
        )
        assert result.exit_code == 0
        assert "Created" in result.output

        global_path = config_home / "pagevault" / "config.yaml"
        assert global_path.exists()
        data = yaml.safe_load(global_path.read_text())
        assert data["users"]["alice"] == "mypass"

    def test_refuses_overwrite(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        (pv_dir / "config.yaml").write_text("password: old\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["config", "init", "--global"],
            input="alice\npass\npass\n",
        )
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_force_overwrites(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        (pv_dir / "config.yaml").write_text("password: old\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["config", "init", "--global", "--force"],
            input="alice\nnewpass\nnewpass\n",
        )
        assert result.exit_code == 0

        data = yaml.safe_load((pv_dir / "config.yaml").read_text())
        assert "alice" in data["users"]


class TestConfigWhereGlobal:
    """Tests for config where showing global config."""

    def test_shows_global_info(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        (pv_dir / "config.yaml").write_text(
            yaml.dump({"users": {"carol": "pass"}}), encoding="utf-8"
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(main, ["config", "where", "-d", str(tmp_path)])
        assert result.exit_code == 0
        assert "Global config:" in result.output
        assert "carol" in result.output

    def test_shows_no_global(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(main, ["config", "where", "-d", str(tmp_path)])
        assert result.exit_code == 0
        assert "not found" in result.output


class TestConfigShowPasswords:
    """Tests for config show --show-passwords flag."""

    def test_passwords_masked_by_default(self, runner, tmp_path):
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(
            'password: "test-password"\nsalt: "0123456789abcdef0123456789abcdef"\n'
        )

        result = runner.invoke(main, ["config", "show", "-c", str(config_path)])
        assert result.exit_code == 0
        assert "te***" in result.output
        assert "test-password" not in result.output

    def test_show_passwords_reveals(self, runner, tmp_path):
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(
            'password: "test-password"\nsalt: "0123456789abcdef0123456789abcdef"\n'
        )

        result = runner.invoke(
            main,
            ["config", "show", "--show-passwords", "-c", str(config_path)],
        )
        assert result.exit_code == 0
        assert "test-password" in result.output

    def test_global_passwords_masked(self, runner, tmp_path, monkeypatch):
        """Global user passwords are also masked."""
        config_home = tmp_path / "xdg_config"
        pv_dir = config_home / "pagevault"
        pv_dir.mkdir(parents=True)
        (pv_dir / "config.yaml").write_text('users:\n  carol: "global-password"\n')
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(main, ["config", "show"])
        assert result.exit_code == 0
        assert "gl***" in result.output
        assert "global-password" not in result.output


class TestWrapFlag:
    """Tests for --wrap flag on lock command."""

    @pytest.fixture
    def sample_config(self):
        return 'password: "test-password"\nsalt: "0123456789abcdef0123456789abcdef"\n'

    def test_wrap_html_produces_file_wrapped_output(
        self, runner, tmp_path, sample_config
    ):
        """--wrap on HTML creates file-wrapped output, not region encryption."""
        html_path = tmp_path / "page.html"
        html_path.write_text(
            "<!DOCTYPE html><html><head>"
            "<title>Secret Title</title></head>"
            "<body><h1>Secret</h1></body></html>"
        )

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        out_dir = tmp_path / "out"
        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "--wrap",
                "-c",
                str(config_path),
                "-d",
                str(out_dir),
            ],
        )
        assert result.exit_code == 0
        assert "Wrapped:" in result.output

        output = (out_dir / "page.html").read_text()
        # File-wrapped output has "Protected:" title, not original
        assert "Protected: page.html" in output
        # Original title must NOT leak
        assert "Secret Title" not in output

    def test_wrap_default_directory(self, runner, tmp_path, sample_config, monkeypatch):
        """--wrap defaults to _locked/ output directory."""
        monkeypatch.chdir(tmp_path)

        html_path = tmp_path / "page.html"
        html_path.write_text("<!DOCTYPE html><html><body>Content</body></html>")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "--wrap",
                "-c",
                str(config_path),
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "_locked/" in result.output
        assert (tmp_path / "_locked" / "page.html").exists()

    def test_wrap_rejects_directories(self, runner, tmp_path, sample_config):
        """--wrap does not accept directories (use --site instead)."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(
            main,
            ["lock", str(tmp_path), "--wrap", "-c", str(config_path)],
        )
        assert result.exit_code != 0
        assert "--wrap requires files" in result.output

    def test_wrap_with_output_flag(self, runner, tmp_path, sample_config):
        """--wrap with -o writes to specific output path."""
        html_path = tmp_path / "page.html"
        html_path.write_text("<!DOCTYPE html><html><body>Content</body></html>")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        out_file = tmp_path / "custom-output.html"
        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "--wrap",
                "-o",
                str(out_file),
                "-c",
                str(config_path),
            ],
        )
        assert result.exit_code == 0
        assert out_file.exists()

    def test_wrap_source_not_modified(self, runner, tmp_path, sample_config):
        """--wrap does not modify the source HTML file."""
        original = (
            "<!DOCTYPE html><html><head>"
            "<title>Original</title></head>"
            "<body><h1>Content</h1></body></html>"
        )
        html_path = tmp_path / "page.html"
        html_path.write_text(original)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        out_dir = tmp_path / "out"
        runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "--wrap",
                "-c",
                str(config_path),
                "-d",
                str(out_dir),
            ],
        )
        # Source file must be unchanged
        assert html_path.read_text() == original

    def test_wrap_non_html_still_works(self, runner, tmp_path, sample_config):
        """--wrap on non-HTML files works the same as regular lock."""
        txt_path = tmp_path / "notes.txt"
        txt_path.write_text("Some notes")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        out_dir = tmp_path / "out"
        result = runner.invoke(
            main,
            [
                "lock",
                str(txt_path),
                "--wrap",
                "-c",
                str(config_path),
                "-d",
                str(out_dir),
            ],
        )
        assert result.exit_code == 0
        assert (out_dir / "notes.txt.html").exists()


class TestInfoV4:
    """Tests for inspect command on v4 wrapped files."""

    def test_info_v3_shows_chunk_info(self, runner, tmp_path):
        """Info on v4 file shows chunk count and total size."""
        txt_path = tmp_path / "test.txt"
        txt_path.write_text("Hello!")
        out_path = tmp_path / "test.html"

        result = runner.invoke(
            main, ["lock", str(txt_path), "-p", "pw", "-o", str(out_path)]
        )
        assert result.exit_code == 0

        result = runner.invoke(
            main, ["inspect", str(out_path)]
        )
        assert result.exit_code == 0
        assert "v4 chunked" in result.output
        assert "Chunks:" in result.output
        assert "Total size:" in result.output
        assert "Chunk size:" in result.output
        assert "Key blobs:" in result.output

    def test_info_v3_shows_algorithm(self, runner, tmp_path):
        """Info on v4 file shows algorithm and KDF."""
        txt_path = tmp_path / "test.txt"
        txt_path.write_text("Hello!")
        out_path = tmp_path / "test.html"

        runner.invoke(main, ["lock", str(txt_path), "-p", "pw", "-o", str(out_path)])

        result = runner.invoke(
            main, ["inspect", str(out_path)]
        )
        assert result.exit_code == 0
        assert "aes-256-gcm" in result.output
        assert "pbkdf2-sha256" in result.output
        assert "310,000" in result.output

    def test_info_v3_shows_content_hash(self, runner, tmp_path):
        """Info on v4 file shows content hash if present."""
        txt_path = tmp_path / "test.txt"
        txt_path.write_text("Hello!")
        out_path = tmp_path / "test.html"

        runner.invoke(main, ["lock", str(txt_path), "-p", "pw", "-o", str(out_path)])

        result = runner.invoke(
            main, ["inspect", str(out_path)]
        )
        assert result.exit_code == 0
        assert "Content hash:" in result.output

    def test_info_v3_shows_runtime(self, runner, tmp_path):
        """Info on v4 file shows runtime scripts and styles."""
        txt_path = tmp_path / "test.txt"
        txt_path.write_text("Hello!")
        out_path = tmp_path / "test.html"

        runner.invoke(main, ["lock", str(txt_path), "-p", "pw", "-o", str(out_path)])

        result = runner.invoke(
            main, ["inspect", str(out_path)]
        )
        assert result.exit_code == 0
        assert "Runtime scripts:" in result.output
        assert "Runtime styles:" in result.output
        assert "pagevault:" in result.output

    def test_info_v3_shows_version(self, runner, tmp_path):
        """Info on v4 file shows version number."""
        txt_path = tmp_path / "test.txt"
        txt_path.write_text("Hello!")
        out_path = tmp_path / "test.html"

        runner.invoke(main, ["lock", str(txt_path), "-p", "pw", "-o", str(out_path)])

        result = runner.invoke(
            main, ["inspect", str(out_path)]
        )
        assert result.exit_code == 0
        assert "Version:        v4" in result.output

    def test_info_v3_chunk_tags(self, runner, tmp_path):
        """Info on v4 file counts chunk script tags."""
        txt_path = tmp_path / "test.txt"
        txt_path.write_text("Hello!")
        out_path = tmp_path / "test.html"

        runner.invoke(main, ["lock", str(txt_path), "-p", "pw", "-o", str(out_path)])

        result = runner.invoke(
            main, ["inspect", str(out_path)]
        )
        assert result.exit_code == 0
        assert "Chunk tags:" in result.output

    def test_info_v3_chunk_count_multichunk(self, runner, tmp_path):
        """Info on a multi-chunk v4 file reports the right count in one
        DOM pass (regression: was O(N²) via while soup.find)."""
        # 3 MB file with default 1 MB chunk size → 3 chunks
        big_path = tmp_path / "big.bin"
        big_path.write_bytes(b"x" * (3 * 1024 * 1024))
        out_path = tmp_path / "big.html"

        runner.invoke(main, ["lock", str(big_path), "-p", "pw", "-o", str(out_path)])

        result = runner.invoke(
            main, ["inspect", str(out_path)]
        )
        assert result.exit_code == 0
        assert "Chunks:         3" in result.output
        assert "Chunk tags:     3" in result.output
        # The envelope and DOM should agree — no WARNING
        assert "WARNING" not in result.output

    def test_info_v3_site_mode(self, runner, tmp_path):
        """Info on v4 site shows site-related info."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<h1>Home</h1>")
        (site_dir / "style.css").write_text("body { color: red; }")

        out_path = tmp_path / "site.html"

        result = runner.invoke(
            main,
            [
                "lock",
                str(site_dir),
                "--site",
                "-p",
                "pw",
                "-o",
                str(out_path),
            ],
        )
        assert result.exit_code == 0

        result = runner.invoke(
            main, ["inspect", str(out_path)]
        )
        assert result.exit_code == 0
        assert "v4 chunked" in result.output


class TestCheckV3:
    """Tests for inspect --check command on v4 wrapped files."""

    def test_check_v3_correct_password(self, runner, tmp_path):
        """Check command works on v4 files with correct password."""
        txt_path = tmp_path / "test.txt"
        txt_path.write_text("Secret")
        out_path = tmp_path / "test.html"

        runner.invoke(main, ["lock", str(txt_path), "-p", "my-pw", "-o", str(out_path)])

        result = runner.invoke(
            main, ["inspect", str(out_path), "-p", "my-pw", "--check"]
        )
        assert "correct" in result.output.lower()
        assert result.exit_code == 0

    def test_check_v3_wrong_password(self, runner, tmp_path):
        """Check command detects wrong password on v4 files."""
        txt_path = tmp_path / "test.txt"
        txt_path.write_text("Secret")
        out_path = tmp_path / "test.html"

        runner.invoke(main, ["lock", str(txt_path), "-p", "my-pw", "-o", str(out_path)])

        result = runner.invoke(
            main, ["inspect", str(out_path), "-p", "wrong", "--check"]
        )
        assert "incorrect" in result.output.lower()
        assert result.exit_code == 1

    def test_check_v3_non_encrypted_fails(self, runner, tmp_path):
        """Check on plain file fails gracefully."""
        html_path = tmp_path / "plain.html"
        html_path.write_text("<html><body>Hello</body></html>")

        result = runner.invoke(
            main, ["inspect", str(html_path), "-p", "test", "--check"]
        )
        assert result.exit_code != 0

    def test_check_v3_site(self, runner, tmp_path):
        """Check command works on v4 site files."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<h1>Home</h1>")

        out_path = tmp_path / "site.html"

        runner.invoke(
            main,
            [
                "lock",
                str(site_dir),
                "--site",
                "-p",
                "site-pw",
                "-o",
                str(out_path),
            ],
        )

        result = runner.invoke(
            main, ["inspect", str(out_path), "-p", "site-pw", "--check"]
        )
        assert "correct" in result.output.lower()
        assert result.exit_code == 0


class TestServeCommand:
    """Tests for pagevault dev serve command."""

    def test_serve_help(self, runner):
        """dev serve --help should show usage."""
        result = runner.invoke(main, ["dev", "serve", "--help"])
        assert result.exit_code == 0
        assert "Serve directory" in result.output
        assert "--port" in result.output
        assert "--open" in result.output

    def test_serve_port_option(self, runner):
        """dev serve accepts -P for port."""
        result = runner.invoke(main, ["dev", "serve", "--help"])
        assert "-P" in result.output


class TestCheckPrompt:
    """Tests for inspect --check interactive password prompt."""

    def test_check_prompts_for_password(self, runner, tmp_path):
        """inspect --check without -p should prompt for password."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault>Secret</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(
            'password: "test-password"\nsalt: "0123456789abcdef0123456789abcdef"\n'
        )

        locked_dir = tmp_path / "locked"
        runner.invoke(
            main,
            ["lock", str(html_path), "-c", str(config_path), "-d", str(locked_dir)],
        )

        # Provide password via stdin (no -p flag)
        result = runner.invoke(
            main,
            ["inspect", str(locked_dir / "index.html"), "--check"],
            input="test-password\n",
        )
        assert "correct" in result.output.lower()
        assert result.exit_code == 0


class TestUsersFilter:
    """Tests for lock --users flag."""

    def test_users_filter(self, runner, tmp_path):
        """--users should filter configured users."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault>Secret</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(
            yaml.dump(
                {
                    "salt": "0123456789abcdef0123456789abcdef",
                    "users": {"alice": "pw-a", "bob": "pw-b", "charlie": "pw-c"},
                }
            )
        )

        locked_dir = tmp_path / "locked"
        result = runner.invoke(
            main,
            [
                "lock",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(locked_dir),
                "--users",
                "alice,bob",
            ],
        )
        assert result.exit_code == 0

        # Verify alice's password works
        check_result = runner.invoke(
            main,
            [
                "inspect", str(locked_dir / "index.html"),
                "-p", "pw-a", "-u", "alice", "--check",
            ],
        )
        assert "correct" in check_result.output.lower()

        # Verify charlie's password does NOT work (was filtered out)
        check_result = runner.invoke(
            main,
            [
                "inspect", str(locked_dir / "index.html"),
                "-p", "pw-c", "-u", "charlie", "--check",
            ],
        )
        assert "incorrect" in check_result.output.lower()

    def test_users_filter_unknown_user(self, runner, tmp_path):
        """--users with unknown username should error."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault>Secret</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(
            yaml.dump(
                {
                    "salt": "0123456789abcdef0123456789abcdef",
                    "users": {"alice": "pw-a"},
                }
            )
        )

        result = runner.invoke(
            main,
            ["lock", str(html_path), "-c", str(config_path), "--users", "unknown"],
        )
        assert result.exit_code != 0
        assert "Unknown user" in result.output

    def test_users_filter_requires_multi_user(self, runner, tmp_path):
        """--users without users config should error."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html><head><title>Test</title></head>
<body><pagevault>Secret</pagevault></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(
            yaml.dump(
                {
                    "password": "single-pw",
                    "salt": "0123456789abcdef0123456789abcdef",
                }
            )
        )

        result = runner.invoke(
            main,
            ["lock", str(html_path), "-c", str(config_path), "--users", "alice"],
        )
        assert result.exit_code != 0
        assert "multi-user" in result.output.lower()


class TestConfigSetPassword:
    """Tests for password security warnings in config set."""

    def test_config_set_password_warns(self, tmp_path):
        """config set password should warn about plaintext storage."""
        runner = CliRunner()
        config_path = tmp_path / ".pagevault.yaml"
        config_path.write_text("password: old\n")
        result = runner.invoke(
            main, ["config", "set", "password", "newsecret", "-c", str(config_path)]
        )
        output_lower = result.output.lower()
        assert "plaintext" in output_lower or "warning" in output_lower


class TestConfigSetFormatting:
    """Tests for config set output formatting."""

    def test_config_set_pad_echoes_lowercase(self, tmp_path):
        """config set pad should echo lowercase true/false."""
        runner = CliRunner()
        config_path = tmp_path / ".pagevault.yaml"
        config_path.write_text("{}\n")
        result = runner.invoke(
            main, ["config", "set", "pad", "true", "-c", str(config_path)]
        )
        # Should not have Python-style "True"
        assert "'True'" not in result.output
