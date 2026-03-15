"""Tests for pagevault.wrap module."""

from pathlib import Path

import pytest
from bs4 import BeautifulSoup
from click.testing import CliRunner

from pagevault.cli import main
from pagevault.config import CONFIG_FILENAME
from pagevault.crypto import PagevaultError
from pagevault.viewers import discover_viewers
from pagevault.wrap import (
    _generate_wrap_html_v3,
    _get_progress_css,
    _get_renderer_js_v3,
    _get_site_renderer_js,
    _get_wrap_css,
    detect_mime,
    wrap_file,
    wrap_site,
)


class TestDetectMime:
    """Tests for MIME type detection."""

    def test_png(self):
        assert detect_mime(Path("image.png")) == "image/png"

    def test_jpg(self):
        assert detect_mime(Path("photo.jpg")) == "image/jpeg"

    def test_pdf(self):
        assert detect_mime(Path("document.pdf")) == "application/pdf"

    def test_markdown(self):
        assert detect_mime(Path("README.md")) == "text/markdown"

    def test_html(self):
        assert detect_mime(Path("index.html")) == "text/html"

    def test_svg(self):
        assert detect_mime(Path("icon.svg")) == "image/svg+xml"

    def test_webp(self):
        assert detect_mime(Path("photo.webp")) == "image/webp"

    def test_css(self):
        assert detect_mime(Path("styles.css")) == "text/css"

    def test_unknown(self):
        assert detect_mime(Path("file.xyz123")) == "application/octet-stream"

    def test_text(self):
        assert detect_mime(Path("notes.txt")) == "text/plain"


class TestWrapFile:
    """Tests for wrap_file function."""

    def test_basic_wrap(self, tmp_path):
        """Test wrapping a simple text file produces v3 output."""
        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        output = wrap_file(test_file, password="password")

        assert output.exists()
        assert output.suffix == ".html"

        content = output.read_text()
        soup = BeautifulSoup(content, "html.parser")
        # v3: envelope in pv-meta, not data-encrypted attribute
        assert soup.find("script", {"id": "pv-meta"}) is not None
        pv = soup.find("pagevault")
        assert pv.get("data-pv-chunked") == "true"
        assert "Protected: test.txt" in content

    def test_wrap_with_custom_output(self, tmp_path):
        """Test wrapping with custom output path."""
        test_file = tmp_path / "data.csv"
        test_file.write_text("a,b,c\n1,2,3")

        output_path = tmp_path / "output" / "data.html"
        result = wrap_file(test_file, password="pw", output_path=output_path)

        assert result == output_path
        assert output_path.exists()

    def test_wrap_binary_file(self, tmp_path):
        """Test wrapping a binary file (e.g., PNG header)."""
        import json

        test_file = tmp_path / "image.png"
        # Write a minimal PNG-like binary
        test_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        output = wrap_file(test_file, password="password")
        assert output.exists()

        content = output.read_text()
        soup = BeautifulSoup(content, "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        assert envelope["v"] == 3
        assert "Protected: image.png" in content

    def test_wrap_pdf(self, tmp_path):
        """Test wrapping a PDF file."""
        test_file = tmp_path / "document.pdf"
        test_file.write_bytes(b"%PDF-1.4" + b"\x00" * 100)

        output = wrap_file(test_file, password="password")

        content = output.read_text()
        soup = BeautifulSoup(content, "html.parser")
        assert soup.find("script", {"id": "pv-meta"}) is not None
        assert soup.find("pagevault").get("data-pv-chunked") == "true"

    def test_encrypted_payload_is_decryptable(self, tmp_path):
        """Test that the v3 encrypted payload can be decrypted."""
        import json

        from pagevault.crypto import decrypt_chunked

        test_file = tmp_path / "secret.txt"
        test_file.write_text("Secret data!")

        output = wrap_file(test_file, password="test-pw")
        content = output.read_text()

        # Extract v3 envelope and chunks
        soup = BeautifulSoup(content, "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        # Decrypt
        data, meta = decrypt_chunked(envelope, chunks, "test-pw")

        # The data should be the raw file bytes (no base64 layer in v3)
        assert data == b"Secret data!"

        # Meta should have file info
        assert meta["type"] == "file"
        assert meta["filename"] == "secret.txt"
        assert meta["mime"] == "text/plain"
        assert meta["size"] == len(b"Secret data!")

    def test_wrap_nonexistent_file(self, tmp_path):
        """Test wrapping a nonexistent file raises error."""
        with pytest.raises(PagevaultError, match="File not found"):
            wrap_file(tmp_path / "nonexistent.txt", password="pw")

    def test_wrap_with_content_hash(self, tmp_path):
        """Test that content hash is included in v3 envelope."""
        import json

        test_file = tmp_path / "test.txt"
        test_file.write_text("Hash test")

        output = wrap_file(test_file, password="pw")
        content = output.read_text()

        soup = BeautifulSoup(content, "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        assert "content_hash" in envelope
        assert len(envelope["content_hash"]) == 32

    def test_wrap_multiuser(self, tmp_path):
        """Test wrapping with multi-user encryption."""
        import json

        from pagevault.crypto import decrypt_chunked

        test_file = tmp_path / "shared.txt"
        test_file.write_text("Shared secret")

        output = wrap_file(
            test_file,
            users={"alice": "pw-a", "bob": "pw-b"},
        )

        content = output.read_text()
        assert 'data-mode="user"' in content

        # Extract v3 envelope and chunks
        soup = BeautifulSoup(content, "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        # Both users should be able to decrypt
        data_a, _ = decrypt_chunked(envelope, chunks, "pw-a", username="alice")
        data_b, _ = decrypt_chunked(envelope, chunks, "pw-b", username="bob")
        assert data_a == b"Shared secret"
        assert data_b == b"Shared secret"

    def test_html_is_self_contained(self, tmp_path):
        """Test output HTML contains all needed runtime."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        output = wrap_file(test_file, password="pw")
        content = output.read_text()

        # Should have crypto JS
        assert "crypto.subtle" in content
        assert "PBKDF2" in content
        assert "AES-GCM" in content

        # Should have renderer JS
        assert "renderFile" in content

        # Should have CSS
        assert ".pagevault-container" in content
        assert ".pagevault-button" in content

    def test_wrap_large_file(self, tmp_path):
        """Test wrapping a larger file."""
        import json

        from pagevault.crypto import decrypt_chunked

        test_file = tmp_path / "large.bin"
        test_file.write_bytes(b"x" * 100000)

        output = wrap_file(test_file, password="pw")
        assert output.exists()

        # Verify decryptability via v3 chunked
        soup = BeautifulSoup(output.read_text(), "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        data, meta = decrypt_chunked(envelope, chunks, "pw")
        assert data == b"x" * 100000

    def test_wrap_unicode_filename(self, tmp_path):
        """Test wrapping a file with unicode in the name."""
        test_file = tmp_path / "日本語ファイル.txt"
        test_file.write_text("日本語テスト")

        output = wrap_file(test_file, password="pw")
        assert output.exists()

        content = output.read_text()
        assert "日本語ファイル.txt" in content


class TestWrapSite:
    """Tests for wrap_site function."""

    def test_basic_site_wrap(self, tmp_path):
        """Test wrapping a simple site directory."""
        import json

        # Create a minimal site
        site_dir = tmp_path / "my-site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body><h1>Home</h1></body></html>")
        (site_dir / "style.css").write_text("body { color: red; }")

        output = wrap_site(site_dir, password="password")

        assert output.exists()
        assert output.name == "my-site.html"

        content = output.read_text()
        soup = BeautifulSoup(content, "html.parser")
        # v3: envelope in pv-meta, not data-encrypted
        assert soup.find("script", {"id": "pv-meta"}) is not None
        pv = soup.find("pagevault")
        assert pv.get("data-pv-chunked") == "true"
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        assert envelope["v"] == 3

    def test_site_custom_output(self, tmp_path):
        """Test wrapping site with custom output path."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Hi</body></html>")

        output_path = tmp_path / "output.html"
        result = wrap_site(site_dir, password="pw", output_path=output_path)

        assert result == output_path
        assert output_path.exists()

    def test_site_custom_entry(self, tmp_path):
        """Test wrapping site with custom entry point."""
        import json

        from pagevault.crypto import decrypt_chunked

        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "home.html").write_text("<html><body>Home</body></html>")

        output = wrap_site(site_dir, password="pw", entry="home.html")

        content = output.read_text()
        soup = BeautifulSoup(content, "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        _, meta = decrypt_chunked(envelope, chunks, "pw")
        assert meta["entry"] == "home.html"

    def test_site_encrypted_payload_contains_zip(self, tmp_path):
        """Test encrypted payload contains a valid zip with all files."""
        import json
        import zipfile
        from io import BytesIO

        from pagevault.crypto import decrypt_chunked

        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<h1>Hello</h1>")
        (site_dir / "style.css").write_text("body { margin: 0; }")

        output = wrap_site(site_dir, password="pw")

        # Extract and decrypt via v3
        soup = BeautifulSoup(output.read_text(), "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        data, meta = decrypt_chunked(envelope, chunks, "pw")

        # Meta should list files
        assert meta["type"] == "site"
        assert meta["entry"] == "index.html"
        assert "index.html" in meta["files"]
        assert "style.css" in meta["files"]

        # Data should be raw zip bytes (no base64 layer in v3)
        with zipfile.ZipFile(BytesIO(data)) as zf:
            names = zf.namelist()
            assert "index.html" in names
            assert "style.css" in names
            assert zf.read("index.html") == b"<h1>Hello</h1>"
            assert zf.read("style.css") == b"body { margin: 0; }"

    def test_site_with_subdirectories(self, tmp_path):
        """Test wrapping site with nested directories."""
        import json

        from pagevault.crypto import decrypt_chunked

        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Home</body></html>")
        images_dir = site_dir / "images"
        images_dir.mkdir()
        (images_dir / "logo.png").write_bytes(b"\x89PNG" + b"\x00" * 50)
        css_dir = site_dir / "css"
        css_dir.mkdir()
        (css_dir / "main.css").write_text("body { margin: 0; }")

        output = wrap_site(site_dir, password="pw")

        # Verify all files in metadata via v3
        soup = BeautifulSoup(output.read_text(), "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        _, meta = decrypt_chunked(envelope, chunks, "pw")

        assert "index.html" in meta["files"]
        assert "images/logo.png" in meta["files"]
        assert "css/main.css" in meta["files"]

    def test_site_missing_entry(self, tmp_path):
        """Test error when entry point doesn't exist."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "page.html").write_text("<html>Page</html>")

        with pytest.raises(PagevaultError, match="Entry point"):
            wrap_site(site_dir, password="pw", entry="index.html")

    def test_site_empty_directory(self, tmp_path):
        """Test error on empty directory."""
        site_dir = tmp_path / "empty"
        site_dir.mkdir()

        with pytest.raises(PagevaultError, match="empty"):
            wrap_site(site_dir, password="pw")

    def test_site_nonexistent_directory(self, tmp_path):
        """Test error on nonexistent directory."""
        with pytest.raises(PagevaultError, match="Directory not found"):
            wrap_site(tmp_path / "nope", password="pw")

    def test_site_includes_jszip_shim(self, tmp_path):
        """Test site output includes JSZip shim and site renderer."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html>Hi</html>")

        output = wrap_site(site_dir, password="pw")
        content = output.read_text()

        assert "ZipReader" in content
        assert "__pagevault_renderSite" in content
        assert "rewriteUrls" in content

    def test_site_multiuser(self, tmp_path):
        """Test wrapping site with multi-user encryption."""
        import json

        from pagevault.crypto import decrypt_chunked

        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html>Secret site</html>")

        output = wrap_site(
            site_dir,
            users={"alice": "pw-a", "bob": "pw-b"},
        )

        content = output.read_text()
        assert 'data-mode="user"' in content

        # Both users can decrypt via v3
        soup = BeautifulSoup(content, "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        _, meta_a = decrypt_chunked(envelope, chunks, "pw-a", username="alice")
        _, meta_b = decrypt_chunked(envelope, chunks, "pw-b", username="bob")
        assert meta_a["type"] == "site"
        assert meta_b["type"] == "site"


class TestWrapFileCli:
    """Tests for 'pagevault lock' CLI command with non-HTML files."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def sample_config(self):
        return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
"""

    def test_wrap_file_basic(self, runner, tmp_path, sample_config):
        """Test basic wrap file command (now using lock for non-HTML)."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello!")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output = tmp_path / "test.html"

        result = runner.invoke(
            main,
            [
                "lock",
                str(test_file),
                "-c",
                str(config_path),
                "-o",
                str(output),
            ],
        )

        assert result.exit_code == 0
        assert "Wrapped:" in result.output
        assert output.exists()

    def test_wrap_file_with_password(self, runner, tmp_path):
        """Test wrap file with -p flag (now using lock for non-HTML)."""
        test_file = tmp_path / "secret.txt"
        test_file.write_text("Secret!")

        output = tmp_path / "secret.html"

        result = runner.invoke(
            main,
            [
                "lock",
                str(test_file),
                "-p",
                "my-password",
                "-o",
                str(output),
            ],
        )

        assert result.exit_code == 0
        assert output.exists()

    def test_wrap_file_prompts_password(self, runner, tmp_path):
        """Test wrap file prompts for password when not provided (now using lock)."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        output = tmp_path / "test.html"

        result = runner.invoke(
            main,
            [
                "lock",
                str(test_file),
                "-o",
                str(output),
            ],
            input="prompted-password\n",
        )

        assert result.exit_code == 0
        assert output.exists()


class TestWrapSiteCli:
    """Tests for 'pagevault lock --site' CLI command."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def sample_config(self):
        return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
"""

    def test_wrap_site_basic(self, runner, tmp_path, sample_config):
        """Test basic wrap site command (now using lock --site)."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Hi</body></html>")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output = tmp_path / "site.html"

        result = runner.invoke(
            main,
            [
                "lock",
                str(site_dir),
                "--site",
                "-c",
                str(config_path),
                "-o",
                str(output),
            ],
        )

        assert result.exit_code == 0
        assert "Wrapped site:" in result.output
        assert output.exists()

    def test_wrap_site_with_entry(self, runner, tmp_path, sample_config):
        """Test wrap site with custom entry point (now using lock --site)."""
        import json

        from pagevault.crypto import decrypt_chunked

        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "home.html").write_text("<html><body>Home</body></html>")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output = tmp_path / "site.html"

        result = runner.invoke(
            main,
            [
                "lock",
                str(site_dir),
                "--site",
                "-c",
                str(config_path),
                "-o",
                str(output),
                "--entry",
                "home.html",
            ],
        )

        assert result.exit_code == 0
        assert output.exists()

        # v3: entry is in encrypted metadata, verify via decrypt
        content = output.read_text()
        soup = BeautifulSoup(content, "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        _, meta = decrypt_chunked(envelope, chunks, "test-password")
        assert meta["entry"] == "home.html"

    def test_wrap_site_missing_entry_fails(self, runner, tmp_path, sample_config):
        """Test wrap site fails when entry point doesn't exist."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "page.html").write_text("<html>Page</html>")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(
            main,
            [
                "lock",
                str(site_dir),
                "--site",
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code != 0
        assert "Entry point" in result.output


class TestMarkdownViewer:
    """Tests for markdown viewer with marked.js conditional inclusion."""

    def test_markdown_file_includes_marked(self, tmp_path):
        """Wrapping a .md file should include marked.js."""
        md_file = tmp_path / "readme.md"
        md_file.write_text("# Hello\n\nSome text.")

        output = wrap_file(md_file, password="pw")
        content = output.read_text()

        # marked.js should be included
        assert "marked v" in content
        # Renderer should reference marked.parse
        assert "marked.parse" in content

    def test_markdown_extension_includes_marked(self, tmp_path):
        """Both .md and .markdown extensions should include marked.js."""
        md_file = tmp_path / "readme.markdown"
        md_file.write_text("# Test")

        output = wrap_file(md_file, password="pw")
        content = output.read_text()
        assert "marked v" in content

    def test_non_markdown_excludes_marked(self, tmp_path):
        """Non-markdown files should NOT include marked.js."""
        txt_file = tmp_path / "notes.txt"
        txt_file.write_text("Just plain text.")

        output = wrap_file(txt_file, password="pw")
        content = output.read_text()
        assert "marked v" not in content

    def test_image_excludes_marked(self, tmp_path):
        """Image files should NOT include marked.js."""
        img_file = tmp_path / "photo.png"
        img_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)

        output = wrap_file(img_file, password="pw")
        content = output.read_text()
        assert "marked v" not in content


class TestMarkdownToggle:
    """Tests for markdown source/rendered toggle."""

    def test_toggle_button_in_renderer(self):
        """Renderer JS should contain toggle button code via MarkdownViewer plugin."""
        viewers = discover_viewers()
        js = _get_renderer_js_v3(viewers)
        assert "toolbar-toggle" in js
        assert "Source" in js
        assert "Rendered" in js

    def test_simplemarkdown_fallback_preserved(self):
        """simpleMarkdown fallback should still exist in renderer via MarkdownViewer."""
        viewers = discover_viewers()
        js = _get_renderer_js_v3(viewers)
        assert "simpleMarkdown" in js


class TestViewerToolbar:
    """Tests for the shared toolbar component."""

    def test_create_toolbar_in_renderer(self):
        """Renderer JS should contain createToolbar function."""
        viewers = discover_viewers()
        js = _get_renderer_js_v3(viewers)
        assert "createToolbar" in js
        assert "toolbar-filename" in js
        assert "toolbar-size" in js

    def test_toolbar_css_present(self):
        """CSS should contain toolbar styles."""
        from pagevault.config import TemplateConfig

        css = _get_wrap_css(TemplateConfig())
        assert ".pagevault-toolbar" in css
        assert ".toolbar-filename" in css
        assert ".toolbar-btn" in css

    def test_wrap_css_dark_mode(self):
        """Wrap CSS should contain dark mode media query."""
        from pagevault.config import TemplateConfig

        css = _get_wrap_css(TemplateConfig())
        assert "prefers-color-scheme: dark" in css
        assert "#1e1e2e" in css  # dark container bg

    def test_progress_css_dark_mode(self):
        """Progress bar CSS should contain dark mode media query."""
        css = _get_progress_css()
        assert "prefers-color-scheme: dark" in css
        assert "#2a2a3a" in css  # dark track bg


class TestImageViewer:
    """Tests for the enhanced image viewer."""

    def test_image_viewer_in_dispatch_table(self):
        """Renderer JS should include image viewer in dispatch table."""
        viewers = discover_viewers()
        js = _get_renderer_js_v3(viewers)
        assert "__pv_image" in js
        assert "'image/*'" in js

    def test_zoom_class_in_renderer(self):
        """Renderer JS should toggle 'zoomed' class (ImageViewer plugin)."""
        viewers = discover_viewers()
        js = _get_renderer_js_v3(viewers)
        assert "zoomed" in js

    def test_image_zoom_css(self):
        """ImageViewer plugin CSS should contain zoom styles."""
        from pagevault.viewers.builtins.image import ImageViewer

        css = ImageViewer().css()
        assert ".pagevault-image-viewer" in css
        assert "img.zoomed" in css
        assert "zoom-in" in css
        assert "zoom-out" in css


class TestTextViewer:
    """Tests for the enhanced text viewer with line numbers."""

    def test_text_viewer_in_dispatch_table(self):
        """Renderer JS should include text viewer in dispatch table."""
        viewers = discover_viewers()
        js = _get_renderer_js_v3(viewers)
        assert "__pv_text" in js
        assert "'text/*'" in js

    def test_line_numbers_css(self):
        """TextViewer plugin CSS should contain line-number gutter styles."""
        from pagevault.viewers.builtins.text import TextViewer

        css = TextViewer().css()
        assert ".line-numbers" in css
        assert "user-select: none" in css
        assert ".pagevault-text-viewer" in css


class TestWrapFileViewers:
    """End-to-end tests: verify correct viewer plugins appear per MIME type."""

    @pytest.mark.parametrize(
        "filename, content, expected_viewer_var",
        [
            ("doc.md", b"# Heading\n\nParagraph", "__pv_markdown"),
            ("notes.txt", b"line1\nline2\nline3", "__pv_text"),
            ("photo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 50, "__pv_image"),
            ("doc.pdf", b"%PDF-1.4" + b"\x00" * 50, "__pv_pdf"),
        ],
    )
    def test_viewer_in_dispatch_table(
        self, tmp_path, filename, content, expected_viewer_var
    ):
        """Each MIME type's viewer appears in the dispatch table."""
        f = tmp_path / filename
        f.write_bytes(content)

        output = wrap_file(f, password="pw")
        html = output.read_text()

        assert expected_viewer_var in html
        assert "__pv_resolveViewer" in html
        # All outputs should have toolbar
        assert "createToolbar" in html

    def test_markdown_gets_marked_js(self, tmp_path):
        """Markdown output should include marked.js library."""
        f = tmp_path / "test.md"
        f.write_text("# Title\n\n| a | b |\n|---|---|\n| 1 | 2 |")

        output = wrap_file(f, password="pw")
        html = output.read_text()

        assert "marked v" in html
        assert "marked.parse" in html

    def test_text_does_not_get_marked_js(self, tmp_path):
        """Text output should NOT include marked.js library."""
        f = tmp_path / "data.csv"
        f.write_text("a,b,c\n1,2,3")

        output = wrap_file(f, password="pw")
        html = output.read_text()

        assert "marked v" not in html


class TestSiteResourceStringRewriting:
    """Tests for dynamic resource string rewriting in site renderer JS."""

    def test_resource_rewriting_regex_present(self):
        """The resource string rewriting regex should appear in site renderer JS."""
        js = _get_site_renderer_js()
        # The regex for matching quoted file-path-like strings
        assert "Rewrite quoted strings that match known resource paths" in js
        assert "htmlFiles.has(resolved)" in js

    def test_json_image_urls_rewritten(self, tmp_path):
        """A site with JSON image URLs in a script tag should produce
        wrapped output containing the resource string rewriting pass."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        img_dir = site_dir / "img"
        img_dir.mkdir()

        # Create a PNG file
        (img_dir / "photo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)

        # Create an HTML page with JSON data referencing the image
        (site_dir / "index.html").write_text(
            "<html><head></head><body>"
            '<script>var data = {"url": "img/photo.png"};</script>'
            "</body></html>"
        )

        output = wrap_site(site_dir, password="pw")
        content = output.read_text()

        # The wrapped output should contain the site renderer with
        # the resource string rewriting logic
        assert "Rewrite quoted strings" in content
        assert "htmlFiles.has" in content

    def test_resource_rewriting_skips_html_paths(self):
        """Quoted strings matching HTML files should NOT be rewritten
        (navigation interceptor handles those)."""
        js = _get_site_renderer_js()
        # The guard: only replace if not in htmlFiles
        assert "!htmlFiles.has(resolved)" in js

    def test_resource_rewriting_skips_absolute_urls(self):
        """Absolute URLs and data URIs should be skipped."""
        js = _get_site_renderer_js()
        assert "val.indexOf('://') !== -1" in js
        assert "val.startsWith('data:')" in js

    def test_site_with_dynamic_refs_wraps_successfully(self, tmp_path):
        """A site with dynamic JS image references should wrap without error
        and include all files in the zip payload."""
        import json

        from pagevault.crypto import decrypt_chunked

        site_dir = tmp_path / "site"
        site_dir.mkdir()
        media_dir = site_dir / "media"
        media_dir.mkdir()

        # Create multiple image files
        for name in ["a.png", "b.jpg", "c.gif"]:
            (media_dir / name).write_bytes(b"\x00" * 20)

        # HTML with JS that dynamically sets image sources
        (site_dir / "index.html").write_text(
            "<html><body>"
            "<script>"
            'var images = ["media/a.png", "media/b.jpg", "media/c.gif"];'
            "images.forEach(function(src) {"
            '  var img = document.createElement("img");'
            "  img.src = src;"
            "  document.body.appendChild(img);"
            "});"
            "</script>"
            "</body></html>"
        )

        output = wrap_site(site_dir, password="pw")
        assert output.exists()

        # Verify all files are in the encrypted payload via v3
        soup = BeautifulSoup(output.read_text(), "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        _, meta = decrypt_chunked(envelope, chunks, "pw")

        assert "index.html" in meta["files"]
        assert "media/a.png" in meta["files"]
        assert "media/b.jpg" in meta["files"]
        assert "media/c.gif" in meta["files"]


class TestWrapFileV3:
    """Tests for wrap_file using v3 chunked format."""

    def test_basic_wrap_produces_chunk_tags(self, tmp_path):
        """wrap_file output has per-chunk script tags, not data-encrypted."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        output = wrap_file(test_file, password="password")
        content = output.read_text()

        soup = BeautifulSoup(content, "html.parser")
        assert soup.find("script", {"id": "pv-meta"}) is not None
        assert soup.find("script", {"id": "pv-0"}) is not None
        pv = soup.find("pagevault")
        assert pv is not None
        assert not pv.has_attr("data-encrypted")
        assert pv.get("data-pv-chunked") == "true"

    def test_roundtrip_via_python_decrypt(self, tmp_path):
        """wrap_file output can be decrypted by Python (parse envelope + chunks)."""
        import json

        test_file = tmp_path / "secret.txt"
        test_file.write_text("Secret data!")

        output = wrap_file(test_file, password="test-pw")
        content = output.read_text()

        soup = BeautifulSoup(content, "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        from pagevault.crypto import decrypt_chunked

        data, meta = decrypt_chunked(envelope, chunks, "test-pw")
        assert data == b"Secret data!"
        assert meta["filename"] == "secret.txt"
        assert meta["mime"] == "text/plain"
        assert meta["type"] == "file"

    def test_binary_file_roundtrip(self, tmp_path):
        """Binary file survives wrap+decrypt roundtrip byte-for-byte."""
        import json
        import os

        test_file = tmp_path / "image.png"
        original_bytes = b"\x89PNG\r\n\x1a\n" + os.urandom(500)
        test_file.write_bytes(original_bytes)

        output = wrap_file(test_file, password="pw")

        soup = BeautifulSoup(output.read_text(), "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        from pagevault.crypto import decrypt_chunked

        data, meta = decrypt_chunked(envelope, chunks, "pw")
        assert data == original_bytes
        assert meta["mime"] == "image/png"

    def test_content_hash_present(self, tmp_path):
        """v3 envelope includes content_hash."""
        import json

        test_file = tmp_path / "test.txt"
        test_file.write_text("Hash me")

        output = wrap_file(test_file, password="pw")
        soup = BeautifulSoup(output.read_text(), "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        assert "content_hash" in envelope
        assert len(envelope["content_hash"]) == 32

    def test_title_shows_protected(self, tmp_path):
        """HTML title says 'Protected: filename'."""
        test_file = tmp_path / "report.pdf"
        test_file.write_bytes(b"%PDF-1.4")

        output = wrap_file(test_file, password="pw")
        content = output.read_text()
        assert "<title>Protected: report.pdf</title>" in content


class TestWrapSiteV3:
    """Tests for wrap_site using v3 chunked format."""

    def test_site_produces_chunk_tags(self, tmp_path):
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Hi</body></html>")

        output = wrap_site(site_dir, password="pw")
        soup = BeautifulSoup(output.read_text(), "html.parser")
        assert soup.find("script", {"id": "pv-meta"}) is not None
        assert soup.find("script", {"id": "pv-0"}) is not None
        pv = soup.find("pagevault")
        assert pv is not None
        assert pv.get("data-pv-chunked") == "true"

    def test_site_roundtrip(self, tmp_path):
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<h1>Hello</h1>")
        (site_dir / "style.css").write_text("body { margin: 0; }")

        output = wrap_site(site_dir, password="pw")
        soup = BeautifulSoup(output.read_text(), "html.parser")

        import json

        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        from pagevault.crypto import decrypt_chunked

        data, meta = decrypt_chunked(envelope, chunks, "pw")

        assert meta["type"] == "site"
        assert meta["entry"] == "index.html"
        assert "index.html" in meta["files"]
        assert "style.css" in meta["files"]

        # Verify zip content
        import zipfile
        from io import BytesIO

        with zipfile.ZipFile(BytesIO(data)) as zf:
            assert zf.read("index.html") == b"<h1>Hello</h1>"

    def test_site_includes_jszip_and_site_renderer(self, tmp_path):
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html>Hi</html>")

        output = wrap_site(site_dir, password="pw")
        content = output.read_text()
        assert "ZipReader" in content or "JSZip" in content

    def test_site_v3_content_hash_in_envelope(self, tmp_path):
        """Content hash should be in the v3 envelope, not a data attribute."""
        import json

        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html>Test</html>")

        output = wrap_site(site_dir, password="pw")
        soup = BeautifulSoup(output.read_text(), "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        assert "content_hash" in envelope
        assert len(envelope["content_hash"]) == 32

    def test_site_v3_multiuser_roundtrip(self, tmp_path):
        """Multi-user site wrap should decrypt for each user."""
        import json

        from pagevault.crypto import decrypt_chunked

        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html>Secret site</html>")

        output = wrap_site(
            site_dir,
            users={"alice": "pw-a", "bob": "pw-b"},
        )

        content = output.read_text()
        assert 'data-mode="user"' in content

        soup = BeautifulSoup(content, "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        _, meta_a = decrypt_chunked(envelope, chunks, "pw-a", username="alice")
        _, meta_b = decrypt_chunked(envelope, chunks, "pw-b", username="bob")
        assert meta_a["type"] == "site"
        assert meta_b["type"] == "site"

    def test_site_v3_with_subdirectories(self, tmp_path):
        """Subdirectories should be preserved in v3 zip payload."""
        import json

        from pagevault.crypto import decrypt_chunked

        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html>Home</html>")
        images_dir = site_dir / "images"
        images_dir.mkdir()
        (images_dir / "logo.png").write_bytes(b"\x89PNG" + b"\x00" * 50)

        output = wrap_site(site_dir, password="pw")
        soup = BeautifulSoup(output.read_text(), "html.parser")
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        _, meta = decrypt_chunked(envelope, chunks, "pw")
        assert "index.html" in meta["files"]
        assert "images/logo.png" in meta["files"]


class TestRendererXssPrevention:
    """Tests for XSS prevention in renderer JS functions."""

    def test_file_renderer_escapes_filename(self):
        """Test _get_renderer_js_v3() uses escapeHtml for filename display."""
        viewers = discover_viewers()
        js = _get_renderer_js_v3(viewers)
        assert "escapeHtml(fname)" in js

    def test_file_renderer_has_escapehtml(self):
        """Test _get_renderer_js() defines escapeHtml."""
        viewers = discover_viewers()
        js = _get_renderer_js_v3(viewers)
        assert "function escapeHtml" in js

    def test_site_renderer_escapes_entry(self):
        """Test _get_site_renderer_js() uses escapeHtml for entry point error."""
        js = _get_site_renderer_js()
        assert "escapeHtml(entry)" in js

    def test_site_renderer_escapes_error_message(self):
        """Test _get_site_renderer_js() uses escapeHtml for error message."""
        js = _get_site_renderer_js()
        assert "escapeHtml(e.message)" in js

    def test_site_renderer_has_escapehtml(self):
        """Test _get_site_renderer_js() defines its own escapeHtml."""
        js = _get_site_renderer_js()
        assert "function escapeHtml" in js


class TestGenerateWrapHtmlV3:
    """Tests for v3 chunked HTML template generation."""

    def test_has_pv_meta_script(self):
        """Output HTML contains a pv-meta script tag with JSON envelope."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 1, "keys": []},
            chunks=["AAAA"],
            title="Protected: test.txt",
            viewers=[],
        )
        soup = BeautifulSoup(html, "html.parser")
        meta_script = soup.find("script", {"id": "pv-meta"})
        assert meta_script is not None
        assert meta_script.get("type") == "application/json"

    def test_pv_meta_contains_envelope_json(self):
        """The pv-meta script tag contains the envelope as valid JSON."""
        import json

        envelope = {"v": 3, "chunk_count": 2, "keys": [{"iv": "abc", "ct": "def"}]}
        html = _generate_wrap_html_v3(
            envelope=envelope,
            chunks=["chunk0", "chunk1"],
            title="Protected: test",
            viewers=[],
        )
        soup = BeautifulSoup(html, "html.parser")
        meta_script = soup.find("script", {"id": "pv-meta"})
        parsed = json.loads(meta_script.string)
        assert parsed == envelope

    def test_has_chunk_script_tags(self):
        """Each chunk gets its own script element with id pv-N."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 3, "keys": []},
            chunks=["chunk0", "chunk1", "chunk2"],
            title="Protected: file",
            viewers=[],
        )
        soup = BeautifulSoup(html, "html.parser")
        for i in range(3):
            el = soup.find("script", {"id": f"pv-{i}"})
            assert el is not None
            assert el.get("type") == "x-pv"
            assert el.string.strip() == f"chunk{i}"

    def test_has_pagevault_element(self):
        """Output has a <pagevault> element for the password prompt."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 0, "keys": []},
            chunks=[],
            title="Protected: test",
            viewers=[],
        )
        soup = BeautifulSoup(html, "html.parser")
        pv = soup.find("pagevault")
        assert pv is not None
        assert pv.get("data-pv-chunked") == "true"

    def test_has_runtime_scripts(self):
        """Output includes crypto and renderer runtime scripts."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 1, "keys": []},
            chunks=["AAAA"],
            title="Protected: test.txt",
            viewers=[],
        )
        assert "decryptV3Chunked" in html
        assert "crypto.subtle" in html
        assert "PBKDF2" in html

    def test_has_progress_bar(self):
        """Output includes progress bar CSS and JS."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 1, "keys": []},
            chunks=["AAAA"],
            title="Protected: test",
            viewers=[],
        )
        assert "pagevault-progress" in html

    def test_title_escaped(self):
        """Title with HTML special chars is escaped."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 0, "keys": []},
            chunks=[],
            title='Protected: <script>alert("xss")</script>',
            viewers=[],
        )
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_no_data_encrypted_attribute(self):
        """v3 does NOT use data-encrypted attribute (chunks are in script tags)."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 1, "keys": []},
            chunks=["AAAA"],
            title="Protected: test",
            viewers=[],
        )
        assert 'data-encrypted="' not in html

    def test_zero_chunks(self):
        """Template with zero chunks should still have pv-meta and pagevault element."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 0, "keys": []},
            chunks=[],
            title="Protected: empty",
            viewers=[],
        )
        soup = BeautifulSoup(html, "html.parser")
        assert soup.find("script", {"id": "pv-meta"}) is not None
        assert soup.find("pagevault") is not None
        # No chunk script tags
        assert soup.find("script", {"id": "pv-0"}) is None

    def test_user_mode_attribute(self):
        """When users dict is provided, pagevault element has data-mode='user'."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 0, "keys": []},
            chunks=[],
            title="Protected: test",
            viewers=[],
            users={"alice": "pw-a"},
        )
        soup = BeautifulSoup(html, "html.parser")
        pv = soup.find("pagevault")
        assert pv.get("data-mode") == "user"

    def test_includes_framework_css(self):
        """Output includes framework CSS (pagevault-container, etc)."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 0, "keys": []},
            chunks=[],
            title="Protected: test",
            viewers=[],
        )
        assert ".pagevault-container" in html
        assert ".pagevault-button" in html

    def test_site_mode_includes_jszip(self):
        """When include_jszip is True, output includes JSZip shim and site renderer."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 1, "keys": []},
            chunks=["AAAA"],
            title="Protected: site",
            viewers=[],
            include_jszip=True,
        )
        assert "ZipReader" in html
        assert "__pagevault_renderSite" in html

    def test_renderer_has_escapehtml(self):
        """The v3 renderer IIFE must define its own escapeHtml."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 0, "keys": []},
            chunks=[],
            title="Protected: test",
            viewers=[],
        )
        assert "function escapeHtml" in html

    def test_crypto_js_v3_hex_to_bytes(self):
        """The v3 crypto JS must use hexToBytes (v3 salt is hex, not base64)."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 0, "keys": []},
            chunks=[],
            title="Protected: test",
            viewers=[],
        )
        assert "hexToBytes" in html

    def test_crypto_js_v3_derive_chunk_iv(self):
        """The v3 crypto JS must use deriveChunkIv for per-chunk IVs."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 0, "keys": []},
            chunks=[],
            title="Protected: test",
            viewers=[],
        )
        assert "deriveChunkIv" in html

    def test_viewer_dispatch_table(self):
        """v3 renderer includes viewer dispatch table when viewers given."""
        viewers = discover_viewers()
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 1, "keys": []},
            chunks=["AAAA"],
            title="Protected: test.png",
            viewers=viewers,
        )
        assert "__pv_resolveViewer" in html
        assert "__pv_viewers" in html
        assert "__pv_image" in html


class TestV3PaddingStrip:
    """Tests for v3 renderer stripping null-byte padding."""

    def test_v3_renderer_truncates_blob_to_meta_size(self):
        """v3 renderer JS should truncate blob using meta.size after decryption."""
        from pagevault.wrap import _get_renderer_js_v3
        js = _get_renderer_js_v3([])
        assert "meta.size" in js
        assert ".slice(" in js or "slice(0" in js

    def test_v3_renderer_has_padding_comment(self):
        """v3 renderer should document the padding strip."""
        from pagevault.wrap import _get_renderer_js_v3
        js = _get_renderer_js_v3([])
        assert "padding" in js.lower() or "pad" in js.lower()
