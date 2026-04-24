"""Tests for pagevault.parser module."""

import pytest
from bs4 import BeautifulSoup

from pagevault.config import DefaultsConfig, PagevaultConfig, TemplateConfig
from pagevault.crypto import PagevaultError, content_hash, decrypt, generate_salt
from pagevault.parser import (
    extract_element_content,
    find_pagevault_elements,
    has_pagevault_elements,
    is_already_encrypted,
    lock_html,
    mark_body,
    mark_elements,
    sync_html_keys,
    unlock_html,
)
from pagevault.runtime._loader import _js_string


class TestMarkElements:
    """Tests for mark_elements function."""

    def test_wraps_single_element_by_id(self):
        """Test wrapping element by ID selector."""
        html = '<html><body><div id="secret">Secret content</div></body></html>'

        result = mark_elements(html, ["#secret"])

        assert "<pagevault>" in result
        assert "</pagevault>" in result
        assert "Secret content" in result

    def test_wraps_element_by_class(self):
        """Test wrapping element by class selector."""
        html = '<html><body><div class="private">Private content</div></body></html>'

        result = mark_elements(html, [".private"])

        soup = BeautifulSoup(result, "html.parser")
        wrapper = soup.find("pagevault")
        assert wrapper is not None
        assert "Private content" in str(wrapper)

    def test_wraps_multiple_selectors(self):
        """Test wrapping elements with multiple selectors."""
        html = """<html><body>
            <div id="first">First</div>
            <div class="second">Second</div>
        </body></html>"""

        result = mark_elements(html, ["#first", ".second"])

        assert result.count("<pagevault>") == 2

    def test_wraps_multiple_matching_elements(self):
        """Test wrapping multiple elements matching same selector."""
        html = """<html><body>
            <div class="secret">One</div>
            <div class="secret">Two</div>
        </body></html>"""

        result = mark_elements(html, [".secret"])

        assert result.count("<pagevault>") == 2

    def test_adds_hint_attribute(self):
        """Test hint attribute is added to wrapper."""
        html = '<html><body><div id="secret">Secret</div></body></html>'

        result = mark_elements(html, ["#secret"], hint="Password hint")

        assert 'hint="Password hint"' in result

    def test_adds_remember_attribute(self):
        """Test remember attribute is added to wrapper."""
        html = '<html><body><div id="secret">Secret</div></body></html>'

        result = mark_elements(html, ["#secret"], remember="local")

        assert 'remember="local"' in result

    def test_adds_both_hint_and_remember(self):
        """Test both hint and remember are added."""
        html = '<html><body><div id="secret">Secret</div></body></html>'

        result = mark_elements(html, ["#secret"], hint="The hint", remember="session")

        assert 'hint="The hint"' in result
        assert 'remember="session"' in result

    def test_wraps_pagevault_elements(self):
        """Test can wrap existing pagevault elements for composability."""
        html = "<html><body><pagevault>Already wrapped</pagevault></body></html>"

        result = mark_elements(html, ["pagevault"])

        # Should be wrapped in another pagevault (closure property)
        assert result.count("<pagevault") == 2

    def test_skips_already_wrapped_elements(self):
        """Test skips elements already inside pagevault."""
        html = (
            "<html><body><pagevault>"
            '<div id="inner">Content</div>'
            "</pagevault></body></html>"
        )

        result = mark_elements(html, ["#inner"])

        # Should not wrap the inner div
        assert result.count("<pagevault>") == 1

    def test_no_selectors_returns_unchanged(self):
        """Test returns unchanged HTML when no selectors provided."""
        html = '<html><body><div id="secret">Secret</div></body></html>'

        result = mark_elements(html, [])

        # No pagevault should be added
        assert "<pagevault>" not in result

    def test_no_matching_elements(self):
        """Test handles no matching elements gracefully."""
        html = "<html><body><div>Regular content</div></body></html>"

        result = mark_elements(html, ["#nonexistent", ".missing"])

        assert "<pagevault>" not in result

    def test_complex_selector(self):
        """Test complex CSS selector."""
        html = """<html><body>
            <article class="post">
                <div class="content">Article content</div>
            </article>
        </body></html>"""

        result = mark_elements(html, ["article.post .content"])

        soup = BeautifulSoup(result, "html.parser")
        wrapper = soup.find("pagevault")
        assert wrapper is not None
        assert "Article content" in str(wrapper)

    def test_integration_with_lock_html(self):
        """Test marked elements can be encrypted."""
        html = (
            "<html><head><title>Test</title></head>"
            '<body><div id="secret">Secret content'
            "</div></body></html>"
        )

        wrapped = mark_elements(html, ["#secret"])
        encrypted = lock_html(wrapped, "password")

        # Content should be encrypted
        assert "Secret content" not in encrypted
        assert "data-pv-v4" in encrypted


class TestHasPagevaultElements:
    """Tests for has_pagevault_elements function."""

    def test_detects_element(self):
        """Test detecting pagevault elements."""
        html = "<html><pagevault>secret</pagevault></html>"
        assert has_pagevault_elements(html) is True

    def test_detects_self_closing(self):
        """Test detecting self-closing elements."""
        html = '<html><pagevault data-encrypted="x"/></html>'
        assert has_pagevault_elements(html) is True

    def test_case_insensitive(self):
        """Test case-insensitive detection."""
        html = "<html><PAGEVAULT>secret</PAGEVAULT></html>"
        assert has_pagevault_elements(html) is True

    def test_no_elements(self):
        """Test returns False when no elements."""
        html = "<html><body>normal content</body></html>"
        assert has_pagevault_elements(html) is False


class TestFindPagevaultElements:
    """Tests for find_pagevault_elements function."""

    def test_finds_single_element(self):
        """Test finding a single element."""
        html = "<html><pagevault>secret</pagevault></html>"
        soup = BeautifulSoup(html, "html.parser")

        elements = find_pagevault_elements(soup)
        assert len(elements) == 1

    def test_finds_multiple_elements(self):
        """Test finding multiple elements."""
        html = """
        <html>
            <pagevault>one</pagevault>
            <pagevault>two</pagevault>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")

        elements = find_pagevault_elements(soup)
        assert len(elements) == 2


class TestExtractElementContent:
    """Tests for extract_element_content function."""

    def test_extracts_text(self):
        """Test extracting text content."""
        html = "<pagevault>secret text</pagevault>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.find("pagevault")

        content = extract_element_content(element)
        assert content == "secret text"

    def test_extracts_nested_html(self):
        """Test extracting nested HTML."""
        html = "<pagevault><div><p>nested</p></div></pagevault>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.find("pagevault")

        content = extract_element_content(element)
        assert "<div>" in content
        assert "<p>nested</p>" in content


class TestIsAlreadyEncrypted:
    """Tests for is_already_encrypted function."""

    def test_encrypted_element(self):
        """Test detecting encrypted element (v4 marker)."""
        html = "<pagevault data-pv-v4></pagevault>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.find("pagevault")

        assert is_already_encrypted(element) is True

    def test_unencrypted_element(self):
        """Test detecting unencrypted element."""
        html = "<pagevault>plaintext</pagevault>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.find("pagevault")

        assert is_already_encrypted(element) is False


class TestLockHtml:
    """Tests for lock_html function."""

    def test_lock_produces_v4_envelope(self):
        """Lock output uses the v4 script-tag envelope, not v2 attribute."""
        html = "<pagevault>Secret</pagevault>"
        locked = lock_html(html, password="pw")
        assert "data-pv-v4" in locked
        assert "data-pv-meta" in locked
        assert 'data-pv-chunk="0"' in locked
        assert "data-encrypted=" not in locked

    def test_v4_roundtrip(self):
        """Lock and unlock a simple document via v4 round-trip."""
        html = "<html><body><pagevault>Secret</pagevault></body></html>"
        locked = lock_html(html, password="pw")
        unlocked = unlock_html(locked, password="pw")
        assert "Secret" in unlocked

    def test_basic_encryption(self):
        """Test basic HTML encryption."""
        html = """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>Secret content</pagevault>
</body>
</html>"""

        result = lock_html(html, "password")

        # Should have v4 envelope markers
        assert "data-pv-v4" in result
        # Original content should be gone
        assert "Secret content" not in result
        # Should have injected runtime
        assert "pagevault" in result.lower()

    def test_preserves_hint(self):
        """Test hint attribute is preserved."""
        html = '<pagevault hint="Use the magic word">Secret</pagevault>'

        result = lock_html(html, "password")
        assert 'data-hint="Use the magic word"' in result

    def test_preserves_remember(self):
        """Test remember attribute is preserved."""
        html = '<pagevault remember="local">Secret</pagevault>'

        result = lock_html(html, "password")
        assert 'data-remember="local"' in result

    def test_uses_config_defaults(self):
        """Test uses config defaults for remember."""
        html = "<pagevault>Secret</pagevault>"
        config = PagevaultConfig(defaults=DefaultsConfig(remember="session"))

        result = lock_html(html, "password", config)
        assert 'data-remember="session"' in result

    def test_injects_runtime(self):
        """Test runtime JS/CSS is injected."""
        html = """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>Secret</pagevault>
</body>
</html>"""

        result = lock_html(html, "password")

        assert "data-pagevault-runtime" in result
        assert "PagevaultHandler" in result
        assert ".pagevault-container" in result

    def test_no_elements_returns_unchanged(self):
        """Test HTML without elements is unchanged."""
        html = "<html><body>Normal content</body></html>"

        result = lock_html(html, "password")
        assert result == html

    def test_relock_preserves_existing_data_encrypted(self):
        """Locking an already-encrypted element preserves its ciphertext.

        Previously we re-encrypted, which silently destroyed the original
        payload (because the element's inner content was already cleared,
        so we were re-encrypting the empty string). Now we skip.

        In v4, the marker attribute is data-pv-v4 and the ciphertext lives
        in <script data-pv-meta>/<script data-pv-chunk="N"> children.
        """
        html = (
            "<pagevault data-pv-v4>"
            '<script type="application/json" data-pv-meta>'
            '{"v":4,"sentinel":"keep-me"}</script>'
            '<script type="x-pv" data-pv-chunk="0">AAAA</script>'
            "</pagevault>"
        )

        result = lock_html(html, "password")

        # Existing envelope preserved, not overwritten
        assert '"sentinel":"keep-me"' in result
        assert "AAAA" in result

    def test_uses_explicit_salt(self):
        """Test encryption uses explicit salt."""
        html = "<pagevault>Secret</pagevault>"
        salt = generate_salt()

        result1 = lock_html(html, "password", salt=salt)
        result2 = lock_html(html, "password", salt=salt)

        # Both should decrypt correctly with same password via unlock_html
        assert "Secret" in unlock_html(result1, "password")
        assert "Secret" in unlock_html(result2, "password")

        # Both envelopes should use the same salt (hex-encoded in the envelope)
        import json as _json
        import re as _re

        def extract_envelope(locked):
            m = _re.search(r'<script[^>]*data-pv-meta[^>]*>([^<]+)</script>', locked)
            assert m is not None, "Envelope script not found"
            return _json.loads(m.group(1))

        env1 = extract_envelope(result1)
        env2 = extract_envelope(result2)
        assert env1["salt"] == salt.hex()
        assert env2["salt"] == salt.hex()


class TestUnlockHtml:
    """Tests for unlock_html function."""

    def test_basic_decryption(self):
        """Test basic HTML decryption."""
        original = "<pagevault>Secret content</pagevault>"
        encrypted = lock_html(original, "password")

        decrypted = unlock_html(encrypted, "password")

        assert "Secret content" in decrypted
        assert "data-pv-v4" not in decrypted

    def test_roundtrip_preserves_content(self):
        """Test encrypt/decrypt roundtrip preserves content."""
        html = """<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
<header>Public Header</header>
<pagevault hint="Hint text">
    <main>
        <h1>Secret Title</h1>
        <p>Secret paragraph.</p>
    </main>
</pagevault>
<footer>Public Footer</footer>
</body>
</html>"""

        encrypted = lock_html(html, "password")
        decrypted = unlock_html(encrypted, "password")

        # Public content should be present
        assert "Public Header" in decrypted
        assert "Public Footer" in decrypted

        # Encrypted content should be restored
        assert "Secret Title" in decrypted
        assert "Secret paragraph" in decrypted

    def test_removes_runtime(self):
        """Test runtime is removed after decryption."""
        html = "<pagevault>Secret</pagevault>"
        encrypted = lock_html(html, "password")

        assert "data-pagevault-runtime" in encrypted

        decrypted = unlock_html(encrypted, "password")
        assert "data-pagevault-runtime" not in decrypted

    def test_wrong_password_fails(self):
        """Test decryption with wrong password fails."""
        html = "<pagevault>Secret</pagevault>"
        encrypted = lock_html(html, "correct")

        with pytest.raises(PagevaultError, match="wrong password"):
            unlock_html(encrypted, "wrong")

    def test_no_elements_returns_unchanged(self):
        """Test HTML without elements is unchanged."""
        html = "<html><body>Normal content</body></html>"

        result = unlock_html(html, "password")
        assert result == html

    def test_preserves_hint_for_reencryption(self):
        """Test hint is preserved as original attribute after decryption."""
        html = '<pagevault hint="Remember the hint">Secret</pagevault>'

        encrypted = lock_html(html, "password")
        decrypted = unlock_html(encrypted, "password")

        assert 'hint="Remember the hint"' in decrypted


class TestMultipleElements:
    """Tests for multiple pagevault elements."""

    def test_encryption_with_multiple_elements(self):
        """Test encrypting multiple elements."""
        html = """
        <pagevault hint="hint1">First</pagevault>
        <pagevault hint="hint2">Second</pagevault>
        """

        result = lock_html(html, "password")

        # Both should be encrypted
        assert "First" not in result
        assert "Second" not in result
        assert result.count("data-pv-v4") == 2
        assert 'data-hint="hint1"' in result
        assert 'data-hint="hint2"' in result

    def test_roundtrip_multiple_elements(self):
        """Test encrypt/decrypt roundtrip with multiple elements."""
        html = """
        <pagevault>First content</pagevault>
        <p>Public content</p>
        <pagevault>Second content</pagevault>
        """

        encrypted = lock_html(html, "password")
        decrypted = unlock_html(encrypted, "password")

        assert "First content" in decrypted
        assert "Second content" in decrypted
        assert "Public content" in decrypted

    def test_mixed_elements_preserves_encrypted_and_encrypts_new(self):
        """lock_html() on a document with a mix of already-encrypted and
        plaintext <pagevault> elements: preserves the former, encrypts
        the latter. The final document has both encrypted."""
        # Build a pre-existing v4 envelope by locking one element first.
        first_html = "<pagevault>Already encrypted</pagevault>"
        first_locked = lock_html(first_html, "password")
        # Extract just the <pagevault ...>...</pagevault> block
        soup = BeautifulSoup(first_locked, "html.parser")
        existing_elem = soup.find("pagevault")
        existing_markup = str(existing_elem)

        html = f"""
        {existing_markup}
        <pagevault>New content</pagevault>
        """

        result = lock_html(html, "password")

        # Both end up with v4 envelope in the output
        assert result.count("data-pv-v4") == 2
        assert "New content" not in result
        # The pre-existing envelope is PRESERVED: unlock should return
        # "Already encrypted" for the first region.
        decrypted = unlock_html(result, "password")
        assert "Already encrypted" in decrypted
        assert "New content" in decrypted


class TestTemplateCustomization:
    """Tests for template customization."""

    def test_custom_colors(self):
        """Test custom colors are applied."""
        html = "<pagevault>Secret</pagevault>"
        config = PagevaultConfig(
            template=TemplateConfig(color_primary="#ff0000", color_secondary="#00ff00")
        )

        result = lock_html(html, "password", config)

        assert "#ff0000" in result
        assert "#00ff00" in result

    def test_custom_text(self):
        """Test custom text is applied."""
        html = "<pagevault>Secret</pagevault>"
        config = PagevaultConfig(
            template=TemplateConfig(
                title="Custom Title",
                button_text="Custom Button",
                error_text="Custom Error",
                placeholder="Custom Placeholder",
            )
        )

        result = lock_html(html, "password", config)

        assert "Custom Title" in result
        assert "Custom Button" in result
        assert "Custom Error" in result
        assert "Custom Placeholder" in result

    def test_custom_css(self):
        """Test custom CSS replaces default styles."""
        html = "<pagevault>Secret</pagevault>"
        custom_css = ".my-custom-class { color: purple; }"

        result = lock_html(html, "password", custom_css=custom_css)

        # Custom CSS should be included
        assert ".my-custom-class" in result
        assert "color: purple" in result
        # Default CSS should NOT be included
        assert ".pagevault-container" not in result

    def test_custom_css_from_config(self):
        """Test custom CSS from config."""
        html = "<pagevault>Secret</pagevault>"
        config = PagevaultConfig(custom_css=".config-class { font-size: 20px; }")

        result = lock_html(html, "password", config)

        assert ".config-class" in result
        assert "font-size: 20px" in result

    def test_custom_css_cli_overrides_config(self):
        """Test CLI custom CSS overrides config custom CSS."""
        html = "<pagevault>Secret</pagevault>"
        config = PagevaultConfig(custom_css=".config-class { color: red; }")
        cli_css = ".cli-class { color: blue; }"

        result = lock_html(html, "password", config, custom_css=cli_css)

        # CLI CSS should be used
        assert ".cli-class" in result
        assert "color: blue" in result
        # Config CSS should NOT be used
        assert ".config-class" not in result

    def test_dark_mode_css(self):
        """Default CSS should contain dark mode media query."""
        html = "<pagevault>Secret</pagevault>"
        result = lock_html(html, "password")
        assert "prefers-color-scheme: dark" in result


class TestContentHashIntegrity:
    """Tests for content hash storage and verification.

    In v4, content_hash is carried inside the encrypted metadata payload
    (envelope.meta.content_hash after decrypt_chunked), not as a DOM
    attribute. These tests decrypt the envelope to verify the hash.
    """

    @staticmethod
    def _extract_meta(locked_html: str, password: str = "password", username=None):
        """Extract decrypted envelope metadata from a locked HTML string."""
        import json as _json

        from pagevault.crypto import decrypt_chunked

        soup = BeautifulSoup(locked_html, "html.parser")
        results = []
        for pv in soup.find_all("pagevault"):
            if not pv.has_attr("data-pv-v4"):
                continue
            meta_script = pv.find("script", attrs={"data-pv-meta": True})
            if not meta_script or not meta_script.string:
                continue
            envelope = _json.loads(meta_script.string)
            chunks = [
                c.string or ""
                for c in sorted(
                    pv.find_all("script", attrs={"data-pv-chunk": True}),
                    key=lambda s: int(s["data-pv-chunk"]),
                )
            ]
            _, meta = decrypt_chunked(envelope, chunks, password, username=username)
            results.append(meta)
        return results

    def test_hash_stored_in_encrypted_element(self):
        """Content hash is stored in the encrypted envelope metadata."""
        html = "<pagevault>Secret content</pagevault>"
        expected_hash = content_hash("Secret content")

        result = lock_html(html, "password")
        metas = self._extract_meta(result)
        assert len(metas) == 1
        assert metas[0]["content_hash"] == expected_hash

    def test_hash_removed_after_decryption(self):
        """No hash/v4 markers survive after unlocking."""
        html = "<pagevault>Secret content</pagevault>"

        encrypted = lock_html(html, "password")
        # Envelope carries a hash
        metas = self._extract_meta(encrypted)
        assert "content_hash" in metas[0]

        decrypted = unlock_html(encrypted, "password")
        assert "data-pv-v4" not in decrypted
        assert "data-content-hash" not in decrypted
        assert "data-pv-meta" not in decrypted

    def test_hash_preserved_through_roundtrip(self):
        """Test content matches after encrypt/decrypt roundtrip."""
        original_content = "<p>Complex <strong>HTML</strong> content</p>"
        html = f"<pagevault>{original_content}</pagevault>"
        original_hash = content_hash(original_content)

        encrypted = lock_html(html, "password")

        metas = self._extract_meta(encrypted)
        assert metas[0]["content_hash"] == original_hash

        decrypted = unlock_html(encrypted, "password")

        # Verify content is restored
        assert original_content in decrypted

    def test_hash_with_unicode_content(self):
        """Test hash works with unicode content."""
        content = "日本語コンテンツ 🔐 αβγδ"
        html = f"<pagevault>{content}</pagevault>"
        expected_hash = content_hash(content)

        result = lock_html(html, "パスワード")
        metas = self._extract_meta(result, password="パスワード")
        assert metas[0]["content_hash"] == expected_hash

    def test_hash_with_empty_content(self):
        """Test hash works with empty content."""
        html = "<pagevault></pagevault>"
        expected_hash = content_hash("")

        result = lock_html(html, "password")
        metas = self._extract_meta(result)
        assert metas[0]["content_hash"] == expected_hash

    def test_multiple_elements_have_correct_hashes(self):
        """Test multiple elements each get their own correct hash."""
        html = """
        <pagevault>First content</pagevault>
        <pagevault>Second content</pagevault>
        """
        hash1 = content_hash("First content")
        hash2 = content_hash("Second content")

        result = lock_html(html, "password")
        metas = self._extract_meta(result)
        hashes = {m["content_hash"] for m in metas}
        assert hashes == {hash1, hash2}


class TestComposableEncryption:
    """Tests for composable/nested encryption (closure property)."""

    def test_relock_preserves_already_encrypted(self):
        """Locking an already-encrypted element is a no-op on that element.

        This used to re-encrypt with the new password, silently destroying
        the original payload (the element's inner content was already
        cleared during the first lock, so the re-encryption encrypted
        the empty string). The new behavior preserves the ciphertext."""
        html = "<pagevault>Secret</pagevault>"

        encrypted1 = lock_html(html, "password1")
        assert "data-pv-v4" in encrypted1

        # Second lock is idempotent on the already-encrypted element
        encrypted2 = lock_html(encrypted1, "password2")

        soup1 = BeautifulSoup(encrypted1, "html.parser")
        soup2 = BeautifulSoup(encrypted2, "html.parser")

        env1 = soup1.find("pagevault").find("script", attrs={"data-pv-meta": True}).string
        env2 = soup2.find("pagevault").find("script", attrs={"data-pv-meta": True}).string

        # Envelope preserved (password1 still decrypts)
        assert env1 == env2

    def test_nested_encryption_via_wrapping(self):
        """Test nested encryption by wrapping encrypted element in new wrapper."""
        html = """<!DOCTYPE html>
<html><head><title>Test</title></head><body>
<pagevault>Secret</pagevault>
</body></html>"""

        # First encrypt with inner password
        encrypted1 = lock_html(html, "inner")
        assert "data-pv-v4" in encrypted1
        assert "Secret" not in encrypted1

        # Wrap the encrypted element in a new pagevault
        wrapped = mark_elements(encrypted1, ["pagevault"])

        # Encrypt outer wrapper with different password
        encrypted2 = lock_html(wrapped, "outer")

        # Should have 2 encrypted elements (outer wrapping inner)
        soup = BeautifulSoup(encrypted2, "html.parser")
        encrypted_elements = soup.find_all("pagevault")
        outer = encrypted_elements[0]
        assert outer.has_attr("data-pv-v4")

        # Decrypt outer layer
        decrypted1 = unlock_html(encrypted2, "outer")
        # Should still have inner encryption
        assert "data-pv-v4" in decrypted1
        assert "Secret" not in decrypted1

        # Decrypt inner layer
        decrypted2 = unlock_html(decrypted1, "inner")
        assert "Secret" in decrypted2

    def test_relock_preserves_existing_ciphertext(self):
        """lock_html() on already-locked HTML is idempotent: already-encrypted
        elements are skipped, preserving their ciphertext.

        This is the closure property: unlock(lock(unlock(lock(html)))) == html.
        The previous behavior (re-encrypting with the new password, destroying
        the original ciphertext by encrypting the empty string) was a footgun
        that silently lost data when users ran `pagevault lock locked.html`.

        To compose encryption layers, explicitly use mark_elements to wrap
        the encrypted element first — see test_nested_encryption_via_wrapping.
        """
        html = "<pagevault>Secret</pagevault>"

        encrypted1 = lock_html(html, "password1")
        encrypted2 = lock_html(encrypted1, "password2")

        # Still only one encrypted element
        soup = BeautifulSoup(encrypted2, "html.parser")
        elements = soup.find_all("pagevault")
        assert len(elements) == 1

        # Envelope PRESERVED (not re-encrypted with password2)
        soup1 = BeautifulSoup(encrypted1, "html.parser")
        env1 = soup1.find("pagevault").find("script", attrs={"data-pv-meta": True}).string
        env2 = elements[0].find("script", attrs={"data-pv-meta": True}).string
        assert env1 == env2

        # And the original password still decrypts it
        decrypted = unlock_html(encrypted2, "password1")
        assert "Secret" in decrypted

    def test_relock_is_idempotent(self):
        """lock(lock(html)) == lock(html) structurally — closure property."""
        html = "<pagevault>A</pagevault><pagevault>B</pagevault>"
        once = lock_html(html, "pw", salt=b"\x00" * 16)
        twice = lock_html(once, "pw", salt=b"\x00" * 16)
        assert once == twice

    def test_wrap_existing_pagevault_element(self):
        """Test wrapping an existing pagevault element for nested encryption."""
        html = "<pagevault data-pv-v4></pagevault>"

        result = mark_elements(html, ["pagevault"])

        # Should be wrapped in another pagevault
        assert result.count("<pagevault") == 2

    def test_multi_password_workflow(self):
        """Test encrypting different elements with different passwords."""
        html = """<html><body>
            <div id="admin">Admin content</div>
            <div id="member">Member content</div>
        </body></html>"""

        # First pass: encrypt admin section
        wrapped1 = mark_elements(html, ["#admin"])
        encrypted1 = lock_html(wrapped1, "admin-password")

        # Second pass: encrypt member section with different password
        wrapped2 = mark_elements(encrypted1, ["#member"])
        encrypted2 = lock_html(wrapped2, "member-password")

        # Both sections should be encrypted
        assert encrypted2.count("data-pv-v4") == 2
        assert "Admin content" not in encrypted2
        assert "Member content" not in encrypted2


class TestPerElementTitle:
    """Tests for per-element title attribute."""

    def test_title_attribute_preserved(self):
        """Test title attribute is preserved during encryption."""
        html = '<pagevault title="Admin Panel">Secret</pagevault>'

        result = lock_html(html, "password")

        assert 'data-title="Admin Panel"' in result

    def test_title_in_wrapped_element(self):
        """Test title added during wrapping."""
        html = '<div id="secret">Content</div>'

        result = mark_elements(html, ["#secret"], title="Secret Section")

        assert 'title="Secret Section"' in result

    def test_title_preserved_through_roundtrip(self):
        """Test title survives encrypt/decrypt cycle."""
        html = '<pagevault title="My Title">Secret</pagevault>'

        encrypted = lock_html(html, "password")
        assert 'data-title="My Title"' in encrypted

        decrypted = unlock_html(encrypted, "password")
        assert 'title="My Title"' in decrypted

    def test_title_appears_in_js_runtime(self):
        """Test JS runtime uses per-element title."""
        html = '<pagevault title="Custom Title">Secret</pagevault>'

        result = lock_html(html, "password")

        # JS should read data-title attribute
        assert "el.getAttribute('data-title')" in result


class TestMarkBody:
    """Tests for mark_body function."""

    def test_wraps_body_content(self):
        """Test basic HTML with body content gets wrapped in pagevault."""
        html = "<html><head><title>Test</title></head><body><p>Hello</p></body></html>"

        result = mark_body(html)

        soup = BeautifulSoup(result, "html.parser")
        wrapper = soup.find("pagevault")
        assert wrapper is not None
        assert "Hello" in str(wrapper)

    def test_preserves_head(self):
        """Test head section is NOT wrapped."""
        html = (
            "<html><head><title>My Title</title></head>"
            "<body><p>Body content</p></body></html>"
        )

        result = mark_body(html)

        soup = BeautifulSoup(result, "html.parser")
        head = soup.find("head")
        assert head is not None
        # Head should not be inside pagevault
        assert head.find_parent("pagevault") is None
        assert "My Title" in str(head)

    def test_single_wrapper(self):
        """Test only one pagevault element is created."""
        html = "<html><head></head><body><p>One</p><p>Two</p><p>Three</p></body></html>"

        result = mark_body(html)

        assert result.count("<pagevault>") == 1

    def test_no_body_returns_unchanged(self):
        """Test HTML without body tag returns unchanged."""
        html = "<html><head><title>Test</title></head></html>"

        result = mark_body(html)

        assert "<pagevault>" not in result

    def test_empty_body_returns_unchanged(self):
        """Test HTML with empty body returns unchanged."""
        html = "<html><head></head><body></body></html>"

        result = mark_body(html)

        assert "<pagevault>" not in result

    def test_whitespace_only_body_returns_unchanged(self):
        """Test body with only whitespace returns unchanged."""
        html = "<html><head></head><body>   \n\t  </body></html>"

        result = mark_body(html)

        assert "<pagevault>" not in result

    def test_hint_attribute(self):
        """Test hint parameter adds attribute to wrapper."""
        html = "<html><head></head><body><p>Content</p></body></html>"

        result = mark_body(html, hint="My hint")

        assert 'hint="My hint"' in result

    def test_title_attribute(self):
        """Test title parameter adds attribute to wrapper."""
        html = "<html><head></head><body><p>Content</p></body></html>"

        result = mark_body(html, title="My title")

        assert 'title="My title"' in result

    def test_remember_attribute(self):
        """Test remember parameter adds attribute to wrapper."""
        html = "<html><head></head><body><p>Content</p></body></html>"

        result = mark_body(html, remember="local")

        assert 'remember="local"' in result

    def test_all_attributes(self):
        """Test all three attributes together."""
        html = "<html><head></head><body><p>Content</p></body></html>"

        result = mark_body(html, hint="The hint", title="The title", remember="session")

        assert 'hint="The hint"' in result
        assert 'title="The title"' in result
        assert 'remember="session"' in result


class TestMultiUserEncryptDecrypt:
    """Tests for multi-user encryption and decryption."""

    def test_encrypt_with_users_sets_data_mode(self):
        """Test lock_html with users param sets data-mode='user' attribute."""
        html = "<pagevault>Secret</pagevault>"

        result = lock_html(html, users={"alice": "pw-a", "bob": "pw-b"})

        assert 'data-mode="user"' in result

    def test_decrypt_with_username(self):
        """Test encrypt with users, decrypt with username param works."""
        html = "<pagevault>Secret for users</pagevault>"

        encrypted = lock_html(html, users={"alice": "pw-a"})
        decrypted = unlock_html(encrypted, "pw-a", username="alice")

        assert "Secret for users" in decrypted

    def test_roundtrip_multiuser(self):
        """Test full encrypt/decrypt roundtrip with users."""
        html = """<!DOCTYPE html>
<html>
<head><title>Multi-user Test</title></head>
<body>
<pagevault>Multi-user secret content</pagevault>
</body>
</html>"""

        encrypted = lock_html(html, users={"alice": "pw-a", "bob": "pw-b"})

        # Both users should be able to decrypt
        decrypted_alice = unlock_html(encrypted, "pw-a", username="alice")
        assert "Multi-user secret content" in decrypted_alice

        decrypted_bob = unlock_html(encrypted, "pw-b", username="bob")
        assert "Multi-user secret content" in decrypted_bob

    def test_multiuser_js_runtime_has_username_field(self):
        """Test encrypted HTML JS contains usernamePlaceholder."""
        html = """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault>Secret</pagevault>
</body>
</html>"""

        result = lock_html(html, users={"alice": "pw-a"})

        assert "usernamePlaceholder" in result

    def test_data_mode_removed_on_decrypt(self):
        """Test data-mode attribute is removed after decryption."""
        html = "<pagevault>Secret</pagevault>"

        encrypted = lock_html(html, users={"alice": "pw-a"})
        assert 'data-mode="user"' in encrypted

        decrypted = unlock_html(encrypted, "pw-a", username="alice")
        assert "data-mode" not in decrypted


class TestSyncHtmlKeys:
    """Tests for sync_html_keys function (v4 envelopes)."""

    def test_sync_adds_user(self):
        """Test encrypt with users, sync to add bob, verify bob can decrypt."""
        html = "<pagevault>Sync secret</pagevault>"

        # Encrypt with alice only
        encrypted = lock_html(html, users={"alice": "pw-a"})

        # Sync to add bob
        result = sync_html_keys(
            encrypted,
            old_users={"alice": "pw-a"},
            new_users={"alice": "pw-a", "bob": "pw-b"},
        )

        # Verify bob can decrypt
        decrypted = unlock_html(result, "pw-b", username="bob")
        assert "Sync secret" in decrypted

    def test_sync_removes_user(self):
        """Test sync to remove bob, verify bob cannot decrypt."""
        html = "<pagevault>Remove user secret</pagevault>"

        # Encrypt with alice and bob
        encrypted = lock_html(html, users={"alice": "pw-a", "bob": "pw-b"})

        # Sync to remove bob
        result = sync_html_keys(
            encrypted,
            old_users={"alice": "pw-a"},
            new_users={"alice": "pw-a"},
        )

        # Verify alice can still decrypt
        decrypted = unlock_html(result, "pw-a", username="alice")
        assert "Remove user secret" in decrypted

        # Verify bob cannot decrypt
        with pytest.raises(PagevaultError):
            unlock_html(result, "pw-b", username="bob")

    def test_sync_rekey(self):
        """Test sync with rekey=True produces a new envelope for the same content."""
        import json as _json

        html = "<pagevault>Rekey secret</pagevault>"

        # Encrypt with alice
        encrypted = lock_html(html, users={"alice": "pw-a"})

        # Capture original envelope
        soup_orig = BeautifulSoup(encrypted, "html.parser")
        orig_meta = soup_orig.find("pagevault").find(
            "script", attrs={"data-pv-meta": True}
        ).string
        orig_env = _json.loads(orig_meta)

        # Sync with rekey
        result = sync_html_keys(
            encrypted,
            old_users={"alice": "pw-a"},
            new_users={"alice": "pw-a"},
            rekey=True,
        )

        # Envelope should differ (new CEK/IVs) even if password is the same
        soup_new = BeautifulSoup(result, "html.parser")
        new_meta = soup_new.find("pagevault").find(
            "script", attrs={"data-pv-meta": True}
        ).string
        new_env = _json.loads(new_meta)
        assert new_env["iv_base"] != orig_env["iv_base"]
        assert new_env["meta_iv"] != orig_env["meta_iv"]

        # Verify alice can still decrypt
        decrypted = unlock_html(result, "pw-a", username="alice")
        assert "Rekey secret" in decrypted

    def test_sync_sets_data_mode(self):
        """Test sync to multi-user sets data-mode='user'."""
        html = "<pagevault>Mode secret</pagevault>"

        # Encrypt with single password
        encrypted = lock_html(html, password="single-pw")

        # Sync to multi-user
        result = sync_html_keys(
            encrypted,
            old_password="single-pw",
            new_users={"alice": "pw-a", "bob": "pw-b"},
        )

        assert 'data-mode="user"' in result

    def test_sync_no_encrypted_elements_returns_unchanged(self):
        """Test HTML without encrypted elements returns unchanged."""
        html = "<html><body>Normal content</body></html>"

        result = sync_html_keys(
            html,
            old_password="pw",
            new_password="new-pw",
        )

        assert result == html


class TestAutoMetadata:
    """Tests for auto-populated metadata during encryption."""

    def test_meta_auto_populated(self):
        """Test lock_html auto-populates meta with encrypted_at and version."""
        import json as _json

        from pagevault.crypto import decrypt_chunked

        html = "<pagevault>Meta test</pagevault>"

        result = lock_html(html, "password")

        # Extract envelope + chunks and decrypt to inspect meta
        soup = BeautifulSoup(result, "html.parser")
        elem = soup.find("pagevault")
        envelope = _json.loads(
            elem.find("script", attrs={"data-pv-meta": True}).string
        )
        chunks = [
            c.string or ""
            for c in sorted(
                elem.find_all("script", attrs={"data-pv-chunk": True}),
                key=lambda s: int(s["data-pv-chunk"]),
            )
        ]
        content_bytes, meta = decrypt_chunked(envelope, chunks, "password")

        assert content_bytes.decode("utf-8") == "Meta test"
        assert meta is not None
        assert "encrypted_at" in meta
        assert "version" in meta
        assert meta.get("kind") == "html_fragment"

    def test_content_hash_unaffected_by_meta(self):
        """Test content hash is computed on inner HTML, not on meta."""
        import json as _json

        from pagevault.crypto import decrypt_chunked

        html = "<pagevault>Hash test content</pagevault>"
        expected_hash = content_hash("Hash test content")

        result = lock_html(html, "password")

        # The content hash should match the inner HTML hash
        soup = BeautifulSoup(result, "html.parser")
        elem = soup.find("pagevault")
        envelope = _json.loads(
            elem.find("script", attrs={"data-pv-meta": True}).string
        )
        chunks = [
            c.string or ""
            for c in sorted(
                elem.find_all("script", attrs={"data-pv-chunk": True}),
                key=lambda s: int(s["data-pv-chunk"]),
            )
        ]
        _, meta = decrypt_chunked(envelope, chunks, "password")
        assert meta["content_hash"] == expected_hash


class TestMultiUserUnlockError:
    """Tests for helpful error when unlocking multi-user files without username."""

    def test_multiuser_unlock_without_username_error(self):
        """Test clear error message when unlocking multi-user file without -u flag."""
        html = "<pagevault>Secret</pagevault>"

        # Lock with multi-user mode
        encrypted = lock_html(html, users={"alice": "pw-a", "bob": "pw-b"})
        assert 'data-mode="user"' in encrypted

        # Try to unlock without username
        with pytest.raises(PagevaultError, match="multi-user encryption"):
            unlock_html(encrypted, "pw-a")  # No username provided

    def test_multiuser_unlock_error_mentions_flag(self):
        """Test error message mentions -u USERNAME flag."""
        html = "<pagevault>Secret</pagevault>"
        encrypted = lock_html(html, users={"alice": "pw-a"})

        with pytest.raises(PagevaultError, match="-u USERNAME"):
            unlock_html(encrypted, "pw-a")

    def test_single_user_unlock_works_without_username(self):
        """Test single-user files work without username (no regression)."""
        html = "<pagevault>Secret</pagevault>"

        encrypted = lock_html(html, password="single-pw")
        # No data-mode="user" attribute
        assert 'data-mode="user"' not in encrypted

        # Unlock should work without username
        decrypted = unlock_html(encrypted, "single-pw")
        assert "Secret" in decrypted


class TestBackwardCompat:
    """Tests for backward compatibility of old function name aliases."""

    def test_encrypt_html_alias_works(self):
        """Test that the old encrypt_html alias still works."""
        from pagevault.parser import encrypt_html

        html = "<pagevault>Backward compat test</pagevault>"

        result = encrypt_html(html, "password")

        assert "data-pv-v4" in result
        assert "Backward compat test" not in result

    def test_decrypt_html_alias_works(self):
        """Test that the old decrypt_html alias still works."""
        from pagevault.parser import decrypt_html, encrypt_html

        html = "<pagevault>Alias roundtrip</pagevault>"

        encrypted = encrypt_html(html, "password")
        decrypted = decrypt_html(encrypted, "password")

        assert "Alias roundtrip" in decrypted

    def test_wrap_elements_alias_works(self):
        """Test that the old wrap_elements_for_encryption alias still works."""
        from pagevault.parser import wrap_elements_for_encryption

        html = '<html><body><div id="secret">Secret</div></body></html>'

        result = wrap_elements_for_encryption(html, ["#secret"])

        assert "<pagevault>" in result

    def test_wrap_body_alias_works(self):
        """Test that the old wrap_body_for_encryption alias still works."""
        from pagevault.parser import wrap_body_for_encryption

        html = "<html><head></head><body><p>Content</p></body></html>"

        result = wrap_body_for_encryption(html)

        assert "<pagevault>" in result


class TestEscapeHtmlInRuntime:
    """Tests for escapeHtml function in generated JS runtime."""

    def test_locked_output_contains_escapehtml(self):
        """Test that locked HTML output contains the escapeHtml function."""
        html = "<pagevault>Secret</pagevault>"

        result = lock_html(html, "password")

        assert "function escapeHtml" in result

    def test_locked_output_uses_escapehtml_for_title(self):
        """Test that the _render() method uses escapeHtml for title."""
        html = "<pagevault>Secret</pagevault>"

        result = lock_html(html, "password")

        assert "escapeHtml(title)" in result

    def test_locked_output_uses_escapehtml_for_hint(self):
        """Test that the _render() method uses escapeHtml for hint."""
        html = "<pagevault>Secret</pagevault>"

        result = lock_html(html, "password")

        assert "escapeHtml(hint)" in result

    def test_locked_output_uses_escapehtml_for_button(self):
        """Test that the _render() method uses escapeHtml for button text."""
        html = "<pagevault>Secret</pagevault>"

        result = lock_html(html, "password")

        assert "escapeHtml(CONFIG.buttonText)" in result


class TestJsStringEscape:
    """Tests for _js_string script-tag escape."""

    def test_escapes_script_close_tag(self):
        """Test that </script> sequences are escaped in JS strings."""
        result = _js_string("</script>alert(1)")

        assert "<\\/script>" in result
        assert "</script>" not in result

    def test_escapes_generic_close_tag(self):
        """Test that any </ sequence is escaped."""
        result = _js_string("foo</bar>baz")

        assert "<\\/bar>" in result

    def test_preserves_normal_strings(self):
        """Test that normal strings are unchanged (except quotes)."""
        result = _js_string("hello world")

        assert result == '"hello world"'

    def test_escapes_backslashes(self):
        """Test backslashes are properly escaped."""
        result = _js_string("back\\slash")

        assert result == '"back\\\\slash"'

    def test_escapes_quotes(self):
        """Test double quotes are properly escaped."""
        result = _js_string('say "hello"')

        assert result == '"say \\"hello\\""'


class TestAttributeRemovalDuringLock:
    """Tests for removing original hint/title/remember attrs during lock."""

    def test_hint_attr_removed_after_lock(self):
        """Test that bare 'hint' attribute is removed after lock."""
        html = '<pagevault hint="Password hint">Secret</pagevault>'

        result = lock_html(html, "password")

        soup = BeautifulSoup(result, "html.parser")
        elem = soup.find("pagevault")
        # data-hint should be present
        assert elem.get("data-hint") == "Password hint"
        # bare hint should NOT be present
        assert "hint" not in elem.attrs or elem.attrs.get("hint") is None
        # Check no bare hint= in the raw HTML (only data-hint=)
        assert 'hint="Password hint"' not in result.replace("data-hint", "REPLACED")

    def test_title_attr_removed_after_lock(self):
        """Test that bare 'title' attribute is removed after lock."""
        html = '<pagevault title="Admin Panel">Secret</pagevault>'

        result = lock_html(html, "password")

        soup = BeautifulSoup(result, "html.parser")
        elem = soup.find("pagevault")
        assert elem.get("data-title") == "Admin Panel"
        assert "title" not in elem.attrs

    def test_remember_attr_removed_after_lock(self):
        """Test that bare 'remember' attribute is removed after lock."""
        html = '<pagevault remember="local">Secret</pagevault>'

        result = lock_html(html, "password")

        soup = BeautifulSoup(result, "html.parser")
        elem = soup.find("pagevault")
        assert elem.get("data-remember") == "local"
        assert "remember" not in elem.attrs

    def test_roundtrip_preserves_attribute_values(self):
        """Test lock->unlock roundtrip still preserves hint/title/remember values."""
        html = (
            '<pagevault hint="My hint" title="My title"'
            ' remember="session">Secret</pagevault>'
        )

        encrypted = lock_html(html, "password")
        decrypted = unlock_html(encrypted, "password")

        # After unlock, the bare attributes should be restored
        assert 'hint="My hint"' in decrypted
        assert 'title="My title"' in decrypted
        assert 'remember="session"' in decrypted
        assert "Secret" in decrypted

    def test_all_attrs_removed_together(self):
        """Test all three attributes are removed simultaneously during lock."""
        html = '<pagevault hint="H" title="T" remember="local">Content</pagevault>'

        result = lock_html(html, "password")

        soup = BeautifulSoup(result, "html.parser")
        elem = soup.find("pagevault")
        # Only data- prefixed versions should exist
        assert elem.get("data-hint") == "H"
        assert elem.get("data-title") == "T"
        assert elem.get("data-remember") == "local"
        # Bare versions should be gone
        assert "hint" not in elem.attrs
        assert "title" not in elem.attrs
        assert "remember" not in elem.attrs
