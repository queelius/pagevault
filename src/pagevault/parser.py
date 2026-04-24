"""HTML parsing and transformation for pagevault.

Handles finding <pagevault> elements, extracting content,
and replacing with encrypted versions.
"""

import re
from datetime import datetime, timezone
from pathlib import Path

from bs4 import BeautifulSoup, NavigableString, Tag

from . import __version__
from .config import DefaultsConfig, PagevaultConfig, TemplateConfig
from .crypto import (
    PagevaultError,
    content_hash,
    decrypt,
    encrypt,
    pad_content,
    rewrap_keys,
)


def _parse_html(html: str) -> BeautifulSoup:
    """Parse HTML with lxml, falling back to html.parser.

    lxml is preferred for speed and accuracy; html.parser is always
    available as a fallback when lxml is not installed.
    """
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return BeautifulSoup(html, "html.parser")


def _set_wrapper_attrs(
    wrapper: Tag,
    hint: str | None,
    title: str | None,
    remember: str | None,
) -> None:
    """Apply optional hint/title/remember attributes to a wrapper tag."""
    if hint:
        wrapper["hint"] = hint
    if title:
        wrapper["title"] = title
    if remember:
        wrapper["remember"] = remember


def mark_elements(
    html: str,
    selectors: list[str],
    hint: str | None = None,
    remember: str | None = None,
    title: str | None = None,
) -> str:
    """Mark elements matching CSS selectors by wrapping in <pagevault> tags.

    Args:
        html: HTML content.
        selectors: List of CSS selectors to match.
        hint: Optional password hint.
        remember: Optional remember mode.
        title: Optional title for the encrypted region.

    Returns:
        Modified HTML with matched elements wrapped.
    """
    if not selectors:
        return html

    soup = _parse_html(html)

    for selector in selectors:
        for element in soup.select(selector):
            # Note: We intentionally allow wrapping pagevault elements.
            # This enables composable encryption - wrapping an already-encrypted
            # element creates a nested encryption layer (closure property).

            # Skip if already wrapped in a pagevault element
            # (prevents double-wrapping the same content in one pass)
            if element.parent and element.parent.name == "pagevault":
                continue

            wrapper = soup.new_tag("pagevault")
            _set_wrapper_attrs(wrapper, hint, title, remember)
            element.wrap(wrapper)

    return str(soup)


def mark_body(
    html: str,
    hint: str | None = None,
    remember: str | None = None,
    title: str | None = None,
) -> str:
    """Mark all body content for encryption by wrapping in a single <pagevault> element.

    Used as default when no --selector is provided.
    Preserves <head> and wraps all <body> children.

    Args:
        html: HTML content.
        hint: Optional password hint.
        remember: Optional remember mode.
        title: Optional title for the encrypted region.

    Returns:
        Modified HTML with body content wrapped, or unchanged if no body/empty body.
    """
    soup = _parse_html(html)

    body = soup.find("body")
    if not body:
        return html

    # Check for real content (not just whitespace)
    has_content = any(
        isinstance(child, Tag) or (isinstance(child, NavigableString) and child.strip())
        for child in body.children
    )

    if not has_content:
        return html

    wrapper = soup.new_tag("pagevault")
    _set_wrapper_attrs(wrapper, hint, title, remember)

    # Move all body children into the wrapper
    for child in list(body.children):
        child.extract()
        wrapper.append(child)

    body.append(wrapper)

    return str(soup)


def find_pagevault_elements(soup: BeautifulSoup) -> list[Tag]:
    """Find all <pagevault> elements in the document.

    Args:
        soup: Parsed HTML document.

    Returns:
        List of pagevault Tag elements.
    """
    return soup.find_all("pagevault")


def has_pagevault_elements(html: str) -> bool:
    """Quick check if HTML contains pagevault elements.

    Args:
        html: HTML string to check.

    Returns:
        True if pagevault elements are present.
    """
    # Quick regex check before full parse
    return bool(re.search(r"<pagevault[\s>]", html, re.IGNORECASE))


def extract_element_content(element: Tag) -> str:
    """Extract the inner HTML content of an element.

    Args:
        element: BeautifulSoup Tag element.

    Returns:
        Inner HTML as string.
    """
    # Get all inner content as string
    return "".join(str(child) for child in element.children)


def is_already_encrypted(element: Tag) -> bool:
    """Check if an element has already been encrypted.

    Args:
        element: pagevault Tag element.

    Returns:
        True if element has data-encrypted attribute.
    """
    return element.has_attr("data-encrypted")


def lock_html(
    html: str,
    password: str | None = None,
    config: PagevaultConfig | None = None,
    salt: bytes | None = None,
    custom_css: str | None = None,
    users: dict[str, str] | None = None,
    meta: dict | None = None,
    pad: bool = False,
) -> str:
    """Lock (encrypt) all <pagevault> regions in an HTML document.

    Args:
        html: The HTML document as a string.
        password: Password for encryption (single-user mode).
        config: Optional configuration for defaults.
        salt: Optional salt for consistent encryption.
        custom_css: Optional custom CSS to replace default styles.
        users: Dict of {username: password} for multi-user encryption.
        meta: Optional metadata dict to encrypt alongside content.

    Returns:
        Modified HTML with encrypted regions.

    Raises:
        PagevaultError: If encryption fails or HTML is invalid.
    """
    if not has_pagevault_elements(html):
        return html  # No changes needed

    soup = _parse_html(html)

    elements = find_pagevault_elements(soup)

    if not elements:
        return html

    # Auto-populate metadata if not provided
    if meta is None:
        meta = {
            "encrypted_at": datetime.now(timezone.utc).isoformat(),
            "version": __version__,
        }

    encrypted_any = False
    had_encrypted = False  # Tracks pre-existing encrypted elements (for runtime injection)

    for element in elements:
        # Skip already-encrypted elements — preserving their ciphertext.
        # Re-encrypting would overwrite with encrypt("") (the element's
        # inner content was cleared during the previous lock), silently
        # destroying the original payload. To compose encryption layers,
        # explicitly wrap with mark_elements first — that creates a new
        # outer <pagevault> whose inner content IS the encrypted element.
        if is_already_encrypted(element):
            had_encrypted = True
            continue

        # Extract attributes
        hint = element.get("hint") or element.get("data-hint")
        title = element.get("title") or element.get("data-title")
        remember = element.get("remember") or element.get("data-remember")

        # Use config defaults if not specified
        if config and remember is None:
            remember = config.defaults.remember

        # Extract and encrypt content
        inner_html = extract_element_content(element)

        # Compute content hash before encryption for integrity verification
        hash_value = content_hash(inner_html)

        # Apply content padding if requested (prevents size leakage)
        use_pad = pad or (config and config.pad)
        plaintext = pad_content(inner_html) if use_pad else inner_html

        encrypted_data = encrypt(
            plaintext, password=password, salt=salt, users=users, meta=meta
        )

        # Clear element content and set encrypted attributes
        element.clear()

        # Remove original attributes (only data- prefixed versions survive)
        for attr_name in ("hint", "title", "remember"):
            if attr_name in element.attrs:
                del element[attr_name]

        element["data-encrypted"] = encrypted_data
        element["data-content-hash"] = hash_value

        for attr_name, value in (
            ("hint", hint),
            ("title", title),
            ("remember", remember),
        ):
            if value:
                element[f"data-{attr_name}"] = value

        # Set data-mode when multi-user
        if users:
            element["data-mode"] = "user"

        encrypted_any = True

    # Inject the runtime if we encrypted something OR if we left
    # pre-existing encrypted elements in place — either way there
    # are elements on the page that need the runtime.
    if encrypted_any or had_encrypted:
        _inject_runtime(soup, config, custom_css)

    # If nothing changed, return original html (preserves exact formatting)
    if not encrypted_any:
        return html

    # Return modified HTML
    # Use formatter=None to preserve original formatting where possible
    return str(soup)


def unlock_html(
    html: str,
    password: str,
    username: str | None = None,
) -> str:
    """Unlock (decrypt) all encrypted <pagevault> regions in an HTML document.

    Args:
        html: The HTML document as a string.
        password: Password for decryption.
        username: Optional username for multi-user content.

    Returns:
        Modified HTML with decrypted regions.

    Raises:
        PagevaultError: If decryption fails or HTML is invalid.
    """
    if not has_pagevault_elements(html):
        return html

    soup = _parse_html(html)

    elements = find_pagevault_elements(soup)

    if not elements:
        return html

    decrypted_any = False

    for element in elements:
        if not is_already_encrypted(element):
            continue  # Skip unencrypted elements

        encrypted_data = element.get("data-encrypted")
        if not encrypted_data:
            continue

        # Check if multi-user file but no username provided
        if element.get("data-mode") == "user" and not username:
            raise PagevaultError(
                "This file uses multi-user encryption. "
                "Specify your username with -u USERNAME"
            )

        # Get expected content hash
        expected_hash = element.get("data-content-hash")

        # Decrypt content — returns (content, meta) tuple
        decrypted_content, _meta = decrypt(
            str(encrypted_data), password, username=username
        )

        # Strip null-byte padding (from --pad option during lock)
        decrypted_content = decrypted_content.rstrip("\x00")

        # Verify content hash if present
        if expected_hash:
            actual_hash = content_hash(decrypted_content)
            if actual_hash != expected_hash:
                raise PagevaultError(
                    "Content hash mismatch: decryption may be corrupted"
                )

        # Replace element content
        element.clear()

        # Parse decrypted content and insert
        # Use list() to avoid iterator invalidation when appending
        decrypted_soup = BeautifulSoup(decrypted_content, "html.parser")
        for child in list(decrypted_soup.children):
            element.append(child)

        # Remove internal attributes
        for attr in ("data-encrypted", "data-content-hash", "data-mode"):
            if attr in element.attrs:
                del element[attr]

        # Restore original attributes from their data-* counterparts
        for attr in ("hint", "title", "remember"):
            data_attr = f"data-{attr}"
            value = element.get(data_attr)
            if data_attr in element.attrs:
                del element[data_attr]
            if value:
                element[attr] = value

        decrypted_any = True

    if decrypted_any:
        # Remove injected runtime
        _remove_runtime(soup)

    return str(soup)


def sync_html_keys(
    html: str,
    old_password: str | None = None,
    old_username: str | None = None,
    old_users: dict[str, str] | None = None,
    new_users: dict[str, str] | None = None,
    new_password: str | None = None,
    rekey: bool = False,
) -> str:
    """Re-wrap keys for all encrypted elements in an HTML document.

    Args:
        html: The HTML document as a string.
        old_password: Old single password for CEK recovery.
        old_username: Username for old_password.
        old_users: Dict of old {username: password} pairs.
        new_users: New {username: password} dict for re-wrapping.
        new_password: New single password for re-wrapping.
        rekey: If True, generate new CEK and re-encrypt content.

    Returns:
        Modified HTML with re-wrapped keys.
    """
    if not has_pagevault_elements(html):
        return html

    soup = _parse_html(html)

    elements = find_pagevault_elements(soup)

    if not elements:
        return html

    modified = False

    for element in elements:
        if not is_already_encrypted(element):
            continue

        encrypted_data = element.get("data-encrypted")
        if not encrypted_data:
            continue

        new_data = rewrap_keys(
            str(encrypted_data),
            old_password=old_password,
            old_username=old_username,
            old_users=old_users,
            new_users=new_users,
            new_password=new_password,
            rekey=rekey,
        )

        element["data-encrypted"] = new_data

        # Update data-mode attribute
        if new_users:
            element["data-mode"] = "user"
        elif "data-mode" in element.attrs:
            del element["data-mode"]

        modified = True

    if not modified:
        return html

    return str(soup)


def _inject_runtime(
    soup: BeautifulSoup,
    config: PagevaultConfig | None = None,
    custom_css: str | None = None,
) -> None:
    """Inject pagevault JavaScript and CSS into the document head.

    Args:
        soup: Parsed HTML document.
        config: Optional configuration for template customization.
        custom_css: Optional custom CSS to replace default styles.
    """
    head = soup.find("head")
    if not head:
        # Create head if it doesn't exist
        html_tag = soup.find("html")
        if html_tag:
            head = soup.new_tag("head")
            html_tag.insert(0, head)
        else:
            # No html tag either, just return
            return

    # Check if already injected
    existing = head.find("script", {"data-pagevault-runtime": True})
    if existing:
        return

    # Get template config
    template = config.template if config else TemplateConfig()
    defaults = config.defaults if config else DefaultsConfig()

    # Determine CSS: custom_css > config.custom_css > default
    css_content = custom_css
    if css_content is None and config and config.custom_css:
        css_content = config.custom_css
    if css_content is None:
        css_content = _get_css(template)

    # Create style tag
    style_tag = soup.new_tag("style")
    style_tag["data-pagevault-runtime"] = "true"
    style_tag.string = css_content
    head.append(style_tag)

    # Create script tag
    script_tag = soup.new_tag("script")
    script_tag["data-pagevault-runtime"] = "true"
    script_tag.string = _get_javascript(template, defaults)
    head.append(script_tag)


def _remove_runtime(soup: BeautifulSoup) -> None:
    """Remove injected pagevault runtime from the document.

    Args:
        soup: Parsed HTML document.
    """
    for tag in soup.find_all(attrs={"data-pagevault-runtime": True}):
        tag.decompose()


def _get_css(template: TemplateConfig) -> str:
    """Generate CSS for the pagevault component."""
    return f"""
/* pagevault styles */

pagevault {{
  display: block;
}}

pagevault[data-encrypted] {{
  min-height: 200px;
  display: flex;
  align-items: center;
  justify-content: center;
}}

.pagevault-container {{
  text-align: center;
  padding: 2rem;
  border: 2px dashed #ccc;
  border-radius: 8px;
  background: #f9f9f9;
  max-width: 400px;
  margin: 2rem auto;
}}

.pagevault-icon {{
  font-size: 3rem;
  margin-bottom: 1rem;
}}

.pagevault-title {{
  font-size: 1.25rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
  color: #333;
}}

.pagevault-hint {{
  color: #666;
  font-size: 0.9rem;
  margin-bottom: 1rem;
}}

.pagevault-form {{
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}}

.pagevault-input {{
  padding: 0.75rem 1rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 1rem;
  outline: none;
  transition: border-color 0.2s;
}}

.pagevault-input:focus {{
  border-color: {template.color_primary};
}}

.pagevault-button {{
  padding: 0.75rem 1rem;
  background: linear-gradient(135deg, {template.color_primary}, {template.color_secondary});
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  cursor: pointer;
  transition: opacity 0.2s;
}}

.pagevault-button:hover {{
  opacity: 0.9;
}}

.pagevault-button:disabled {{
  opacity: 0.5;
  cursor: not-allowed;
}}

.pagevault-error {{
  color: #dc3545;
  font-size: 0.9rem;
  margin-top: 0.5rem;
}}

.pagevault-remember {{
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.9rem;
  color: #666;
}}

.pagevault-remember input {{
  margin: 0;
}}

/* Dark mode */
@media (prefers-color-scheme: dark) {{
  .pagevault-container {{ background: #1e1e2e; border-color: #444; }}
  .pagevault-title {{ color: #e0e0e0; }}
  .pagevault-hint {{ color: #999; }}
  .pagevault-input {{ background: #2a2a3a; border-color: #555; color: #e0e0e0; }}
  .pagevault-remember {{ color: #999; }}
}}
"""



def _get_javascript(template: TemplateConfig, defaults: DefaultsConfig) -> str:
    """Generate JavaScript for the pagevault Web Component."""
    from .runtime import build_region_js

    return build_region_js(template, defaults)


def process_file(
    input_path: Path,
    output_path: Path,
    password: str | None = None,
    config: PagevaultConfig | None = None,
    encrypt_mode: bool | None = None,
    mode: str | None = None,
    custom_css: str | None = None,
    users: dict[str, str] | None = None,
    username: str | None = None,
    meta: dict | None = None,
    pad: bool = False,
) -> bool:
    """Process a single HTML file.

    Args:
        input_path: Path to input HTML file.
        output_path: Path to write output file.
        password: Password for encryption/decryption.
        config: Optional configuration.
        encrypt_mode: Deprecated. Use mode instead. True for lock, False for unlock.
        mode: "lock" or "unlock". Takes precedence over encrypt_mode.
        custom_css: Optional custom CSS (overrides config.custom_css).
        users: Dict of {username: password} for multi-user encryption.
        username: Username for decryption in multi-user mode.
        meta: Optional metadata dict.

    Returns:
        True if file was modified, False if no changes needed.

    Raises:
        PagevaultError: If processing fails.
    """
    # Resolve mode: explicit `mode` wins, then legacy `encrypt_mode`, default = lock
    if mode is not None:
        do_lock = mode == "lock"
    elif encrypt_mode is not None:
        do_lock = encrypt_mode
    else:
        do_lock = True

    try:
        html = input_path.read_text(encoding="utf-8")
    except OSError as e:
        raise PagevaultError(f"Cannot read file {input_path}: {e}") from e

    if do_lock:
        processed = lock_html(
            html,
            password=password,
            config=config,
            salt=config.salt if config else None,
            custom_css=custom_css,
            users=users,
            meta=meta,
            pad=pad,
        )
    else:
        processed = unlock_html(html, password, username=username)

    if processed == html:
        return False

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        output_path.write_text(processed, encoding="utf-8")
    except OSError as e:
        raise PagevaultError(f"Cannot write file {output_path}: {e}") from e

    return True


# Backward-compatibility aliases (tested by test_parser.py)
encrypt_html = lock_html
decrypt_html = unlock_html
wrap_elements_for_encryption = mark_elements
wrap_body_for_encryption = mark_body
