"""HTML parsing and transformation for pagevault.

Handles finding <pagevault> elements, extracting content,
and replacing with encrypted versions.
"""

import re
from dataclasses import dataclass
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


@dataclass
class EncryptedRegion:
    """Represents an encrypted region in the HTML."""

    original_content: str
    encrypted_data: str
    hint: str | None
    remember: str | None


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

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    for selector in selectors:
        for element in soup.select(selector):
            # Note: We intentionally allow wrapping pagevault elements.
            # This enables composable encryption - wrapping an already-encrypted
            # element creates a nested encryption layer (closure property).

            # Skip if already wrapped in a pagevault element
            # (prevents double-wrapping the same content in one pass)
            if element.parent and element.parent.name == "pagevault":
                continue

            # Create wrapper element
            wrapper = soup.new_tag("pagevault")
            if hint:
                wrapper["hint"] = hint
            if title:
                wrapper["title"] = title
            if remember:
                wrapper["remember"] = remember

            # Wrap the element
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
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    body = soup.find("body")
    if not body:
        return html

    # Check for real content (not just whitespace)
    has_content = False
    for child in body.children:
        if isinstance(child, Tag):
            has_content = True
            break
        if isinstance(child, NavigableString) and child.strip():
            has_content = True
            break

    if not has_content:
        return html

    # Create wrapper element
    wrapper = soup.new_tag("pagevault")
    if hint:
        wrapper["hint"] = hint
    if title:
        wrapper["title"] = title
    if remember:
        wrapper["remember"] = remember

    # Move all body children into the wrapper
    children = list(body.children)
    for child in children:
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

    # Parse with lxml for better handling, fall back to html.parser
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

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

    for element in elements:
        # Note: We intentionally do NOT skip already-encrypted elements.
        # This enables composable encryption (closure property) - the output
        # of encrypt can be input to encrypt, allowing multi-password workflows.

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

        if hint:
            element["data-hint"] = hint

        if title:
            element["data-title"] = title

        if remember:
            element["data-remember"] = remember

        # Set data-mode when multi-user
        if users:
            element["data-mode"] = "user"

        encrypted_any = True

    if encrypted_any:
        # Inject the pagevault runtime into <head>
        _inject_runtime(soup, config, custom_css)

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

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

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

        # Preserve attributes for re-encryption
        hint = element.get("data-hint")
        title = element.get("data-title")
        remember = element.get("data-remember")

        # Replace element content
        element.clear()

        # Parse decrypted content and insert
        # Use list() to avoid iterator invalidation when appending
        decrypted_soup = BeautifulSoup(decrypted_content, "html.parser")
        for child in list(decrypted_soup.children):
            element.append(child)

        # Remove encrypted attributes, keep original ones
        del element["data-encrypted"]
        if "data-content-hash" in element.attrs:
            del element["data-content-hash"]
        if "data-mode" in element.attrs:
            del element["data-mode"]
        if "data-hint" in element.attrs:
            del element["data-hint"]
            if hint:
                element["hint"] = hint
        if "data-title" in element.attrs:
            del element["data-title"]
            if title:
                element["title"] = title
        if "data-remember" in element.attrs:
            del element["data-remember"]
            if remember:
                element["remember"] = remember

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

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

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
    return f"""
/* pagevault runtime v2 */
(function() {{
  'use strict';

  function escapeHtml(str) {{
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }}

  const STORAGE_KEY = 'pagevault_passwords';
  const CONFIG = {{
    title: {_js_string(template.title)},
    buttonText: {_js_string(template.button_text)},
    errorText: {_js_string(template.error_text)},
    placeholder: {_js_string(template.placeholder)},
    usernamePlaceholder: {_js_string(template.username_placeholder)},
    defaultRemember: {_js_string(defaults.remember)},
    rememberDays: {defaults.remember_days},
    autoPrompt: {str(defaults.auto_prompt).lower()}
  }};

  // Crypto utilities
  async function computeHash(content) {{
    // Compute truncated SHA-256 hash for integrity verification
    // Must match Python's content_hash() implementation
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    // Truncate to first 16 bytes (128 bits) to match Python implementation
    const hashArray = new Uint8Array(hashBuffer).slice(0, 16);
    return Array.from(hashArray, b => b.toString(16).padStart(2, '0')).join('');
  }}

  async function deriveKey(secret, salt) {{
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    return crypto.subtle.deriveKey(
      {{
        name: 'PBKDF2',
        salt: salt,
        iterations: 310000,
        hash: 'SHA-256'
      }},
      keyMaterial,
      {{ name: 'AES-GCM', length: 256 }},
      false,
      ['decrypt']
    );
  }}

  async function decryptContent(encryptedBase64, password, username) {{
    try {{
      // Decode outer base64
      const jsonStr = atob(encryptedBase64);
      const data = JSON.parse(jsonStr);

      // Validate version
      if (data.v !== 2) throw new Error('Unsupported version: ' + data.v);

      // Decode components
      const salt = Uint8Array.from(atob(data.salt), c => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(data.iv), c => c.charCodeAt(0));
      const ct = Uint8Array.from(atob(data.ct), c => c.charCodeAt(0));

      // Build secret: "username:password" or just "password"
      const secret = username ? username + ':' + password : password;

      // ONE PBKDF2 derivation with shared salt
      const wrappingKey = await deriveKey(secret, salt);

      // Try each key blob to recover CEK
      let cek = null;
      for (const keyBlob of data.keys) {{
        const blobIv = Uint8Array.from(atob(keyBlob.iv), c => c.charCodeAt(0));
        const blobCt = Uint8Array.from(atob(keyBlob.ct), c => c.charCodeAt(0));
        try {{
          const rawCek = await crypto.subtle.decrypt(
            {{ name: 'AES-GCM', iv: blobIv }},
            wrappingKey,
            blobCt
          );
          cek = rawCek;
          break;
        }} catch (e) {{
          // Wrong key blob, try next
          continue;
        }}
      }}

      if (!cek) throw new Error('No matching key found');

      // Import recovered CEK
      const cekKey = await crypto.subtle.importKey(
        'raw',
        cek,
        {{ name: 'AES-GCM', length: 256 }},
        false,
        ['decrypt']
      );

      // Decrypt content with CEK
      const decrypted = await crypto.subtle.decrypt(
        {{ name: 'AES-GCM', iv: iv }},
        cekKey,
        ct
      );

      // Parse inner JSON wrapper
      const inner = JSON.parse(new TextDecoder().decode(decrypted));
      return {{ content: inner.c, meta: inner.m || null }};
    }} catch (e) {{
      console.error('Decryption failed:', e);
      return null;
    }}
  }}

  // Storage utilities
  function getStoredPasswords() {{
    try {{
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored) return {{}};
      const data = JSON.parse(stored);
      // Check expiration
      const now = Date.now();
      const filtered = {{}};
      for (const [key, value] of Object.entries(data)) {{
        if (!value.expires || value.expires > now) {{
          filtered[key] = value;
        }}
      }}
      return filtered;
    }} catch {{
      return {{}};
    }}
  }}

  function storeCredentials(password, username, remember) {{
    if (remember === 'none') return;
    const cred = username ? {{ username, password }} : {{ password }};
    if (remember === 'session') {{
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(cred));
      return;
    }}
    const data = getStoredPasswords();
    const expires = CONFIG.rememberDays > 0
      ? Date.now() + (CONFIG.rememberDays * 24 * 60 * 60 * 1000)
      : null;
    data[location.origin] = {{ ...cred, expires }};
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  }}

  function getStoredCredentials() {{
    // Check session first
    const session = sessionStorage.getItem(STORAGE_KEY);
    if (session) {{
      try {{
        const cred = JSON.parse(session);
        return cred.password ? cred : {{ password: session }};
      }} catch {{
        return {{ password: session }};
      }}
    }}
    // Check localStorage
    const data = getStoredPasswords();
    const entry = data[location.origin];
    if (!entry) return null;
    return entry.password ? entry : null;
  }}

  function clearStoredPasswords() {{
    localStorage.removeItem(STORAGE_KEY);
    sessionStorage.removeItem(STORAGE_KEY);
  }}

  // URL fragment handling (only logout — password via URL removed for security)
  function checkFragment() {{
    const hash = location.hash.slice(1);
    if (!hash) return null;

    if (hash === 'pagevault_logout') {{
      clearStoredPasswords();
      // Navigate without the hash — works on file:// unlike history.replaceState
      location.replace(location.pathname + location.search);
      return 'logout';
    }}

    return null;
  }}

  // Element handler — uses a plain class instead of Custom Elements because
  // the spec requires hyphenated names and <pagevault> has no hyphen.
  // All values set via innerHTML are either:
  //   - escapeHtml()-wrapped user strings (hint, title, placeholder, button text)
  //   - static HTML template literals (form structure, lock icon)
  //   - decrypted content from AES-256-GCM (trusted after authenticated decryption)
  class PagevaultHandler {{
    constructor(el) {{
      this.el = el;
      this.el._pvDecrypted = false;
      this._render();
      this._tryAutoDecrypt();
    }}

    _render() {{
      const el = this.el;
      const hint = el.getAttribute('data-hint');
      const title = el.getAttribute('data-title') || CONFIG.title;
      const remember = el.getAttribute('data-remember') || CONFIG.defaultRemember;
      const isUserMode = el.getAttribute('data-mode') === 'user';

      el.innerHTML = `
        <div class="pagevault-container">
          <div class="pagevault-icon">\U0001f512</div>
          <div class="pagevault-title">${{escapeHtml(title)}}</div>
          ${{hint ? `<div class="pagevault-hint">${{escapeHtml(hint)}}</div>` : ''}}
          <form class="pagevault-form">
            ${{isUserMode ? `<input type="text" class="pagevault-input pagevault-username" placeholder="${{escapeHtml(CONFIG.usernamePlaceholder)}}" autocomplete="username">` : ''}}
            <input type="password" class="pagevault-input" placeholder="${{escapeHtml(CONFIG.placeholder)}}" autocomplete="current-password">
            ${{remember === 'ask' ? `
              <label class="pagevault-remember">
                <input type="checkbox" name="remember">
                Remember on this device
              </label>
            ` : ''}}
            <button type="submit" class="pagevault-button">${{escapeHtml(CONFIG.buttonText)}}</button>
            <div class="pagevault-error" style="display: none;"></div>
          </form>
        </div>
      `;

      const form = el.querySelector('form');
      const passwordInput = el.querySelector('input[type="password"]');
      const usernameInput = el.querySelector('.pagevault-username');
      const error = el.querySelector('.pagevault-error');

      form.addEventListener('submit', async (e) => {{
        e.preventDefault();
        const password = passwordInput.value;
        if (!password) return;
        const username = usernameInput ? usernameInput.value : null;

        // Capture checkbox state BEFORE decryption replaces innerHTML
        const rememberCheckbox = el.querySelector('input[name="remember"]');
        const wantsRemember = remember === 'local' || (rememberCheckbox && rememberCheckbox.checked);

        const button = el.querySelector('button');
        button.disabled = true;
        button.textContent = 'Decrypting...';

        const success = await this._decrypt(password, username);

        if (!success) {{
          error.textContent = CONFIG.errorText;
          error.style.display = 'block';
          button.disabled = false;
          button.textContent = CONFIG.buttonText;
          passwordInput.value = '';
          passwordInput.focus();
        }} else {{
          // Store credentials if requested
          if (wantsRemember) {{
            storeCredentials(password, username, 'local');
          }} else if (remember === 'session') {{
            storeCredentials(password, username, 'session');
          }}
        }}
      }});

      // Focus appropriate input if auto-prompt
      if (CONFIG.autoPrompt) {{
        const focusTarget = usernameInput || passwordInput;
        setTimeout(() => focusTarget.focus(), 100);
      }}
    }}

    async _tryAutoDecrypt() {{
      // Check URL fragment (only logout supported)
      const fragment = checkFragment();
      if (fragment === 'logout') return;

      // Try stored credentials
      const cred = getStoredCredentials();
      if (cred) {{
        await this._decrypt(cred.password, cred.username || null);
      }}
    }}

    async _decrypt(password, username) {{
      const el = this.el;
      const encrypted = el.getAttribute('data-encrypted');
      if (!encrypted) return false;

      const expectedHash = el.getAttribute('data-content-hash');

      const result = await decryptContent(encrypted, password, username);
      if (result === null) return false;

      // Strip null-byte padding (from --pad option during lock)
      const content = result.content.replace(/\0+$/, '');
      const meta = result.meta;

      // Verify content hash if present
      if (expectedHash) {{
        const actualHash = await computeHash(content);
        if (actualHash !== expectedHash) {{
          console.error('Content hash mismatch - decryption may be corrupted');
          return false;
        }}
      }}

      // Remove encrypted attributes and reveal content
      el.removeAttribute('data-encrypted');
      el.removeAttribute('data-content-hash');
      el.removeAttribute('data-mode');
      // Decrypted content is trusted — it was authenticated by AES-256-GCM
      // (user encrypted their own content; AES-GCM provides authenticity)
      el.innerHTML = content;
      el._pvDecrypted = true;

      // === Script activation after decryption ===
      // innerHTML doesn't execute <script> tags (HTML5 spec).
      // Re-create each script so the browser executes it.
      // Safe: content was authenticated by AES-256-GCM decryption.

      // Neutralize document.write/writeln — they would destroy the page
      // after DOMContentLoaded (safe: we restore them after activation)
      var origWrite = document.write;
      var origWriteln = document.writeln;
      document.write = function() {{}};
      document.writeln = function() {{}};

      // Shim DOMContentLoaded — already fired, collect callbacks
      var dcl = document.addEventListener;
      var dclCallbacks = [];
      document.addEventListener = function(type, fn, opts) {{
        if (type === 'DOMContentLoaded') dclCallbacks.push(fn);
        else dcl.call(document, type, fn, opts);
      }};

      // Shim window load event — already fired, collect callbacks
      var wal = window.addEventListener;
      var wlCallbacks = [];
      window.addEventListener = function(type, fn, opts) {{
        if (type === 'load') wlCallbacks.push(fn);
        else wal.call(window, type, fn, opts);
      }};

      // Only re-execute scripts meant to run (not JSON data blocks)
      function isExecutable(s) {{
        var t = (s.getAttribute('type') || '').toLowerCase();
        if (!t || t === 'text/javascript' || t === 'application/javascript' || t === 'module') return true;
        return false;
      }}

      var scripts = Array.from(el.querySelectorAll('script'));

      // Activate sequentially — external scripts must load before next runs
      function activateNext(i) {{
        if (i >= scripts.length) {{
          // Restore originals
          document.addEventListener = dcl;
          window.addEventListener = wal;
          document.write = origWrite;
          document.writeln = origWriteln;
          // Fire collected lifecycle callbacks
          dclCallbacks.forEach(function(fn) {{
            try {{ fn(); }} catch(e) {{ console.error('[pagevault] DOMContentLoaded callback error:', e); }}
          }});
          wlCallbacks.forEach(function(fn) {{
            try {{ fn(); }} catch(e) {{ console.error('[pagevault] load callback error:', e); }}
          }});
          if (typeof window.onload === 'function') {{
            try {{ window.onload(); }} catch(e) {{ console.error('[pagevault] onload error:', e); }}
          }}
          el.dispatchEvent(new CustomEvent('pagevault:decrypted', {{
            bubbles: true,
            detail: {{ element: el, meta: meta }}
          }}));
          return;
        }}
        var old = scripts[i];
        if (!isExecutable(old)) {{ activateNext(i + 1); return; }}
        var s = document.createElement('script');
        for (var j = 0; j < old.attributes.length; j++) {{
          var a = old.attributes[j];
          if (a.name === 'type' && a.value.toLowerCase() === 'module' && !old.src) continue;
          s.setAttribute(a.name, a.value);
        }}
        var hasSrc = old.hasAttribute('src');
        if (!hasSrc && old.textContent) s.textContent = old.textContent;
        if (hasSrc) {{
          s.onload = function() {{ activateNext(i + 1); }};
          s.onerror = function() {{ console.error('[pagevault] Failed to load:', old.src); activateNext(i + 1); }};
        }}
        old.parentNode.replaceChild(s, old);
        if (!hasSrc) activateNext(i + 1);
      }}
      activateNext(0);

      return true;
    }}
  }}

  // Initialize all encrypted <pagevault> elements.
  // Wrapped in DOMContentLoaded since the script is in <head> but the
  // elements are in <body> — they don't exist yet at script parse time.
  function initAll() {{
    document.querySelectorAll('pagevault[data-encrypted]').forEach(function(el) {{
      if (!el._pvHandler) {{
        el._pvHandler = new PagevaultHandler(el);
      }}
    }});
  }}
  if (document.readyState === 'loading') {{
    document.addEventListener('DOMContentLoaded', initAll);
  }} else {{
    initAll();
  }}
}})();
"""


def _js_string(s: str) -> str:
    """Escape a string for JavaScript."""
    return (
        '"'
        + s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("</", "<\\/")
        + '"'
    )


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
    # Resolve mode from either parameter
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
        salt = config.salt if config else None
        processed = lock_html(
            html,
            password=password,
            config=config,
            salt=salt,
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


# Backward-compatibility aliases
encrypt_html = lock_html
decrypt_html = unlock_html
wrap_elements_for_encryption = mark_elements
wrap_body_for_encryption = mark_body
# Alias for old function names
find_lockhtml_elements = find_pagevault_elements
has_lockhtml_elements = has_pagevault_elements
