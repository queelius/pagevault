"""Universal encrypted payload generation for pagevault.

Wraps arbitrary files and directories into self-contained encrypted HTML
that can be decrypted and rendered in the browser.
"""

import logging
import mimetypes
import re
import zipfile
from io import BytesIO
from pathlib import Path

from .config import PagevaultConfig
from .crypto import (
    PagevaultError,
    content_hash_bytes,
    encrypt_chunked,
    pad_content_bytes,
)
from .viewers import discover_viewers, resolve_viewer

logger = logging.getLogger(__name__)

# Defense-in-depth: re-validate viewer names before JS injection even though
# ViewerPlugin.__init_subclass__ already checks at class definition time.
_SAFE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_SAFE_MIME_RE = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_.+]*/(\*|[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_.+]*)$"
)

# MIME type detection
MIME_OVERRIDES = {
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
}


def detect_mime(path: Path) -> str:
    """Detect MIME type of a file.

    Args:
        path: Path to the file.

    Returns:
        MIME type string.
    """
    suffix = path.suffix.lower()
    if suffix in MIME_OVERRIDES:
        return MIME_OVERRIDES[suffix]

    mime, _ = mimetypes.guess_type(str(path))
    return mime or "application/octet-stream"


def wrap_file(
    file_path: Path,
    password: str | None = None,
    config: PagevaultConfig | None = None,
    output_path: Path | None = None,
    users: dict[str, str] | None = None,
    pad: bool = False,
) -> Path:
    """Wrap a single file into a self-contained encrypted HTML.

    Args:
        file_path: Path to the file to wrap.
        password: Encryption password.
        config: Optional configuration.
        output_path: Output HTML path. Defaults to <filename>.html.
        users: Dict of {username: password} for multi-user.

    Returns:
        Path to the generated HTML file.

    Raises:
        PagevaultError: If file cannot be read or encryption fails.
    """
    file_path = Path(file_path)
    if not file_path.is_file():
        raise PagevaultError(f"File not found: {file_path}")

    # Read file bytes
    try:
        file_bytes = file_path.read_bytes()
    except OSError as e:
        raise PagevaultError(f"Cannot read file {file_path}: {e}") from e

    # Detect MIME type
    mime = detect_mime(file_path)

    # Build metadata
    meta = {
        "type": "file",
        "filename": file_path.name,
        "mime": mime,
        "size": len(file_bytes),
    }

    # Get salt from config
    salt = config.salt if config else None

    # Compute content hash for integrity (before padding, on raw bytes)
    hash_value = content_hash_bytes(file_bytes)

    # Apply content padding if requested (pad raw bytes)
    use_pad = pad or (config and config.pad)
    data_to_encrypt = pad_content_bytes(file_bytes) if use_pad else file_bytes

    # Encrypt using v3 chunked format (raw bytes, no base64 layer)
    envelope, chunks = encrypt_chunked(
        data_to_encrypt,
        password=password,
        salt=salt,
        users=users,
        meta=meta,
    )

    # Add content hash to envelope for integrity verification
    envelope["content_hash"] = hash_value

    # Determine output path
    if output_path is None:
        output_path = file_path.with_suffix(".html")

    # Discover active viewers and resolve dependencies for this file type
    viewers = discover_viewers(config)
    _log_active_viewers(viewers)
    matching_viewer = resolve_viewer(mime, viewers)
    viewer_deps = matching_viewer.dependencies() if matching_viewer else []

    # Generate v3 HTML
    html = _generate_wrap_html_v3(
        envelope=envelope,
        chunks=chunks,
        title=f"Protected: {file_path.name}",
        viewers=viewers,
        viewer_deps=viewer_deps,
        config=config,
        users=users,
    )

    # Write output
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_text(html, encoding="utf-8")
    except OSError as e:
        raise PagevaultError(f"Cannot write output {output_path}: {e}") from e

    return output_path


def wrap_site(
    dir_path: Path,
    password: str | None = None,
    config: PagevaultConfig | None = None,
    output_path: Path | None = None,
    users: dict[str, str] | None = None,
    entry: str = "index.html",
    pad: bool = False,
) -> Path:
    """Wrap a directory into a self-contained encrypted HTML.

    Args:
        dir_path: Path to the directory to wrap.
        password: Encryption password.
        config: Optional configuration.
        output_path: Output HTML path. Defaults to <dirname>.html.
        users: Dict of {username: password} for multi-user.
        entry: Entry point HTML file within the directory.

    Returns:
        Path to the generated HTML file.

    Raises:
        PagevaultError: If directory cannot be read or encryption fails.
    """
    dir_path = Path(dir_path)
    if not dir_path.is_dir():
        raise PagevaultError(f"Directory not found: {dir_path}")

    # Zip the directory
    zip_buffer = BytesIO()
    file_list = []

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(dir_path.rglob("*")):
            if file_path.is_file():
                rel = file_path.relative_to(dir_path)
                rel_str = str(rel).replace("\\", "/")  # Normalize to forward slashes
                file_list.append(rel_str)
                zf.write(file_path, rel_str)

    if not file_list:
        raise PagevaultError(f"Directory is empty: {dir_path}")

    # Verify entry point exists
    if entry not in file_list:
        raise PagevaultError(
            f"Entry point '{entry}' not found in directory. "
            f"Available files: {', '.join(file_list[:10])}"
        )

    zip_bytes = zip_buffer.getvalue()

    # Build metadata
    meta = {
        "type": "site",
        "entry": entry,
        "files": file_list,
    }

    # Get salt from config
    salt = config.salt if config else None

    # Compute content hash on raw bytes (before padding)
    hash_value = content_hash_bytes(zip_bytes)

    # Apply content padding if requested (pad raw bytes)
    use_pad = pad or (config and config.pad)
    data_to_encrypt = pad_content_bytes(zip_bytes) if use_pad else zip_bytes

    # Encrypt using v3 chunked format (raw bytes, no base64 layer)
    envelope, chunks = encrypt_chunked(
        data_to_encrypt,
        password=password,
        salt=salt,
        users=users,
        meta=meta,
    )

    # Add content hash to envelope for integrity verification
    envelope["content_hash"] = hash_value

    # Determine output path
    if output_path is None:
        output_path = dir_path.parent / f"{dir_path.name}.html"

    # Generate v3 HTML.
    # Site mode uses its own renderer (__pagevault_renderSite) that handles
    # all file types via data URIs inside the site iframe. Individual file
    # viewers are not needed — the site's own HTML/CSS/JS runs inside the
    # sandboxed iframe. Passing viewers=[] produces an empty dispatch table,
    # which is intentional: renderFile is only reached for non-site payloads.
    html = _generate_wrap_html_v3(
        envelope=envelope,
        chunks=chunks,
        title=f"Protected: {dir_path.name}",
        config=config,
        users=users,
        include_jszip=True,
        entry=entry,
    )

    # Write output
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_text(html, encoding="utf-8")
    except OSError as e:
        raise PagevaultError(f"Cannot write output {output_path}: {e}") from e

    return output_path


def _log_active_viewers(viewers: list) -> None:
    """Log active viewer plugins at INFO level for auditability."""
    if not viewers:
        return
    for viewer in viewers:
        source = type(viewer).__module__.rsplit(".", 1)[0]
        logger.info(
            "Active viewer: %s (%s) [%s]",
            viewer.name,
            ", ".join(viewer.mime_types),
            source,
        )



def _html_escape(s: str) -> str:
    """Escape a string for HTML attribute values."""
    return (
        s.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _get_wrap_css(template) -> str:
    """Generate framework CSS for the wrap password prompt and viewer chrome.

    Viewer-specific CSS (image zoom, text line numbers, markdown styles)
    is provided by each ViewerPlugin.css() method and composed separately.
    """
    return f"""
/* pagevault wrap styles */
:root {{
  --pv-color-primary: {template.color_primary};
  --pv-color-secondary: {template.color_secondary};
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}

pagevault {{
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
}}

pagevault[data-decrypted] {{
  display: block;
  min-height: auto;
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

.pagevault-icon {{ font-size: 3rem; margin-bottom: 1rem; }}
.pagevault-title {{ font-size: 1.25rem; font-weight: 600; margin-bottom: 0.5rem; color: #333; }}
.pagevault-hint {{ color: #666; font-size: 0.9rem; margin-bottom: 1rem; }}
.pagevault-filename {{ color: #999; font-size: 0.8rem; margin-bottom: 1rem; font-family: monospace; }}

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
.pagevault-input:focus {{ border-color: {template.color_primary}; }}

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
.pagevault-button:hover {{ opacity: 0.9; }}
.pagevault-button:disabled {{ opacity: 0.5; cursor: not-allowed; }}
.pagevault-error {{ color: #dc3545; font-size: 0.9rem; margin-top: 0.5rem; }}

/* Toolbar */
.pagevault-toolbar {{
  position: sticky;
  top: 0;
  z-index: 100;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 1rem;
  background: #f8f8f8;
  border-bottom: 1px solid #ddd;
  font-size: 0.85rem;
}}
.toolbar-filename {{
  font-family: 'Consolas', 'Monaco', monospace;
  font-weight: 600;
  color: #333;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}
.toolbar-size {{ color: #888; white-space: nowrap; }}
.toolbar-btn {{
  margin-left: auto;
  padding: 0.3rem 0.75rem;
  background: {template.color_primary};
  color: white;
  text-decoration: none;
  border: none;
  border-radius: 3px;
  font-size: 0.8rem;
  cursor: pointer;
  white-space: nowrap;
}}
.toolbar-btn:hover {{ opacity: 0.85; }}
.toolbar-btn.active {{ background: #555; }}
.toolbar-toggle {{ margin-left: 0; }}

/* Viewer base */
.pagevault-viewer {{ width: 100%; }}
.pagevault-viewer iframe {{ width: 100%; height: calc(100vh - 40px); border: none; }}
.pagevault-viewer pre {{
  margin: 0;
  white-space: pre-wrap;
  word-wrap: break-word;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 0.9rem;
  line-height: 1.6;
}}

/* Download view */
.pagevault-download {{
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 50vh;
  gap: 1rem;
}}
.pagevault-download a {{
  display: inline-block;
  padding: 1rem 2rem;
  background: {template.color_primary};
  color: white;
  text-decoration: none;
  border-radius: 4px;
  font-size: 1.1rem;
}}
.pagevault-download a:hover {{ opacity: 0.9; }}
.pagevault-download .file-info {{ color: #666; font-size: 0.9rem; }}

/* Site viewer */
.pagevault-site-frame {{ width: 100%; height: 100vh; border: none; }}

/* Dark mode */
@media (prefers-color-scheme: dark) {{
  body {{ background: #1a1a2a; color: #e0e0e0; }}
  .pagevault-container {{ background: #1e1e2e; border-color: #444; }}
  .pagevault-title {{ color: #e0e0e0; }}
  .pagevault-hint {{ color: #999; }}
  .pagevault-filename {{ color: #777; }}
  .pagevault-input {{ background: #2a2a3a; border-color: #555; color: #e0e0e0; }}
  .pagevault-toolbar {{ background: #252535; border-bottom-color: #444; }}
  .toolbar-filename {{ color: #e0e0e0; }}
  .toolbar-size {{ color: #999; }}
  .pagevault-download .file-info {{ color: #999; }}
}}
"""



def _escape_for_script_block(s: str) -> str:
    """Escape content for safe embedding inside a <script> or <style> block.

    Replaces ``</`` with ``<\\/`` to prevent premature closing of the
    enclosing HTML tag. This is the same defense used by _js_string()
    in parser.py — see MEMORY.md "Script-tag breakout" entry.
    """
    return s.replace("</", "<\\/")


def _build_viewer_dispatch(viewers: list) -> tuple[str, str]:
    """Build JS viewer variable definitions and dispatch table entries.

    Validates each viewer's name and MIME types against strict regexes
    (defense-in-depth), escapes JS output to prevent ``</script>`` breakout,
    and returns the two JS code fragments needed by renderer IIFEs.

    Args:
        viewers: Active ViewerPlugin instances.

    Returns:
        Tuple of (viewer_defs, dispatch_table) as JS code strings.
    """
    viewer_defs_parts: list[str] = []
    dispatch_entries: list[str] = []

    for viewer in viewers:
        if not _SAFE_NAME_RE.match(viewer.name):
            logger.warning("Skipping viewer with unsafe name: %r", viewer.name)
            continue
        # for/else: else runs only if no break (all MIME types passed)
        for mt in viewer.mime_types:
            if not _SAFE_MIME_RE.match(mt):
                logger.warning(
                    "Skipping viewer %r: unsafe MIME type %r",
                    viewer.name,
                    mt,
                )
                break
        else:
            var_name = "__pv_" + viewer.name
            safe_js = _escape_for_script_block(viewer.js())
            viewer_defs_parts.append("  var " + var_name + " = " + safe_js + ";")
            for mime_type in viewer.mime_types:
                dispatch_entries.append("    '" + mime_type + "': " + var_name)

    return "\n\n".join(viewer_defs_parts), ",\n".join(dispatch_entries)



def _get_progress_css() -> str:
    """Generate CSS for the v3 chunk-decryption progress bar."""
    return """
/* pagevault progress bar */
.pagevault-progress {
  width: 100%;
  background: #e2e8f0;
  border-radius: 8px;
  overflow: hidden;
  margin: 1rem 0;
  height: 24px;
}
.pagevault-progress-bar {
  height: 100%;
  background: var(--pv-color-primary, #4a6fa5);
  transition: width 0.2s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-size: 0.75rem;
  font-weight: 600;
  white-space: nowrap;
}

/* Dark mode */
@media (prefers-color-scheme: dark) {
  .pagevault-progress { background: #2a2a3a; }
}
"""


def _generate_wrap_html_v3(  # noqa: E501
    envelope: dict,
    chunks: list[str],
    title: str,
    viewers: list | None = None,
    viewer_deps: list[str] | None = None,
    config: PagevaultConfig | None = None,
    users: dict[str, str] | None = None,
    include_jszip: bool = False,
    entry: str | None = None,
) -> str:
    """Generate self-contained HTML with v3 chunked encrypted payload.

    Instead of a single ``data-encrypted`` attribute, v3 stores the
    envelope as JSON in a ``<script id="pv-meta">`` tag and each
    encrypted chunk in its own ``<script id="pv-N" type="x-pv">`` tag.
    This avoids the HTML attribute size limit for large payloads and
    allows the browser to free each chunk element after decryption.

    Args:
        envelope: JSON-serializable envelope dict (v, chunk_count, keys, salt, etc.).
        chunks: List of base64-encoded encrypted chunk strings.
        title: HTML page title.
        viewers: Active ViewerPlugin instances for the dispatch table.
        viewer_deps: JS dependency contents to bundle (from matching viewer).
        config: Optional configuration.
        users: Multi-user dict (affects data-mode attribute).
        include_jszip: Whether to include JSZip library for site mode.
        entry: Entry point for site mode.

    Returns:
        Complete HTML string.
    """
    import json as _json

    from .config import TemplateConfig

    template = config.template if config else TemplateConfig()

    # Serialize envelope as JSON for the meta script tag
    envelope_json = _json.dumps(envelope)

    # Build chunk script tags
    chunk_tags = "\n".join(
        f'<script id="pv-{i}" type="x-pv">{chunk}</script>'
        for i, chunk in enumerate(chunks)
    )

    # Build pagevault element attributes
    pv_attrs = ['data-pv-chunked="true"']
    if users:
        pv_attrs.append('data-mode="user"')
    pv_attrs_str = " ".join(pv_attrs)

    # Compose CSS: framework + active viewer styles + progress bar.
    # Viewer CSS is escaped to prevent </style> breakout.
    framework_css = _get_wrap_css(template)
    viewer_css = "\n".join(
        _escape_for_script_block(v.css()) for v in (viewers or []) if v.css()
    )
    progress_css = _get_progress_css()
    css = framework_css + viewer_css + progress_css

    crypto_js = _get_crypto_js_v3()
    renderer_js = _get_renderer_js_v3(viewers or [])

    jszip_block = ""
    site_js = ""
    if include_jszip:
        jszip_block = f"\n<script data-pagevault-runtime>{_get_jszip_shim()}</script>"
        site_js = _get_site_renderer_js()

    # Include viewer dependencies (e.g. marked.js for markdown).
    # Dependencies are escaped to prevent </script> breakout.
    dep_blocks = "".join(
        f"\n<script data-pagevault-runtime>{_escape_for_script_block(dep)}</script>"
        for dep in (viewer_deps or [])
    )

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_html_escape(title)}</title>
  <style data-pagevault-runtime>{css}</style>
</head>
<body>
<script id="pv-meta" type="application/json">{envelope_json}</script>
{chunk_tags}
  <pagevault {pv_attrs_str}></pagevault>{jszip_block}{dep_blocks}
  <script data-pagevault-runtime>
{crypto_js}

{renderer_js}

{site_js}
  </script>
</body>
</html>"""


def _get_crypto_js_v3() -> str:  # noqa: E501
    """Generate the v3 chunked crypto JS for wrap payloads.

    Key differences from v2 ``_get_crypto_js()``:
    - Salt is hex-encoded (not base64).
    - CEK is unwrapped from the envelope's ``keys`` array.
    - Metadata is encrypted separately (``meta_iv`` / ``meta_ct``).
    - Chunks use per-chunk IVs derived from ``iv_base`` XOR'd with chunk index.
    - Each chunk's DOM element is removed after reading to free memory.
    - Returns ``{blob, meta}`` (raw Blob) instead of ``{content, meta}`` (base64 string).
    """
    return """
// pagevault v3 chunked crypto runtime
(function() {
  'use strict';

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  function b64ToBytes(b64) {
    const raw = atob(b64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes;
  }

  function deriveChunkIv(ivBase, chunkIndex) {
    const iv = new Uint8Array(ivBase);
    iv[8]  ^= (chunkIndex >>> 24) & 0xFF;
    iv[9]  ^= (chunkIndex >>> 16) & 0xFF;
    iv[10] ^= (chunkIndex >>> 8)  & 0xFF;
    iv[11] ^=  chunkIndex         & 0xFF;
    return iv;
  }

  async function deriveKey(secret, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(secret), 'PBKDF2', false, ['deriveBits', 'deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: 310000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  async function decryptV3Chunked(envelope, password, username, onProgress) {
    try {
      const salt = hexToBytes(envelope.salt);
      const secret = username ? username + ':' + password : password;
      const wrappingKey = await deriveKey(secret, salt);

      // Unwrap CEK — try each key blob until one succeeds
      let cekRaw = null;
      for (const keyBlob of envelope.keys) {
        const blobIv = b64ToBytes(keyBlob.iv);
        const blobCt = b64ToBytes(keyBlob.ct);
        try {
          cekRaw = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: blobIv }, wrappingKey, blobCt
          );
          break;
        } catch (e) { continue; }
      }
      if (!cekRaw) throw new Error('No matching key found \\u2014 wrong password?');

      const cek = await crypto.subtle.importKey(
        'raw', cekRaw, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
      );

      // Decrypt metadata
      const metaIv = b64ToBytes(envelope.meta_iv);
      const metaCt = b64ToBytes(envelope.meta_ct);
      const metaPlain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: metaIv }, cek, metaCt
      );
      const meta = JSON.parse(new TextDecoder().decode(metaPlain));

      // Decrypt chunks — read each DOM element, then remove it to free memory
      const ivBase = b64ToBytes(envelope.iv_base);
      const parts = [];
      for (let i = 0; i < envelope.chunk_count; i++) {
        const el = document.getElementById('pv-' + i);
        if (!el) throw new Error('Missing chunk element pv-' + i);
        const b64 = el.textContent;
        el.remove();
        const ct = b64ToBytes(b64);
        const chunkIv = deriveChunkIv(ivBase, i);
        const plain = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: chunkIv }, cek, ct
        );
        parts.push(new Uint8Array(plain));
        if (onProgress) onProgress(i + 1, envelope.chunk_count);
      }

      const blob = new Blob(parts, { type: meta.mime || 'application/octet-stream' });
      return { blob: blob, meta: meta };
    } catch (e) {
      console.error('v3 decryption failed:', e);
      return null;
    }
  }

  window.__pagevault = window.__pagevault || {};
  window.__pagevault.decryptV3Chunked = decryptV3Chunked;
})();"""


def _get_renderer_js_v3(viewers: list) -> str:  # noqa: E501
    """Generate the v3 file renderer JS with viewer dispatch table and progress bar.

    Reads the envelope from ``<script id="pv-meta">``, uses
    ``decryptV3Chunked`` (from ``_get_crypto_js_v3``), and shows a
    progress bar during chunk decryption. After decryption, dispatches
    to the appropriate viewer or download fallback.

    Security notes:
    - Self-contained IIFE with its own ``escapeHtml()`` (can't share between IIFEs).
    - Viewer name/MIME: validated against strict regex before injection into JS.
    - Viewer js() output: escaped via ``_escape_for_script_block()`` to prevent
      ``</script>`` breakout.
    """
    viewer_defs, dispatch_table = _build_viewer_dispatch(viewers)

    return f"""
// pagevault v3 chunked renderer
(function() {{
  'use strict';

  var pvEl = document.querySelector('pagevault[data-pv-chunked]');
  if (!pvEl) return;

  var isUserMode = pvEl.getAttribute('data-mode') === 'user';

  // Read envelope from pv-meta script tag
  var metaScript = document.getElementById('pv-meta');
  if (!metaScript) return;
  var envelope;
  try {{
    envelope = JSON.parse(metaScript.textContent);
  }} catch (e) {{
    pvEl.innerHTML = '<div class="pagevault-error">Invalid envelope metadata</div>';
    return;
  }}

  // Render password prompt
  pvEl.innerHTML = '<div class="pagevault-container">' +
    '<div class="pagevault-icon">\\u{{1F512}}</div>' +
    '<div class="pagevault-title">Protected Content</div>' +
    '<form class="pagevault-form">' +
    (isUserMode ? '<input type="text" class="pagevault-input" placeholder="Username" autocomplete="username">' : '') +
    '<input type="password" class="pagevault-input pagevault-password" placeholder="Password" autocomplete="current-password">' +
    '<button type="submit" class="pagevault-button">Decrypt</button>' +
    '<div class="pagevault-error" style="display: none;"></div>' +
    '</form></div>';

  var form = pvEl.querySelector('form');
  var pwdInput = pvEl.querySelector('.pagevault-password');
  var userInput = pvEl.querySelector('input[placeholder="Username"]');
  var errorDiv = pvEl.querySelector('.pagevault-error');
  var button = pvEl.querySelector('button');

  form.addEventListener('submit', async function(e) {{
    e.preventDefault();
    var password = pwdInput.value;
    if (!password) return;
    var username = userInput ? userInput.value : null;

    button.disabled = true;
    button.textContent = 'Decrypting...';
    errorDiv.style.display = 'none';

    // Show progress bar for multi-chunk payloads
    var progressContainer = null;
    var progressBar = null;
    if (envelope.chunk_count > 1) {{
      progressContainer = document.createElement('div');
      progressContainer.className = 'pagevault-progress';
      progressBar = document.createElement('div');
      progressBar.className = 'pagevault-progress-bar';
      progressBar.style.width = '0%';
      progressContainer.appendChild(progressBar);
      pvEl.querySelector('.pagevault-container').appendChild(progressContainer);
    }}

    function onProgress(done, total) {{
      if (progressBar) {{
        var pct = Math.round((done / total) * 100);
        progressBar.style.width = pct + '%';
        progressBar.textContent = pct + '%';
      }}
    }}

    var result = await window.__pagevault.decryptV3Chunked(envelope, password, username, onProgress);
    if (!result) {{
      if (progressContainer) progressContainer.remove();
      errorDiv.textContent = 'Wrong password';
      errorDiv.style.display = 'block';
      button.disabled = false;
      button.textContent = 'Decrypt';
      pwdInput.value = '';
      pwdInput.focus();
      return;
    }}

    var meta = result.meta || {{}};
    // Strip null-byte padding (from --pad option during lock)
    if (meta.size && result.blob.size > meta.size) {{
      result.blob = result.blob.slice(0, meta.size, result.blob.type);
    }}
    pvEl.setAttribute('data-decrypted', 'true');

    if (meta.type === 'site' && window.__pagevault_renderSite) {{
      var ab = await result.blob.arrayBuffer();
      window.__pagevault_renderSite(pvEl, new Uint8Array(ab), meta);
    }} else {{
      await renderFile(pvEl, result.blob, meta);
    }}
  }});

  setTimeout(function() {{ pwdInput.focus(); }}, 100);

  function escapeHtml(str) {{
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }}

  function formatSize(bytes) {{
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }}

  function createToolbar(fname, size, downloadUrl) {{
    var toolbar = document.createElement('div');
    toolbar.className = 'pagevault-toolbar';
    toolbar.innerHTML =
      '<span class="toolbar-filename">' + escapeHtml(fname) + '</span>' +
      '<span class="toolbar-size">' + formatSize(size) + '</span>' +
      '<a class="toolbar-btn" href="' + downloadUrl + '" download="' + escapeHtml(fname) + '">Download</a>';
    return toolbar;
  }}

  function renderDownloadView(viewer, url, fname, size) {{
    viewer.innerHTML =
      '<div class="pagevault-download">' +
        '<div class="pagevault-icon">\\u{{1F4C4}}</div>' +
        '<a href="' + url + '" download="' + escapeHtml(fname) + '">Download ' + escapeHtml(fname) + '</a>' +
        '<div class="file-info">' + formatSize(size) + '</div>' +
      '</div>';
  }}

  // --- Viewer plugins (injected from ViewerPlugin.js()) ---

{viewer_defs}

  // Dispatch table: MIME type/pattern -> viewer function
  var __pv_viewers = {{
{dispatch_table}
  }};

  function __pv_resolveViewer(mime) {{
    if (__pv_viewers[mime]) return __pv_viewers[mime];
    var prefix = mime.split('/')[0] + '/*';
    if (__pv_viewers[prefix]) return __pv_viewers[prefix];
    return null;
  }}

  async function renderFile(container, blob, meta) {{
    var mime = meta.mime || 'application/octet-stream';
    var fname = meta.filename || 'download';
    var size = meta.size || blob.size;
    var url = URL.createObjectURL(blob);

    var toolbar = createToolbar(fname, size, url);
    var viewer = document.createElement('div');
    viewer.className = 'pagevault-viewer';

    var renderFn = __pv_resolveViewer(mime);
    if (renderFn) {{
      await renderFn(viewer, blob, url, meta, toolbar);
    }} else {{
      renderDownloadView(viewer, url, fname, size);
    }}

    container.innerHTML = '';
    container.appendChild(toolbar);
    container.appendChild(viewer);
  }}
}})();"""


def _get_jszip_shim() -> str:
    """Get a minimal JSZip-compatible implementation for site mode.

    This is a shim that uses the browser's built-in DecompressionStream API
    (available in modern browsers) to decompress zip files without a full
    JSZip library.
    """
    return """
// Minimal ZIP reader using native browser APIs
(function() {
  'use strict';

  class ZipReader {
    constructor(buffer) {
      this.buffer = buffer;
      this.view = new DataView(buffer);
      this.entries = [];
      this._parse();
    }

    _parse() {
      // Find end of central directory
      let eocdOffset = -1;
      for (let i = this.buffer.byteLength - 22; i >= 0; i--) {
        if (this.view.getUint32(i, true) === 0x06054b50) {
          eocdOffset = i;
          break;
        }
      }
      if (eocdOffset === -1) throw new Error('Invalid ZIP file');

      const cdOffset = this.view.getUint32(eocdOffset + 16, true);
      const cdCount = this.view.getUint16(eocdOffset + 10, true);

      let offset = cdOffset;
      for (let i = 0; i < cdCount; i++) {
        if (this.view.getUint32(offset, true) !== 0x02014b50) break;

        const compression = this.view.getUint16(offset + 10, true);
        const compSize = this.view.getUint32(offset + 20, true);
        const uncompSize = this.view.getUint32(offset + 24, true);
        const nameLen = this.view.getUint16(offset + 28, true);
        const extraLen = this.view.getUint16(offset + 30, true);
        const commentLen = this.view.getUint16(offset + 32, true);
        const localHeaderOffset = this.view.getUint32(offset + 42, true);

        const nameBytes = new Uint8Array(this.buffer, offset + 46, nameLen);
        const name = new TextDecoder().decode(nameBytes);

        this.entries.push({
          name, compression, compSize, uncompSize, localHeaderOffset
        });

        offset += 46 + nameLen + extraLen + commentLen;
      }
    }

    async getFile(name) {
      const entry = this.entries.find(e => e.name === name);
      if (!entry) return null;

      // Read local file header to find data offset
      const lh = entry.localHeaderOffset;
      const lhNameLen = this.view.getUint16(lh + 26, true);
      const lhExtraLen = this.view.getUint16(lh + 28, true);
      const dataOffset = lh + 30 + lhNameLen + lhExtraLen;

      const compressedData = new Uint8Array(this.buffer, dataOffset, entry.compSize);

      if (entry.compression === 0) {
        // Stored (no compression)
        return compressedData;
      } else if (entry.compression === 8) {
        // Deflate
        const ds = new DecompressionStream('deflate-raw');
        const writer = ds.writable.getWriter();
        const reader = ds.readable.getReader();

        writer.write(compressedData);
        writer.close();

        const chunks = [];
        let totalLen = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
          totalLen += value.length;
        }

        const result = new Uint8Array(totalLen);
        let off = 0;
        for (const chunk of chunks) {
          result.set(chunk, off);
          off += chunk.length;
        }
        return result;
      }

      throw new Error('Unsupported compression: ' + entry.compression);
    }

    getFileNames() {
      return this.entries.map(e => e.name).filter(n => !n.endsWith('/'));
    }
  }

  window.__pagevault_ZipReader = ZipReader;
})();"""


def _get_site_renderer_js() -> str:
    """Generate the site renderer JS for URL rewriting.

    Uses data URIs instead of blob URLs to avoid cross-origin issues when
    the wrapped HTML is opened from file:// (where blob:null origins are
    opaque and can't be shared between parent and iframe). Internal page
    navigation is handled via postMessage from an injected interceptor script.
    """
    return """
// pagevault site renderer
(function() {
  'use strict';

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  window.__pagevault_renderSite = async function(container, zipBytes, meta) {
    const entry = meta.entry || 'index.html';

    try {
      const zip = new window.__pagevault_ZipReader(zipBytes.buffer);
      const fileNames = zip.getFileNames();

      // Load all files and build resource map
      const resources = {};
      const htmlFiles = new Set();

      for (const name of fileNames) {
        const data = await zip.getFile(name);
        if (!data) continue;
        const ext = name.split('.').pop().toLowerCase();
        const mime = getMimeForExt(ext);
        resources[name] = { data: data, mime: mime, uri: null };
        if (mime === 'text/html') htmlFiles.add(name);
      }

      // Lazily convert binary data to data URI (cached)
      function toDataUri(name) {
        var r = resources[name];
        if (!r) return null;
        if (!r.uri) r.uri = 'data:' + r.mime + ';base64,' + uint8ToBase64(r.data);
        return r.uri;
      }

      // Get HTML file content as text
      function getHtml(name) {
        var r = resources[name];
        if (!r) return null;
        return new TextDecoder().decode(r.data);
      }

      // Rewrite resource URLs in HTML to data URIs
      function rewriteUrls(html, fromPage) {
        var attrPattern = /(src|href|srcset|poster|action)=(["'])([^"']+?)\\2/gi;
        html = html.replace(attrPattern, function(match, attr, quote, url) {
          if (url.startsWith('http://') || url.startsWith('https://') ||
              url.startsWith('//') || url.startsWith('data:') ||
              url.startsWith('#') || url.startsWith('javascript:') ||
              url.startsWith('mailto:')) {
            return match;
          }
          var clean = url.split('#')[0].split('?')[0];
          var resolved = resolvePath(fromPage, clean);
          // Leave <a href> to HTML pages alone — nav interceptor handles them
          if (attr.toLowerCase() === 'href' && htmlFiles.has(resolved)) {
            return match;
          }
          var uri = toDataUri(resolved);
          if (uri) return attr + '=' + quote + uri + quote;
          return match;
        });

        // Rewrite CSS url() references
        html = html.replace(/url\\((['"]?)([^)'"]+?)\\1\\)/gi, function(match, quote, url) {
          if (url.startsWith('http://') || url.startsWith('https://') ||
              url.startsWith('data:') || url.startsWith('#')) {
            return match;
          }
          var resolved = resolvePath(fromPage, url);
          var uri = toDataUri(resolved);
          if (uri) return 'url(' + quote + uri + quote + ')';
          return match;
        });

        // Rewrite quoted strings that match known resource paths.
        // Catches dynamic JS references like img.src = imageData.url
        // where the URL is stored in JSON/JS as "media/xxx.png".
        html = html.replace(/(["'])((?:[a-zA-Z0-9_\\-./]+\\/)?[a-zA-Z0-9_\\-.]+\\.[a-zA-Z0-9]{1,10})\\1/g, function(match, quote, val) {
          // Skip data URIs and absolute URLs
          if (val.indexOf('://') !== -1 || val.startsWith('data:')) return match;
          var clean = val.split('#')[0].split('?')[0];
          var resolved = resolvePath(fromPage, clean);
          // Only replace if it's a known non-HTML resource
          if (resources[resolved] && !htmlFiles.has(resolved)) {
            var uri = toDataUri(resolved);
            if (uri) return quote + uri + quote;
          }
          return match;
        });

        return html;
      }

      // Track current page for relative path resolution
      var currentPage = entry;

      // Create iframe — no sandbox (user-trusted content)
      container.innerHTML = '';
      var iframe = document.createElement('iframe');
      iframe.className = 'pagevault-site-frame';
      container.appendChild(iframe);

      // Shim pushState/replaceState after iframe loads to prevent
      // SecurityError when opened from file:// (srcdoc = about:srcdoc URL)
      iframe.addEventListener('load', function() {
        try {
          var h = iframe.contentWindow.history;
          var ps = h.pushState.bind(h);
          var rs = h.replaceState.bind(h);
          h.pushState = function() { try { return ps.apply(h, arguments); } catch(e) {} };
          h.replaceState = function() { try { return rs.apply(h, arguments); } catch(e) {} };
        } catch(e) {}
      });

      function renderPage(pageName) {
        var html = getHtml(pageName);
        if (!html) return false;
        currentPage = pageName;
        html = rewriteUrls(html, pageName);
        html = injectNavScript(html);
        // Use srcdoc so iframe inherits parent origin — needed for
        // localStorage, blob URLs, etc. under file:// protocol.
        iframe.srcdoc = html;
        return true;
      }

      // Listen for internal link clicks from iframe
      window.addEventListener('message', function(e) {
        if (!e.data || e.data.type !== 'pagevault-nav') return;
        var href = e.data.href;
        var clean = href.split('#')[0].split('?')[0];
        if (!clean) return;
        var target = resolvePath(currentPage, clean);
        if (htmlFiles.has(target)) {
          renderPage(target);
        }
      });

      // Load entry page
      if (!renderPage(entry)) {
        container.innerHTML = '<div class="pagevault-error">Entry point not found: ' + escapeHtml(entry) + '</div>';
      }
    } catch (e) {
      container.innerHTML = '<div class="pagevault-error">Failed to load site: ' + escapeHtml(e.message) + '</div>';
    }
  };

  function uint8ToBase64(data) {
    var binary = '';
    var len = data.length;
    for (var i = 0; i < len; i += 8192) {
      binary += String.fromCharCode.apply(null, data.subarray(i, Math.min(i + 8192, len)));
    }
    return btoa(binary);
  }

  function injectNavScript(html) {
    // Intercept clicks on internal links and forward to parent via postMessage.
    // Split 'script' tags to avoid closing the outer <script> in the wrapper HTML.
    var tag = '<scr' + 'ipt>document.addEventListener("click",function(e){' +
      'var a=e.target.closest("a");if(!a)return;' +
      'var h=a.getAttribute("href");' +
      'if(!h||h.startsWith("http://")||h.startsWith("https://")||' +
      'h.startsWith("//")||h.startsWith("#")||h.startsWith("data:")||' +
      'h.startsWith("javascript:")||h.startsWith("mailto:"))return;' +
      'e.preventDefault();' +
      'window.parent.postMessage({type:"pagevault-nav",href:h},"*");' +
      '});</scr' + 'ipt>';
    var idx = html.lastIndexOf('</body>');
    if (idx !== -1) return html.slice(0, idx) + tag + html.slice(idx);
    return html + tag;
  }

  function resolvePath(fromPage, href) {
    if (!href) return fromPage;
    // Handle absolute paths (strip leading / since zip paths don't have it)
    if (href.startsWith('/')) {
      return href.substring(1);
    }
    href = href.replace(/^\\.\\//g, '');
    // Get directory of the referring page
    var parts = fromPage.split('/');
    parts.pop();
    var segments = href.split('/');
    for (var i = 0; i < segments.length; i++) {
      if (segments[i] === '..') parts.pop();
      else if (segments[i] !== '.' && segments[i] !== '') parts.push(segments[i]);
    }
    return parts.length ? parts.join('/') : href;
  }

  function getMimeForExt(ext) {
    var mimes = {
      html: 'text/html', htm: 'text/html',
      css: 'text/css', js: 'text/javascript',
      json: 'application/json', xml: 'application/xml',
      png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
      gif: 'image/gif', svg: 'image/svg+xml', webp: 'image/webp',
      ico: 'image/x-icon',
      pdf: 'application/pdf',
      woff: 'font/woff', woff2: 'font/woff2',
      ttf: 'font/ttf', eot: 'application/vnd.ms-fontobject',
      mp4: 'video/mp4', webm: 'video/webm',
      mp3: 'audio/mpeg', ogg: 'audio/ogg',
      txt: 'text/plain', md: 'text/markdown',
    };
    return mimes[ext] || 'application/octet-stream';
  }
})();"""
