"""Universal encrypted payload generation for pagevault.

Wraps arbitrary files and directories into self-contained encrypted HTML
that can be decrypted and rendered in the browser.
"""

import logging
import mimetypes
import zipfile
from io import BytesIO
from pathlib import Path

from .config import PagevaultConfig
from .crypto import (
    PagevaultError,
    content_hash_bytes,
    encrypt_v4,
    pad_content_bytes,
)
from .viewers import discover_viewers, resolve_viewer

logger = logging.getLogger(__name__)

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


def _encrypt_payload(
    data: bytes,
    meta: dict,
    password: str | None,
    users: dict[str, str] | None,
    config: PagevaultConfig | None,
    pad: bool,
) -> tuple[dict, list[str]]:
    """Hash, optionally pad, then v4-chunk-encrypt raw bytes.

    Returns the envelope (with ``content_hash`` added) and the list of
    base64-encoded chunk ciphertexts. Shared by :func:`wrap_file` and
    :func:`wrap_site` — they differ only in how ``data`` and ``meta`` are
    built.
    """
    hash_value = content_hash_bytes(data)
    use_pad = pad or (config and config.pad)
    payload = pad_content_bytes(data) if use_pad else data

    envelope, chunks = encrypt_v4(
        payload,
        password=password,
        salt=config.salt if config else None,
        users=users,
        meta=meta,
    )
    envelope["content_hash"] = hash_value
    return envelope, chunks


def _write_wrap_output(output_path: Path, html: str) -> None:
    """Create parent dirs and write the wrapped HTML output."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_text(html, encoding="utf-8")
    except OSError as e:
        raise PagevaultError(f"Cannot write output {output_path}: {e}") from e


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

    mime = detect_mime(file_path)
    meta = {
        "type": "file",
        "filename": file_path.name,
        "mime": mime,
        "size": len(file_bytes),
    }

    envelope, chunks = _encrypt_payload(file_bytes, meta, password, users, config, pad)

    # Discover active viewers and resolve dependencies for this file type
    viewers = discover_viewers(config)
    _log_active_viewers(viewers)
    matching_viewer = resolve_viewer(mime, viewers)
    viewer_deps = matching_viewer.dependencies() if matching_viewer else []

    html = _generate_wrap_html_v4(
        envelope=envelope,
        chunks=chunks,
        title=f"Protected: {file_path.name}",
        viewers=viewers,
        viewer_deps=viewer_deps,
        config=config,
        users=users,
    )

    if output_path is None:
        output_path = file_path.with_suffix(".html")
    output_path = Path(output_path)
    _write_wrap_output(output_path, html)
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
    meta = {
        "type": "site",
        "entry": entry,
        "files": file_list,
    }

    envelope, chunks = _encrypt_payload(zip_bytes, meta, password, users, config, pad)

    # Site mode uses its own renderer (__pagevault_renderSite) that handles
    # all file types via data URIs inside the site iframe. Individual file
    # viewers are not needed — the site's own HTML/CSS/JS runs inside the
    # sandboxed iframe. Passing viewers=[] produces an empty dispatch table,
    # which is intentional: renderFile is only reached for non-site payloads.
    html = _generate_wrap_html_v4(
        envelope=envelope,
        chunks=chunks,
        title=f"Protected: {dir_path.name}",
        config=config,
        users=users,
        include_jszip=True,
        entry=entry,
    )

    if output_path is None:
        output_path = dir_path.parent / f"{dir_path.name}.html"
    output_path = Path(output_path)
    _write_wrap_output(output_path, html)
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




def _get_progress_css() -> str:
    """Generate CSS for the v4 chunk-decryption progress bar."""
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


def _generate_wrap_html_v4(  # noqa: E501
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
    """Generate self-contained HTML with v4 chunked encrypted payload.

    Instead of a single ``data-encrypted`` attribute, v4 stores the
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

    # Assemble the wrap runtime via the runtime module.
    # build_wrap_js returns a single IIFE containing crypto + chunks + progress
    # + prompt + optional jszip + optional site renderer + viewer dispatch +
    # file renderer. Callers that need the site path pass is_site=True.
    from .runtime import build_wrap_js

    wrap_js = build_wrap_js(
        template=template,
        viewers=viewers or [],
        include_jszip=include_jszip,
        is_site=include_jszip,  # site-mode and jszip-mode are coupled today
    )

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
  <pagevault {pv_attrs_str}></pagevault>{dep_blocks}
  <script data-pagevault-runtime>
{wrap_js}
  </script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Backward-compat wrappers for tests. The internal runtime is now assembled
# by pagevault.runtime.build_wrap_js; these wrappers keep the old names
# returning behaviorally-equivalent JS so test_wrap.py / test_viewers.py
# continue to pass. The wrappers return the FULL wrap runtime IIFE (crypto
# + renderer + site renderer if requested), which is a superset of what
# the old individual helpers returned. Tests that assert on substring
# presence (e.g. "escapeHtml", "renderFile") continue to pass.


def _get_renderer_js_v4(viewers: list) -> str:
    """Build the wrap runtime JS (file-renderer mode).

    Thin wrapper delegating to runtime.build_wrap_js. Returns the full
    IIFE that contains crypto, chunks, progress, prompt, viewer dispatch,
    and the file renderer.
    """
    from .runtime import build_wrap_js

    return build_wrap_js(viewers=viewers)


def _get_site_renderer_js() -> str:
    """Build the wrap runtime JS including the site renderer.

    Thin wrapper delegating to runtime.build_wrap_js. Returns the full
    IIFE with jszip + site renderer + nav injector + file renderer.
    """
    from .runtime import build_wrap_js

    return build_wrap_js(include_jszip=True, is_site=True)


