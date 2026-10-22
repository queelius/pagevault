"""Universal encrypted payload generation for pagevault.

Wraps arbitrary files and directories into self-contained encrypted HTML
that can be decrypted and rendered in the browser.
"""

import html
import json
import logging
import mimetypes
import zipfile
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from pathlib import Path, PurePosixPath, PureWindowsPath

from bs4 import BeautifulSoup, Tag

from ._fs import atomic_write
from .config import PagevaultConfig
from .crypto import (
    PagevaultError,
    content_hash_bytes,
    decrypt_v4,
    encrypt_v4,
    pad_content_bytes,
)
from .parser import _parse_html, has_pagevault_elements
from .runtime._loader import _escape_for_script_block
from .viewers import discover_viewers, resolve_viewer

# Re-exported for tests that import from pagevault.wrap. The canonical
# implementation lives in runtime._loader; this avoids two copies drifting.
__all__ = ["_escape_for_script_block"]

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

    ``content_hash`` and the unpadded ``size`` go into the *encrypted* meta,
    never the cleartext envelope: a plaintext hash readable without the
    password would let anyone confirm a guess about the contents. Shared by
    :func:`wrap_file` and :func:`wrap_site`, which differ only in how
    ``data`` and ``meta`` are built.

    Returns the envelope and the list of base64-encoded chunk ciphertexts.
    """
    use_pad = pad or (config and config.pad)
    payload = pad_content_bytes(data) if use_pad else data

    return encrypt_v4(
        payload,
        password=password,
        salt=config.salt if config else None,
        users=users,
        meta={**meta, "size": len(data), "content_hash": content_hash_bytes(data)},
    )


def _write_wrap_output(output_path: Path, html: str) -> None:
    """Create parent dirs and write the wrapped HTML output."""
    try:
        atomic_write(output_path, html)
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


def default_site_output_path(dir_path: Path) -> Path:
    """Default output for a wrapped site: ``<dirname>.html`` beside the directory.

    The directory is resolved first so that ``.`` yields ``../<name>.html``
    rather than a file literally named ``.html``.
    """
    dir_path = Path(dir_path).resolve()
    return dir_path.parent / f"{dir_path.name}.html"


def _site_files(dir_path: Path, output_path: Path) -> list[tuple[Path, str]]:
    """List ``(path, archive_name)`` pairs to bundle from a site directory.

    The bundle is readable by every user the site is encrypted for, so
    hidden paths (any component starting with ``.``: ``.pagevault.yaml``
    with its credentials, ``.git/``, ``.env``) are never included, and
    neither is the output file itself when it lives inside the directory.
    """
    output_resolved = output_path.resolve()
    selected = []
    for file_path in sorted(dir_path.rglob("*")):
        rel = file_path.relative_to(dir_path)
        if any(part.startswith(".") for part in rel.parts):
            continue
        if not file_path.is_file() or file_path.resolve() == output_resolved:
            continue
        selected.append((file_path, rel.as_posix()))
    return selected


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
    dir_path = Path(dir_path).resolve()
    if not dir_path.is_dir():
        raise PagevaultError(f"Directory not found: {dir_path}")

    if output_path is None:
        output_path = default_site_output_path(dir_path)
    output_path = Path(output_path)

    # Zip the directory
    zip_buffer = BytesIO()
    file_list = []

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path, arcname in _site_files(dir_path, output_path):
            file_list.append(arcname)
            zf.write(file_path, arcname)

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
    # The entry point is read from `meta` by the in-browser site renderer,
    # so we don't need to pass it through to the HTML template here.
    html = _generate_wrap_html_v4(
        envelope=envelope,
        chunks=chunks,
        title=f"Protected: {dir_path.name}",
        config=config,
        users=users,
        include_jszip=True,
    )

    _write_wrap_output(output_path, html)
    return output_path


class WrapKind(str, Enum):
    """What a wrapped payload holds (the ``type`` field of its meta)."""

    FILE = "file"
    SITE = "site"


@dataclass(frozen=True)
class WrappedPayload:
    """The decrypted contents of a wrapped file or site.

    ``data`` is the original bytes (padding removed, hash verified): the
    file itself for :attr:`WrapKind.FILE`, a zip archive for
    :attr:`WrapKind.SITE`. ``meta`` is the decrypted metadata. It is
    authenticated, but written by whoever made the file, so names in it
    are sanitized before they touch the filesystem.
    """

    kind: WrapKind
    meta: dict
    data: bytes

    @property
    def filename(self) -> str:
        """The wrapped file's name, reduced to a bare final component."""
        if self.kind is not WrapKind.FILE:
            raise PagevaultError(f"A {self.kind.value} payload has no filename")
        stored = str(self.meta.get("filename", ""))
        name = PureWindowsPath(PurePosixPath(stored).name).name
        if name in ("", ".", ".."):
            raise PagevaultError(f"Unusable filename in payload: {stored!r}")
        return name

    def extract_site(self, dest: Path) -> list[Path]:
        """Extract a site payload under ``dest``; returns the files written.

        Every member is checked before anything is written, so an archive
        with an entry that would land outside ``dest`` writes nothing.
        """
        if self.kind is not WrapKind.SITE:
            raise PagevaultError(f"A {self.kind.value} payload is not a site")
        dest = Path(dest)
        try:
            archive = zipfile.ZipFile(BytesIO(self.data))
        except zipfile.BadZipFile as e:
            raise PagevaultError(f"Site payload is not a valid zip: {e}") from e

        with archive:
            members = [m for m in archive.infolist() if not m.is_dir()]
            for member in members:
                parts = PurePosixPath(member.filename.replace("\\", "/")).parts
                if not parts or parts[0] == "/" or ".." in parts:
                    raise PagevaultError(
                        f"Site entry would extract outside {dest}: {member.filename!r}"
                    )
            written = []
            for member in members:
                target = dest.joinpath(*PurePosixPath(member.filename).parts)
                atomic_write(target, archive.read(member))
                written.append(target)
        return written


@dataclass
class WrapDocument:
    """A parsed wrapped-file HTML document.

    The Python-side reader for the encoding :func:`_generate_wrap_html_v4`
    writes: a ``<pagevault data-pv-chunked>`` element plus document-level
    ``<script id="pv-meta">`` and ``<script id="pv-N">`` tags. Chunks are
    located by id for ``N < chunk_count``, exactly as the browser runtime
    does; that count is unauthenticated, so :meth:`decrypt` checks the
    result against the size in the encrypted meta.
    """

    soup: BeautifulSoup
    element: Tag
    meta_script: Tag
    envelope: dict
    chunk_tags: list[Tag]

    @classmethod
    def parse(cls, html: str) -> "WrapDocument | None":
        """Parse ``html``; returns None unless it is a wrapped document."""
        if not has_pagevault_elements(html):
            return None
        soup = _parse_html(html)
        element = soup.find("pagevault", attrs={"data-pv-chunked": True})
        meta_script = soup.find("script", id="pv-meta")
        if element is None or meta_script is None:
            return None
        try:
            envelope = json.loads(meta_script.string or "")
        except json.JSONDecodeError as e:
            raise PagevaultError(f"Invalid pv-meta JSON: {e}") from e
        if not isinstance(envelope, dict):
            raise PagevaultError("Invalid pv-meta: expected a JSON object")
        count = envelope.get("chunk_count", 0)
        if not isinstance(count, int) or count < 0:
            raise PagevaultError(f"Invalid chunk_count: {count!r}")
        chunk_tags = []
        for i in range(count):
            tag = soup.find("script", id=f"pv-{i}")
            if tag is None:
                raise PagevaultError(f"Missing chunk {i} of {count}")
            chunk_tags.append(tag)
        return cls(soup, element, meta_script, envelope, chunk_tags)

    def decrypt(self, password: str, username: str | None = None) -> WrappedPayload:
        """Decrypt with one credential, verifying size and content hash."""
        chunks = [(tag.string or "").strip() for tag in self.chunk_tags]
        data, meta = decrypt_v4(self.envelope, chunks, password, username=username)
        if not isinstance(meta, dict):
            raise PagevaultError("Invalid payload metadata")
        try:
            kind = WrapKind(meta.get("type"))
        except ValueError:
            raise PagevaultError(
                f"Unknown wrapped payload type: {meta.get('type')!r}"
            ) from None

        # Only the encrypted meta is trusted here. Files from pagevault
        # <= 0.4.2 also carry a cleartext envelope content_hash, which is
        # unauthenticated and deliberately ignored.
        size = meta.get("size")
        if isinstance(size, int):
            if len(data) < size:
                raise PagevaultError("Integrity check failed: content truncated")
            data = data[:size]
        expected = meta.get("content_hash")
        if expected and content_hash_bytes(data) != expected:
            raise PagevaultError("Integrity check failed: content hash mismatch")
        return WrappedPayload(kind=kind, meta=meta, data=data)

    def rekey(self, old_users: dict[str, str], new_users: dict[str, str]) -> str:
        """Re-encrypt for ``new_users``, recovering the content with any old user.

        Produces fresh ciphertext (new CEK, salt and IVs) and keeps the
        padding, metadata and runtime as they were; only the envelope and
        chunk scripts change.
        """
        if not new_users:
            raise PagevaultError("'new_users' must not be empty")
        payload = None
        for username, password in old_users.items():
            try:
                payload = self.decrypt(password, username=username)
                break
            except PagevaultError:
                continue
        if payload is None:
            raise PagevaultError("Cannot recover content: no valid old credentials")

        envelope, chunks = _encrypt_payload(
            payload.data,
            payload.meta,
            password=None,
            users=new_users,
            config=None,
            pad=self.envelope.get("total_size") != len(payload.data),
        )

        self.meta_script.string = json.dumps(envelope)
        for tag in self.chunk_tags:
            tag.extract()
        anchor = self.meta_script
        self.chunk_tags = []
        for i, chunk in enumerate(chunks):
            tag = self.soup.new_tag("script", id=f"pv-{i}", type="x-pv")
            tag.string = chunk
            anchor.insert_after(tag)
            anchor = tag
            self.chunk_tags.append(tag)
        self.element["data-mode"] = "user"
        self.envelope = envelope
        return str(self.soup)


def unwrap_html(
    html: str, password: str, username: str | None = None
) -> WrappedPayload:
    """Decrypt a wrapped-file HTML document.

    Raises:
        PagevaultError: If ``html`` is not a wrapped document or decryption fails.
    """
    doc = WrapDocument.parse(html)
    if doc is None:
        raise PagevaultError("Not a pagevault wrapped file")
    return doc.decrypt(password, username=username)


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

    Returns:
        Complete HTML string.
    """
    from .config import TemplateConfig

    template = config.template if config else TemplateConfig()

    # Serialize envelope as JSON for the meta script tag
    envelope_json = json.dumps(envelope)

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
  <title>{html.escape(title, quote=True)}</title>
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


