"""pagevault browser runtime assembly.

Loads JavaScript assets from the runtime package and assembles them into
a self-contained IIFE for injection into encrypted HTML documents.
"""

import logging

from ..config import DefaultsConfig, TemplateConfig
from ..viewers.base import _SAFE_MIME_RE, _SAFE_NAME_RE
from ._loader import _escape_for_script_block, _load_asset, _make_config_prelude

logger = logging.getLogger(__name__)


def _wrap_iife(banner: str, prelude: str, parts: list[str]) -> str:
    """Wrap a CONFIG prelude + JS parts in a strict-mode IIFE.

    The runtime is always self-contained: callers compose a list of
    asset bodies (already escaped where needed), and this helper joins
    them with newlines and emits a single IIFE with the given banner
    comment.
    """
    inner = prelude + "\n".join(parts)
    header = f"\n/* {banner} */\n(function() {{\n  'use strict';\n\n"
    footer = "\n})();\n"
    return header + inner + footer


def build_region_js(
    template: TemplateConfig | None = None,
    defaults: DefaultsConfig | None = None,
) -> str:
    """Assemble the region-encryption browser runtime as a self-contained IIFE.

    Loads JS assets in order: escape.js, crypto.js, storage.js,
    activation.js, region/handler.js, and wraps them in a strict-mode IIFE
    with a CONFIG prelude derived from template and defaults.

    Args:
        template: Template configuration. Defaults to TemplateConfig().
        defaults: Defaults configuration. Defaults to DefaultsConfig().

    Returns:
        Complete JavaScript IIFE string ready for injection into a <script> tag.
    """
    if template is None:
        template = TemplateConfig()
    if defaults is None:
        defaults = DefaultsConfig()

    parts = [
        _load_asset("core/escape.js"),
        _load_asset("core/crypto.js"),
        _load_asset("core/chunks.js"),
        _load_asset("core/storage.js"),
        _load_asset("core/activation.js"),
        _load_asset("region/handler.js"),
    ]
    return _wrap_iife(
        "pagevault runtime v4",
        _make_config_prelude(template, defaults),
        parts,
    )


def build_wrap_js(
    template: TemplateConfig | None = None,
    viewers: list | None = None,
    include_jszip: bool = False,
    is_site: bool = False,
) -> str:
    """Assemble the file/site-wrap browser runtime as a self-contained IIFE.

    Includes: crypto.js (v4 decrypt), chunks.js (readV4FromScope),
    progress.js (progress bar), prompt.js (password form),
    file_renderer.js (IIFE entry that dispatches to viewer or site renderer).

    If include_jszip: adds jszip_shim.js for ZIP reading.
    If is_site: adds nav_injector.js and site_renderer.js for __pagevault_renderSite.

    Viewer dispatch table is emitted BEFORE file_renderer.js so the renderer
    can see window.__pv_viewers.

    Args:
        template: Template configuration for CSS/text. Defaults to TemplateConfig().
        viewers: Active ViewerPlugin instances for the dispatch table.
        include_jszip: Include the ZIP reader (for site mode).
        is_site: Include site renderer and nav injector.

    Returns:
        Complete JavaScript IIFE string.
    """
    if template is None:
        template = TemplateConfig()

    parts = [
        _load_asset("core/escape.js"),
        _load_asset("core/crypto.js"),
        _load_asset("core/chunks.js"),
        _load_asset("core/progress.js"),
        _load_asset("wrap/prompt.js"),
    ]

    if include_jszip:
        parts.append(_load_asset("wrap/jszip_shim.js"))

    if is_site:
        parts.append(_load_asset("wrap/nav_injector.js"))
        parts.append(_load_asset("wrap/site_renderer.js"))

    # Viewer dispatch table populated before the file renderer runs
    if viewers:
        parts.append(_build_viewer_dispatch(viewers))

    parts.append(_load_asset("wrap/file_renderer.js"))

    return _wrap_iife(
        "pagevault wrap runtime v4",
        _make_config_prelude(template, DefaultsConfig()),
        parts,
    )


def _build_viewer_dispatch(viewers: list) -> str:
    """Build JS that registers each viewer in window.__pv_viewers.

    Validates each viewer's name and MIME types against strict regexes
    (defense-in-depth). Skips viewers with unsafe names or MIME types.
    Viewer js() output is escaped to prevent </script> breakout.

    Args:
        viewers: Active ViewerPlugin instances.

    Returns:
        JS code that populates window.__pv_viewers with viewer functions.
    """
    lines = ["window.__pv_viewers = window.__pv_viewers || {};"]

    for viewer in viewers:
        if not _SAFE_NAME_RE.match(viewer.name):
            logger.warning("Skipping viewer with unsafe name: %r", viewer.name)
            continue

        # Validate each MIME type; if any is unsafe, skip the whole viewer.
        valid_mimes = []
        unsafe = False
        for mt in viewer.mime_types:
            if not _SAFE_MIME_RE.match(mt):
                logger.warning(
                    "Skipping viewer %r: unsafe MIME type %r", viewer.name, mt
                )
                unsafe = True
                break
            valid_mimes.append(mt)
        if unsafe or not valid_mimes:
            continue

        safe_js = _escape_for_script_block(viewer.js())
        lines.append("(function() {")
        lines.append(f"  var viewer = {safe_js};")
        for mime in valid_mimes:
            lines.append(f"  window.__pv_viewers[{mime!r}] = viewer;")
        lines.append("})();")

    return "\n".join(lines)
