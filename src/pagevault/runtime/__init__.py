"""pagevault browser runtime assembly.

Loads JavaScript assets from the runtime package and assembles them into
a self-contained IIFE for injection into encrypted HTML documents.
"""

from ..config import DefaultsConfig, TemplateConfig
from ._loader import _load_asset, _make_config_prelude


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

    prelude = _make_config_prelude(template, defaults)

    parts = [
        _load_asset("core/escape.js"),
        _load_asset("core/crypto.js"),
        _load_asset("core/storage.js"),
        _load_asset("core/activation.js"),
        _load_asset("region/handler.js"),
    ]

    inner = prelude + "\n".join(parts)

    header = "\n/* pagevault runtime v2 */\n(function() {\n  'use strict';\n\n"
    footer = "\n})();\n"
    return header + inner + footer
