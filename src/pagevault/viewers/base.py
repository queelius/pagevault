"""Base class for pagevault viewer plugins."""

import re
from abc import ABC, abstractmethod
from importlib.resources import files

# Viewer names must be safe JS identifiers: lowercase alpha start, then
# lowercase alphanumeric or underscore. This prevents injection when the
# name is interpolated into JavaScript variable names.
_SAFE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

# MIME types must match: type/subtype (with +suffix), or type/* wildcard.
# This prevents JS string-literal breakout when injected into dispatch tables.
_SAFE_MIME_RE = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_.+]*"
    r"/(\*|[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_.+]*)$"
)


class ViewerPlugin(ABC):
    """Abstract base class for viewer plugins.

    Every viewer must define class attributes:
        name: Unique identifier (e.g. "image", "markdown").
              Must match [a-z][a-z0-9_]* (safe as a JS identifier).
        mime_types: List of MIME patterns (exact or wildcard like "image/*").
                    Must be non-empty; each entry must be a valid MIME pattern.
        priority: Higher wins when multiple viewers match (default 0).

    And implement:
        js(): Returns the async viewer function as a JS string.
        css(): Returns viewer-specific CSS (may be empty string).

    Optionally override:
        dependencies(): Returns JS library contents to bundle.

    Security / Trust Model:
        A viewer's js() method injects arbitrary JavaScript into the
        encrypted HTML output. Installing a third-party viewer package
        (via pip) is equivalent to trusting that package with access to
        all decrypted content. Only install viewer plugins from sources
        you trust. The framework validates ``name`` and ``mime_types``
        at class definition time to prevent injection via those fields,
        but cannot sandbox the JS returned by ``js()``.
    """

    name: str
    mime_types: list[str]
    priority: int = 0

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Validate required class attributes at definition time."""
        super().__init_subclass__(**kwargs)

        # Skip validation for intermediate abstract classes
        if getattr(cls, "__abstractmethods__", None):
            return

        # --- name ---
        if not hasattr(cls, "name"):
            raise TypeError(f"ViewerPlugin subclass {cls.__name__} must define 'name'")
        if not isinstance(cls.name, str) or not _SAFE_NAME_RE.match(cls.name):
            raise TypeError(
                f"ViewerPlugin subclass {cls.__name__} has invalid name "
                f"{cls.name!r}: must match [a-z][a-z0-9_]*"
            )

        # --- mime_types ---
        if not hasattr(cls, "mime_types"):
            raise TypeError(
                f"ViewerPlugin subclass {cls.__name__} must define 'mime_types'"
            )
        if not isinstance(cls.mime_types, list) or not cls.mime_types:
            raise TypeError(
                f"ViewerPlugin subclass {cls.__name__}: "
                f"mime_types must be a non-empty list"
            )
        for mt in cls.mime_types:
            if not isinstance(mt, str) or not _SAFE_MIME_RE.match(mt):
                raise TypeError(
                    f"ViewerPlugin subclass {cls.__name__} has invalid "
                    f"MIME type {mt!r}: must match type/subtype or type/*"
                )

    @abstractmethod
    def js(self) -> str:
        """Return the browser-side viewer function.

        Must return a complete async function expression:
            async function(container, blob, url, meta, toolbar) { ... }

        Parameters available inside the function:
            container: DOM element to render into (viewer owns it)
            blob: Blob with correct MIME type
            url: pre-created objectURL for the blob
            meta: { filename, mime, size }
            toolbar: DOM element with download button; viewer can append buttons

        Security: The returned JS is injected verbatim into the output HTML.
        Do not include ``</script>`` in the output — the framework escapes
        ``</`` to ``<\\/`` as a safety measure, but avoiding it is preferred.
        """
        ...

    @abstractmethod
    def css(self) -> str:
        """Return viewer-specific CSS.

        Use var(--pv-color-primary) and var(--pv-color-secondary) for
        theme colors set by the framework.
        Return empty string if no CSS needed.

        Security: Do not include ``</style>`` in the output.
        """
        ...

    def dependencies(self) -> list[str]:
        """Return JS library contents to bundle.

        Each string is the full content of a JS file that will be
        included as a separate <script> block before the renderer.
        """
        return []

    @classmethod
    def _load_js_asset(cls, filename: str) -> str:
        """Load a JS asset from src/pagevault/js/viewers/<filename>."""
        return (files("pagevault.js") / "viewers" / filename).read_text(encoding="utf-8")

    @classmethod
    def _load_css_asset(cls, filename: str) -> str:
        """Load a CSS asset from src/pagevault/js/viewers/<filename>."""
        return (files("pagevault.js") / "viewers" / filename).read_text(encoding="utf-8")
