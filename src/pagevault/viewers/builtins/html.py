"""HTML viewer using srcdoc iframe."""

from pagevault.viewers.base import ViewerPlugin


class HtmlViewer(ViewerPlugin):
    """Viewer for HTML files using srcdoc iframe.

    Uses ``srcdoc`` instead of a blob URL so the iframe inherits the
    parent document's origin.  This is critical for ``file://`` contexts
    where blob URLs get an opaque ``null`` origin, breaking localStorage,
    nested blob URLs, and other APIs that require a real origin.

    No ``sandbox`` attribute is set because wrapped content is always
    user-trusted (the user explicitly encrypted their own file).
    """

    name = "html"
    mime_types = ["text/html"]
    priority = 0

    def js(self) -> str:
        return self._load_js_asset("html.js")

    def css(self) -> str:
        return ""
