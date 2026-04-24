"""Text viewer with line numbers."""

from pagevault.viewers.base import ViewerPlugin


class TextViewer(ViewerPlugin):
    """Viewer for text files with line numbers."""

    name = "text"
    mime_types = ["text/*", "application/json", "application/xml"]
    priority = 0

    def js(self) -> str:
        return self._load_js_asset("text.js")

    def css(self) -> str:
        return self._load_css_asset("text.css")
