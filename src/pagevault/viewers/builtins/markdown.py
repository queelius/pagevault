"""Markdown viewer with rendered/source toggle."""

from importlib.resources import files

from pagevault.viewers.base import ViewerPlugin

# Security note: The markdown viewer uses innerHTML to render HTML produced by
# marked.js (a trusted library) or simpleMarkdown (which escapes all HTML
# entities first via &amp;/&lt;/&gt; replacement). This is the same trust
# model as the original wrap.py code. The innerHTML is NOT fed user-controlled
# strings — only sanitized markdown output.


class MarkdownViewer(ViewerPlugin):
    """Viewer for markdown files with rendered/source toggle.

    Uses vendored marked.js for full rendering, with a simple
    fallback when marked.js is unavailable.
    """

    name = "markdown"
    mime_types = ["text/markdown"]
    priority = 10  # Higher than TextViewer's text/* wildcard

    def js(self) -> str:
        return self._load_js_asset("markdown.js")

    def css(self) -> str:
        return self._load_css_asset("markdown.css")

    def dependencies(self) -> list[str]:
        return [(files("pagevault") / "vendor" / "marked.min.js").read_text(encoding="utf-8")]
