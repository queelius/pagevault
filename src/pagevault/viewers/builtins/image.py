"""Image viewer with click-to-zoom."""

from pagevault.viewers.base import ViewerPlugin


class ImageViewer(ViewerPlugin):
    """Viewer for image files with click-to-zoom."""

    name = "image"
    mime_types = ["image/*"]
    priority = 0

    def js(self) -> str:
        return self._load_js_asset("image.js")

    def css(self) -> str:
        return self._load_css_asset("image.css")
