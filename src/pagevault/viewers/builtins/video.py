"""Video viewer using the browser's built-in HTML5 video player."""

from pagevault.viewers.base import ViewerPlugin


class VideoViewer(ViewerPlugin):
    """Viewer for video files using HTML5 <video> element."""

    name = "video"
    mime_types = ["video/*"]
    priority = 0

    def js(self) -> str:
        return self._load_js_asset("video.js")

    def css(self) -> str:
        return self._load_css_asset("video.css")
