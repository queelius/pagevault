"""Audio viewer using the browser's built-in HTML5 audio player."""

from pagevault.viewers.base import ViewerPlugin


class AudioViewer(ViewerPlugin):
    """Viewer for audio files using HTML5 <audio> element."""

    name = "audio"
    mime_types = ["audio/*"]
    priority = 0

    def js(self) -> str:
        return self._load_js_asset("audio.js")

    def css(self) -> str:
        return self._load_css_asset("audio.css")
