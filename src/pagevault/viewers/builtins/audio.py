"""Audio viewer using the browser's built-in HTML5 audio player."""

from pagevault.viewers.base import ViewerPlugin


class AudioViewer(ViewerPlugin):
    """Viewer for audio files using HTML5 <audio> element."""

    name = "audio"
    mime_types = ["audio/*"]
    priority = 0

    def js(self) -> str:
        return """async function(container, blob, url, meta, toolbar) {
    container.className = 'pagevault-viewer pagevault-audio-viewer';
    var audio = document.createElement('audio');
    audio.controls = true;
    audio.src = url;
    container.appendChild(audio);
}"""

    def css(self) -> str:
        return """
/* Audio viewer */
.pagevault-audio-viewer {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 200px;
  padding: 2rem;
  background: #f5f5f5;
}
.pagevault-audio-viewer audio {
  width: 100%;
  max-width: 600px;
}

/* Dark mode */
@media (prefers-color-scheme: dark) {
  .pagevault-audio-viewer { background: #1a1a2a; }
}"""
