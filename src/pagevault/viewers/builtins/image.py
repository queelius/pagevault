"""Image viewer with click-to-zoom."""

from pagevault.viewers.base import ViewerPlugin


class ImageViewer(ViewerPlugin):
    """Viewer for image files with click-to-zoom."""

    name = "image"
    mime_types = ["image/*"]
    priority = 0

    def js(self) -> str:
        return """async function(container, blob, url, meta, toolbar) {
    container.className = 'pagevault-viewer pagevault-image-viewer';
    var img = document.createElement('img');
    img.src = url;
    img.alt = meta.filename;
    img.addEventListener('click', function() { img.classList.toggle('zoomed'); });
    container.appendChild(img);
}"""

    def css(self) -> str:
        return """
/* Image viewer */
.pagevault-image-viewer {
  display: flex;
  justify-content: center;
  align-items: flex-start;
  min-height: calc(100vh - 40px);
  background: #f0f0f0;
  padding: 1rem;
  overflow: auto;
}
.pagevault-image-viewer img {
  max-width: 100%;
  max-height: calc(100vh - 72px);
  height: auto;
  display: block;
  cursor: zoom-in;
  object-fit: contain;
}
.pagevault-image-viewer img.zoomed {
  max-width: none;
  max-height: none;
  cursor: zoom-out;
}

/* Dark mode */
@media (prefers-color-scheme: dark) {
  .pagevault-image-viewer { background: #1a1a2a; }
}"""
