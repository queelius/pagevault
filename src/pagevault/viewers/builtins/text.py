"""Text viewer with line numbers."""

from pagevault.viewers.base import ViewerPlugin


class TextViewer(ViewerPlugin):
    """Viewer for text files with line numbers."""

    name = "text"
    mime_types = ["text/*", "application/json", "application/xml"]
    priority = 0

    def js(self) -> str:
        return """async function(container, blob, url, meta, toolbar) {
    container.className = 'pagevault-viewer pagevault-text-viewer';
    var text = await blob.text();
    var lines = text.split('\\n');
    var gutter = document.createElement('div');
    gutter.className = 'line-numbers';
    for (var i = 1; i <= lines.length; i++) {
        var num = document.createElement('div');
        num.textContent = i;
        gutter.appendChild(num);
    }
    var pre = document.createElement('pre');
    pre.textContent = text;
    container.appendChild(gutter);
    container.appendChild(pre);
}"""

    def css(self) -> str:
        return """
/* Text viewer with line numbers */
.pagevault-text-viewer {
  display: flex;
  min-height: calc(100vh - 40px);
  background: #f5f5f5;
}
.pagevault-text-viewer .line-numbers {
  padding: 1rem 0.75rem 1rem 1rem;
  text-align: right;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 0.9rem;
  line-height: 1.6;
  color: #999;
  user-select: none;
  -webkit-user-select: none;
  border-right: 1px solid #ddd;
  background: #eee;
}
.pagevault-text-viewer pre {
  flex: 1;
  padding: 1rem;
  overflow-x: auto;
}

/* Dark mode */
@media (prefers-color-scheme: dark) {
  .pagevault-text-viewer { background: #1a1a2a; color: #e0e0e0; }
  .pagevault-text-viewer .line-numbers { background: #252535; border-right-color: #444; color: #666; }
}"""
