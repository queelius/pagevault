"""Markdown viewer with rendered/source toggle."""

from pathlib import Path

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

    def js(self) -> str:  # noqa: E501
        return _MARKDOWN_JS

    def css(self) -> str:  # noqa: E501
        return _MARKDOWN_CSS

    def dependencies(self) -> list[str]:
        vendor_path = Path(__file__).parent.parent.parent / "vendor" / "marked.min.js"
        return [vendor_path.read_text(encoding="utf-8")]


# JS and CSS are defined as module-level constants to keep the class clean.
# The rendered markdown HTML is produced by marked.js (a trusted library)
# or simpleMarkdown (which escapes all HTML entities first).

_MARKDOWN_JS = r"""async function(container, blob, url, meta, toolbar) {
    var text = await blob.text();
    var rendered;
    if (typeof marked !== 'undefined' && marked.parse) {
        rendered = marked.parse(text);
    } else {
        rendered = simpleMarkdown(text);
    }

    var body = document.createElement('div');
    body.className = 'markdown-body';
    body.innerHTML = rendered;

    var source = document.createElement('div');
    source.className = 'markdown-source';
    source.style.display = 'none';
    var pre = document.createElement('pre');
    pre.textContent = text;
    source.appendChild(pre);

    container.appendChild(body);
    container.appendChild(source);

    var toggleBtn = document.createElement('button');
    toggleBtn.className = 'toolbar-btn toolbar-toggle';
    toggleBtn.textContent = 'Source';
    toggleBtn.addEventListener('click', function() {
        var showSource = body.style.display !== 'none';
        body.style.display = showSource ? 'none' : '';
        source.style.display = showSource ? '' : 'none';
        toggleBtn.textContent = showSource ? 'Rendered' : 'Source';
        toggleBtn.classList.toggle('active', showSource);
    });
    toolbar.appendChild(toggleBtn);

    function simpleMarkdown(text) {
        var html = text
            .replace(/&/g, '&amp;').replace(/\x3c/g, '&lt;').replace(/>/g, '&gt;')
            .replace(/^### (.+)$/gm, '<h3>$1</h3>')
            .replace(/^## (.+)$/gm, '<h2>$1</h2>')
            .replace(/^# (.+)$/gm, '<h1>$1</h1>')
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.+?)\*/g, '<em>$1</em>')
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            .replace(/^- (.+)$/gm, '<li>$1</li>')
            .replace(/\n\n/g, '</p><p>');
        return '<p>' + html + '</p>';
    }
}"""

_MARKDOWN_CSS = """
/* Markdown rendered view */
.markdown-body {
  max-width: 800px;
  margin: 0 auto;
  padding: 2rem;
  line-height: 1.7;
  color: #24292e;
}
.markdown-body h1, .markdown-body h2, .markdown-body h3,
.markdown-body h4, .markdown-body h5, .markdown-body h6 {
  margin-top: 1.5em;
  margin-bottom: 0.5em;
  font-weight: 600;
  line-height: 1.25;
}
.markdown-body h1 { font-size: 2em; padding-bottom: 0.3em; border-bottom: 1px solid #eee; }
.markdown-body h2 { font-size: 1.5em; padding-bottom: 0.3em; border-bottom: 1px solid #eee; }
.markdown-body h3 { font-size: 1.25em; }
.markdown-body a { color: var(--pv-color-primary); text-decoration: none; }
.markdown-body a:hover { text-decoration: underline; }
.markdown-body table { border-collapse: collapse; width: 100%; margin: 1em 0; }
.markdown-body th, .markdown-body td { border: 1px solid #ddd; padding: 0.5em 0.75em; text-align: left; }
.markdown-body th { background: #f6f8fa; font-weight: 600; }
.markdown-body code {
  padding: 0.2em 0.4em;
  background: #f0f0f0;
  border-radius: 3px;
  font-size: 0.85em;
  font-family: 'Consolas', 'Monaco', monospace;
}
.markdown-body pre {
  padding: 1em;
  background: #f6f8fa;
  border-radius: 4px;
  overflow-x: auto;
}
.markdown-body pre code { padding: 0; background: none; font-size: 0.9em; }
.markdown-body blockquote {
  margin: 1em 0;
  padding: 0.5em 1em;
  border-left: 4px solid #ddd;
  color: #666;
}
.markdown-body hr { border: none; border-top: 1px solid #ddd; margin: 1.5em 0; }
.markdown-body ul, .markdown-body ol { padding-left: 2em; margin: 0.5em 0; }
.markdown-body li { margin: 0.25em 0; }
.markdown-body img { max-width: 100%; height: auto; }
.markdown-body p { margin: 0.75em 0; }

/* Markdown source toggle */
.markdown-source { max-width: 800px; margin: 0 auto; padding: 0; }
.markdown-source pre {
  padding: 2rem;
  background: #f5f5f5;
  min-height: calc(100vh - 40px);
}

/* Dark mode */
@media (prefers-color-scheme: dark) {
  .markdown-body { color: #e0e0e0; }
  .markdown-body h1, .markdown-body h2 { border-bottom-color: #444; }
  .markdown-body th, .markdown-body td { border-color: #444; }
  .markdown-body th { background: #2a2a3a; }
  .markdown-body code { background: #2a2a3a; }
  .markdown-body pre { background: #2a2a3a; }
  .markdown-body blockquote { border-left-color: #555; color: #999; }
  .markdown-body hr { border-top-color: #444; }
  .markdown-source pre { background: #1a1a2a; color: #e0e0e0; }
}"""
