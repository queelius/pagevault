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
        return """async function(container, blob, url, meta, toolbar) {
    var iframe = document.createElement('iframe');
    var text = await blob.text();
    iframe.srcdoc = text;
    iframe.addEventListener('load', function() {
        try {
            var h = iframe.contentWindow.history;
            var ps = h.pushState.bind(h);
            var rs = h.replaceState.bind(h);
            h.pushState = function() { try { return ps.apply(h, arguments); } catch(e) {} };
            h.replaceState = function() { try { return rs.apply(h, arguments); } catch(e) {} };
        } catch(e) {}
    });
    container.appendChild(iframe);
}"""

    def css(self) -> str:
        return ""
