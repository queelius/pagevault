async function(container, blob, url, meta, toolbar) {
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
}