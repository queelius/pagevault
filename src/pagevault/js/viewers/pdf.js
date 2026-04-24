async function(container, blob, url, meta, toolbar) {
    var iframe = document.createElement('iframe');
    iframe.src = url;
    container.appendChild(iframe);
}