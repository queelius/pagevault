async function(container, blob, url, meta, toolbar) {
    container.className = 'pagevault-viewer pagevault-text-viewer';
    var text = await blob.text();
    var lines = text.split('\n');
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
}