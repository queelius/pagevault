async function(container, blob, url, meta, toolbar) {
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
}
