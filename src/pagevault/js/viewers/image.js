async function(container, blob, url, meta, toolbar) {
    container.className = 'pagevault-viewer pagevault-image-viewer';
    var img = document.createElement('img');
    img.src = url;
    img.alt = meta.filename;
    img.addEventListener('click', function() { img.classList.toggle('zoomed'); });
    container.appendChild(img);
}