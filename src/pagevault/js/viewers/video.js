async function(container, blob, url, meta, toolbar) {
    container.className = 'pagevault-viewer pagevault-video-viewer';
    var video = document.createElement('video');
    video.controls = true;
    video.src = url;
    container.appendChild(video);
}