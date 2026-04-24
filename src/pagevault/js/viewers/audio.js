async function(container, blob, url, meta, toolbar) {
    container.className = 'pagevault-viewer pagevault-audio-viewer';
    var audio = document.createElement('audio');
    audio.controls = true;
    audio.src = url;
    container.appendChild(audio);
}