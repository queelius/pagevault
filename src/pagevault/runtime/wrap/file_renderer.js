  // pagevault file/site renderer — IIFE entry point for wrap HTML.
  //
  // Finds the <pagevault data-pv-chunked> element, reads the v4 envelope via
  // readV4FromScope(document) (from core/chunks.js), renders the password
  // prompt via renderWrapPrompt (from wrap/prompt.js), and on successful
  // decryption dispatches to the appropriate viewer or to __pagevault_renderSite.
  //
  // Viewer dispatch table (window.__pv_viewers) is populated separately by
  // build_wrap_js() via _build_viewer_dispatch().

  (function() {
    'use strict';

    var pvEl = document.querySelector('pagevault[data-pv-chunked]');
    if (!pvEl) return;

    var isUserMode = pvEl.getAttribute('data-mode') === 'user';

    var scoped = readV4FromScope(document);
    if (!scoped) {
      pvEl.innerHTML = '<div class="pagevault-error">Invalid envelope metadata</div>';
      return;
    }
    var envelope = scoped.envelope;
    var chunks = scoped.chunks;

    renderWrapPrompt(pvEl, isUserMode, async function onSubmit(password, username) {
      // Show progress bar for multi-chunk payloads
      var progressObj = null;
      if (envelope.chunk_count > 1) {
        progressObj = createProgressBar(pvEl.querySelector('.pagevault-container'));
      }

      function onProgress(done, total) {
        if (progressObj) progressObj.update(done, total);
      }

      var result = await decryptV4(envelope, chunks, password, username, onProgress);

      if (!result) {
        if (progressObj) progressObj.remove();
        return { success: false, error: 'Wrong password' };
      }

      var meta = result.meta || {};
      // Strip null-byte padding (from --pad option during lock).
      // result.bytes is a Uint8Array; size is in meta.size (original unpadded length).
      var bytes = result.bytes;
      if (meta.size && bytes.length > meta.size) {
        bytes = bytes.slice(0, meta.size);
      }

      var blob = new Blob([bytes], { type: meta.mime || 'application/octet-stream' });

      pvEl.setAttribute('data-decrypted', 'true');

      if (meta.type === 'site' && window.__pagevault_renderSite) {
        window.__pagevault_renderSite(pvEl, bytes, meta);
      } else {
        await renderFile(pvEl, blob, meta);
      }

      return { success: true };
    });

    function escapeHtml(str) {
      return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function formatSize(bytes) {
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / 1048576).toFixed(1) + ' MB';
    }

    function createToolbar(fname, size, downloadUrl) {
      var toolbar = document.createElement('div');
      toolbar.className = 'pagevault-toolbar';
      toolbar.innerHTML =
        '<span class="toolbar-filename">' + escapeHtml(fname) + '</span>' +
        '<span class="toolbar-size">' + formatSize(size) + '</span>' +
        '<a class="toolbar-btn" href="' + downloadUrl + '" download="' + escapeHtml(fname) + '">Download</a>';
      return toolbar;
    }

    function renderDownloadView(viewer, url, fname, size) {
      viewer.innerHTML =
        '<div class="pagevault-download">' +
          '<div class="pagevault-icon">\u{1F4C4}</div>' +
          '<a href="' + url + '" download="' + escapeHtml(fname) + '">Download ' + escapeHtml(fname) + '</a>' +
          '<div class="file-info">' + formatSize(size) + '</div>' +
        '</div>';
    }

    function __pv_resolveViewer(mime) {
      var viewers = window.__pv_viewers || {};
      if (viewers[mime]) return viewers[mime];
      var prefix = mime.split('/')[0] + '/*';
      if (viewers[prefix]) return viewers[prefix];
      return null;
    }

    async function renderFile(container, blob, meta) {
      var mime = meta.mime || 'application/octet-stream';
      var fname = meta.filename || 'download';
      var size = meta.size || blob.size;
      var url = URL.createObjectURL(blob);

      var toolbar = createToolbar(fname, size, url);
      var viewer = document.createElement('div');
      viewer.className = 'pagevault-viewer';

      var renderFn = __pv_resolveViewer(mime);
      if (renderFn) {
        await renderFn(viewer, blob, url, meta, toolbar);
      } else {
        renderDownloadView(viewer, url, fname, size);
      }

      container.innerHTML = '';
      container.appendChild(toolbar);
      container.appendChild(viewer);
    }

  })();
