  // pagevault site renderer — decrypts a ZIP and renders it as an iframe site.
  //
  // Fix #2 (listener leak): The message listener is registered at MODULE SCOPE
  // (below), not inside __pagevault_renderSite. On repeated calls the function
  // only updates module-level state variables that the single listener reads.
  //
  // Fix #5 (overbroad regex): The "rewrite quoted strings that match known resource
  // paths" regex pass has been DELETED. It matched arbitrary string literals in JS
  // (e.g. comparison values, JSON keys) and corrupted them by replacing them with
  // data URIs. Users needing dynamic JS resource references should use fetch(),
  // which is handled by the fetch shim injected into srcdoc iframes.

  (function() {
    'use strict';

    function escapeHtml(str) {
      return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Strip ?query and #fragment from a URL. Used wherever we need the
    // path-only form for resolving against the in-memory resource map.
    function stripQueryHash(s) {
      return s.split('#')[0].split('?')[0];
    }

    // Module-level state — populated by __pagevault_renderSite on each call.
    // The single message listener (below) reads these instead of closure variables.
    var _site_iframe = null;
    var _site_resources = null;
    var _site_htmlFiles = null;
    var _site_currentPage = null;
    var _site_entry = null;

    // --- Single module-scope message listener (Fix #2) ---
    window.addEventListener('message', function(e) {
      if (_site_iframe === null || e.source !== _site_iframe.contentWindow) return;
      if (!e.data || !e.data.type) return;
      if (e.data.type === 'pagevault-nav') {
        var clean = stripQueryHash(e.data.href);
        if (!clean) return;
        var target = resolvePath(_site_currentPage, clean);
        if (_site_htmlFiles && _site_htmlFiles.has(target)) {
          renderPage(target);
        }
      } else if (e.data.type === 'pagevault-fetch') {
        var resolved = resolvePath(_site_currentPage, stripQueryHash(e.data.path));
        var r = _site_resources && _site_resources[resolved];
        var response = {
          type: 'pagevault-fetch-response',
          id: e.data.id,
          data: r ? toDataUri(resolved) : null
        };
        if (r) response.mime = r.mime;
        _site_iframe.contentWindow.postMessage(response, '*');
      }
    });

    window.__pagevault_renderSite = async function(container, zipBytes, meta) {
      _site_entry = meta.entry || 'index.html';

      try {
        var zip = new window.__pagevault_ZipReader(zipBytes.buffer);
        var fileNames = zip.getFileNames();

        // Load all files and build resource map
        _site_resources = {};
        _site_htmlFiles = new Set();

        for (var fi = 0; fi < fileNames.length; fi++) {
          var name = fileNames[fi];
          var data = await zip.getFile(name);
          if (!data) continue;
          var ext = name.split('.').pop().toLowerCase();
          var mime = getMimeForExt(ext);
          _site_resources[name] = { data: data, mime: mime, uri: null };
          if (mime === 'text/html') _site_htmlFiles.add(name);
        }

        // Create iframe — no sandbox (user-trusted content)
        container.innerHTML = '';
        _site_iframe = document.createElement('iframe');
        _site_iframe.className = 'pagevault-site-frame';
        container.appendChild(_site_iframe);

        // Shim pushState/replaceState after iframe loads to prevent
        // SecurityError when opened from file:// (srcdoc = about:srcdoc URL)
        _site_iframe.addEventListener('load', function() {
          try {
            var h = _site_iframe.contentWindow.history;
            var ps = h.pushState.bind(h);
            var rs = h.replaceState.bind(h);
            h.pushState = function() { try { return ps.apply(h, arguments); } catch(e2) {} };
            h.replaceState = function() { try { return rs.apply(h, arguments); } catch(e2) {} };
          } catch(e2) {}
        });

        // Load entry page
        if (!renderPage(_site_entry)) {
          container.innerHTML = '<div class="pagevault-error">Entry point not found: ' + escapeHtml(_site_entry) + '</div>';
        }
      } catch (e) {
        container.innerHTML = '<div class="pagevault-error">Failed to load site: ' + escapeHtml(e.message) + '</div>';
      }
    };

    function renderPage(pageName) {
      var html = getHtml(pageName);
      if (!html) return false;
      _site_currentPage = pageName;
      html = rewriteUrls(html, pageName);
      html = injectNavScript(html);
      // Use srcdoc so iframe inherits parent origin — needed for
      // localStorage, blob URLs, etc. under file:// protocol.
      _site_iframe.srcdoc = html;
      return true;
    }

    // Lazily convert binary data to data URI (cached)
    function toDataUri(name) {
      var r = _site_resources[name];
      if (!r) return null;
      if (!r.uri) r.uri = 'data:' + r.mime + ';base64,' + uint8ToBase64(r.data);
      return r.uri;
    }

    // Get HTML file content as text
    function getHtml(name) {
      var r = _site_resources[name];
      if (!r) return null;
      return new TextDecoder().decode(r.data);
    }

    // Rewrite resource URLs in HTML to data URIs
    function rewriteUrls(html, fromPage) {
      var attrPattern = /(src|href|srcset|poster|action)=(["'])([^"']+?)\2/gi;
      html = html.replace(attrPattern, function(match, attr, quote, url) {
        if (url.startsWith('http://') || url.startsWith('https://') ||
            url.startsWith('//') || url.startsWith('data:') ||
            url.startsWith('#') || url.startsWith('javascript:') ||
            url.startsWith('mailto:')) {
          return match;
        }
        // Handle srcset: multiple URLs with descriptors
        if (attr.toLowerCase() === 'srcset') {
          var entries = url.split(',');
          var rewritten = entries.map(function(entry) {
            var parts = entry.trim().split(/\s+/);
            var src = parts[0];
            var descriptor = parts.slice(1).join(' ');
            var resolved = resolvePath(fromPage, stripQueryHash(src));
            var uri = toDataUri(resolved);
            if (uri) return uri + (descriptor ? ' ' + descriptor : '');
            return entry.trim();
          });
          return attr + '=' + quote + rewritten.join(', ') + quote;
        }
        var resolved = resolvePath(fromPage, stripQueryHash(url));
        // Leave <a href> to HTML pages alone — nav interceptor handles them
        if (attr.toLowerCase() === 'href' && _site_htmlFiles.has(resolved)) {
          return match;
        }
        var uri = toDataUri(resolved);
        if (uri) return attr + '=' + quote + uri + quote;
        return match;
      });

      // Rewrite CSS url() references
      html = html.replace(/url\((['"]?)([^)'"]+?)\1\)/gi, function(match, quote, url) {
        if (url.startsWith('http://') || url.startsWith('https://') ||
            url.startsWith('data:') || url.startsWith('#')) {
          return match;
        }
        var resolved = resolvePath(fromPage, url);
        var uri = toDataUri(resolved);
        if (uri) return 'url(' + quote + uri + quote + ')';
        return match;
      });

      // Rewrite CSS @import with bare string syntax
      html = html.replace(/@import\s+(['"])([^'"]+?)\1/gi, function(match, quote, url) {
        if (url.startsWith('http://') || url.startsWith('https://') ||
            url.startsWith('data:')) {
          return match;
        }
        var resolved = resolvePath(fromPage, url);
        var uri = toDataUri(resolved);
        if (uri) return '@import ' + quote + uri + quote;
        return match;
      });

      // NOTE: The "rewrite quoted strings that match known resource paths" pass
      // that was previously here has been deleted (Fix #5). It was too broad:
      // it matched arbitrary JS string literals used for comparisons, JSON keys,
      // etc. and corrupted them by replacing them with data URIs. For dynamic
      // JS resource loading, use fetch() — the fetch shim injected by
      // injectNavScript() intercepts relative fetch() calls and resolves them
      // via postMessage to the parent frame's resource map.

      return html;
    }

    // injectNavScript is defined by nav_injector.js, which is included
    // before site_renderer.js in the build_wrap_js assembly order.

    function resolvePath(fromPage, href) {
      if (!href) return fromPage;
      // Handle absolute paths (strip leading / since zip paths don't have it)
      if (href.startsWith('/')) {
        return href.substring(1);
      }
      href = href.replace(/^\.\//g, '');
      // Get directory of the referring page
      var parts = fromPage.split('/');
      parts.pop();
      var segments = href.split('/');
      for (var i = 0; i < segments.length; i++) {
        if (segments[i] === '..') parts.pop();
        else if (segments[i] !== '.' && segments[i] !== '') parts.push(segments[i]);
      }
      return parts.length ? parts.join('/') : href;
    }

    function getMimeForExt(ext) {
      var mimes = {
        html: 'text/html', htm: 'text/html',
        css: 'text/css', js: 'text/javascript',
        json: 'application/json', xml: 'application/xml',
        png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
        gif: 'image/gif', svg: 'image/svg+xml', webp: 'image/webp',
        ico: 'image/x-icon',
        pdf: 'application/pdf',
        woff: 'font/woff', woff2: 'font/woff2',
        ttf: 'font/ttf', eot: 'application/vnd.ms-fontobject',
        mp4: 'video/mp4', webm: 'video/webm',
        mp3: 'audio/mpeg', ogg: 'audio/ogg',
        txt: 'text/plain', md: 'text/markdown',
      };
      return mimes[ext] || 'application/octet-stream';
    }

    function uint8ToBase64(data) {
      var binary = '';
      var len = data.length;
      for (var i = 0; i < len; i += 8192) {
        binary += String.fromCharCode.apply(null, data.subarray(i, Math.min(i + 8192, len)));
      }
      return btoa(binary);
    }

  })();
