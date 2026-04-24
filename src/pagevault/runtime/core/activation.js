// === Script activation infrastructure ===
  // Snapshot the original page methods ONCE at runtime load. All handlers
  // share these — concurrent decryption is serialized via __pvActivationChain
  // so the shims always restore the true originals, never another handler's shim.
  var __pvOrigDocAddListener = document.addEventListener.bind(document);
  var __pvOrigWinAddListener = window.addEventListener.bind(window);
  var __pvOrigDocWrite = document.write.bind(document);
  var __pvOrigDocWriteln = document.writeln.bind(document);
  var __pvActivationChain = Promise.resolve();

  // Re-execute scripts in a decrypted region. The browser does not run
  // <script> tags inserted via innerHTML, so we re-create each one.
  // Inline scripts run synchronously on replaceChild; external scripts
  // (with src) load asynchronously — we wait for onload before the next.
  // Lifecycle events (DOMContentLoaded, load) already fired before
  // decryption, so we shim them, collect callbacks, and fire after
  // activation. Errors in any script are caught and logged so the
  // shims always restore via the finally block.
  function __pvActivateContent(el, meta, done) {
    var origOnload = window.onload;  // snapshot for change-detection
    var dclCallbacks = [];
    var wlCallbacks = [];

    // Install shims (page-wide for the duration of activation)
    document.write = function(s) {
      if (s) console.warn('[pagevault] document.write() suppressed during activation:', s);
    };
    document.writeln = function(s) {
      if (s) console.warn('[pagevault] document.writeln() suppressed during activation:', s);
    };
    document.addEventListener = function(type, fn, opts) {
      if (type === 'DOMContentLoaded') dclCallbacks.push(fn);
      else __pvOrigDocAddListener(type, fn, opts);
    };
    window.addEventListener = function(type, fn, opts) {
      if (type === 'load') wlCallbacks.push(fn);
      else __pvOrigWinAddListener(type, fn, opts);
    };

    function restoreShims() {
      document.addEventListener = __pvOrigDocAddListener;
      window.addEventListener = __pvOrigWinAddListener;
      document.write = __pvOrigDocWrite;
      document.writeln = __pvOrigDocWriteln;
    }

    // Permissive JS MIME-type detection (matches HTML spec)
    function isExecutable(s) {
      var t = (s.getAttribute('type') || '').toLowerCase();
      if (!t) return true;
      if (t === 'module') return true;
      return /javascript|ecmascript|jscript/.test(t);
    }

    var scripts = Array.from(el.querySelectorAll('script'));

    function finalize() {
      restoreShims();
      dclCallbacks.forEach(function(fn) {
        try { fn(); } catch(e) { console.error('[pagevault] DOMContentLoaded callback error:', e); }
      });
      wlCallbacks.forEach(function(fn) {
        try { fn(); } catch(e) { console.error('[pagevault] load callback error:', e); }
      });
      // Only re-fire onload if a decrypted script REPLACED it
      if (typeof window.onload === 'function' && window.onload !== origOnload) {
        try { window.onload(new Event('load')); } catch(e) { console.error('[pagevault] onload error:', e); }
      }
      el.dispatchEvent(new CustomEvent('pagevault:activated', {
        bubbles: true,
        detail: { element: el, meta: meta }
      }));
      done();
    }

    function activateNext(i) {
      try {
        // Loop through synchronous (inline) scripts; only recurse on async boundary
        while (i < scripts.length) {
          var old = scripts[i];
          if (!isExecutable(old)) { i++; continue; }
          if (!old.parentNode) { i++; continue; }  // ancestor was removed by an earlier script
          var s = document.createElement('script');
          for (var j = 0; j < old.attributes.length; j++) {
            var a = old.attributes[j];
            s.setAttribute(a.name, a.value);
          }
          var hasSrc = old.hasAttribute('src');
          if (!hasSrc && old.textContent) s.textContent = old.textContent;
          if (hasSrc) {
            // Capture index and src in IIFE so closures don't share mutated state
            (function(idx, srcUrl) {
              s.onload = function() { activateNext(idx + 1); };
              s.onerror = function() {
                console.error('[pagevault] Failed to load:', srcUrl);
                activateNext(idx + 1);
              };
            })(i, old.getAttribute('src'));
            old.parentNode.replaceChild(s, old);
            return;  // suspend until onload/onerror fires
          }
          old.parentNode.replaceChild(s, old);
          i++;
        }
        finalize();
      } catch (e) {
        console.error('[pagevault] script activation error:', e);
        try { finalize(); } catch(_) {}
      }
    }

    activateNext(0);
  }
