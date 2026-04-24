  // readV4FromScope — collect encrypted envelope + chunk texts from the DOM.
  //
  // Supports two layouts:
  //   Region format: <script data-pv-meta> + <script data-pv-chunk="N"> siblings
  //                  inside a <pagevault> element.
  //   Wrap format:   <script id="pv-meta"> + <script id="pv-N"> at document level.
  //
  // Arguments:
  //   scope — the element to search within (a <pagevault> el for region;
  //            document for wrap).
  //
  // Returns {envelope, chunks} where envelope is the parsed JSON object and
  // chunks is an ordered array of base64 strings, or null if the meta script
  // is not found.  Each chunk element is removed from the DOM after being read
  // to free memory.

  function readV4FromScope(scope) {
    // --- Locate meta script ---
    var metaScript = null;

    // Region layout: direct child with data-pv-meta attribute
    if (scope.querySelector) {
      metaScript = scope.querySelector('script[data-pv-meta]');
    }
    // Wrap layout fallback: <script id="pv-meta"> anywhere in document
    if (!metaScript) {
      metaScript = document.getElementById('pv-meta');
    }
    if (!metaScript) return null;

    var envelope;
    try {
      envelope = JSON.parse(metaScript.textContent);
    } catch (e) {
      console.error('[pagevault] Invalid pv-meta JSON:', e);
      return null;
    }

    var chunks = [];

    // --- Collect chunks: region layout (data-pv-chunk attribute) ---
    var chunkTags = [];
    if (scope.querySelectorAll) {
      var tagged = scope.querySelectorAll('script[data-pv-chunk]');
      for (var i = 0; i < tagged.length; i++) {
        var el = tagged[i];
        var idx = parseInt(el.getAttribute('data-pv-chunk'), 10);
        if (!Number.isNaN(idx)) {
          chunkTags.push([idx, el.textContent || '', el]);
        }
      }
    }

    if (chunkTags.length > 0) {
      // Sort by index and extract text; remove each element to free memory.
      chunkTags.sort(function(a, b) { return a[0] - b[0]; });
      for (var j = 0; j < chunkTags.length; j++) {
        chunks.push(chunkTags[j][1]);
        chunkTags[j][2].remove();
      }
    } else {
      // --- Wrap layout fallback: <script id="pv-N"> ---
      var count = envelope.chunk_count || 0;
      for (var k = 0; k < count; k++) {
        var chunkEl = document.getElementById('pv-' + k);
        if (!chunkEl) {
          console.error('[pagevault] Missing chunk element pv-' + k);
          return null;
        }
        chunks.push(chunkEl.textContent || '');
        chunkEl.remove();
      }
    }

    return { envelope: envelope, chunks: chunks };
  }
