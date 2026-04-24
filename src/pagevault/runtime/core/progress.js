  // createProgressBar — create a chunked-decryption progress bar.
  //
  // Arguments:
  //   container — the DOM element to append the progress bar into.
  //
  // Returns an object with:
  //   update(done, total) — update bar to done/total percentage
  //   remove()            — remove bar from DOM
  //
  // Only creates the progress bar if chunk_count > 1 (single-chunk files
  // don't need it). The returned object is always safe to call regardless.

  function createProgressBar(container) {
    var progressContainer = document.createElement('div');
    progressContainer.className = 'pagevault-progress';
    var progressBar = document.createElement('div');
    progressBar.className = 'pagevault-progress-bar';
    progressBar.style.width = '0%';
    progressContainer.appendChild(progressBar);
    container.appendChild(progressContainer);

    return {
      update: function(done, total) {
        var pct = Math.round((done / total) * 100);
        progressBar.style.width = pct + '%';
        progressBar.textContent = pct + '%';
      },
      remove: function() {
        progressContainer.remove();
      }
    };
  }
