  // Element handler — uses a plain class instead of Custom Elements because
  // the spec requires hyphenated names and <pagevault> has no hyphen.
  // All values set via innerHTML are either:
  //   - escapeHtml()-wrapped user strings (hint, title, placeholder, button text)
  //   - static HTML template literals (form structure, lock icon)
  //   - decrypted content from AES-256-GCM (trusted after authenticated decryption)
  class PagevaultHandler {
    constructor(el) {
      this.el = el;
      this.el._pvDecrypted = false;
      this._render();
      this._tryAutoDecrypt();
    }

    _render() {
      const el = this.el;
      const hint = el.getAttribute('data-hint');
      const title = el.getAttribute('data-title') || CONFIG.title;
      const remember = el.getAttribute('data-remember') || CONFIG.defaultRemember;
      const isUserMode = el.getAttribute('data-mode') === 'user';

      el.innerHTML = `
        <div class="pagevault-container">
          <div class="pagevault-icon">🔒</div>
          <div class="pagevault-title">${escapeHtml(title)}</div>
          ${hint ? `<div class="pagevault-hint">${escapeHtml(hint)}</div>` : ''}
          <form class="pagevault-form">
            ${isUserMode ? `<input type="text" class="pagevault-input pagevault-username" placeholder="${escapeHtml(CONFIG.usernamePlaceholder)}" autocomplete="username">` : ''}
            <input type="password" class="pagevault-input" placeholder="${escapeHtml(CONFIG.placeholder)}" autocomplete="current-password">
            ${remember === 'ask' ? `
              <label class="pagevault-remember">
                <input type="checkbox" name="remember">
                Remember on this device
              </label>
            ` : ''}
            <button type="submit" class="pagevault-button">${escapeHtml(CONFIG.buttonText)}</button>
            <div class="pagevault-error" style="display: none;"></div>
          </form>
        </div>
      `;

      const form = el.querySelector('form');
      const passwordInput = el.querySelector('input[type="password"]');
      const usernameInput = el.querySelector('.pagevault-username');
      const error = el.querySelector('.pagevault-error');

      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = passwordInput.value;
        if (!password) return;
        const username = usernameInput ? usernameInput.value : null;

        // Capture checkbox state BEFORE decryption replaces innerHTML
        const rememberCheckbox = el.querySelector('input[name="remember"]');
        const wantsRemember = remember === 'local' || (rememberCheckbox && rememberCheckbox.checked);

        const button = el.querySelector('button');
        button.disabled = true;
        button.textContent = 'Decrypting...';

        const success = await this._decrypt(password, username);

        if (!success) {
          error.textContent = CONFIG.errorText;
          error.style.display = 'block';
          button.disabled = false;
          button.textContent = CONFIG.buttonText;
          passwordInput.value = '';
          passwordInput.focus();
        } else {
          // Store credentials if requested
          if (wantsRemember) {
            storeCredentials(password, username, 'local');
          } else if (remember === 'session') {
            storeCredentials(password, username, 'session');
          }
        }
      });

      // Focus appropriate input if auto-prompt
      if (CONFIG.autoPrompt) {
        const focusTarget = usernameInput || passwordInput;
        setTimeout(() => focusTarget.focus(), 100);
      }
    }

    async _tryAutoDecrypt() {
      // Check URL fragment (only logout supported)
      const fragment = checkFragment();
      if (fragment === 'logout') return;

      // Try stored credentials
      const cred = getStoredCredentials();
      if (cred) {
        await this._decrypt(cred.password, cred.username || null);
      }
    }

    async _decrypt(password, username) {
      const el = this.el;
      const encrypted = el.getAttribute('data-encrypted');
      if (!encrypted) return false;

      const expectedHash = el.getAttribute('data-content-hash');

      const result = await decryptContent(encrypted, password, username);
      if (result === null) return false;

      // Strip null-byte padding (from --pad option during lock)
      const content = result.content.replace(/\0+$/, '');
      const meta = result.meta;

      // Verify content hash if present
      if (expectedHash) {
        const actualHash = await computeHash(content);
        if (actualHash !== expectedHash) {
          console.error('Content hash mismatch - decryption may be corrupted');
          return false;
        }
      }

      // Remove encrypted attributes and reveal content
      el.removeAttribute('data-encrypted');
      el.removeAttribute('data-content-hash');
      el.removeAttribute('data-mode');
      // Decrypted content is trusted — it was authenticated by AES-256-GCM
      // (user encrypted their own content; AES-GCM provides authenticity)
      el.innerHTML = content;
      el._pvDecrypted = true;

      // Fire decrypted event immediately — content is in the DOM,
      // listeners that just need to know "the content is here" don't
      // wait for script activation. A separate pagevault:activated
      // event fires after all scripts have run.
      el.dispatchEvent(new CustomEvent('pagevault:decrypted', {
        bubbles: true,
        detail: { element: el, meta: meta }
      }));

      // Serialize script activation across handlers via a page-level
      // promise chain. Global shims (document.addEventListener,
      // document.write, etc.) cannot be safely interleaved across
      // concurrent decryptions, so we ensure only one activation runs
      // at a time. See __pvActivateContent for the activation routine.
      __pvActivationChain = __pvActivationChain.then(function() {
        return new Promise(function(resolve) {
          __pvActivateContent(el, meta, resolve);
        });
      });

      return true;
    }
  }

  // Initialize all encrypted <pagevault> elements.
  // Wrapped in DOMContentLoaded since the script is in <head> but the
  // elements are in <body> — they don't exist yet at script parse time.
  function initAll() {
    document.querySelectorAll('pagevault[data-encrypted]').forEach(function(el) {
      if (!el._pvHandler) {
        el._pvHandler = new PagevaultHandler(el);
      }
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAll);
  } else {
    initAll();
  }
