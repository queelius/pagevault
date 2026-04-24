  // renderWrapPrompt — render the password prompt form into a <pagevault> element.
  //
  // Arguments:
  //   el         — the <pagevault> container element
  //   isUserMode — true if username input should be shown (data-mode="user")
  //   onSubmit   — async function(password, username) called on form submit.
  //                Must return {success: bool, error?: string}.
  //
  // The prompt renders itself, attaches a submit handler, and auto-focuses
  // the password (or username) field after a short delay.
  //
  // Security note: innerHTML below contains only static template markup;
  // no user-supplied strings are interpolated here. Dynamic values (filenames,
  // error messages) are set via textContent or escapeHtml() at the call site.

  function renderWrapPrompt(el, isUserMode, onSubmit) {
    el.innerHTML = '<div class="pagevault-container">' +
      '<div class="pagevault-icon">\u{1F512}</div>' +
      '<div class="pagevault-title">Protected Content</div>' +
      '<form class="pagevault-form">' +
      (isUserMode ? '<input type="text" class="pagevault-input" placeholder="Username" autocomplete="username">' : '') +
      '<input type="password" class="pagevault-input pagevault-password" placeholder="Password" autocomplete="current-password">' +
      '<button type="submit" class="pagevault-button">Decrypt</button>' +
      '<div class="pagevault-error" style="display: none;"></div>' +
      '</form></div>';

    var form = el.querySelector('form');
    var pwdInput = el.querySelector('.pagevault-password');
    var userInput = el.querySelector('input[placeholder="Username"]');
    var errorDiv = el.querySelector('.pagevault-error');
    var button = el.querySelector('button');

    form.addEventListener('submit', async function(e) {
      e.preventDefault();
      var password = pwdInput.value;
      if (!password) return;
      var username = userInput ? userInput.value : null;

      button.disabled = true;
      button.textContent = 'Decrypting...';
      errorDiv.style.display = 'none';

      var result = await onSubmit(password, username);

      if (!result.success) {
        errorDiv.textContent = result.error || 'Wrong password';
        errorDiv.style.display = 'block';
        button.disabled = false;
        button.textContent = 'Decrypt';
        pwdInput.value = '';
        pwdInput.focus();
      }
    });

    setTimeout(function() {
      var focusTarget = userInput || pwdInput;
      focusTarget.focus();
    }, 100);
  }
