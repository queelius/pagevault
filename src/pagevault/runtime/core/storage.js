  // Storage utilities
  const STORAGE_KEY = 'pagevault_passwords';

  function getStoredPasswords() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored) return {};
      const data = JSON.parse(stored);
      // Check expiration
      const now = Date.now();
      const filtered = {};
      for (const [key, value] of Object.entries(data)) {
        if (!value.expires || value.expires > now) {
          filtered[key] = value;
        }
      }
      return filtered;
    } catch {
      return {};
    }
  }

  function storeCredentials(password, username, remember) {
    if (remember === 'none') return;
    const cred = username ? { username, password } : { password };
    if (remember === 'session') {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(cred));
      return;
    }
    const data = getStoredPasswords();
    const expires = CONFIG.rememberDays > 0
      ? Date.now() + (CONFIG.rememberDays * 24 * 60 * 60 * 1000)
      : null;
    data[location.origin] = { ...cred, expires };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  }

  function getStoredCredentials() {
    // Check session first
    const session = sessionStorage.getItem(STORAGE_KEY);
    if (session) {
      try {
        const cred = JSON.parse(session);
        return cred.password ? cred : { password: session };
      } catch {
        return { password: session };
      }
    }
    // Check localStorage
    const data = getStoredPasswords();
    const entry = data[location.origin];
    if (!entry) return null;
    return entry.password ? entry : null;
  }

  function clearStoredPasswords() {
    localStorage.removeItem(STORAGE_KEY);
    sessionStorage.removeItem(STORAGE_KEY);
  }

  // URL fragment handling (only logout — password via URL removed for security)
  function checkFragment() {
    const hash = location.hash.slice(1);
    if (!hash) return null;

    if (hash === 'pagevault_logout') {
      clearStoredPasswords();
      // Navigate without the hash — works on file:// unlike history.replaceState
      location.replace(location.pathname + location.search);
      return 'logout';
    }

    return null;
  }
