  // Remembered keys.
  //
  // "Remember" never stores a password. It stores the key the password
  // derives for one salt (deriveWrappingBits in crypto.js), which opens
  // pages locked with that password and salt and reveals nothing else, so a
  // password reused on other sites is not exposed by remembering it here.
  //
  //   'local'   — IndexedDB, as a non-extractable CryptoKey: page script can
  //               use it, but cannot read its bytes, and it expires after
  //               CONFIG.rememberDays (0 = never).
  //   'session' — sessionStorage, which holds only strings, so the raw key
  //               bytes (base64); gone when the tab closes.
  //
  // Entries are keyed by the envelope's salt (hex), so pages locked with
  // the same config share one entry. Storage that is unavailable (blocked
  // cookies, private windows, browsers without IndexedDB on file://) just
  // means nothing is remembered.
  const KEY_DB_NAME = 'pagevault';
  const KEY_STORE = 'keys';
  const SESSION_KEYS = 'pagevault_keys';
  // Where pagevault <= 0.4.2 stored plaintext passwords; purged on sight.
  const LEGACY_PASSWORDS = 'pagevault_passwords';

  function purgeLegacyPasswords() {
    // Separately: one storage throwing must not spare the other's copy.
    try { localStorage.removeItem(LEGACY_PASSWORDS); } catch (e) { /* unavailable */ }
    try { sessionStorage.removeItem(LEGACY_PASSWORDS); } catch (e) { /* unavailable */ }
  }

  // Open the key database at its current version, creating the store if
  // it is missing. Any same-origin page (for file://, any local HTML file)
  // can create a "pagevault" database without it; opening that at a fixed
  // version would never upgrade, so a missing store is repaired by opening
  // one version higher. Resolves to null when IndexedDB is unusable.
  function _openKeyDb(version) {
    return new Promise(function(resolve) {
      try {
        const req = version ? indexedDB.open(KEY_DB_NAME, version)
                            : indexedDB.open(KEY_DB_NAME);
        req.onupgradeneeded = function() {
          if (!req.result.objectStoreNames.contains(KEY_STORE)) {
            req.result.createObjectStore(KEY_STORE, { keyPath: 'salt' });
          }
        };
        req.onsuccess = function() {
          const db = req.result;
          // Let another tab's repair upgrade proceed.
          db.onversionchange = function() { db.close(); };
          if (db.objectStoreNames.contains(KEY_STORE)) {
            resolve(db);
            return;
          }
          db.close();
          resolve(version ? null : _openKeyDb(db.version + 1));
        };
        req.onerror = function() { resolve(null); };
        req.onblocked = function() { resolve(null); };
      } catch (e) {
        resolve(null);
      }
    });
  }

  // Run fn(store) in one transaction; resolves to the result of the request
  // fn returns (if any), or null on any failure.
  async function _withKeyStore(mode, fn) {
    const db = await _openKeyDb();
    if (!db) return null;
    return new Promise(function(resolve) {
      try {
        const tx = db.transaction(KEY_STORE, mode);
        const req = fn(tx.objectStore(KEY_STORE));
        tx.oncomplete = function() { db.close(); resolve(req ? req.result : null); };
        tx.onerror = tx.onabort = function() { db.close(); resolve(null); };
      } catch (e) {
        db.close();
        resolve(null);
      }
    });
  }

  function _readSessionKeys() {
    try {
      return JSON.parse(sessionStorage.getItem(SESSION_KEYS) || '{}') || {};
    } catch (e) {
      return {};
    }
  }

  function _bytesToB64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  // Remember the key derived for saltHex. bits is deriveWrappingBits' output.
  async function rememberKey(saltHex, bits, remember) {
    if (remember === 'session') {
      try {
        const keys = _readSessionKeys();
        keys[saltHex] = _bytesToB64(new Uint8Array(bits));
        sessionStorage.setItem(SESSION_KEYS, JSON.stringify(keys));
      } catch (e) { /* storage unavailable */ }
      return;
    }
    if (remember !== 'local') return;
    const key = await importWrappingKey(bits);
    const expires = CONFIG.rememberDays > 0
      ? Date.now() + (CONFIG.rememberDays * 24 * 60 * 60 * 1000)
      : null;
    await _withKeyStore('readwrite', function(store) {
      store.put({ salt: saltHex, key: key, expires: expires });
    });
  }

  // The remembered key for saltHex as a CryptoKey, or null.
  async function recallKey(saltHex) {
    const b64 = _readSessionKeys()[saltHex];
    if (typeof b64 === 'string') {
      try {
        return await importWrappingKey(_b64ToBytes(b64));
      } catch (e) { /* malformed entry: fall through */ }
    }
    const entry = await _withKeyStore('readonly', function(store) {
      return store.get(saltHex);
    });
    if (!entry || !(entry.key instanceof CryptoKey)) return null;
    if (entry.expires && entry.expires <= Date.now()) {
      await forgetKey(saltHex);
      return null;
    }
    return entry.key;
  }

  // Only expiry forgets a key. One that fails to open a page is kept: pages
  // sharing a salt can still differ in password or user list, and a retry
  // costs one AES unwrap, not a PBKDF2.
  async function forgetKey(saltHex) {
    try {
      const keys = _readSessionKeys();
      if (saltHex in keys) {
        delete keys[saltHex];
        sessionStorage.setItem(SESSION_KEYS, JSON.stringify(keys));
      }
    } catch (e) { /* storage unavailable */ }
    await _withKeyStore('readwrite', function(store) { store.delete(saltHex); });
  }

  async function forgetAllKeys() {
    purgeLegacyPasswords();
    try { sessionStorage.removeItem(SESSION_KEYS); } catch (e) { /* unavailable */ }
    await _withKeyStore('readwrite', function(store) { store.clear(); });
  }

  // URL fragment handling (only logout — password via URL removed for security)
  async function checkFragment() {
    const hash = location.hash.slice(1);
    if (!hash) return null;

    if (hash === 'pagevault_logout') {
      await forgetAllKeys();
      // Navigate without the hash — works on file:// unlike history.replaceState
      location.replace(location.pathname + location.search);
      return 'logout';
    }

    return null;
  }
