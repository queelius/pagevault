  // Crypto utilities
  async function computeHash(content) {
    // Compute truncated SHA-256 hash for integrity verification
    // Must match Python's content_hash() implementation
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    // Truncate to first 16 bytes (128 bits) to match Python implementation
    const hashArray = new Uint8Array(hashBuffer).slice(0, 16);
    return Array.from(hashArray, b => b.toString(16).padStart(2, '0')).join('');
  }

  async function deriveKey(secret, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 310000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  async function decryptContent(encryptedBase64, password, username) {
    try {
      // Decode outer base64
      const jsonStr = atob(encryptedBase64);
      const data = JSON.parse(jsonStr);

      // Validate version
      if (data.v !== 2) throw new Error('Unsupported version: ' + data.v);

      // Decode components
      const salt = Uint8Array.from(atob(data.salt), c => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(data.iv), c => c.charCodeAt(0));
      const ct = Uint8Array.from(atob(data.ct), c => c.charCodeAt(0));

      // Build secret: "username:password" or just "password"
      const secret = username ? username + ':' + password : password;

      // ONE PBKDF2 derivation with shared salt
      const wrappingKey = await deriveKey(secret, salt);

      // Try each key blob to recover CEK
      let cek = null;
      for (const keyBlob of data.keys) {
        const blobIv = Uint8Array.from(atob(keyBlob.iv), c => c.charCodeAt(0));
        const blobCt = Uint8Array.from(atob(keyBlob.ct), c => c.charCodeAt(0));
        try {
          const rawCek = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: blobIv },
            wrappingKey,
            blobCt
          );
          cek = rawCek;
          break;
        } catch (e) {
          // Wrong key blob, try next
          continue;
        }
      }

      if (!cek) throw new Error('No matching key found');

      // Import recovered CEK
      const cekKey = await crypto.subtle.importKey(
        'raw',
        cek,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      // Decrypt content with CEK
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        cekKey,
        ct
      );

      // Parse inner JSON wrapper
      const inner = JSON.parse(new TextDecoder().decode(decrypted));
      return { content: inner.c, meta: inner.m || null };
    } catch (e) {
      console.error('Decryption failed:', e);
      return null;
    }
  }
