  // v4 chunked crypto helpers for region + wrap decryption.
  //
  // Usage:
  //   const result = await decryptV4(envelope, chunks, password, username, onProgress);
  //   // result is {bytes: Uint8Array, meta: object} or null on failure.
  //
  // The envelope is the parsed JSON from a <script data-pv-meta>/<script id="pv-meta"> tag.
  // chunks is an ordered array of base64 strings (region callers pass
  // the chunk text content; wrap callers typically collect from the DOM
  // and remove each element after decryption to free memory).

  function _hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  function _b64ToBytes(b64) {
    const raw = atob(b64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes;
  }

  function _deriveChunkIv(ivBase, chunkIndex) {
    const iv = new Uint8Array(ivBase);
    iv[8]  ^= (chunkIndex >>> 24) & 0xFF;
    iv[9]  ^= (chunkIndex >>> 16) & 0xFF;
    iv[10] ^= (chunkIndex >>> 8)  & 0xFF;
    iv[11] ^=  chunkIndex         & 0xFF;
    return iv;
  }

  async function _deriveKey(secret, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(secret), 'PBKDF2', false, ['deriveBits', 'deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: 310000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  // Content integrity hash used by region decryption to verify
  // meta.content_hash against the decrypted text. Matches Python's
  // content_hash(): first 16 bytes of SHA-256(utf-8(content)) as hex.
  async function computeHash(content) {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hashBuffer).slice(0, 16);
    return Array.from(hashArray, b => b.toString(16).padStart(2, '0')).join('');
  }

  async function decryptV4(envelope, chunks, password, username, onProgress) {
    try {
      if (envelope.v !== 4) {
        throw new Error('Unsupported envelope version: ' + envelope.v);
      }

      const salt = _hexToBytes(envelope.salt);
      const secret = username ? username + ':' + password : password;
      const wrappingKey = await _deriveKey(secret, salt);

      // Unwrap CEK — try each key blob until one succeeds.
      let cekRaw = null;
      for (const keyBlob of envelope.keys) {
        const blobIv = _b64ToBytes(keyBlob.iv);
        const blobCt = _b64ToBytes(keyBlob.ct);
        try {
          cekRaw = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: blobIv }, wrappingKey, blobCt
          );
          break;
        } catch (e) { continue; }
      }
      if (!cekRaw) throw new Error('No matching key found — wrong password?');

      const cek = await crypto.subtle.importKey(
        'raw', cekRaw, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
      );

      // Decrypt metadata (independent of chunks).
      const metaIv = _b64ToBytes(envelope.meta_iv);
      const metaCt = _b64ToBytes(envelope.meta_ct);
      const metaPlain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: metaIv }, cek, metaCt
      );
      const meta = JSON.parse(new TextDecoder().decode(metaPlain));

      // Decrypt chunks.
      const ivBase = _b64ToBytes(envelope.iv_base);
      const parts = [];
      let totalLen = 0;
      for (let i = 0; i < envelope.chunk_count; i++) {
        const b64 = chunks[i];
        if (typeof b64 !== 'string') {
          throw new Error('Missing chunk ' + i);
        }
        const ct = _b64ToBytes(b64);
        const chunkIv = _deriveChunkIv(ivBase, i);
        const plain = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: chunkIv }, cek, ct
        );
        const plainBytes = new Uint8Array(plain);
        parts.push(plainBytes);
        totalLen += plainBytes.length;
        if (onProgress) onProgress(i + 1, envelope.chunk_count);
      }

      // Concatenate chunks into one contiguous Uint8Array.
      const bytes = new Uint8Array(totalLen);
      let offset = 0;
      for (const p of parts) {
        bytes.set(p, offset);
        offset += p.length;
      }

      return { bytes: bytes, meta: meta };
    } catch (e) {
      console.error('v4 decryption failed:', e);
      return null;
    }
  }
