# v3 Chunked Encryption Format

**Date:** 2026-02-17
**Status:** Approved
**Branch:** `feature/streaming-decryption`

## Problem

pagevault v2 encrypts file/site payloads as a single monolithic AES-GCM blob, nested inside three layers of base64 encoding. For an 87MB file:

- `file_bytes` (87MB) -> base64 (116MB) -> JSON `{"c": ..., "m": ...}` -> AES-GCM encrypt -> base64 -> JSON envelope -> base64 = **~198MB HTML output**
- Browser decryption creates 5-6 simultaneous full-size copies: **~700MB peak memory**
- Chrome crashes on files over ~50-80MB

## Solution

v3 format with two key changes:

1. **Encrypt raw bytes, not base64-of-bytes** — eliminates one base64 layer (198MB -> 116MB HTML, 40% smaller)
2. **Per-chunk DOM elements, removed after processing** — peak memory drops from ~700MB to ~120MB

## v3 Wire Format

### HTML Structure

```html
<script id="pv-meta" type="application/json">
{
  "v": 3,
  "alg": "aes-256-gcm",
  "kdf": "pbkdf2-sha256",
  "iter": 310000,
  "salt": "<base64 16-byte salt>",
  "keys": [{"iv": "<base64>", "ct": "<base64>"}],
  "iv_base": "<base64 12-byte base IV>",
  "chunk_size": 1048576,
  "chunk_count": 87,
  "total_size": 91226112,
  "meta_iv": "<base64 12-byte IV>",
  "meta_ct": "<base64 small encrypted JSON metadata>"
}
</script>
<script id="pv-0" type="x-pv">BASE64_OF_ENCRYPTED_CHUNK_0</script>
<script id="pv-1" type="x-pv">BASE64_OF_ENCRYPTED_CHUNK_1</script>
...
<script id="pv-86" type="x-pv">BASE64_OF_ENCRYPTED_CHUNK_86</script>
<!-- Password prompt UI element -->
<pagevault data-pv-chunked="true"></pagevault>
<script data-pagevault-runtime>
  // Crypto + renderer JS (same pattern as v2)
</script>
```

### Metadata Envelope

The `pv-meta` script tag contains:

| Field | Type | Description |
|-------|------|-------------|
| `v` | int | Version: `3` |
| `alg` | string | `"aes-256-gcm"` |
| `kdf` | string | `"pbkdf2-sha256"` |
| `iter` | int | `310000` |
| `salt` | base64 | 16-byte PBKDF2 salt |
| `keys` | array | CEK key blobs (same as v2) |
| `iv_base` | base64 | 12-byte random base IV for chunk derivation |
| `chunk_size` | int | Plaintext bytes per chunk (default: 1,048,576) |
| `chunk_count` | int | Total number of chunks |
| `total_size` | int | Total plaintext size in bytes |
| `meta_iv` | base64 | 12-byte IV for metadata encryption |
| `meta_ct` | base64 | AES-GCM encrypted JSON metadata (filename, mime, type, size) |
| `content_hash` | string | SHA-256 truncated hash of raw plaintext bytes |

### Key Wrapping (unchanged from v2)

- Random CEK (32 bytes)
- PBKDF2-SHA256(secret, salt, 310000 iterations) -> wrapping key
- AES-GCM wrap CEK per user
- `keys[]` array identical to v2

### Chunk IV Derivation

Each chunk `i` uses: `IV = iv_base XOR i` (big-endian in last 4 bytes of the 12-byte IV).

```
iv_base:  [b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11]
chunk 0:  [b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11]         (unchanged)
chunk 1:  [b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11^0x01]
chunk N:  [b0 b1 b2 b3 b4 b5 b6 b7 (b8..b11 XOR N)]
```

This gives 2^32 unique IVs per payload (~4 billion chunks = 4 PB at 1MB chunks).

### Chunk Ciphertext

Each `pv-N` script element contains the base64 encoding of `AES-GCM(cek, chunk_iv, plaintext_chunk)`. The ciphertext includes the 16-byte GCM authentication tag (appended by AES-GCM).

- Chunks 0 through N-2: exactly `chunk_size` bytes of plaintext -> `chunk_size + 16` bytes ciphertext
- Chunk N-1 (last): `remaining` bytes of plaintext -> `remaining + 16` bytes ciphertext

### Encrypted Metadata

Metadata is encrypted separately from content, using a dedicated IV (`meta_iv`) and the same CEK:

```json
{"type": "file", "filename": "report.pdf", "mime": "application/pdf", "size": 91226112}
```

For site mode:
```json
{"type": "site", "entry": "index.html", "files": ["index.html", "style.css", ...]}
```

## Encryption Pipeline (Python)

```
file_bytes (87 MB)
    |
    v
Split into 1 MB chunks: [chunk_0, chunk_1, ..., chunk_86]
    |
    v
For each chunk i:
    iv_i = iv_base XOR i
    ct_i = AES-GCM-encrypt(cek, iv_i, chunk_i)
    b64_i = base64(ct_i)
    |
    v
Emit HTML with one <script> per chunk + metadata envelope
```

Total HTML size: `sum(len(base64(ct_i)))` + small overhead
= `87 MB * (4/3)` + `87 * 16 bytes` (GCM tags) + ~2KB (metadata + runtime JS)
= **~116 MB** (vs 198 MB in v2)

## Decryption Pipeline (Browser JS)

```
1. Parse pv-meta script tag -> JSON
2. PBKDF2(password, salt) -> wrapping key
3. Try unwrap CEK from each key blob (same as v2)
4. Decrypt meta_ct -> {filename, mime, size, type}
5. Show progress bar

6. For i = 0 to chunk_count-1:
     el = document.getElementById('pv-' + i)
     b64 = el.textContent           // ~1.3 MB
     el.remove()                     // Free DOM node -> GC
     ct = Uint8Array(atob(b64))      // ~1 MB
     iv = iv_base XOR i
     plain = AES-GCM-decrypt(cek, iv, ct)  // ~1 MB
     parts.push(plain)
     updateProgress(i + 1, chunk_count)

7. blob = new Blob(parts, {type: mime})
8. Pass blob + metadata to viewer
```

### Memory Profile

```
                    DOM        Heap       Blob (pageable)
Start:              116 MB     ~2 MB      0 MB
Chunk 1 processed:  114.7 MB   ~4 MB      1 MB
Chunk 44 processed:  58 MB     ~4 MB      43 MB
Chunk 87 processed:   0 MB     ~4 MB      87 MB
Viewer rendering:     0 MB     ~4 MB      87 MB
                    ─────────────────────────────
Peak JS heap: ~120 MB  (vs ~700 MB in v2)
```

Browsers handle Blob objects efficiently and can page parts to disk.

## Content Hashing

Content hash is computed on the raw plaintext bytes (before chunking):

```python
hash_value = hashlib.sha256(file_bytes).digest()[:16].hex()
```

Stored in the metadata envelope as `content_hash`. Verified after reassembly:

```javascript
const reassembled = new Blob(parts);
const buffer = await reassembled.arrayBuffer();
const hash = await crypto.subtle.digest('SHA-256', buffer);
// Compare truncated hash with metadata content_hash
```

GCM tags authenticate each chunk individually. The content hash provides end-to-end integrity verification that all chunks assembled correctly.

## Files Changed

| File | Changes |
|------|---------|
| `crypto.py` | Add `encrypt_chunked()` returning metadata + list of chunk ciphertexts. Add `_decrypt_v3()`. Update `decrypt()` to dispatch on version. Update `inspect_payload()` for v3. |
| `wrap.py` | Change `wrap_file()` and `wrap_site()` to use `encrypt_chunked()`. New `_generate_wrap_html_v3()` template emitting per-chunk script tags. New `_get_crypto_js_v3()` with chunked decrypt. New renderer JS with progress bar. |
| `parser.py` | No changes. Region encryption stays v2 (small payloads, no chunking needed). |
| `tests/test_crypto.py` | v3 encrypt/decrypt roundtrips, chunk boundary edge cases, IV derivation correctness, single-chunk files, empty files. |
| `tests/test_wrap.py` | v3 file/site wrap roundtrips, verify per-chunk DOM structure, content hash verification. |
| `tests/test_integration.py` | End-to-end v3 lock/unlock with CLI, large file simulation. |

## Scope Boundaries

**In scope:**
- v3 chunked format for `wrap_file()` and `wrap_site()`
- Progress bar UI during decryption
- Content hash on raw bytes
- `inspect_payload()` / `verify_password()` support for v3
- `rewrap_keys()` for v3 payloads

**Out of scope:**
- Backward compatibility in browser JS (v2 files keep their embedded v2 JS)
- Region encryption changes (parser.py stays v2)
- Streaming within a single AES-GCM chunk (WebCrypto API is atomic)
- True streaming for files larger than available RAM (would require different cipher)

## Verification

```bash
pytest tests/ -v
pytest tests/ -v --cov=pagevault
ruff check src/ tests/
ruff format --check src/ tests/

# Encrypt 87MB file and verify output is ~116MB (not ~198MB)
pagevault lock examples/conversations/index.html --wrap -p test

# Open in browser, verify progress bar and successful decryption
# Verify Chrome doesn't crash
```
