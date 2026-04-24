# pagevault v4 Envelope Format

This document specifies the v4 encrypted envelope format used by pagevault
starting with version 0.4.0. v4 unifies the formerly separate v2
(attribute-embedded) and v3 (chunked, file/site) formats into a single
chunked envelope with a `meta.kind` discriminator for region / file / site.

**Breaking change from v0.3.x:** v0.3.x encrypted files (v2 regions and v3
wraps) cannot be decrypted by v0.4.0. Users must re-lock.

## Cryptographic Parameters

| Parameter    | Value                      |
|--------------|----------------------------|
| Algorithm    | AES-256-GCM                |
| KDF          | PBKDF2-HMAC-SHA256         |
| Iterations   | 310,000                    |
| Salt length  | 16 bytes (128 bits)        |
| IV length    | 12 bytes (96 bits)         |
| Key length   | 32 bytes (256 bits)        |
| Chunk size   | 1,048,576 bytes (1 MiB)    |
| Hash length  | 16 bytes (truncated SHA-256) |

## Envelope JSON

```json
{
  "v": 4,
  "alg": "aes-256-gcm",
  "kdf": "pbkdf2-sha256",
  "iter": 310000,
  "salt": "<hex, 16 bytes>",
  "iv_base": "<base64, 12 bytes>",
  "chunk_size": 1048576,
  "chunk_count": N,
  "total_size": <original_bytes_length>,
  "meta_iv": "<base64, 12 bytes>",
  "meta_ct": "<base64, encrypted JSON metadata>",
  "keys": [
    {"iv": "<base64, 12 bytes>", "ct": "<base64, wrapped CEK>"}
  ]
}
```

### Field semantics

- `v`: Always `4`. Any other value must be rejected.
- `alg`, `kdf`, `iter`: Identify the primitives. Implementations may hard-code
  these and reject other values.
- `salt`: Hex-encoded PBKDF2 salt.
- `iv_base`: Base64-encoded 12-byte IV prefix. Per-chunk IVs are derived by
  XORing the chunk index (big-endian 32-bit) into bytes 8-11 of `iv_base`.
  Chunk 0 uses `iv_base` unchanged (XOR with 0).
- `chunk_size`: Declared chunk size for cleartext (last chunk may be smaller).
- `chunk_count`: Number of ciphertext chunks.
- `total_size`: Original plaintext length in bytes. Used to detect truncation.
- `meta_iv` / `meta_ct`: Metadata encrypted independently from the content
  chunks, under the same CEK, so metadata can be obtained without touching
  all chunks.
- `keys`: Array of per-user wrapped CEKs. Each entry is `{iv, ct}` where `iv`
  is the AES-GCM IV and `ct` is the ciphertext of the CEK. Both are
  base64-encoded.

### Key wrapping

The Content Encryption Key (CEK) is a random 32-byte value. For each
credential (single-password or per-user `{username: password}`), a wrapping
key is derived as:

```
secret = username ? username + ":" + password : password
wrapping_key = PBKDF2-SHA256(secret, salt, 310000, 32)
```

The CEK is AES-256-GCM-encrypted under `wrapping_key` with a random IV,
producing one `{iv, ct}` entry in `keys`.

## Encrypted metadata JSON

Encrypted separately (`meta_iv`, `meta_ct`), the metadata is a JSON object:

```json
{
  "kind": "html_fragment" | "file" | "site",
  "filename": "report.pdf",
  "mime": "application/pdf",
  "entry": "index.html",
  "content_hash": "<hex, 16 bytes>",
  "encrypted_at": "2026-04-24T00:00:00Z",
  "version": "0.4.0"
}
```

### Kind discriminator

- `html_fragment`: Encrypted region inside a page. Plaintext is HTML text.
- `file`: Single wrapped file. Plaintext is the raw file bytes.
- `site`: Directory bundled as a zip. Plaintext is a zip archive.

### Fields by kind

| Field          | html_fragment | file   | site   |
|----------------|---------------|--------|--------|
| `kind`         | required      | required | required |
| `filename`     | -             | required | -      |
| `mime`         | -             | required | -      |
| `entry`        | -             | -      | required |
| `content_hash` | optional      | optional | optional |
| `encrypted_at` | optional      | optional | optional |
| `version`      | optional      | optional | optional |

`content_hash` is the first 16 bytes of `SHA-256(plaintext)`, hex-encoded.
When present, decryptors verify it matches the decrypted bytes.

## HTML Serialization

### Regions (`kind = "html_fragment"`)

```html
<pagevault data-pv-v4>
  <script type="application/json" data-pv-meta>{envelope JSON}</script>
  <script type="x-pv" data-pv-chunk="0">{base64 chunk 0}</script>
  <script type="x-pv" data-pv-chunk="1">{base64 chunk 1}</script>
  <!-- ...additional chunks... -->
</pagevault>
```

Attributes on `<pagevault>`:

- `data-pv-v4`: Marks the element as a v4-encrypted region. Always present.
- `data-mode="user"`: Present iff multi-user mode.
- `data-hint`, `data-title`, `data-remember`: Preserved from `hint`, `title`,
  `remember` attributes on the pre-lock element.

### Files (`kind = "file"`) and Sites (`kind = "site"`)

Wrap outputs continue to use the document-level script layout introduced in
v3, with the version field bumped to 4:

```html
<script id="pv-meta" type="application/json">{envelope JSON}</script>
<script id="pv-0" type="x-pv">{base64 chunk 0}</script>
<script id="pv-1" type="x-pv">{base64 chunk 1}</script>
<!-- ... -->
<pagevault data-pv-v4></pagevault>
```

The (empty) `<pagevault>` element acts as the render target. The wrap
runtime reads `<script id="pv-meta">` and `<script id="pv-N">` directly.

## Chunking and IV derivation

Plaintext is split into consecutive `chunk_size`-byte chunks (the last may be
smaller). For chunk at index `i`:

```
chunk_iv = iv_base[0:8] || (iv_base[8:12] XOR be32(i))
chunk_ct = AES-256-GCM-Encrypt(cek, chunk_iv, chunk_pt, aad="")
```

`chunk_iv` for `i = 0` is `iv_base` unchanged. Chunks are reassembled by
concatenating decrypted plaintexts in chunk-index order. Resulting length
must equal `total_size`.

## Security notes

- The `keys` array is independent of the chunk stream: a user can be added
  or revoked (via `sync --rekey` or equivalent) by re-wrapping the CEK
  without re-encrypting content.
- The per-chunk IV scheme uses the first 8 bytes of `iv_base` as a nonce
  prefix; the last 4 bytes are the chunk counter. 2^32 chunks per envelope
  is the hard cap; pagevault raises earlier since 1 MiB chunks at 2^32 would
  exceed filesystem limits.
- AES-GCM per-key IV reuse is catastrophic; each envelope generates a fresh
  random `iv_base`, so envelope-to-envelope IV reuse cannot occur.
- Metadata confidentiality: `filename`, `mime`, `entry`, `content_hash` are
  all encrypted. Only the envelope parameters, `chunk_count`, `total_size`,
  and the presence of a wrapping for each user are observable without a
  valid credential.
