# v3 Chunked Encryption Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace monolithic AES-GCM encryption in file/site wrapping with chunked format that reduces browser peak memory from ~700MB to ~120MB for large files.

**Architecture:** New `encrypt_chunked()` splits raw file bytes into 1MB chunks with counter-derived IVs. HTML template emits one `<script>` per chunk so the browser can process-and-discard each element. Metadata is encrypted separately. Region encryption (parser.py) stays v2.

**Tech Stack:** Python `cryptography` library (AES-GCM), WebCrypto API (browser), BeautifulSoup (test parsing)

---

### Task 1: Chunked Encryption Core (crypto.py)

**Files:**
- Modify: `src/pagevault/crypto.py`
- Test: `tests/test_crypto.py`

**Step 1: Write the failing tests**

Add a new `TestChunkedEncryption` class to `tests/test_crypto.py`:

```python
from pagevault.crypto import (
    CHUNK_SIZE,
    VERSION_V3,
    _derive_chunk_iv,
    decrypt_chunked,
    encrypt_chunked,
    # ... existing imports ...
)


class TestChunkIvDerivation:
    """Tests for _derive_chunk_iv helper."""

    def test_chunk_0_equals_base(self):
        """Chunk 0 IV equals the base IV (XOR with 0 is identity)."""
        iv_base = os.urandom(12)
        assert _derive_chunk_iv(iv_base, 0) == iv_base

    def test_chunk_ivs_are_unique(self):
        """Different chunk indices produce different IVs."""
        iv_base = os.urandom(12)
        ivs = {_derive_chunk_iv(iv_base, i).hex() for i in range(100)}
        assert len(ivs) == 100

    def test_xor_last_4_bytes(self):
        """IV derivation XORs chunk index into last 4 bytes (big-endian)."""
        iv_base = b'\x00' * 12
        iv_1 = _derive_chunk_iv(iv_base, 1)
        assert iv_1 == b'\x00' * 11 + b'\x01'

        iv_256 = _derive_chunk_iv(iv_base, 256)
        assert iv_256 == b'\x00' * 10 + b'\x01\x00'


class TestChunkedEncryption:
    """Tests for v3 chunked encrypt/decrypt."""

    def test_basic_roundtrip(self):
        """Encrypt bytes then decrypt, verify roundtrip."""
        data = b"Hello, World! This is test content."
        envelope, chunks = encrypt_chunked(data, password="test-pw")
        result_data, result_meta = decrypt_chunked(envelope, chunks, "test-pw")
        assert result_data == data

    def test_single_chunk(self):
        """Data smaller than chunk_size produces exactly one chunk."""
        data = b"small"
        envelope, chunks = encrypt_chunked(data, password="pw")
        assert envelope["chunk_count"] == 1
        assert len(chunks) == 1

    def test_exact_chunk_boundary(self):
        """Data exactly equal to chunk_size produces one chunk."""
        data = b"x" * CHUNK_SIZE
        envelope, chunks = encrypt_chunked(data, password="pw")
        assert envelope["chunk_count"] == 1
        assert len(chunks) == 1

    def test_two_chunks(self):
        """Data slightly over chunk_size produces two chunks."""
        data = b"x" * (CHUNK_SIZE + 1)
        envelope, chunks = encrypt_chunked(data, password="pw")
        assert envelope["chunk_count"] == 2
        assert len(chunks) == 2

    def test_large_data_roundtrip(self):
        """Roundtrip with multiple chunks."""
        data = os.urandom(CHUNK_SIZE * 3 + 500)
        envelope, chunks = encrypt_chunked(data, password="pw")
        assert envelope["chunk_count"] == 4
        result_data, _ = decrypt_chunked(envelope, chunks, "pw")
        assert result_data == data

    def test_empty_data(self):
        """Empty bytes encrypt and decrypt correctly."""
        data = b""
        envelope, chunks = encrypt_chunked(data, password="pw")
        assert envelope["chunk_count"] == 0
        assert len(chunks) == 0
        result_data, _ = decrypt_chunked(envelope, chunks, "pw")
        assert result_data == b""

    def test_envelope_fields(self):
        """Envelope dict contains all required v3 fields."""
        data = b"test"
        envelope, _ = encrypt_chunked(data, password="pw")
        assert envelope["v"] == 3
        assert envelope["alg"] == "aes-256-gcm"
        assert envelope["kdf"] == "pbkdf2-sha256"
        assert envelope["iter"] == 310000
        assert "salt" in envelope
        assert "keys" in envelope
        assert "iv_base" in envelope
        assert envelope["chunk_size"] == CHUNK_SIZE
        assert envelope["chunk_count"] == 1
        assert envelope["total_size"] == 4
        assert "meta_iv" in envelope
        assert "meta_ct" in envelope

    def test_metadata_encrypted(self):
        """Metadata is encrypted and recoverable."""
        data = b"test"
        meta = {"type": "file", "filename": "test.txt", "mime": "text/plain"}
        envelope, chunks = encrypt_chunked(data, password="pw", meta=meta)
        _, result_meta = decrypt_chunked(envelope, chunks, "pw")
        assert result_meta == meta

    def test_wrong_password_fails(self):
        """Decryption with wrong password raises error."""
        data = b"secret"
        envelope, chunks = encrypt_chunked(data, password="correct")
        with pytest.raises(PagevaultError, match="wrong password"):
            decrypt_chunked(envelope, chunks, "wrong")

    def test_multiuser_roundtrip(self):
        """Multi-user encrypt then decrypt as each user."""
        data = b"shared content"
        users = {"alice": "pw-a", "bob": "pw-b"}
        envelope, chunks = encrypt_chunked(data, users=users)

        data_a, _ = decrypt_chunked(envelope, chunks, "pw-a", username="alice")
        data_b, _ = decrypt_chunked(envelope, chunks, "pw-b", username="bob")
        assert data_a == data
        assert data_b == data

    def test_explicit_salt(self):
        """Explicit salt is used in envelope."""
        from pagevault.crypto import generate_salt, salt_to_hex
        salt = generate_salt()
        data = b"test"
        envelope, _ = encrypt_chunked(data, password="pw", salt=salt)
        assert envelope["salt"] == salt_to_hex(salt)

    def test_custom_chunk_size(self):
        """Custom chunk_size is respected."""
        data = b"x" * 100
        envelope, chunks = encrypt_chunked(
            data, password="pw", chunk_size=30
        )
        assert envelope["chunk_size"] == 30
        assert envelope["chunk_count"] == 4  # ceil(100/30)
        assert len(chunks) == 4
        result, _ = decrypt_chunked(envelope, chunks, "pw")
        assert result == data

    def test_different_ciphertext_each_time(self):
        """Same data produces different ciphertext (random IV + CEK)."""
        data = b"same content"
        _, chunks1 = encrypt_chunked(data, password="pw")
        _, chunks2 = encrypt_chunked(data, password="pw")
        assert chunks1 != chunks2
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_crypto.py::TestChunkIvDerivation -v && pytest tests/test_crypto.py::TestChunkedEncryption -v`
Expected: ImportError or FAIL (functions don't exist yet)

**Step 3: Implement in crypto.py**

Add these constants and functions to `src/pagevault/crypto.py`:

```python
# After existing constants:
VERSION_V3 = 3
CHUNK_SIZE = 1_048_576  # 1 MB


def _derive_chunk_iv(iv_base: bytes, chunk_index: int) -> bytes:
    """Derive chunk IV by XORing chunk index into last 4 bytes of base IV.

    Args:
        iv_base: 12-byte base IV.
        chunk_index: 0-based chunk index.

    Returns:
        12-byte derived IV for this chunk.
    """
    iv = bytearray(iv_base)
    # XOR chunk_index (big-endian uint32) into last 4 bytes
    iv[8] ^= (chunk_index >> 24) & 0xFF
    iv[9] ^= (chunk_index >> 16) & 0xFF
    iv[10] ^= (chunk_index >> 8) & 0xFF
    iv[11] ^= chunk_index & 0xFF
    return bytes(iv)


def encrypt_chunked(
    data: bytes,
    password: str | None = None,
    salt: bytes | None = None,
    users: dict[str, str] | None = None,
    meta: dict | None = None,
    chunk_size: int = CHUNK_SIZE,
) -> tuple[dict, list[str]]:
    """Encrypt raw bytes using v3 chunked format.

    Splits data into chunks, encrypts each with a counter-derived IV.
    Metadata is encrypted separately.

    Args:
        data: Raw bytes to encrypt.
        password: Single password for encryption.
        salt: Optional 16-byte salt.
        users: Dict of {username: password} for multi-user.
        meta: Optional metadata dict (encrypted separately).
        chunk_size: Plaintext bytes per chunk (default 1MB).

    Returns:
        Tuple of (envelope_dict, chunk_base64_list).
        envelope_dict has all fields needed for the pv-meta script tag.
        chunk_base64_list has one base64 string per encrypted chunk.
    """
    if password is not None and users is not None:
        raise PagevaultError("Cannot specify both 'password' and 'users'")
    if password is None and users is None:
        raise PagevaultError("Must specify either 'password' or 'users'")

    if salt is None:
        salt = os.urandom(SALT_LENGTH)
    elif len(salt) != SALT_LENGTH:
        raise PagevaultError(f"Salt must be {SALT_LENGTH} bytes")

    # Generate CEK and base IV
    cek = os.urandom(KEY_LENGTH)
    iv_base = os.urandom(IV_LENGTH)

    # Build key blobs (identical to v2)
    keys = []
    if users:
        for username, user_password in users.items():
            secret = _build_secret(user_password, username)
            wrapping_key = _derive_key(secret, salt)
            wrap_iv, wrap_ct = _wrap_key(cek, wrapping_key)
            keys.append({
                "iv": base64.b64encode(wrap_iv).decode("ascii"),
                "ct": base64.b64encode(wrap_ct).decode("ascii"),
            })
    else:
        secret = _build_secret(password)
        wrapping_key = _derive_key(secret, salt)
        wrap_iv, wrap_ct = _wrap_key(cek, wrapping_key)
        keys.append({
            "iv": base64.b64encode(wrap_iv).decode("ascii"),
            "ct": base64.b64encode(wrap_ct).decode("ascii"),
        })

    # Encrypt metadata separately
    meta_iv = os.urandom(IV_LENGTH)
    meta_json = json.dumps(meta or {}).encode("utf-8")
    aesgcm = AESGCM(cek)
    meta_ct = aesgcm.encrypt(meta_iv, meta_json, None)

    # Split data into chunks and encrypt each
    chunk_b64_list = []
    total_size = len(data)

    if total_size > 0:
        for i in range(0, total_size, chunk_size):
            chunk_data = data[i:i + chunk_size]
            chunk_iv = _derive_chunk_iv(iv_base, i // chunk_size)
            chunk_ct = aesgcm.encrypt(chunk_iv, chunk_data, None)
            chunk_b64_list.append(
                base64.b64encode(chunk_ct).decode("ascii")
            )

    chunk_count = len(chunk_b64_list)

    envelope = {
        "v": VERSION_V3,
        "alg": ALGORITHM,
        "kdf": KDF,
        "iter": ITERATIONS,
        "salt": salt.hex(),
        "keys": keys,
        "iv_base": base64.b64encode(iv_base).decode("ascii"),
        "chunk_size": chunk_size,
        "chunk_count": chunk_count,
        "total_size": total_size,
        "meta_iv": base64.b64encode(meta_iv).decode("ascii"),
        "meta_ct": base64.b64encode(meta_ct).decode("ascii"),
    }

    return envelope, chunk_b64_list


def decrypt_chunked(
    envelope: dict,
    chunks: list[str],
    password: str,
    username: str | None = None,
) -> tuple[bytes, dict]:
    """Decrypt v3 chunked payload.

    Args:
        envelope: Metadata dict from encrypt_chunked.
        chunks: List of base64-encoded chunk ciphertexts.
        password: Decryption password.
        username: Optional username for multi-user.

    Returns:
        Tuple of (raw_bytes, metadata_dict).

    Raises:
        PagevaultError: If decryption fails.
    """
    if envelope.get("v") != VERSION_V3:
        raise PagevaultError(f"Expected v3, got v{envelope.get('v')}")

    # Recover salt
    try:
        salt = bytes.fromhex(envelope["salt"])
    except (ValueError, KeyError) as e:
        raise PagevaultError(f"Invalid salt in envelope: {e}") from e

    # Unwrap CEK (same as v2)
    secret = _build_secret(password, username)
    wrapping_key = _derive_key(secret, salt)

    cek = None
    for key_blob in envelope.get("keys", []):
        try:
            blob_iv = base64.b64decode(key_blob["iv"])
            blob_ct = base64.b64decode(key_blob["ct"])
        except Exception:
            continue
        result = _unwrap_key(blob_iv, blob_ct, wrapping_key)
        if result is not None:
            cek = result
            break

    if cek is None:
        raise PagevaultError(
            "Decryption failed: wrong password or tampered ciphertext"
        )

    aesgcm = AESGCM(cek)

    # Decrypt metadata
    try:
        meta_iv = base64.b64decode(envelope["meta_iv"])
        meta_ct = base64.b64decode(envelope["meta_ct"])
        meta_bytes = aesgcm.decrypt(meta_iv, meta_ct, None)
        meta = json.loads(meta_bytes.decode("utf-8"))
    except Exception as e:
        raise PagevaultError(f"Failed to decrypt metadata: {e}") from e

    # Decrypt chunks
    iv_base = base64.b64decode(envelope["iv_base"])
    chunk_size = envelope["chunk_size"]
    total_size = envelope["total_size"]

    if total_size == 0:
        return b"", meta

    parts = []
    for i, chunk_b64 in enumerate(chunks):
        chunk_iv = _derive_chunk_iv(iv_base, i)
        try:
            chunk_ct = base64.b64decode(chunk_b64)
            chunk_data = aesgcm.decrypt(chunk_iv, chunk_ct, None)
        except Exception as e:
            raise PagevaultError(
                f"Failed to decrypt chunk {i}: {e}"
            ) from e
        parts.append(chunk_data)

    return b"".join(parts), meta
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_crypto.py::TestChunkIvDerivation tests/test_crypto.py::TestChunkedEncryption -v`
Expected: All PASS

**Step 5: Run full crypto test suite for regressions**

Run: `pytest tests/test_crypto.py -v`
Expected: All PASS (v2 tests unchanged)

**Step 6: Lint**

Run: `ruff check src/pagevault/crypto.py tests/test_crypto.py && ruff format --check src/pagevault/crypto.py tests/test_crypto.py`

**Step 7: Commit**

```bash
git add src/pagevault/crypto.py tests/test_crypto.py
git commit -m "feat: add v3 chunked encryption in crypto.py

Adds encrypt_chunked() and decrypt_chunked() with counter-derived
chunk IVs. Metadata encrypted separately from content chunks.
Key wrapping identical to v2."
```

---

### Task 2: Content Hash for Bytes + inspect/verify v3 (crypto.py)

**Files:**
- Modify: `src/pagevault/crypto.py`
- Test: `tests/test_crypto.py`

**Step 1: Write the failing tests**

```python
from pagevault.crypto import content_hash_bytes


class TestContentHashBytes:
    """Tests for content_hash_bytes (raw bytes variant)."""

    def test_hash_length(self):
        result = content_hash_bytes(b"test content")
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic(self):
        data = b"Hello, world!"
        assert content_hash_bytes(data) == content_hash_bytes(data)

    def test_different_data(self):
        assert content_hash_bytes(b"A") != content_hash_bytes(b"B")

    def test_empty_bytes(self):
        result = content_hash_bytes(b"")
        assert len(result) == 32
        assert result == "e3b0c44298fc1c149afbf4c8996fb924"

    def test_matches_string_variant_for_utf8(self):
        """For UTF-8 encodable strings, both hash functions agree."""
        text = "Hello World"
        assert content_hash(text) == content_hash_bytes(text.encode("utf-8"))


class TestInspectPayloadV3:
    """Tests for inspect_payload with v3 chunked payloads."""

    def test_inspect_v3(self):
        data = b"x" * 100
        envelope, _ = encrypt_chunked(data, password="pw")
        # inspect_payload_v3 takes the envelope dict directly
        info = inspect_payload_v3(envelope)
        assert info["version"] == 3
        assert info["algorithm"] == "aes-256-gcm"
        assert info["chunk_count"] == 1
        assert info["chunk_size"] == CHUNK_SIZE
        assert info["total_size"] == 100
        assert info["key_count"] == 1

    def test_inspect_v3_multiuser(self):
        data = b"test"
        users = {"alice": "pw-a", "bob": "pw-b"}
        envelope, _ = encrypt_chunked(data, users=users)
        info = inspect_payload_v3(envelope)
        assert info["key_count"] == 2


class TestVerifyPasswordV3:
    """Tests for verify_password_v3 with chunked payloads."""

    def test_correct_password(self):
        envelope, _ = encrypt_chunked(b"secret", password="correct")
        assert verify_password_v3(envelope, "correct") is True

    def test_wrong_password(self):
        envelope, _ = encrypt_chunked(b"secret", password="correct")
        assert verify_password_v3(envelope, "wrong") is False

    def test_multiuser(self):
        envelope, _ = encrypt_chunked(
            b"shared", users={"alice": "pw-a", "bob": "pw-b"}
        )
        assert verify_password_v3(envelope, "pw-a", username="alice") is True
        assert verify_password_v3(envelope, "pw-b", username="bob") is True
        assert verify_password_v3(envelope, "pw-a", username="bob") is False
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_crypto.py::TestContentHashBytes tests/test_crypto.py::TestInspectPayloadV3 tests/test_crypto.py::TestVerifyPasswordV3 -v`
Expected: ImportError

**Step 3: Implement**

Add to `src/pagevault/crypto.py`:

```python
def content_hash_bytes(data: bytes) -> str:
    """Compute truncated SHA-256 hash of raw bytes."""
    digest = hashlib.sha256(data).digest()
    return digest[:HASH_LENGTH].hex()


def inspect_payload_v3(envelope: dict) -> dict[str, Any]:
    """Inspect a v3 chunked envelope dict without decrypting."""
    return {
        "version": envelope.get("v"),
        "algorithm": envelope.get("alg", "unknown"),
        "kdf": envelope.get("kdf", "unknown"),
        "iterations": envelope.get("iter", 0),
        "key_count": len(envelope.get("keys", [])),
        "chunk_size": envelope.get("chunk_size", 0),
        "chunk_count": envelope.get("chunk_count", 0),
        "total_size": envelope.get("total_size", 0),
    }


def verify_password_v3(
    envelope: dict,
    password: str,
    username: str | None = None,
) -> bool:
    """Verify password against a v3 envelope (key unwrap only)."""
    if envelope.get("v") != VERSION_V3:
        raise PagevaultError(f"Expected v3, got v{envelope.get('v')}")

    try:
        salt = bytes.fromhex(envelope["salt"])
    except (ValueError, KeyError) as e:
        raise PagevaultError(f"Invalid salt: {e}") from e

    secret = _build_secret(password, username)
    wrapping_key = _derive_key(secret, salt)

    for key_blob in envelope.get("keys", []):
        try:
            blob_iv = base64.b64decode(key_blob["iv"])
            blob_ct = base64.b64decode(key_blob["ct"])
        except Exception:
            continue
        if _unwrap_key(blob_iv, blob_ct, wrapping_key) is not None:
            return True
    return False
```

**Step 4: Run tests**

Run: `pytest tests/test_crypto.py -v`
Expected: All PASS

**Step 5: Lint + Commit**

```bash
ruff check src/pagevault/crypto.py tests/test_crypto.py
ruff format --check src/pagevault/crypto.py tests/test_crypto.py
git add src/pagevault/crypto.py tests/test_crypto.py
git commit -m "feat: add content_hash_bytes, inspect_payload_v3, verify_password_v3"
```

---

### Task 3: v3 HTML Template Generation (wrap.py)

**Files:**
- Modify: `src/pagevault/wrap.py`
- Test: `tests/test_wrap.py`

This is the largest task — it creates the new HTML template that emits per-chunk `<script>` elements and the browser-side v3 crypto + renderer JS.

**Step 1: Write the failing tests**

Add to `tests/test_wrap.py`:

```python
from pagevault.wrap import _generate_wrap_html_v3


class TestGenerateWrapHtmlV3:
    """Tests for v3 chunked HTML template generation."""

    def test_has_pv_meta_script(self):
        """Output HTML contains a pv-meta script tag with JSON envelope."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 1, "keys": []},
            chunks=["AAAA"],
            title="Protected: test.txt",
            viewers=[],
        )
        soup = BeautifulSoup(html, "html.parser")
        meta_script = soup.find("script", {"id": "pv-meta"})
        assert meta_script is not None
        assert meta_script.get("type") == "application/json"

    def test_has_chunk_script_tags(self):
        """Each chunk gets its own script element with id pv-N."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 3, "keys": []},
            chunks=["chunk0", "chunk1", "chunk2"],
            title="Protected: file",
            viewers=[],
        )
        soup = BeautifulSoup(html, "html.parser")
        for i in range(3):
            el = soup.find("script", {"id": f"pv-{i}"})
            assert el is not None
            assert el.get("type") == "x-pv"
            assert el.string.strip() == f"chunk{i}"

    def test_has_pagevault_element(self):
        """Output has a <pagevault> element for the password prompt."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 0, "keys": []},
            chunks=[],
            title="Protected: test",
            viewers=[],
        )
        soup = BeautifulSoup(html, "html.parser")
        pv = soup.find("pagevault")
        assert pv is not None
        assert pv.get("data-pv-chunked") == "true"

    def test_has_runtime_scripts(self):
        """Output includes crypto and renderer runtime scripts."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 1, "keys": []},
            chunks=["AAAA"],
            title="Protected: test.txt",
            viewers=[],
        )
        assert "decryptV3Chunked" in html
        assert "crypto.subtle" in html
        assert "PBKDF2" in html

    def test_has_progress_bar(self):
        """Output includes progress bar CSS and JS."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 1, "keys": []},
            chunks=["AAAA"],
            title="Protected: test",
            viewers=[],
        )
        assert "pagevault-progress" in html

    def test_title_escaped(self):
        """Title with HTML special chars is escaped."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 0, "keys": []},
            chunks=[],
            title='Protected: <script>alert("xss")</script>',
            viewers=[],
        )
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_no_data_encrypted_attribute(self):
        """v3 does NOT use data-encrypted attribute (chunks are in script tags)."""
        html = _generate_wrap_html_v3(
            envelope={"v": 3, "chunk_count": 1, "keys": []},
            chunks=["AAAA"],
            title="Protected: test",
            viewers=[],
        )
        assert 'data-encrypted="' not in html
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_wrap.py::TestGenerateWrapHtmlV3 -v`
Expected: ImportError

**Step 3: Implement `_generate_wrap_html_v3` and JS generators**

Add to `src/pagevault/wrap.py`:

- `_generate_wrap_html_v3(envelope, chunks, title, config, users, viewers, viewer_deps, include_jszip, entry)` — builds the HTML template with per-chunk script tags
- `_get_crypto_js_v3()` — browser-side v3 decrypt with progress callback
- `_get_renderer_js_v3(viewers)` — renderer with progress bar UI
- `_get_site_renderer_js_v3()` — site renderer (same as v2 but called after v3 decrypt)

The implementation is large (JS code in f-strings). Key structural elements:

1. **pv-meta script tag** with `JSON.stringify(envelope)`
2. **pv-0 through pv-N script tags** with chunk base64 data
3. **pagevault element** with `data-pv-chunked="true"` (no data-encrypted)
4. **Crypto JS** with `decryptV3Chunked(envelope, password, username, onProgress)`
5. **Renderer JS** with progress bar that shows `chunk X/N (Y%)`
6. **CSS** for `.pagevault-progress` bar

I will not write the full JS here (it's ~200 lines of f-string JS). The exact code should follow the pseudocode in `docs/plans/2026-02-17-streaming-decryption-design.md` section "Decryption Pipeline (Browser JS)".

**Step 4: Run tests**

Run: `pytest tests/test_wrap.py::TestGenerateWrapHtmlV3 -v`
Expected: All PASS

**Step 5: Lint + Commit**

```bash
ruff check src/pagevault/wrap.py tests/test_wrap.py
ruff format --check src/pagevault/wrap.py tests/test_wrap.py
git add src/pagevault/wrap.py tests/test_wrap.py
git commit -m "feat: add v3 HTML template with per-chunk script tags and progress bar"
```

---

### Task 4: wrap_file v3 Integration (wrap.py)

**Files:**
- Modify: `src/pagevault/wrap.py` (wrap_file function)
- Test: `tests/test_wrap.py`

**Step 1: Write the failing tests**

```python
class TestWrapFileV3:
    """Tests for wrap_file using v3 chunked format."""

    def test_basic_wrap_produces_chunk_tags(self, tmp_path):
        """wrap_file output has per-chunk script tags, not data-encrypted."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        output = wrap_file(test_file, password="password")
        content = output.read_text()

        # v3: has chunk script tags
        soup = BeautifulSoup(content, "html.parser")
        assert soup.find("script", {"id": "pv-meta"}) is not None
        assert soup.find("script", {"id": "pv-0"}) is not None
        # v3: no data-encrypted attribute
        pv = soup.find("pagevault")
        assert pv is not None
        assert not pv.has_attr("data-encrypted")
        assert pv.get("data-pv-chunked") == "true"

    def test_roundtrip_via_python_decrypt(self, tmp_path):
        """wrap_file output can be decrypted by Python (parse envelope + chunks)."""
        test_file = tmp_path / "secret.txt"
        test_file.write_text("Secret data!")

        output = wrap_file(test_file, password="test-pw")
        content = output.read_text()

        # Extract envelope and chunks from HTML
        soup = BeautifulSoup(content, "html.parser")
        import json
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        from pagevault.crypto import decrypt_chunked
        data, meta = decrypt_chunked(envelope, chunks, "test-pw")
        assert data == b"Secret data!"
        assert meta["filename"] == "secret.txt"
        assert meta["mime"] == "text/plain"
        assert meta["type"] == "file"

    def test_output_smaller_than_v2(self, tmp_path):
        """v3 output should be smaller than v2 would be (no inner base64)."""
        test_file = tmp_path / "large.bin"
        test_file.write_bytes(b"x" * 10000)

        output = wrap_file(test_file, password="pw")
        v3_size = output.stat().st_size

        # v2 would base64-encode the data inside encrypt(), then base64 again
        # for the HTML attribute. v3 skips one layer.
        # v3 should be roughly 4/3 * 10000 + overhead ≈ 14KB
        # v2 would be roughly (4/3)^2 * 10000 + overhead ≈ 18KB
        # Just verify v3 is reasonable (not 2x the input)
        assert v3_size < 10000 * 2  # Well under 2x input size

    def test_binary_file_roundtrip(self, tmp_path):
        """Binary file survives wrap+decrypt roundtrip byte-for-byte."""
        test_file = tmp_path / "image.png"
        original_bytes = b"\x89PNG\r\n\x1a\n" + os.urandom(500)
        test_file.write_bytes(original_bytes)

        output = wrap_file(test_file, password="pw")

        soup = BeautifulSoup(output.read_text(), "html.parser")
        import json
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        from pagevault.crypto import decrypt_chunked
        data, meta = decrypt_chunked(envelope, chunks, "pw")
        assert data == original_bytes
        assert meta["mime"] == "image/png"

    def test_content_hash_present(self, tmp_path):
        """v3 envelope includes content_hash."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hash me")

        output = wrap_file(test_file, password="pw")
        soup = BeautifulSoup(output.read_text(), "html.parser")
        import json
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        assert "content_hash" in envelope
        assert len(envelope["content_hash"]) == 32

    def test_title_shows_protected(self, tmp_path):
        """HTML title says 'Protected: filename'."""
        test_file = tmp_path / "report.pdf"
        test_file.write_bytes(b"%PDF-1.4")

        output = wrap_file(test_file, password="pw")
        content = output.read_text()
        assert "<title>Protected: report.pdf</title>" in content
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_wrap.py::TestWrapFileV3 -v`
Expected: FAIL (wrap_file still uses v2)

**Step 3: Modify `wrap_file` to use v3**

Change `wrap_file()` in `src/pagevault/wrap.py`:

```python
def wrap_file(file_path, password=None, config=None, output_path=None,
              users=None, pad=False):
    file_path = Path(file_path)
    if not file_path.is_file():
        raise PagevaultError(f"File not found: {file_path}")

    try:
        file_bytes = file_path.read_bytes()
    except OSError as e:
        raise PagevaultError(f"Cannot read file {file_path}: {e}") from e

    mime = detect_mime(file_path)

    meta = {
        "type": "file",
        "filename": file_path.name,
        "mime": mime,
        "size": len(file_bytes),
    }

    salt = config.salt if config else None
    hash_value = content_hash_bytes(file_bytes)

    # Apply content padding if requested
    use_pad = pad or (config and config.pad)
    if use_pad:
        file_bytes = pad_content_bytes(file_bytes)

    # v3 chunked encryption (raw bytes, no base64 wrapping)
    envelope, chunks = encrypt_chunked(
        file_bytes, password=password, salt=salt, users=users, meta=meta,
    )
    envelope["content_hash"] = hash_value

    # ... output path, viewer discovery, HTML generation ...
    # Call _generate_wrap_html_v3 instead of _generate_wrap_html
```

Also add `pad_content_bytes` to crypto.py (pads raw bytes to power-of-2).
Also add `content_hash_bytes` import to wrap.py.

**Step 4: Run tests**

Run: `pytest tests/test_wrap.py::TestWrapFileV3 -v`
Expected: All PASS

**Step 5: Fix any failing existing tests**

Run: `pytest tests/test_wrap.py -v`

Some existing `TestWrapFile` tests will fail because they look for `data-encrypted` attribute. Update them to parse v3 structure:
- `test_encrypted_payload_is_decryptable`: change to extract pv-meta + pv-N
- `test_wrap_with_content_hash`: check envelope instead of attribute
- `test_wrap_large_file`: update extraction logic
- `test_html_is_self_contained`: update assertions

**Step 6: Lint + Commit**

```bash
ruff check src/pagevault/wrap.py src/pagevault/crypto.py tests/test_wrap.py
git add src/pagevault/wrap.py src/pagevault/crypto.py tests/test_wrap.py
git commit -m "feat: switch wrap_file to v3 chunked format

Eliminates inner base64 layer. Output HTML ~40% smaller.
Browser can process-and-discard chunks for low memory usage."
```

---

### Task 5: wrap_site v3 Integration (wrap.py)

**Files:**
- Modify: `src/pagevault/wrap.py` (wrap_site function)
- Test: `tests/test_wrap.py`

**Step 1: Write the failing tests**

```python
class TestWrapSiteV3:
    """Tests for wrap_site using v3 chunked format."""

    def test_site_produces_chunk_tags(self, tmp_path):
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Hi</body></html>")

        output = wrap_site(site_dir, password="pw")
        soup = BeautifulSoup(output.read_text(), "html.parser")
        assert soup.find("script", {"id": "pv-meta"}) is not None
        assert soup.find("script", {"id": "pv-0"}) is not None

    def test_site_roundtrip(self, tmp_path):
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<h1>Hello</h1>")
        (site_dir / "style.css").write_text("body { margin: 0; }")

        output = wrap_site(site_dir, password="pw")
        soup = BeautifulSoup(output.read_text(), "html.parser")

        import json
        envelope = json.loads(soup.find("script", {"id": "pv-meta"}).string)
        chunks = []
        i = 0
        while True:
            el = soup.find("script", {"id": f"pv-{i}"})
            if not el:
                break
            chunks.append(el.string.strip())
            i += 1

        from pagevault.crypto import decrypt_chunked
        data, meta = decrypt_chunked(envelope, chunks, "pw")

        assert meta["type"] == "site"
        assert meta["entry"] == "index.html"
        assert "index.html" in meta["files"]
        assert "style.css" in meta["files"]

        # Verify zip content
        import zipfile
        from io import BytesIO
        with zipfile.ZipFile(BytesIO(data)) as zf:
            assert zf.read("index.html") == b"<h1>Hello</h1>"

    def test_site_includes_jszip_and_site_renderer(self, tmp_path):
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html>Hi</html>")

        output = wrap_site(site_dir, password="pw")
        content = output.read_text()
        assert "ZipReader" in content
        assert "__pagevault_renderSite" in content
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_wrap.py::TestWrapSiteV3 -v`

**Step 3: Modify `wrap_site` to use v3**

Same pattern as wrap_file: call `encrypt_chunked` with raw zip bytes instead of `encrypt` with base64-encoded zip.

**Step 4: Fix existing site tests, run full suite**

Run: `pytest tests/test_wrap.py -v`

**Step 5: Lint + Commit**

```bash
git add src/pagevault/wrap.py tests/test_wrap.py
git commit -m "feat: switch wrap_site to v3 chunked format"
```

---

### Task 6: CLI Updates (info, check for v3)

**Files:**
- Modify: `src/pagevault/cli.py`
- Test: `tests/test_cli.py`

**Step 1: Write the failing tests**

```python
class TestInfoV3:
    """Tests for 'pagevault info' on v3 wrapped files."""

    def test_info_v3_file(self, runner, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello!")
        config_path = tmp_path / ".pagevault.yaml"
        config_path.write_text('password: "pw"\nsalt: "0123456789abcdef0123456789abcdef"')

        output = tmp_path / "test.html"
        runner.invoke(main, ["lock", str(test_file), "-c", str(config_path),
                             "-o", str(output)])
        assert output.exists()

        result = runner.invoke(main, ["info", str(output)])
        assert result.exit_code == 0
        assert "v3" in result.output
        assert "chunk" in result.output.lower()


class TestCheckV3:
    """Tests for 'pagevault check' on v3 wrapped files."""

    def test_check_v3_correct_password(self, runner, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("Secret")
        output = tmp_path / "test.html"
        runner.invoke(main, ["lock", str(test_file), "-p", "my-pw",
                             "-o", str(output)])

        result = runner.invoke(main, ["check", str(output), "-p", "my-pw"])
        assert "correct" in result.output.lower()

    def test_check_v3_wrong_password(self, runner, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("Secret")
        output = tmp_path / "test.html"
        runner.invoke(main, ["lock", str(test_file), "-p", "my-pw",
                             "-o", str(output)])

        result = runner.invoke(main, ["check", str(output), "-p", "wrong"])
        assert "incorrect" in result.output.lower()
```

**Step 2: Implement**

Update `info` and `check` commands in `cli.py` to detect v3 HTML structure: look for `<script id="pv-meta">` in addition to `<pagevault data-encrypted>`.

For `info`: parse the `pv-meta` JSON, call `inspect_payload_v3()`.
For `check`: parse the `pv-meta` JSON, call `verify_password_v3()`.

**Step 3: Run tests**

Run: `pytest tests/test_cli.py -v`

**Step 4: Lint + Commit**

```bash
git add src/pagevault/cli.py tests/test_cli.py
git commit -m "feat: update info and check commands for v3 chunked files"
```

---

### Task 7: End-to-End Integration Tests

**Files:**
- Modify: `tests/test_integration.py`

**Step 1: Write integration tests**

```python
class TestV3WrapIntegration:
    """End-to-end tests for v3 chunked wrap/unwrap."""

    def test_wrap_file_cli_roundtrip(self, tmp_path):
        """Lock a non-HTML file via CLI, verify output is v3."""
        runner = CliRunner()
        test_file = tmp_path / "report.pdf"
        test_file.write_bytes(b"%PDF-1.4" + b"\x00" * 1000)

        output = tmp_path / "report.html"
        result = runner.invoke(
            main, ["lock", str(test_file), "-p", "pw", "-o", str(output)]
        )
        assert result.exit_code == 0

        # Verify v3 structure
        content = output.read_text()
        soup = BeautifulSoup(content, "html.parser")
        meta_el = soup.find("script", {"id": "pv-meta"})
        assert meta_el is not None

        import json
        envelope = json.loads(meta_el.string)
        assert envelope["v"] == 3

    def test_wrap_site_cli_roundtrip(self, tmp_path):
        """Lock --site via CLI, verify output is v3."""
        runner = CliRunner()
        site = tmp_path / "mysite"
        site.mkdir()
        (site / "index.html").write_text("<h1>Hello</h1>")

        output = tmp_path / "site.html"
        result = runner.invoke(
            main, ["lock", str(site), "--site", "-p", "pw",
                   "-o", str(output)]
        )
        assert result.exit_code == 0

        content = output.read_text()
        soup = BeautifulSoup(content, "html.parser")
        meta_el = soup.find("script", {"id": "pv-meta"})
        assert meta_el is not None

        import json
        envelope = json.loads(meta_el.string)
        assert envelope["v"] == 3

    def test_region_encryption_still_v2(self, tmp_path):
        """HTML region encryption (parser.py) still uses v2."""
        html = "<pagevault>Secret content</pagevault>"
        encrypted = lock_html(html, "password")

        soup = BeautifulSoup(encrypted, "html.parser")
        pv = soup.find("pagevault")
        assert pv.has_attr("data-encrypted")

        # Verify it's v2
        import json
        payload = json.loads(base64.b64decode(pv["data-encrypted"]))
        assert payload["v"] == 2

    def test_multi_chunk_file(self, tmp_path):
        """File larger than chunk_size produces multiple chunks."""
        from pagevault.crypto import CHUNK_SIZE
        test_file = tmp_path / "big.bin"
        test_file.write_bytes(os.urandom(CHUNK_SIZE * 2 + 100))

        output = tmp_path / "big.html"
        runner = CliRunner()
        result = runner.invoke(
            main, ["lock", str(test_file), "-p", "pw", "-o", str(output)]
        )
        assert result.exit_code == 0

        soup = BeautifulSoup(output.read_text(), "html.parser")
        # Should have 3 chunks
        assert soup.find("script", {"id": "pv-0"}) is not None
        assert soup.find("script", {"id": "pv-1"}) is not None
        assert soup.find("script", {"id": "pv-2"}) is not None
        assert soup.find("script", {"id": "pv-3"}) is None

    def test_wrap_flag_produces_v3(self, tmp_path):
        """--wrap flag on HTML file produces v3 chunked output."""
        html_file = tmp_path / "page.html"
        html_file.write_text("<html><body><h1>Secret</h1></body></html>")

        output = tmp_path / "locked" / "page.html"
        runner = CliRunner()
        result = runner.invoke(
            main, ["lock", str(html_file), "--wrap", "-p", "pw",
                   "-o", str(output)]
        )
        assert result.exit_code == 0

        soup = BeautifulSoup(output.read_text(), "html.parser")
        assert soup.find("script", {"id": "pv-meta"}) is not None
```

**Step 2: Run tests**

Run: `pytest tests/test_integration.py -v`

**Step 3: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: add v3 chunked encryption integration tests"
```

---

### Task 8: Final Verification

**Step 1: Full test suite**

Run: `pytest tests/ -v`
Expected: All PASS

**Step 2: Coverage check**

Run: `pytest tests/ -v --cov=pagevault`
Expected: Coverage maintained or improved from baseline

**Step 3: Lint check**

Run: `ruff check src/ tests/ && ruff format --check src/ tests/`
Expected: Clean

**Step 4: Manual test with large file**

```bash
# Test with the 87MB conversations file
pagevault lock examples/conversations/index.html --wrap -p test -o /tmp/big-test.html
ls -lh /tmp/big-test.html  # Should be ~116MB, not ~198MB
# Open in browser and verify decryption with progress bar
```

**Step 5: Commit any remaining fixes + final summary commit**

```bash
git add -A
git commit -m "feat: v3 chunked encryption — complete implementation

- 40% smaller output files (eliminated inner base64 layer)
- Per-chunk DOM elements enable process-and-discard in browser
- Peak browser memory ~120MB vs ~700MB for 87MB input
- Progress bar during decryption
- Region encryption (parser.py) unchanged (still v2)"
```

---

## Dependency Graph

```
Task 1 (crypto core)
  └── Task 2 (crypto utilities)
       └── Task 4 (wrap_file v3)
            └── Task 5 (wrap_site v3)
       └── Task 3 (HTML template)
            └── Task 4
            └── Task 5
  └── Task 6 (CLI updates) — depends on Tasks 4+5
  └── Task 7 (integration tests) — depends on Tasks 4+5+6
  └── Task 8 (final verification) — depends on all above
```

Tasks 1 and 2 are sequential (2 depends on 1).
Task 3 can run in parallel with Task 2.
Tasks 4 and 5 depend on both 2 and 3.
Tasks 6, 7, 8 are sequential at the end.
