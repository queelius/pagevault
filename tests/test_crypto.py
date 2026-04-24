"""Tests for pagevault.crypto module."""

import os

import pytest

from pagevault.crypto import (
    CHUNK_SIZE,
    SALT_LENGTH,
    VERSION,
    PagevaultError,
    _derive_chunk_iv,
    _unwrap_key,
    _wrap_key,
    content_hash,
    content_hash_bytes,
    decrypt_v4,
    encrypt_v4,
    generate_salt,
    hex_to_salt,
    inspect_payload_v4,
    pad_content,
    salt_to_hex,
    verify_password_v4,
)


class TestSaltFunctions:
    """Tests for salt utility functions."""

    def test_generate_salt_length(self):
        """Test generated salt has correct length."""
        salt = generate_salt()
        assert len(salt) == SALT_LENGTH

    def test_generate_salt_random(self):
        """Test generated salts are different."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        assert salt1 != salt2

    def test_salt_to_hex(self):
        """Test salt to hex conversion."""
        salt = generate_salt()
        hex_str = salt_to_hex(salt)

        assert len(hex_str) == SALT_LENGTH * 2
        assert all(c in "0123456789abcdef" for c in hex_str)

    def test_hex_to_salt(self):
        """Test hex to salt conversion."""
        original = generate_salt()
        hex_str = salt_to_hex(original)
        restored = hex_to_salt(hex_str)

        assert restored == original

    def test_hex_to_salt_invalid(self):
        """Test invalid hex string fails."""
        with pytest.raises(PagevaultError, match="Invalid hex"):
            hex_to_salt("not-hex!")

    def test_hex_to_salt_wrong_length(self):
        """Test wrong length hex string fails."""
        with pytest.raises(PagevaultError, match="must be"):
            hex_to_salt("0123")  # Too short


class TestContentHash:
    """Tests for content_hash() function for integrity verification."""

    def test_hash_length(self):
        """Hash output is 32 hex characters (128 bits)."""
        result = content_hash("test content")
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_deterministic(self):
        """Same content produces same hash."""
        content = "Hello, world!"
        hash1 = content_hash(content)
        hash2 = content_hash(content)
        assert hash1 == hash2

    def test_hash_different_content(self):
        """Different content produces different hashes."""
        hash1 = content_hash("content A")
        hash2 = content_hash("content B")
        assert hash1 != hash2

    def test_hash_empty_content(self):
        """Empty string has a valid hash."""
        result = content_hash("")
        assert len(result) == 32
        # SHA-256 of empty string, truncated to 16 bytes
        assert result == "e3b0c44298fc1c149afbf4c8996fb924"

    def test_hash_unicode_content(self):
        """Unicode content produces valid hash."""
        result = content_hash("こんにちは世界 🔐")
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_html_content(self):
        """HTML content produces valid hash."""
        html = "<div><p>Secret content</p></div>"
        result = content_hash(html)
        assert len(result) == 32

    def test_hash_whitespace_sensitive(self):
        """Hash is sensitive to whitespace differences."""
        hash1 = content_hash("content")
        hash2 = content_hash("content ")
        hash3 = content_hash(" content")
        assert hash1 != hash2
        assert hash1 != hash3
        assert hash2 != hash3


class TestMultiUserChunked:
    """Tests for multi-user encryption via the chunked (v4) API."""

    def test_multiuser_encrypt_decrypt(self):
        """Encrypt with multiple users and decrypt as each user."""
        plaintext = b"Shared secret content"
        users = {"alice": "pw-a", "bob": "pw-b"}

        env, chunks = encrypt_v4(plaintext, users=users)

        # Both users can decrypt
        content_a, _ = decrypt_v4(env, chunks, "pw-a", username="alice")
        assert content_a == plaintext

        content_b, _ = decrypt_v4(env, chunks, "pw-b", username="bob")
        assert content_b == plaintext

    def test_multiuser_wrong_username_fails(self):
        """Decrypt with wrong username should fail."""
        users = {"alice": "pw-a", "bob": "pw-b"}
        env, chunks = encrypt_v4(b"Secret", users=users)

        with pytest.raises(PagevaultError, match="wrong password"):
            decrypt_v4(env, chunks, "pw-a", username="charlie")

    def test_multiuser_wrong_password_fails(self):
        """Decrypt with right username but wrong password should fail."""
        env, chunks = encrypt_v4(b"Secret", users={"alice": "pw-a"})

        with pytest.raises(PagevaultError, match="wrong password"):
            decrypt_v4(env, chunks, "wrong-pw", username="alice")

    def test_cannot_specify_both_password_and_users(self):
        """Specifying both password and users should raise PagevaultError."""
        with pytest.raises(PagevaultError, match="Cannot specify both"):
            encrypt_v4(b"test", password="pw", users={"alice": "pw-a"})

    def test_must_specify_password_or_users(self):
        """Specifying neither password nor users should raise PagevaultError."""
        with pytest.raises(PagevaultError, match="Must specify either"):
            encrypt_v4(b"test")

    def test_shared_salt_across_key_blobs(self):
        """All key blobs in a multi-user envelope share the same salt."""
        users = {"alice": "pw-a", "bob": "pw-b", "charlie": "pw-c"}
        env, _ = encrypt_v4(b"test", users=users)

        assert "salt" in env
        assert len(env["keys"]) == 3
        for key_blob in env["keys"]:
            assert "salt" not in key_blob

    def test_unique_wrap_ivs(self):
        """Each key blob should have a different IV."""
        users = {"alice": "pw-a", "bob": "pw-b", "charlie": "pw-c"}
        env, _ = encrypt_v4(b"test", users=users)
        ivs = [blob["iv"] for blob in env["keys"]]
        assert len(set(ivs)) == len(ivs)


class TestMetadataChunked:
    """Tests for metadata support in chunked (v4) encryption."""

    def test_metadata_roundtrip(self):
        """Encrypt with metadata and verify it survives decryption."""
        meta = {"key": "value"}
        data = b"Content with metadata"
        env, chunks = encrypt_v4(data, password="pw", meta=meta)
        content, returned_meta = decrypt_v4(env, chunks, "pw")

        assert content == data
        assert returned_meta == meta

    def test_no_metadata_returns_empty_dict(self):
        """Encrypt without meta returns an empty dict on decrypt."""
        env, chunks = encrypt_v4(b"No metadata here", password="pw")
        content, returned_meta = decrypt_v4(env, chunks, "pw")

        assert content == b"No metadata here"
        assert returned_meta == {}

    def test_metadata_with_nested_dict(self):
        """Encrypt with nested metadata dict."""
        meta = {
            "author": "alice",
            "tags": ["secret", "important"],
            "settings": {"level": 3, "enabled": True},
        }

        env, chunks = encrypt_v4(b"Nested metadata", password="pw", meta=meta)
        content, returned_meta = decrypt_v4(env, chunks, "pw")

        assert content == b"Nested metadata"
        assert returned_meta == meta

    def test_metadata_does_not_affect_content(self):
        """Same content with different meta should decrypt to same content."""
        env1, ch1 = encrypt_v4(b"Same content", password="pw", meta={"a": 1})
        env2, ch2 = encrypt_v4(b"Same content", password="pw", meta={"b": 2})

        content1, meta1 = decrypt_v4(env1, ch1, "pw")
        content2, meta2 = decrypt_v4(env2, ch2, "pw")

        assert content1 == content2 == b"Same content"
        assert meta1 == {"a": 1}
        assert meta2 == {"b": 2}


class TestKeyWrapping:
    """Tests for low-level key wrapping functions."""

    def test_wrap_unwrap_roundtrip(self):
        """Wrap and unwrap a key, verify roundtrip."""
        cek = os.urandom(32)
        wrapping_key = os.urandom(32)

        iv, ct = _wrap_key(cek, wrapping_key)
        unwrapped = _unwrap_key(iv, ct, wrapping_key)

        assert unwrapped == cek

    def test_unwrap_with_wrong_key_returns_none(self):
        """Unwrapping with wrong wrapping key returns None."""
        cek = os.urandom(32)
        wrapping_key = os.urandom(32)
        wrong_key = os.urandom(32)

        iv, ct = _wrap_key(cek, wrapping_key)
        result = _unwrap_key(iv, ct, wrong_key)

        assert result is None


# NOTE: rewrap_keys() was a v2-only API and is removed in v0.4.0.
# Re-wrapping for v4 envelopes happens at the parser layer
# (parser.sync_html_keys) or by re-encrypting via encrypt_v4().


class TestPadContent:
    """Tests for pad_content function."""

    def test_pads_to_power_of_2(self):
        """Test padding reaches a power-of-2 byte boundary."""
        text = "Hello"  # 5 bytes UTF-8
        padded = pad_content(text)
        assert len(padded.encode("utf-8")) == 8  # next power of 2 after 5

    def test_exact_power_of_2_no_change(self):
        """Test content already at power-of-2 is unchanged."""
        text = "ab"  # exactly 2 bytes
        padded = pad_content(text)
        assert padded == text

    def test_empty_string_no_change(self):
        """Test empty string is unchanged."""
        padded = pad_content("")
        assert padded == ""

    def test_large_content(self):
        """Test padding works for larger content."""
        text = "x" * 1000  # 1000 bytes
        padded = pad_content(text)
        padded_len = len(padded.encode("utf-8"))
        assert padded_len == 1024  # next power of 2 after 1000

    def test_padded_starts_with_original(self):
        """Test padded content starts with original content."""
        text = "Hello World"
        padded = pad_content(text)
        assert padded.startswith(text)

    def test_unicode_content(self):
        """Test padding works with multi-byte Unicode."""
        text = "Hello 世界"  # 5 + 1 + 6 = 12 bytes
        padded = pad_content(text)
        padded_len = len(padded.encode("utf-8"))
        assert padded_len == 16  # next power of 2 after 12

    def test_pad_encrypt_decrypt_roundtrip(self):
        """Padded bytes survive chunked encrypt/decrypt; NUL padding can
        be stripped by the caller (mirrors parser.py:unlock_html)."""
        original = "<p>Secret content</p>"
        padded = pad_content(original)
        assert len(padded.encode("utf-8")) > len(original.encode("utf-8"))

        env, chunks = encrypt_v4(padded.encode("utf-8"), password="pw")
        decrypted_bytes, _meta = decrypt_v4(env, chunks, "pw")

        stripped = decrypted_bytes.decode("utf-8").rstrip("\x00")
        assert stripped == original


# NOTE: inspect_payload() and verify_password() were v2-only APIs and
# are removed in v0.4.0. Use inspect_payload_v4() / verify_password_v4()
# against a v4 envelope dict (TestInspectPayloadV4 / TestVerifyPasswordV4).


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
        iv_base = b"\x00" * 12
        iv_1 = _derive_chunk_iv(iv_base, 1)
        assert iv_1 == b"\x00" * 11 + b"\x01"

        iv_256 = _derive_chunk_iv(iv_base, 256)
        assert iv_256 == b"\x00" * 10 + b"\x01\x00"


class TestChunkedEncryption:
    """Tests for v4 chunked encrypt/decrypt."""

    def test_basic_roundtrip(self):
        """Encrypt bytes then decrypt, verify roundtrip."""
        data = b"Hello, World! This is test content."
        envelope, chunks = encrypt_v4(data, password="test-pw")
        result_data, result_meta = decrypt_v4(envelope, chunks, "test-pw")
        assert result_data == data

    def test_single_chunk(self):
        """Data smaller than chunk_size produces exactly one chunk."""
        data = b"small"
        envelope, chunks = encrypt_v4(data, password="pw")
        assert envelope["chunk_count"] == 1
        assert len(chunks) == 1

    def test_exact_chunk_boundary(self):
        """Data exactly equal to chunk_size produces one chunk."""
        data = b"x" * CHUNK_SIZE
        envelope, chunks = encrypt_v4(data, password="pw")
        assert envelope["chunk_count"] == 1
        assert len(chunks) == 1

    def test_two_chunks(self):
        """Data slightly over chunk_size produces two chunks."""
        data = b"x" * (CHUNK_SIZE + 1)
        envelope, chunks = encrypt_v4(data, password="pw")
        assert envelope["chunk_count"] == 2
        assert len(chunks) == 2

    def test_large_data_roundtrip(self):
        """Roundtrip with multiple chunks."""
        data = os.urandom(CHUNK_SIZE * 3 + 500)
        envelope, chunks = encrypt_v4(data, password="pw")
        assert envelope["chunk_count"] == 4
        result_data, _ = decrypt_v4(envelope, chunks, "pw")
        assert result_data == data

    def test_empty_data(self):
        """Empty bytes encrypt and decrypt correctly."""
        data = b""
        envelope, chunks = encrypt_v4(data, password="pw")
        assert envelope["chunk_count"] == 0
        assert len(chunks) == 0
        result_data, _ = decrypt_v4(envelope, chunks, "pw")
        assert result_data == b""

    def test_envelope_fields(self):
        """Envelope dict contains all required v4 fields."""
        data = b"test"
        envelope, _ = encrypt_v4(data, password="pw")
        assert envelope["v"] == VERSION
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
        envelope, chunks = encrypt_v4(data, password="pw", meta=meta)
        _, result_meta = decrypt_v4(envelope, chunks, "pw")
        assert result_meta == meta

    def test_wrong_password_fails(self):
        """Decryption with wrong password raises error."""
        data = b"secret"
        envelope, chunks = encrypt_v4(data, password="correct")
        with pytest.raises(PagevaultError, match="wrong password"):
            decrypt_v4(envelope, chunks, "wrong")

    def test_multiuser_roundtrip(self):
        """Multi-user encrypt then decrypt as each user."""
        data = b"shared content"
        users = {"alice": "pw-a", "bob": "pw-b"}
        envelope, chunks = encrypt_v4(data, users=users)

        data_a, _ = decrypt_v4(envelope, chunks, "pw-a", username="alice")
        data_b, _ = decrypt_v4(envelope, chunks, "pw-b", username="bob")
        assert data_a == data
        assert data_b == data

    def test_explicit_salt(self):
        """Explicit salt is used in envelope."""
        salt = generate_salt()
        data = b"test"
        envelope, _ = encrypt_v4(data, password="pw", salt=salt)
        assert envelope["salt"] == salt_to_hex(salt)

    def test_custom_chunk_size(self):
        """Custom chunk_size is respected."""
        data = b"x" * 100
        envelope, chunks = encrypt_v4(data, password="pw", chunk_size=30)
        assert envelope["chunk_size"] == 30
        assert envelope["chunk_count"] == 4  # ceil(100/30)
        assert len(chunks) == 4
        result, _ = decrypt_v4(envelope, chunks, "pw")
        assert result == data

    def test_different_ciphertext_each_time(self):
        """Same data produces different ciphertext (random IV + CEK)."""
        data = b"same content"
        _, chunks1 = encrypt_v4(data, password="pw")
        _, chunks2 = encrypt_v4(data, password="pw")
        assert chunks1 != chunks2

    def test_truncated_chunks_raises(self):
        """Passing fewer chunks than expected raises error."""
        data = b"x" * 100
        envelope, chunks = encrypt_v4(data, password="pw", chunk_size=30)
        assert len(chunks) == 4
        with pytest.raises(PagevaultError, match="length mismatch"):
            decrypt_v4(envelope, chunks[:2], "pw")

    def test_chunk_size_zero_raises(self):
        """chunk_size=0 raises PagevaultError."""
        with pytest.raises(PagevaultError, match="chunk_size must be positive"):
            encrypt_v4(b"data", password="pw", chunk_size=0)

    def test_chunk_size_negative_raises(self):
        """chunk_size<0 raises PagevaultError."""
        with pytest.raises(PagevaultError, match="chunk_size must be positive"):
            encrypt_v4(b"data", password="pw", chunk_size=-1)

    def test_empty_users_dict_raises(self):
        """Empty users dict raises PagevaultError."""
        with pytest.raises(PagevaultError, match="must not be empty"):
            encrypt_v4(b"data", users={})

    def test_iv_counter_overflow_raises(self):
        """Chunk index >= 2^32 raises error."""
        iv_base = b"\x00" * 12
        with pytest.raises(PagevaultError, match="exceeds"):
            _derive_chunk_iv(iv_base, 2**32)


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


class TestInspectPayloadV4:
    """Tests for inspect_payload_v4 with v4 chunked payloads."""

    def test_inspect_v4(self):
        data = b"x" * 100
        envelope, _ = encrypt_v4(data, password="pw")
        info = inspect_payload_v4(envelope)
        assert info["version"] == 4
        assert info["algorithm"] == "aes-256-gcm"
        assert info["chunk_count"] == 1
        assert info["chunk_size"] == CHUNK_SIZE
        assert info["total_size"] == 100
        assert info["key_count"] == 1

    def test_inspect_v4_multiuser(self):
        data = b"test"
        users = {"alice": "pw-a", "bob": "pw-b"}
        envelope, _ = encrypt_v4(data, users=users)
        info = inspect_payload_v4(envelope)
        assert info["key_count"] == 2


class TestVerifyPasswordV4:
    """Tests for verify_password_v4 with chunked payloads."""

    def test_correct_password(self):
        envelope, _ = encrypt_v4(b"secret", password="correct")
        assert verify_password_v4(envelope, "correct") is True

    def test_wrong_password(self):
        envelope, _ = encrypt_v4(b"secret", password="correct")
        assert verify_password_v4(envelope, "wrong") is False

    def test_multiuser(self):
        envelope, _ = encrypt_v4(b"shared", users={"alice": "pw-a", "bob": "pw-b"})
        assert verify_password_v4(envelope, "pw-a", username="alice") is True
        assert verify_password_v4(envelope, "pw-b", username="bob") is True
        assert verify_password_v4(envelope, "pw-a", username="bob") is False
