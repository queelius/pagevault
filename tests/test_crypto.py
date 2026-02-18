"""Tests for pagevault.crypto module."""

import base64
import json
import os

import pytest

from pagevault.crypto import (
    CHUNK_SIZE,
    ITERATIONS,
    SALT_LENGTH,
    VERSION_V3,
    PagevaultError,
    _derive_chunk_iv,
    _unwrap_key,
    _wrap_key,
    content_hash,
    content_hash_bytes,
    decrypt,
    decrypt_chunked,
    encrypt,
    encrypt_chunked,
    generate_salt,
    hex_to_salt,
    inspect_payload,
    inspect_payload_v3,
    pad_content,
    rewrap_keys,
    salt_to_hex,
    verify_password,
    verify_password_v3,
)


class TestEncryptDecrypt:
    """Tests for encrypt/decrypt functions."""

    def test_basic_roundtrip(self):
        """Test encryption followed by decryption returns original."""
        plaintext = "Hello, World!"
        password = "test-password"

        ciphertext = encrypt(plaintext, password=password)
        content, meta = decrypt(ciphertext, password)

        assert content == plaintext

    def test_empty_string(self):
        """Test encryption of empty string."""
        plaintext = ""
        password = "test-password"

        ciphertext = encrypt(plaintext, password=password)
        content, meta = decrypt(ciphertext, password)

        assert content == plaintext

    def test_unicode_content(self):
        """Test encryption of unicode content."""
        plaintext = "Hello 世界! 🔒 émoji"
        password = "test-password"

        ciphertext = encrypt(plaintext, password=password)
        content, meta = decrypt(ciphertext, password)

        assert content == plaintext

    def test_large_content(self):
        """Test encryption of large content."""
        plaintext = "x" * 100000
        password = "test-password"

        ciphertext = encrypt(plaintext, password=password)
        content, meta = decrypt(ciphertext, password)

        assert content == plaintext

    def test_html_content(self):
        """Test encryption of HTML content."""
        plaintext = """
        <div class="content">
            <h1>Secret Title</h1>
            <p>Secret paragraph with <strong>formatting</strong>.</p>
        </div>
        """
        password = "test-password"

        ciphertext = encrypt(plaintext, password=password)
        content, meta = decrypt(ciphertext, password)

        assert content == plaintext

    def test_wrong_password(self):
        """Test decryption with wrong password fails."""
        plaintext = "Secret content"
        password = "correct-password"
        wrong_password = "wrong-password"

        ciphertext = encrypt(plaintext, password=password)

        with pytest.raises(PagevaultError, match="wrong password"):
            decrypt(ciphertext, wrong_password)

    def test_different_ciphertext_each_time(self):
        """Test that same plaintext produces different ciphertext."""
        plaintext = "Same content"
        password = "test-password"

        ciphertext1 = encrypt(plaintext, password=password)
        ciphertext2 = encrypt(plaintext, password=password)

        # Different due to random IV
        assert ciphertext1 != ciphertext2

        # But both decrypt correctly
        content1, _ = decrypt(ciphertext1, password)
        content2, _ = decrypt(ciphertext2, password)
        assert content1 == plaintext
        assert content2 == plaintext

    def test_with_explicit_salt(self):
        """Test encryption with explicit salt."""
        plaintext = "Secret content"
        password = "test-password"
        salt = generate_salt()

        ciphertext = encrypt(plaintext, password=password, salt=salt)
        content, meta = decrypt(ciphertext, password)

        assert content == plaintext

        # Verify salt is in payload
        decoded = json.loads(base64.b64decode(ciphertext))
        assert base64.b64decode(decoded["salt"]) == salt

    def test_invalid_salt_length(self):
        """Test encryption with wrong salt length fails."""
        with pytest.raises(PagevaultError, match="Salt must be"):
            encrypt("test", password="password", salt=b"short")


class TestCiphertextFormat:
    """Tests for ciphertext format validation."""

    def test_ciphertext_is_base64(self):
        """Test that ciphertext is valid base64."""
        ciphertext = encrypt("test", password="password")

        # Should not raise
        decoded = base64.b64decode(ciphertext)
        assert len(decoded) > 0

    def test_ciphertext_contains_json(self):
        """Test that ciphertext contains valid JSON."""
        ciphertext = encrypt("test", password="password")
        decoded = base64.b64decode(ciphertext)

        data = json.loads(decoded)
        assert isinstance(data, dict)

    def test_ciphertext_has_required_fields(self):
        """Test that ciphertext has all required fields."""
        ciphertext = encrypt("test", password="password")
        decoded = base64.b64decode(ciphertext)
        data = json.loads(decoded)

        assert data["v"] == 2
        assert data["alg"] == "aes-256-gcm"
        assert data["kdf"] == "pbkdf2-sha256"
        assert data["iter"] == ITERATIONS
        assert "salt" in data
        assert "iv" in data
        assert "ct" in data
        assert "keys" in data
        assert isinstance(data["keys"], list)
        assert len(data["keys"]) >= 1

    def test_invalid_base64_fails(self):
        """Test decryption of invalid base64 fails."""
        with pytest.raises(PagevaultError, match="Invalid base64"):
            decrypt("not-valid-base64!!!", "password")

    def test_invalid_json_fails(self):
        """Test decryption of invalid JSON fails."""
        invalid = base64.b64encode(b"not json").decode()
        with pytest.raises(PagevaultError, match="Invalid JSON"):
            decrypt(invalid, "password")

    def test_missing_version_fails(self):
        """Test decryption with missing version fails."""
        payload = {"salt": "AA==", "iv": "AA==", "ct": "AA==", "keys": []}
        invalid = base64.b64encode(json.dumps(payload).encode()).decode()
        with pytest.raises(PagevaultError, match="Unsupported format version"):
            decrypt(invalid, "password")

    def test_wrong_version_fails(self):
        """Test decryption with wrong version fails."""
        payload = {"v": 99, "salt": "AA==", "iv": "AA==", "ct": "AA==", "keys": []}
        invalid = base64.b64encode(json.dumps(payload).encode()).decode()
        with pytest.raises(PagevaultError, match="Unsupported format version"):
            decrypt(invalid, "password")

    def test_missing_fields_fail(self):
        """Test decryption with missing fields fails."""
        for missing in ["salt", "iv", "ct", "keys"]:
            payload = {
                "v": 2,
                "salt": "AA==",
                "iv": "AA==",
                "ct": "AA==",
                "keys": [{"iv": "AA==", "ct": "AA=="}],
            }
            del payload[missing]
            invalid = base64.b64encode(json.dumps(payload).encode()).decode()
            with pytest.raises(
                PagevaultError, match=f"Missing required field: {missing}"
            ):
                decrypt(invalid, "password")


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


class TestMultiUser:
    """Tests for multi-user encryption and decryption."""

    def test_multiuser_encrypt_decrypt(self):
        """Encrypt with multiple users and decrypt as each user."""
        plaintext = "Shared secret content"
        users = {"alice": "pw-a", "bob": "pw-b"}

        ciphertext = encrypt(plaintext, users=users)

        # Both users can decrypt
        content_a, _ = decrypt(ciphertext, "pw-a", username="alice")
        assert content_a == plaintext

        content_b, _ = decrypt(ciphertext, "pw-b", username="bob")
        assert content_b == plaintext

    def test_multiuser_wrong_username_fails(self):
        """Decrypt with wrong username should fail."""
        plaintext = "Secret"
        users = {"alice": "pw-a", "bob": "pw-b"}

        ciphertext = encrypt(plaintext, users=users)

        with pytest.raises(PagevaultError, match="wrong password"):
            decrypt(ciphertext, "pw-a", username="charlie")

    def test_multiuser_wrong_password_fails(self):
        """Decrypt with right username but wrong password should fail."""
        plaintext = "Secret"
        users = {"alice": "pw-a"}

        ciphertext = encrypt(plaintext, users=users)

        with pytest.raises(PagevaultError, match="wrong password"):
            decrypt(ciphertext, "wrong-pw", username="alice")

    def test_cannot_specify_both_password_and_users(self):
        """Specifying both password and users should raise PagevaultError."""
        with pytest.raises(PagevaultError, match="Cannot specify both"):
            encrypt("test", password="pw", users={"alice": "pw-a"})

    def test_must_specify_password_or_users(self):
        """Specifying neither password nor users should raise PagevaultError."""
        with pytest.raises(PagevaultError, match="Must specify either"):
            encrypt("test")

    def test_shared_salt_across_key_blobs(self):
        """All key blobs in a multi-user payload share the same salt."""
        users = {"alice": "pw-a", "bob": "pw-b", "charlie": "pw-c"}
        ciphertext = encrypt("test", users=users)

        data = json.loads(base64.b64decode(ciphertext))

        # There is a single salt at the top level, shared by all key blobs
        assert "salt" in data
        assert len(data["keys"]) == 3
        # Key blobs themselves don't have separate salt fields
        for key_blob in data["keys"]:
            assert "salt" not in key_blob

    def test_unique_wrap_ivs(self):
        """Each key blob should have a different IV."""
        users = {"alice": "pw-a", "bob": "pw-b", "charlie": "pw-c"}
        ciphertext = encrypt("test", users=users)

        data = json.loads(base64.b64decode(ciphertext))
        ivs = [blob["iv"] for blob in data["keys"]]

        # All IVs should be unique
        assert len(set(ivs)) == len(ivs)


class TestMetadata:
    """Tests for metadata support in encrypt/decrypt."""

    def test_metadata_roundtrip(self):
        """Encrypt with metadata and verify it survives decryption."""
        plaintext = "Content with metadata"
        meta = {"key": "value"}

        ciphertext = encrypt(plaintext, password="pw", meta=meta)
        content, returned_meta = decrypt(ciphertext, "pw")

        assert content == plaintext
        assert returned_meta == meta

    def test_no_metadata_returns_none(self):
        """Encrypt without meta param returns (content, None) on decrypt."""
        plaintext = "No metadata here"

        ciphertext = encrypt(plaintext, password="pw")
        content, returned_meta = decrypt(ciphertext, "pw")

        assert content == plaintext
        assert returned_meta is None

    def test_metadata_with_nested_dict(self):
        """Encrypt with nested metadata dict."""
        plaintext = "Nested metadata"
        meta = {
            "author": "alice",
            "tags": ["secret", "important"],
            "settings": {"level": 3, "enabled": True},
        }

        ciphertext = encrypt(plaintext, password="pw", meta=meta)
        content, returned_meta = decrypt(ciphertext, "pw")

        assert content == plaintext
        assert returned_meta == meta

    def test_metadata_does_not_affect_content(self):
        """Same content with different meta should decrypt to same content."""
        plaintext = "Same content"

        ct1 = encrypt(plaintext, password="pw", meta={"a": 1})
        ct2 = encrypt(plaintext, password="pw", meta={"b": 2})

        content1, meta1 = decrypt(ct1, "pw")
        content2, meta2 = decrypt(ct2, "pw")

        assert content1 == content2 == plaintext
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


class TestRewrapKeys:
    """Tests for rewrap_keys() function."""

    def test_rewrap_add_user(self):
        """Encrypt with one user, rewrap to add another user."""
        plaintext = "shared secret"
        ciphertext = encrypt(plaintext, users={"alice": "pw-a"})

        # Rewrap to add bob
        rewrapped = rewrap_keys(
            ciphertext,
            old_users={"alice": "pw-a"},
            new_users={"alice": "pw-a", "bob": "pw-b"},
        )

        # Both can decrypt
        content_a, _ = decrypt(rewrapped, "pw-a", username="alice")
        assert content_a == plaintext

        content_b, _ = decrypt(rewrapped, "pw-b", username="bob")
        assert content_b == plaintext

    def test_rewrap_remove_user(self):
        """Encrypt with two users, rewrap to remove one."""
        plaintext = "shared secret"
        ciphertext = encrypt(plaintext, users={"alice": "pw-a", "bob": "pw-b"})

        # Rewrap with only alice
        rewrapped = rewrap_keys(
            ciphertext,
            old_users={"alice": "pw-a"},
            new_users={"alice": "pw-a"},
        )

        # Alice can still decrypt
        content_a, _ = decrypt(rewrapped, "pw-a", username="alice")
        assert content_a == plaintext

        # Bob can no longer decrypt
        with pytest.raises(PagevaultError, match="wrong password"):
            decrypt(rewrapped, "pw-b", username="bob")

    def test_rewrap_change_password(self):
        """Encrypt with one user, rewrap to change their password."""
        plaintext = "secret"
        ciphertext = encrypt(plaintext, users={"alice": "pw1"})

        # Rewrap with new password for alice
        rewrapped = rewrap_keys(
            ciphertext,
            old_users={"alice": "pw1"},
            new_users={"alice": "pw2"},
        )

        # New password works
        content, _ = decrypt(rewrapped, "pw2", username="alice")
        assert content == plaintext

        # Old password no longer works
        with pytest.raises(PagevaultError, match="wrong password"):
            decrypt(rewrapped, "pw1", username="alice")

    def test_rewrap_single_password_to_users(self):
        """Encrypt with single password, rewrap to multi-user."""
        plaintext = "migrating to multi-user"
        ciphertext = encrypt(plaintext, password="pw")

        # Rewrap from single password to users
        rewrapped = rewrap_keys(
            ciphertext,
            old_password="pw",
            new_users={"alice": "pw-a"},
        )

        # Alice can decrypt
        content, _ = decrypt(rewrapped, "pw-a", username="alice")
        assert content == plaintext

        # Old single password no longer works
        with pytest.raises(PagevaultError, match="wrong password"):
            decrypt(rewrapped, "pw")

    def test_rekey_generates_new_ciphertext(self):
        """Rekey generates new CEK, content still decryptable but ciphertext changed."""
        plaintext = "rekey me"
        ciphertext = encrypt(plaintext, password="pw")

        # Rewrap with rekey
        rewrapped = rewrap_keys(
            ciphertext,
            old_password="pw",
            new_password="pw",
            rekey=True,
        )

        # Content still decryptable
        content, _ = decrypt(rewrapped, "pw")
        assert content == plaintext

        # But the ciphertext payload changed (new CEK, new IV, new ct)
        orig_data = json.loads(base64.b64decode(ciphertext))
        new_data = json.loads(base64.b64decode(rewrapped))
        assert orig_data["ct"] != new_data["ct"]
        assert orig_data["iv"] != new_data["iv"]

    def test_rewrap_requires_valid_old_credentials(self):
        """Rewrap with wrong old credentials should raise PagevaultError."""
        ciphertext = encrypt("secret", password="correct-pw")

        with pytest.raises(PagevaultError, match="Cannot recover CEK"):
            rewrap_keys(
                ciphertext,
                old_password="wrong-pw",
                new_password="new-pw",
            )

    def test_rewrap_requires_new_target(self):
        """Rewrap without new_users or new_password should raise PagevaultError."""
        ciphertext = encrypt("secret", password="pw")

        with pytest.raises(
            PagevaultError, match="Must provide new_users or new_password"
        ):
            rewrap_keys(
                ciphertext,
                old_password="pw",
            )


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
        """Test padded content survives encrypt/decrypt with null-byte stripping."""
        original = "<p>Secret content</p>"
        padded = pad_content(original)
        assert len(padded.encode("utf-8")) > len(original.encode("utf-8"))

        encrypted = encrypt(padded, password="pw")
        decrypted, _meta = decrypt(encrypted, password="pw")

        # After stripping null bytes, original content is recovered
        stripped = decrypted.rstrip("\x00")
        assert stripped == original


class TestInspectPayload:
    """Tests for inspect_payload function."""

    def test_inspect_basic(self):
        """Test inspecting a basic encrypted payload."""
        payload = encrypt("test content", password="pw")
        info = inspect_payload(payload)

        assert info["version"] == 2
        assert info["algorithm"] == "aes-256-gcm"
        assert info["kdf"] == "pbkdf2-sha256"
        assert info["iterations"] == 310000
        assert info["key_count"] == 1
        assert info["salt_length"] == 16
        assert info["iv_length"] == 12
        assert info["ciphertext_length"] > 0

    def test_inspect_multi_user(self):
        """Test inspecting a multi-user payload."""
        payload = encrypt(
            "secret", users={"alice": "pw-a", "bob": "pw-b", "charlie": "pw-c"}
        )
        info = inspect_payload(payload)

        assert info["key_count"] == 3

    def test_inspect_invalid_base64(self):
        """Test error on invalid base64."""
        with pytest.raises(PagevaultError, match="Invalid base64"):
            inspect_payload("not-valid-base64!!!")

    def test_inspect_invalid_json(self):
        """Test error on valid base64 but invalid JSON."""
        import base64

        payload = base64.b64encode(b"not json").decode("ascii")
        with pytest.raises(PagevaultError, match="Invalid JSON"):
            inspect_payload(payload)


class TestVerifyPassword:
    """Tests for verify_password function."""

    def test_correct_password(self):
        """Test correct password returns True."""
        payload = encrypt("secret", password="correct-pw")
        assert verify_password(payload, "correct-pw") is True

    def test_wrong_password(self):
        """Test wrong password returns False."""
        payload = encrypt("secret", password="correct-pw")
        assert verify_password(payload, "wrong-pw") is False

    def test_multi_user_correct(self):
        """Test correct user/password returns True."""
        payload = encrypt("secret", users={"alice": "pw-a", "bob": "pw-b"})
        assert verify_password(payload, "pw-a", username="alice") is True
        assert verify_password(payload, "pw-b", username="bob") is True

    def test_multi_user_wrong(self):
        """Test wrong user/password returns False."""
        payload = encrypt("secret", users={"alice": "pw-a"})
        assert verify_password(payload, "pw-a", username="bob") is False
        assert verify_password(payload, "wrong", username="alice") is False

    def test_invalid_payload(self):
        """Test error on invalid payload."""
        with pytest.raises(PagevaultError):
            verify_password("invalid", "pw")


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
        assert envelope["v"] == VERSION_V3
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
        salt = generate_salt()
        data = b"test"
        envelope, _ = encrypt_chunked(data, password="pw", salt=salt)
        assert envelope["salt"] == salt_to_hex(salt)

    def test_custom_chunk_size(self):
        """Custom chunk_size is respected."""
        data = b"x" * 100
        envelope, chunks = encrypt_chunked(data, password="pw", chunk_size=30)
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

    def test_truncated_chunks_raises(self):
        """Passing fewer chunks than expected raises error."""
        data = b"x" * 100
        envelope, chunks = encrypt_chunked(data, password="pw", chunk_size=30)
        assert len(chunks) == 4
        with pytest.raises(PagevaultError, match="length mismatch"):
            decrypt_chunked(envelope, chunks[:2], "pw")

    def test_chunk_size_zero_raises(self):
        """chunk_size=0 raises PagevaultError."""
        with pytest.raises(PagevaultError, match="chunk_size must be positive"):
            encrypt_chunked(b"data", password="pw", chunk_size=0)

    def test_chunk_size_negative_raises(self):
        """chunk_size<0 raises PagevaultError."""
        with pytest.raises(PagevaultError, match="chunk_size must be positive"):
            encrypt_chunked(b"data", password="pw", chunk_size=-1)

    def test_empty_users_dict_raises(self):
        """Empty users dict raises PagevaultError."""
        with pytest.raises(PagevaultError, match="must not be empty"):
            encrypt_chunked(b"data", users={})

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


class TestInspectPayloadV3:
    """Tests for inspect_payload_v3 with v3 chunked payloads."""

    def test_inspect_v3(self):
        data = b"x" * 100
        envelope, _ = encrypt_chunked(data, password="pw")
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
        envelope, _ = encrypt_chunked(b"shared", users={"alice": "pw-a", "bob": "pw-b"})
        assert verify_password_v3(envelope, "pw-a", username="alice") is True
        assert verify_password_v3(envelope, "pw-b", username="bob") is True
        assert verify_password_v3(envelope, "pw-a", username="bob") is False
