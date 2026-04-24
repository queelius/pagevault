"""Core cryptographic functions for pagevault.

Provides AES-256-GCM encryption with PBKDF2-SHA256 key derivation,
compatible with WebCrypto API for browser-side decryption.

v4 is the unified envelope format: content is split into fixed-size
chunks encrypted with a random CEK; metadata is encrypted separately;
the CEK is wrapped per-user under a PBKDF2-derived wrapping key.
See docs/v4-envelope.md for the full specification.
"""

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Cryptographic parameters (must match browser-side implementation)
VERSION_V3 = 4  # Envelope version for the chunked (v4) format. Name kept pre-rename.
ALGORITHM = "aes-256-gcm"
KDF = "pbkdf2-sha256"
ITERATIONS = 310000
SALT_LENGTH = 16  # 128 bits
IV_LENGTH = 12  # 96 bits (standard for GCM)
KEY_LENGTH = 32  # 256 bits
CHUNK_SIZE = 1_048_576  # 1 MB default chunk size


class PagevaultError(Exception):
    """Base exception for pagevault errors."""

    pass


def _derive_key(secret: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from secret using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(secret.encode("utf-8"))


def _build_secret(password: str, username: str | None = None) -> str:
    """Build the secret string for key derivation.

    If username is provided, secret is "username:password".
    Otherwise, secret is just the password.
    """
    if username:
        return f"{username}:{password}"
    return password


def _wrap_key(cek: bytes, wrapping_key: bytes) -> tuple[bytes, bytes]:
    """Wrap a CEK with a wrapping key using AES-256-GCM.

    Args:
        cek: Content Encryption Key to wrap.
        wrapping_key: Key derived from user's password.

    Returns:
        Tuple of (iv, ciphertext) for the wrapped key.
    """
    iv = os.urandom(IV_LENGTH)
    aesgcm = AESGCM(wrapping_key)
    ct = aesgcm.encrypt(iv, cek, None)
    return iv, ct


def _unwrap_key(iv: bytes, ct: bytes, wrapping_key: bytes) -> bytes | None:
    """Unwrap a CEK using a wrapping key.

    Args:
        iv: IV used for wrapping.
        ct: Ciphertext of the wrapped key.
        wrapping_key: Key derived from user's password.

    Returns:
        The unwrapped CEK, or None if the wrapping key is wrong.
    """
    aesgcm = AESGCM(wrapping_key)
    try:
        return aesgcm.decrypt(iv, ct, None)
    except Exception:
        return None


def _wrap_cek_for_users(
    cek: bytes,
    salt: bytes,
    password: str | None = None,
    users: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    """Wrap a CEK for one or more users, returning base64-encoded key blobs.

    Exactly one of ``password`` or ``users`` must be provided.

    Args:
        cek: Content Encryption Key to wrap.
        salt: Salt for PBKDF2 key derivation.
        password: Single password (no username).
        users: Dict of {username: password} for multi-user wrapping.

    Returns:
        List of dicts, each with base64 ``iv`` and ``ct`` strings.
    """
    credentials: list[tuple[str, str | None]] = []
    if users:
        credentials = [(pwd, uname) for uname, pwd in users.items()]
    else:
        credentials = [(password, None)]

    keys: list[dict[str, str]] = []
    for pwd, uname in credentials:
        secret = _build_secret(pwd, uname)
        wrapping_key = _derive_key(secret, salt)
        wrap_iv, wrap_ct = _wrap_key(cek, wrapping_key)
        keys.append(
            {
                "iv": base64.b64encode(wrap_iv).decode("ascii"),
                "ct": base64.b64encode(wrap_ct).decode("ascii"),
            }
        )
    return keys


def _try_unwrap_cek(keys_list: list[dict], wrapping_key: bytes) -> bytes | None:
    """Try to unwrap a CEK from a list of key blobs.

    Iterates through key blobs attempting to unwrap with the given
    wrapping key. Returns the first successful result.

    Args:
        keys_list: List of key blob dicts with base64 ``iv`` and ``ct``.
        wrapping_key: Derived wrapping key to try.

    Returns:
        The unwrapped CEK bytes, or None if no blob matched.
    """
    for key_blob in keys_list:
        try:
            blob_iv = base64.b64decode(key_blob["iv"])
            blob_ct = base64.b64decode(key_blob["ct"])
        except Exception:
            continue
        result = _unwrap_key(blob_iv, blob_ct, wrapping_key)
        if result is not None:
            return result
    return None


def generate_salt() -> bytes:
    """Generate a random salt for consistent encryption.

    Returns:
        16-byte random salt.
    """
    return os.urandom(SALT_LENGTH)


def salt_to_hex(salt: bytes) -> str:
    """Convert salt bytes to hex string for config storage."""
    return salt.hex()


def hex_to_salt(hex_str: str) -> bytes:
    """Convert hex string back to salt bytes.

    Raises:
        PagevaultError: If hex string is invalid or wrong length.
    """
    try:
        salt = bytes.fromhex(hex_str)
    except ValueError as e:
        raise PagevaultError(f"Invalid hex string for salt: {e}") from e

    if len(salt) != SALT_LENGTH:
        raise PagevaultError(
            f"Salt must be {SALT_LENGTH} bytes ({SALT_LENGTH * 2} hex chars), "
            f"got {len(salt)} bytes"
        )
    return salt


# Content hash parameters
HASH_LENGTH = 16  # 128 bits (32 hex chars) - sufficient for integrity check


def pad_content(plaintext: str) -> str:
    """Pad plaintext to nearest power-of-2 byte boundary.

    Appends null bytes (\\x00) so the total byte length is a power of 2.
    This prevents approximate content size leakage from ciphertext length.

    Args:
        plaintext: The plaintext content to pad.

    Returns:
        Padded plaintext string (original content + null padding).
    """
    raw_bytes = plaintext.encode("utf-8")
    length = len(raw_bytes)
    if length == 0:
        return plaintext

    # Find next power of 2 >= length
    target = 1 << (length - 1).bit_length()
    if target == length:
        return plaintext

    # Pad with null bytes
    padding = b"\x00" * (target - length)
    return (raw_bytes + padding).decode("utf-8", errors="replace")


def pad_content_bytes(data: bytes) -> bytes:
    """Pad raw bytes to next power-of-2 length.

    Args:
        data: Raw bytes to pad.

    Returns:
        Padded bytes (with null bytes appended).
    """
    length = len(data)
    if length == 0:
        return data
    target = 1 << (length - 1).bit_length()
    return data + b"\x00" * (target - length)


def content_hash(content: str) -> str:
    """Compute truncated SHA-256 hash of content for integrity verification.

    Args:
        content: The plaintext content to hash.

    Returns:
        Hex-encoded truncated hash (32 characters / 128 bits).
    """
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return digest[:HASH_LENGTH].hex()


def content_hash_bytes(data: bytes) -> str:
    """Compute truncated SHA-256 hash of raw bytes.

    Args:
        data: Raw bytes to hash.

    Returns:
        Hex string of first 16 bytes of SHA-256 digest (32 hex chars).
    """
    digest = hashlib.sha256(data).digest()
    return digest[:HASH_LENGTH].hex()


# ---------------------------------------------------------------------------
# v3 chunked encryption
# ---------------------------------------------------------------------------


def _derive_chunk_iv(iv_base: bytes, chunk_index: int) -> bytes:
    """Derive chunk IV by XORing chunk index into last 4 bytes of base IV.

    The chunk index is encoded as a 4-byte big-endian integer and XORed
    into bytes 8-11 of the 12-byte base IV.  Chunk 0 returns the base IV
    unchanged (XOR with 0 is identity).

    Args:
        iv_base: 12-byte base IV.
        chunk_index: Zero-based chunk index.

    Returns:
        12-byte derived IV for this chunk.
    """
    if chunk_index >= 2**32:
        raise PagevaultError(f"Chunk index {chunk_index} exceeds 2^32 IV counter space")
    iv = bytearray(iv_base)
    iv[8] ^= (chunk_index >> 24) & 0xFF
    iv[9] ^= (chunk_index >> 16) & 0xFF
    iv[10] ^= (chunk_index >> 8) & 0xFF
    iv[11] ^= chunk_index & 0xFF
    return bytes(iv)


def encrypt_v4(
    data: bytes,
    password: str | None = None,
    salt: bytes | None = None,
    users: dict[str, str] | None = None,
    meta: dict | None = None,
    chunk_size: int = CHUNK_SIZE,
) -> tuple[dict, list[str]]:
    """Encrypt raw bytes using v3 chunked format.

    Data is split into fixed-size chunks, each encrypted with AES-256-GCM
    using a counter-derived IV.  Metadata is encrypted separately.  The
    content encryption key (CEK) is wrapped per-user identically to v2.

    Args:
        data: Raw bytes to encrypt.
        password: Single password (no username) for key derivation.
        salt: Optional 16-byte salt.  If None, generates random.
        users: Dict of {username: password} for multi-user encryption.
        meta: Optional metadata dict to encrypt alongside content.
        chunk_size: Bytes per chunk (default 1 MB).

    Returns:
        Tuple of (envelope_dict, list_of_base64_chunk_ciphertexts).

    Raises:
        PagevaultError: On invalid arguments.
    """
    if password is not None and users is not None:
        raise PagevaultError("Cannot specify both 'password' and 'users'")
    if password is None and users is None:
        raise PagevaultError("Must specify either 'password' or 'users'")
    if users is not None and len(users) == 0:
        raise PagevaultError("'users' dict must not be empty")

    if chunk_size <= 0:
        raise PagevaultError(f"chunk_size must be positive, got {chunk_size}")

    # Salt
    if salt is None:
        salt = os.urandom(SALT_LENGTH)
    elif len(salt) != SALT_LENGTH:
        raise PagevaultError(f"Salt must be {SALT_LENGTH} bytes")

    # Random CEK and base IV
    cek = os.urandom(KEY_LENGTH)
    iv_base = os.urandom(IV_LENGTH)

    # Wrap CEK for each user/password
    keys = _wrap_cek_for_users(cek, salt, password=password, users=users)

    aesgcm = AESGCM(cek)

    # Encrypt metadata
    meta_iv = os.urandom(IV_LENGTH)
    meta_json = json.dumps(meta or {}).encode("utf-8")
    meta_ct = aesgcm.encrypt(meta_iv, meta_json, None)

    # Encrypt data chunks
    total_size = len(data)
    chunk_b64_list: list[str] = []
    for i in range(0, total_size, chunk_size):
        chunk_data = data[i : i + chunk_size]
        chunk_iv = _derive_chunk_iv(iv_base, i // chunk_size)
        chunk_ct = aesgcm.encrypt(chunk_iv, chunk_data, None)
        chunk_b64_list.append(base64.b64encode(chunk_ct).decode("ascii"))

    chunk_count = len(chunk_b64_list)
    if chunk_count >= 2**32:
        raise PagevaultError("Too many chunks: exceeds 2^32 IV counter space")

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


def decrypt_v4(
    envelope: dict,
    chunks: list[str],
    password: str,
    username: str | None = None,
) -> tuple[bytes, dict]:
    """Decrypt v3 chunked payload.

    Recovers the CEK via key unwrapping, decrypts metadata, then decrypts
    each chunk using counter-derived IVs and concatenates the results.

    Args:
        envelope: The v3 envelope dict from encrypt_v4().
        chunks: List of base64-encoded chunk ciphertexts.
        password: The password used for encryption.
        username: Optional username for multi-user content.

    Returns:
        Tuple of (decrypted_bytes, metadata_dict).

    Raises:
        PagevaultError: If decryption fails.
    """
    if envelope.get("v") != VERSION_V3:
        raise PagevaultError(f"Expected v3, got v{envelope.get('v')}")

    try:
        salt = bytes.fromhex(envelope["salt"])
    except (ValueError, KeyError) as e:
        raise PagevaultError(f"Invalid salt in envelope: {e}") from e

    secret = _build_secret(password, username)
    wrapping_key = _derive_key(secret, salt)

    # Try each key blob to unwrap CEK
    cek = _try_unwrap_cek(envelope.get("keys", []), wrapping_key)
    if cek is None:
        raise PagevaultError("Decryption failed: wrong password or tampered ciphertext")

    aesgcm = AESGCM(cek)

    # Decrypt metadata
    try:
        meta_iv = base64.b64decode(envelope["meta_iv"])
        meta_ct = base64.b64decode(envelope["meta_ct"])
        meta_bytes = aesgcm.decrypt(meta_iv, meta_ct, None)
        meta = json.loads(meta_bytes.decode("utf-8"))
    except Exception as e:
        raise PagevaultError(f"Failed to decrypt metadata: {e}") from e

    try:
        iv_base = base64.b64decode(envelope["iv_base"])
        total_size = envelope["total_size"]
    except Exception as e:
        raise PagevaultError(f"Missing required envelope field: {e}") from e

    if total_size == 0:
        return b"", meta

    # Decrypt each chunk
    parts: list[bytes] = []
    for i, chunk_b64 in enumerate(chunks):
        chunk_iv = _derive_chunk_iv(iv_base, i)
        try:
            chunk_ct = base64.b64decode(chunk_b64)
            chunk_data = aesgcm.decrypt(chunk_iv, chunk_ct, None)
        except Exception as e:
            raise PagevaultError(f"Failed to decrypt chunk {i}: {e}") from e
        parts.append(chunk_data)

    result = b"".join(parts)
    if len(result) != total_size:
        raise PagevaultError(
            f"Data length mismatch: expected {total_size}, got {len(result)}"
        )
    return result, meta


def inspect_payload_v3(envelope: dict) -> dict[str, Any]:
    """Inspect a v3 chunked envelope dict without decrypting.

    Args:
        envelope: The parsed JSON from a pv-meta script tag.

    Returns:
        Dict with version, algorithm, kdf, iterations, key_count,
        chunk_size, chunk_count, total_size.
    """
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
    """Verify password against a v3 envelope (key unwrap only, fast).

    Args:
        envelope: The parsed JSON from a pv-meta script tag.
        password: Password to verify.
        username: Optional username for multi-user.

    Returns:
        True if password successfully unwraps at least one key blob.

    Raises:
        PagevaultError: If envelope is not v3 or has invalid salt.
    """
    if envelope.get("v") != VERSION_V3:
        raise PagevaultError(f"Expected v3, got v{envelope.get('v')}")

    try:
        salt = bytes.fromhex(envelope["salt"])
    except (ValueError, KeyError) as e:
        raise PagevaultError(f"Invalid salt: {e}") from e

    secret = _build_secret(password, username)
    wrapping_key = _derive_key(secret, salt)

    return _try_unwrap_cek(envelope.get("keys", []), wrapping_key) is not None
