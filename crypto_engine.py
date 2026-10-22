"""
Cryptographic engine for Secure Cloud Storage.

Design (envelope encryption)
----------------------------
    password --scrypt(kek_salt)--> KEK  (key-encryption key, never stored)
    KEK  wraps  UMK                      (per-user master key, random 256-bit)
    UMK  wraps  DEK                      (per-file data key, random 256-bit)
    DEK  encrypts file contents          (chunked AES-256-GCM)
    UMK  also encrypts file names        (AES-256-GCM)

Why envelope encryption?
  * Changing a password only re-wraps one 32-byte key, not every file.
  * Every file has its own key, so one leaked DEK exposes one file only.
  * The storage backend (local disk / S3) only ever sees ciphertext.

File format (what is actually uploaded to storage)
--------------------------------------------------
    header  : MAGIC(4) | nonce_prefix(4) | chunk_size(4, big endian)
    records : [ct_len(4) | ciphertext+tag] ...   (one per chunk)

    nonce_i = nonce_prefix || counter_i (8 bytes, big endian)
    AAD_i   = header || (0x01 if last chunk else 0x00)

The counter in the nonce stops chunks being reordered, the final-chunk flag in
the AAD stops truncation, and the header in the AAD stops header tampering.
"""
from __future__ import annotations

import hmac
import os
import struct
from typing import BinaryIO, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEY_LEN = 32          # AES-256
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
MAGIC = b"SCS1"
CHUNK_SIZE = 64 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
_HEADER = struct.Struct(">4s4sI")
HEADER_LEN = _HEADER.size

DEFAULT_SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1


class CryptoError(Exception):
    """Base class for all crypto failures."""


class IntegrityError(CryptoError):
    """Ciphertext was modified, truncated, or the wrong key was used."""


# --------------------------------------------------------------------------- #
# Keys, salts, passwords
# --------------------------------------------------------------------------- #
def new_key() -> bytes:
    return os.urandom(KEY_LEN)


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_key(password: str, salt: bytes, n: int = DEFAULT_SCRYPT_N) -> bytes:
    """Stretch a password into a 256-bit key with scrypt."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def hash_password(password: str, n: int = DEFAULT_SCRYPT_N) -> tuple[bytes, bytes]:
    """Return (salt, hash) for login verification. Independent of the KEK salt."""
    salt = new_salt()
    return salt, derive_key(password, salt, n)


def verify_password(password: str, salt: bytes, expected: bytes,
                    n: int = DEFAULT_SCRYPT_N) -> bool:
    return hmac.compare_digest(derive_key(password, salt, n), expected)


# --------------------------------------------------------------------------- #
# Small-blob AEAD (key wrapping, file names)
# --------------------------------------------------------------------------- #
def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM encrypt a small blob. Output: nonce(12) || ciphertext+tag."""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise IntegrityError("Sealed blob is too short")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
    except InvalidTag as exc:
        raise IntegrityError("Wrong key or corrupted data") from exc


# Readable aliases for key wrapping.
wrap_key = seal
unwrap_key = unseal


# --------------------------------------------------------------------------- #
# Streaming file encryption
# --------------------------------------------------------------------------- #
def _read_up_to(src: BinaryIO, n: int) -> bytes:
    """Read exactly n bytes unless EOF is hit first."""
    parts, remaining = [], n
    while remaining:
        block = src.read(remaining)
        if not block:
            break
        parts.append(block)
        remaining -= len(block)
    return b"".join(parts)


def encrypt_stream(src: BinaryIO, dst: BinaryIO, dek: bytes,
                   chunk_size: int = CHUNK_SIZE) -> int:
    """Encrypt src -> dst with chunked AES-256-GCM. Returns plaintext size."""
    if len(dek) != KEY_LEN:
        raise CryptoError("DEK must be 32 bytes")
    aes = AESGCM(dek)
    prefix = os.urandom(4)
    header = _HEADER.pack(MAGIC, prefix, chunk_size)
    dst.write(header)

    total = 0
    counter = 0
    current = _read_up_to(src, chunk_size)
    while True:
        upcoming = _read_up_to(src, chunk_size)
        final = not upcoming
        nonce = prefix + struct.pack(">Q", counter)
        ct = aes.encrypt(nonce, current, header + (b"\x01" if final else b"\x00"))
        dst.write(struct.pack(">I", len(ct)))
        dst.write(ct)
        total += len(current)
        if final:
            return total
        current = upcoming
        counter += 1


def _read_chunk_len(src: BinaryIO) -> Optional[int]:
    raw = _read_up_to(src, 4)
    if not raw:
        return None
    if len(raw) != 4:
        raise IntegrityError("Truncated ciphertext")
    return struct.unpack(">I", raw)[0]


def decrypt_stream(src: BinaryIO, dst: BinaryIO, dek: bytes) -> int:
    """
    Decrypt src -> dst. Returns plaintext size.

    NOTE: plaintext is written chunk by chunk, so callers must not expose `dst`
    until this function returns without raising (the web app decrypts into a
    temporary file first for exactly this reason).
    """
    header = _read_up_to(src, HEADER_LEN)
    if len(header) != HEADER_LEN:
        raise IntegrityError("Not an encrypted file (header too short)")
    magic, prefix, chunk_size = _HEADER.unpack(header)
    if magic != MAGIC:
        raise IntegrityError("Not an encrypted file (bad magic)")
    if not 0 < chunk_size <= MAX_CHUNK_SIZE:
        raise IntegrityError("Invalid chunk size in header")

    aes = AESGCM(dek)
    total = 0
    counter = 0
    ct_len = _read_chunk_len(src)
    if ct_len is None:
        raise IntegrityError("Ciphertext has no data records")

    while True:
        if not TAG_LEN <= ct_len <= chunk_size + TAG_LEN:
            raise IntegrityError("Invalid chunk length")
        ct = _read_up_to(src, ct_len)
        if len(ct) != ct_len:
            raise IntegrityError("Truncated ciphertext")
        next_len = _read_chunk_len(src)
        final = next_len is None
        nonce = prefix + struct.pack(">Q", counter)
        try:
            pt = aes.decrypt(nonce, ct, header + (b"\x01" if final else b"\x00"))
        except InvalidTag as exc:
            raise IntegrityError(
                "Integrity check failed (wrong key, tampering, or truncation)"
            ) from exc
        dst.write(pt)
        total += len(pt)
        if final:
            return total
        ct_len = next_len
        counter += 1
