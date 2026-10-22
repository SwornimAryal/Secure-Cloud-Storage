import io
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crypto_engine as ce  # noqa: E402

N = 2 ** 10   # cheap scrypt for tests


def enc(data: bytes, key: bytes, chunk: int = ce.CHUNK_SIZE) -> bytes:
    out = io.BytesIO()
    ce.encrypt_stream(io.BytesIO(data), out, key, chunk)
    return out.getvalue()


def dec(blob: bytes, key: bytes) -> bytes:
    out = io.BytesIO()
    ce.decrypt_stream(io.BytesIO(blob), out, key)
    return out.getvalue()


class StreamTests(unittest.TestCase):
    def setUp(self):
        self.key = ce.new_key()

    def test_roundtrip_sizes(self):
        c = ce.CHUNK_SIZE
        for size in (0, 1, 15, c - 1, c, c + 1, 3 * c, 3 * c + 17):
            data = os.urandom(size)
            self.assertEqual(dec(enc(data, self.key), self.key), data, f"size={size}")

    def test_small_chunks(self):
        data = os.urandom(1000)
        self.assertEqual(dec(enc(data, self.key, chunk=64), self.key), data)

    def test_ciphertext_differs_each_time(self):
        data = b"same plaintext"
        self.assertNotEqual(enc(data, self.key), enc(data, self.key))

    def test_plaintext_not_visible(self):
        marker = b"TOP-SECRET-MARKER" * 10
        self.assertNotIn(b"TOP-SECRET-MARKER", enc(marker, self.key))

    def test_wrong_key(self):
        blob = enc(b"hello", self.key)
        with self.assertRaises(ce.IntegrityError):
            dec(blob, ce.new_key())

    def test_bit_flip_anywhere_is_detected(self):
        blob = enc(os.urandom(300), self.key, chunk=100)
        for pos in range(0, len(blob), 7):
            bad = bytearray(blob)
            bad[pos] ^= 0x01
            with self.assertRaises(ce.CryptoError, msg=f"byte {pos}"):
                dec(bytes(bad), self.key)

    def test_truncation_detected(self):
        c = 100
        blob = enc(os.urandom(450), self.key, chunk=c)
        # drop the final record entirely
        pos = ce.HEADER_LEN
        last_start = pos
        while pos < len(blob):
            last_start = pos
            (n,) = struct.unpack(">I", blob[pos:pos + 4])
            pos += 4 + n
        with self.assertRaises(ce.IntegrityError):
            dec(blob[:last_start], self.key)
        with self.assertRaises(ce.IntegrityError):      # mid-record cut
            dec(blob[:-5], self.key)

    def test_chunk_reordering_detected(self):
        blob = enc(os.urandom(300), self.key, chunk=100)
        records, pos = [], ce.HEADER_LEN
        while pos < len(blob):
            (n,) = struct.unpack(">I", blob[pos:pos + 4])
            records.append(blob[pos:pos + 4 + n])
            pos += 4 + n
        swapped = blob[:ce.HEADER_LEN] + records[1] + records[0] + b"".join(records[2:])
        with self.assertRaises(ce.IntegrityError):
            dec(swapped, self.key)

    def test_garbage_rejected(self):
        for junk in (b"", b"short", b"XXXX" + os.urandom(100)):
            with self.assertRaises(ce.IntegrityError):
                dec(junk, self.key)


class KeyTests(unittest.TestCase):
    def test_seal_unseal(self):
        k = ce.new_key()
        blob = ce.seal(k, b"secret", b"ctx")
        self.assertEqual(ce.unseal(k, blob, b"ctx"), b"secret")

    def test_aad_binding(self):
        k = ce.new_key()
        blob = ce.seal(k, b"secret", b"file-1")
        with self.assertRaises(ce.IntegrityError):
            ce.unseal(k, blob, b"file-2")

    def test_wrap_unwrap_dek(self):
        umk, dek = ce.new_key(), ce.new_key()
        self.assertEqual(ce.unwrap_key(umk, ce.wrap_key(umk, dek, b"x"), b"x"), dek)

    def test_password_hash(self):
        salt, h = ce.hash_password("correct horse battery", N)
        self.assertTrue(ce.verify_password("correct horse battery", salt, h, N))
        self.assertFalse(ce.verify_password("wrong password!!", salt, h, N))

    def test_kdf_deterministic_and_salted(self):
        s = ce.new_salt()
        self.assertEqual(ce.derive_key("pw", s, N), ce.derive_key("pw", s, N))
        self.assertNotEqual(ce.derive_key("pw", s, N), ce.derive_key("pw", ce.new_salt(), N))


if __name__ == "__main__":
    unittest.main()
