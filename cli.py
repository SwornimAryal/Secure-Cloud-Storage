#!/usr/bin/env python3
"""
Standalone command-line tool: password-encrypt any file before putting it in
ANY cloud drive (Dropbox, Google Drive, S3, USB stick...). Uses the same
chunked AES-256-GCM engine as the web app.

    python cli.py encrypt  report.pdf            -> report.pdf.enc
    python cli.py decrypt  report.pdf.enc        -> report.pdf
    python cli.py encrypt  a.zip -o out.bin --force

File layout:  "SCSP" | log2(scrypt N) (1 byte) | salt (16 bytes) | <crypto_engine stream>
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

import crypto_engine as ce

MAGIC = b"SCSP"
LOG2_N = 15      # scrypt cost 2**15 (~32 MB RAM); raise for more brute-force resistance


def _password(confirm: bool) -> str:
    pw = os.environ.get("SCS_PASSWORD") or getpass.getpass("Password: ")
    if confirm and not os.environ.get("SCS_PASSWORD"):
        if pw != getpass.getpass("Confirm password: "):
            sys.exit("Passwords do not match.")
    if len(pw) < 10:
        sys.exit("Use a password of at least 10 characters.")
    return pw


def _check_out(path: str, force: bool) -> None:
    if os.path.exists(path) and not force:
        sys.exit(f"{path} already exists (use --force to overwrite).")


def encrypt(args) -> None:
    out = args.output or args.input + ".enc"
    _check_out(out, args.force)
    pw = _password(confirm=True)
    salt = ce.new_salt()
    key = ce.derive_key(pw, salt, 2 ** LOG2_N)
    with open(args.input, "rb") as src, open(out, "wb") as dst:
        dst.write(MAGIC + bytes([LOG2_N]) + salt)
        size = ce.encrypt_stream(src, dst, key)
    os.chmod(out, 0o600)
    print(f"Encrypted {size} bytes -> {out}")


def decrypt(args) -> None:
    if args.output:
        out = args.output
    elif args.input.endswith(".enc"):
        out = args.input[:-4]
    else:
        sys.exit("Cannot guess output name; pass -o.")
    _check_out(out, args.force)

    with open(args.input, "rb") as src:
        head = src.read(len(MAGIC) + 1 + ce.SALT_LEN)
        if len(head) < len(MAGIC) + 1 + ce.SALT_LEN or head[:4] != MAGIC:
            sys.exit("Not a file produced by this tool.")
        log2n, salt = head[4], head[5:]
        if not 10 <= log2n <= 22:
            sys.exit("Unsupported scrypt parameters in file header.")
        key = ce.derive_key(_password(confirm=False), salt, 2 ** log2n)
        try:
            with open(out, "wb") as dst:
                size = ce.decrypt_stream(src, dst, key)
        except ce.IntegrityError as exc:
            if os.path.exists(out):
                os.remove(out)                    # never leave unverified plaintext behind
            sys.exit(f"Decryption failed: {exc}")
    os.chmod(out, 0o600)
    print(f"Decrypted {size} bytes -> {out}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, fn in (("encrypt", encrypt), ("decrypt", decrypt)):
        p = sub.add_parser(name)
        p.add_argument("input")
        p.add_argument("-o", "--output")
        p.add_argument("--force", action="store_true", help="overwrite existing output")
        p.set_defaults(fn=fn)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
