<<<<<<< HEAD
# Secure Cloud Storage

An encrypted file vault in Python (Flask) with a single-page dashboard.
Files are encrypted with **AES-256-GCM before they reach the storage backend**
(local disk or any S3-compatible bucket), so storage only ever holds ciphertext.

## Features

**Security / crypto**
- AES-256-GCM, chunked (64 KB) so large files stream instead of loading into RAM
- Envelope encryption: password → KEK → user master key → per-file key
- scrypt for password hashing and key derivation
- Detects tampering, truncation, chunk reordering and wrong keys; bad data is never released
- File names and activity-log file names are encrypted too
- Change password without re-encrypting any file

**Product**
- Dashboard: drag-and-drop upload, per-file progress, search, sort, rename, delete
- **Share links**: expiry, download limits, revoke. The decryption key is in the
  URL `#fragment` and is never stored server-side
- **Storage quota** per user with a usage meter
- **Activity log**: sign-ins, failed sign-ins, uploads, downloads, shares
- Light / dark theme, responsive layout, keyboard shortcut (`/` to search)
- Password strength meter on sign-up
- Pluggable storage: local disk or S3 (AWS, MinIO, R2 ...)
- Standalone `cli.py` for encrypting any file by hand

**Web hardening**
- CSRF tokens (forms + `X-CSRF-Token` header for the API)
- Strict CSP (`script-src 'self'`, no inline JS or CSS), `nosniff`, `X-Frame-Options: DENY`, `no-store`
- Login rate limit, equalised login timing, session rotation on login
- Every query scoped to the owner; share endpoints rate-limited
- 45 automated tests + browser end-to-end run

## Quick start (macOS / Linux)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
python3 app.py            # open http://127.0.0.1:5000
```
Windows PowerShell: `python -m venv .venv`, `.venv\Scripts\Activate.ps1`,
`$env:SECRET_KEY = python -c "import secrets;print(secrets.token_hex(32))"`.

Production (single process, several threads, behind HTTPS):
```bash
COOKIE_SECURE=1 gunicorn -w 1 --threads 8 -b 0.0.0.0:8000 "app:create_app()"
```

### Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | random per start | Flask session signing key. Set it in production |
| `COOKIE_SECURE` | `0` | `1` when served over HTTPS |
| `STORAGE_BACKEND` | `local` | `local` or `s3` |
| `LOCAL_STORAGE_DIR` | `./data/blobs` | Where ciphertext goes (local backend) |
| `S3_BUCKET`, `S3_PREFIX`, `S3_REGION`, `S3_ENDPOINT_URL`, `S3_SSE` | – | S3 settings (`pip install -r requirements-s3.txt`) |
| `MAX_UPLOAD_MB` | `100` | Largest single upload |
| `QUOTA_MB` | `500` | Storage per user |
| `SESSION_TTL_SECONDS` | `1800` | Idle time before keys are dropped from memory |

### CLI
```bash
python3 cli.py encrypt report.pdf        # -> report.pdf.enc
python3 cli.py decrypt report.pdf.enc    # -> report.pdf
```

### Tests
```bash
python3 -m unittest discover -s tests -v
```

## Project layout

```
app.py             Flask app factory: pages, auth, JSON API, share endpoints
crypto_engine.py   AES-GCM streaming, scrypt, key wrapping  (security core)
storage.py         LocalStorage and S3Storage backends
db.py              SQLite: users, files, shares, audit log
security.py        In-memory KeyVault + rate limiter
config.py          Environment-driven settings
cli.py             Standalone encrypt/decrypt tool
templates/         base (auth pages), app (dashboard), share (public page), ...
static/            style.css, theme.js, auth.js, app.js, share.js
tests/             test_crypto.py, test_app.py
```

## How it works

### 1. Key hierarchy

```
password ──scrypt(kek_salt)──► KEK ──wraps──► UMK ──wraps──► DEK ──encrypts──► file bytes
                                                │
                                                ├──encrypts──► file name
                                                └──encrypts──► activity-log names
```

| Key | Created | Stored as |
|---|---|---|
| KEK (key-encryption key) | at login, from the password | never stored |
| UMK (user master key) | random, at registration | wrapped by KEK, in `users` |
| DEK (data key) | random, per upload | wrapped by UMK, in `files` |

*Why this shape?* Changing your password re-wraps one 32-byte key instead of
re-encrypting every file; a leaked DEK exposes one file; the login hash uses a
separate salt, so it can't be turned into the KEK.

### 2. Stored file format

```
header : "SCS1" | nonce_prefix (4) | chunk_size (4)
records: [ length (4) | ciphertext + 16-byte tag ] ...
nonce  = nonce_prefix || chunk_counter (8 bytes)
AAD    = header || (0x01 if last chunk else 0x00)
```
The counter in the nonce stops reordering, the "last chunk" flag in the AAD
stops truncation, and the header in the AAD stops header tampering. Sealed
blobs (names, wrapped keys) also bind a context string such as `name:<file_id>`,
so a blob copied to another row fails to decrypt.

### 3. Upload → download

1. Browser sends the file to `POST /api/upload` (XHR, so progress is shown).
2. Server generates a DEK, streams the file through `encrypt_stream` into a
   temp buffer, checks the quota, then writes ciphertext to storage.
3. DB row stores: name (sealed with UMK), size, storage key, DEK (wrapped with UMK).
4. Download unwraps the DEK with the UMK held in memory, decrypts into a temp
   file, and only sends it if **every** chunk's tag verified.

### 4. The key vault

At login the UMK is unwrapped and kept in server memory (`KeyVault`) under a
random token. The browser cookie carries only that token. The UMK disappears on
logout, after `SESSION_TTL_SECONDS` idle, or on server restart.

### 5. Share links

```
https://host/s/<token>#<share_key>
        │                │
        │                └ stays in the browser; never in the DB, never in a request URL
        └ looked up in the DB
```
- Creating a link generates a random **share key**, wraps the file's DEK and name
  with it, and stores only those wrapped values plus expiry and limit.
- The share page's JS reads the key from `location.hash` and POSTs it in the
  request body. The server unwraps, decrypts, verifies and streams the file.
- Download counting is a single atomic SQL `UPDATE ... WHERE downloads < max`, so
  races can't exceed the limit. Tampered files don't consume a download.
- Revoking deletes the row; deleting the file cascades to its links. Because the
  key isn't stored, a link can't be re-displayed: revoke and create a new one.

### 6. API reference (all require login + `X-CSRF-Token` unless noted)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/files` | List files, usage, active-share counts |
| POST | `/api/upload` | Upload one file (multipart `file`) |
| GET | `/download/<id>` | Download (decrypted) |
| PATCH | `/api/files/<id>` | Rename `{name}` |
| DELETE | `/api/files/<id>` | Delete file + its links |
| POST | `/api/files/<id>/share` | Create link `{hours, max_downloads}` → `{token, key}` |
| GET | `/api/shares` | List links with status |
| DELETE | `/api/shares/<token>` | Revoke |
| GET | `/api/activity` | Last 100 events |
| POST | `/api/s/<token>/meta` | **Public.** `{key}` → name, size, expiry |
| POST | `/api/s/<token>/file` | **Public.** `{key}` → decrypted bytes |

### 7. Database tables

`users` (salts, login hash, wrapped UMK) · `files` (sealed name, wrapped DEK,
storage key) · `shares` (wrapped DEK, sealed name, expiry, limits, counter) ·
`audit` (event, ip, sealed file name). All encrypted values are
`nonce || ciphertext || tag`.

## Security properties and limits

Protects against:
- Storage/bucket compromise or a curious cloud provider (only ciphertext and wrapped keys there)
- Modification of stored files (GCM tags fail, nothing is released)
- One user reading another's files or links

Know before real use:
- **No password recovery.** Forgetting the password loses the files, by design.
- **Not end-to-end.** The server sees plaintext and the password during upload,
  download and login. This protects data *at rest*, not against a compromised
  app server. True E2EE would move the crypto into the browser (WebCrypto).
- Share links are decrypted server-side; the "key in `#`" keeps the key out of
  the database, logs and Referer headers, but the server does see it per request.
  Serve over HTTPS and avoid logging request bodies.
- The UMK sits in process memory while logged in → run one worker with threads,
  or move `KeyVault` to Redis for multi-process setups.
- Rate limiters are in-memory; add one at your reverse proxy too.
- File sizes and upload times are not hidden.
- Get an independent security review before storing sensitive data.

## Ideas to extend
TOTP two-factor login, recipient-specific sharing with public keys, file
versions, folders, virus scanning hook, background key-rotation job,
browser-side (WebCrypto) encryption for true E2EE.
=======
# Secure-Cloud-Storage
>>>>>>> a096e0f4aa7b01a69bb2df0d5b357551d56b3320
