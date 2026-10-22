"""Secure Cloud Storage - Flask application (HTML pages + JSON API)."""
from __future__ import annotations

import base64
import hmac
import os
import re
import secrets
import tempfile
import uuid
from functools import wraps

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from werkzeug.exceptions import HTTPException

import crypto_engine as ce
from config import Config
from db import Database, UsernameTaken, now_iso
from security import KeyVault, LoginLimiter
from storage import StorageError, build_storage

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
SPOOL_LIMIT = 8 * 1024 * 1024          # keep up to 8 MB of temp data in RAM
MB = 1024 * 1024
CSRF_EXEMPT = {"api_share_meta", "api_share_file"}   # public, capability-based endpoints


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


def clean_filename(raw: str | None) -> str:
    name = (raw or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
    return (name or "unnamed")[:255]


def b64u_enc(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_dec_key(text: str) -> bytes:
    text = text.strip()
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if len(raw) != ce.KEY_LEN:
        raise ValueError("bad key length")
    return raw


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    db = Database(app.config["DATABASE"])
    db.init()
    storage = build_storage(app.config)
    vault = KeyVault(app.config["SESSION_TTL_SECONDS"])
    limiter = LoginLimiter(app.config["LOGIN_MAX_ATTEMPTS"], app.config["LOGIN_WINDOW_SECONDS"])
    share_limiter = LoginLimiter(20, 600)          # bad share tokens / keys per IP
    scrypt_n = app.config["SCRYPT_N"]
    quota_bytes = lambda: app.config["QUOTA_MB"] * MB      # noqa: E731

    # ------------------------------------------------------------------ #
    # CSRF, security headers, error handling
    # ------------------------------------------------------------------ #
    def csrf_token() -> str:
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def _csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE") \
                and request.endpoint not in CSRF_EXEMPT:
            sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not expected or not hmac.compare_digest(sent, expected):
                abort(400, "Invalid or missing CSRF token. Reload the page and try again.")

    @app.after_request
    def _headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(ApiError)
    def _api_error(e: ApiError):
        return jsonify(error=e.message), e.status

    @app.errorhandler(HTTPException)
    def _http_error(e: HTTPException):
        message = e.description
        if e.code == 413:
            message = f"Upload too large (limit {app.config['MAX_CONTENT_LENGTH'] // MB} MB per file)."
        if request.path.startswith("/api/"):
            return jsonify(error=message), e.code
        return render_template("error.html", code=e.code, message=message), e.code

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            entry = vault.get(session.get("token"))
            if entry is None:
                session.pop("token", None)
                if request.path.startswith("/api/"):
                    return jsonify(error="Session expired. Please sign in again."), 401
                flash("Please sign in to continue.", "warning")
                return redirect(url_for("login"))
            g.user_id, g.username, g.umk = entry.user_id, entry.username, entry.umk
            return view(*args, **kwargs)
        return wrapped

    # AAD strings bind each sealed value to its row so blobs can't be swapped.
    name_aad = lambda fid: b"name:" + fid.encode()                      # noqa: E731
    dek_aad = lambda fid: b"dek:" + fid.encode()                        # noqa: E731
    share_dek_aad = lambda tok: b"share-dek:" + tok.encode()            # noqa: E731
    share_name_aad = lambda tok: b"share-name:" + tok.encode()          # noqa: E731

    def log(user_id: int, event: str, ref: str | None = None,
            name: str | None = None, umk: bytes | None = None) -> None:
        detail = ce.seal(umk, name.encode("utf-8"), b"audit") if (umk and name) else None
        db.add_audit(user_id, event, ref, detail, request.remote_addr)

    def file_name(row) -> str:
        try:
            return ce.unseal(g.umk, row["name_enc"], name_aad(row["id"])).decode("utf-8")
        except ce.CryptoError:
            return "<unreadable name>"

    def file_json(row, shared: int = 0) -> dict:
        return {"id": row["id"], "name": file_name(row), "size": row["size"],
                "created": row["created_at"], "shared": shared}

    def usage_json() -> dict:
        used, count = db.usage(g.user_id)
        return {"used": used, "quota": quota_bytes(), "count": count}

    def owned_file(file_id: str):
        row = db.get_file(g.user_id, file_id)              # always scoped to the owner
        if row is None:
            raise ApiError("File not found.", 404)
        return row

    def decrypt_to_temp(storage_key: str, dek: bytes):
        """Decrypt into a temp file; plaintext is only released if every tag verified."""
        plain = tempfile.SpooledTemporaryFile(max_size=SPOOL_LIMIT)
        try:
            with storage.get(storage_key) as cipher:
                ce.decrypt_stream(cipher, plain, dek)
        except StorageError as exc:
            plain.close()
            raise ApiError(str(exc), 502)
        except ce.IntegrityError:
            plain.close()
            raise ApiError("This file failed its integrity check and was NOT released. "
                           "It may be corrupted or have been tampered with in storage.", 500)
        plain.seek(0)
        return plain

    # ------------------------------------------------------------------ #
    # Pages & auth
    # ------------------------------------------------------------------ #
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")
            min_len = app.config["MIN_PASSWORD_LENGTH"]

            error = None
            if not USERNAME_RE.match(username):
                error = "Username must be 3-32 characters: letters, digits, . _ -"
            elif len(password) < min_len:
                error = f"Password must be at least {min_len} characters."
            elif password != confirm:
                error = "Passwords do not match."

            if error:
                flash(error, "error")
            else:
                auth_salt, auth_hash = ce.hash_password(password, scrypt_n)
                kek_salt = ce.new_salt()
                kek = ce.derive_key(password, kek_salt, scrypt_n)
                umk = ce.new_key()
                wrapped_umk = ce.wrap_key(kek, umk, b"umk")
                try:
                    uid = db.create_user(username, auth_salt, auth_hash, kek_salt, wrapped_umk)
                except UsernameTaken:
                    flash("That username is already taken.", "error")
                else:
                    log(uid, "register")
                    flash("Account created. You can sign in now.", "success")
                    return redirect(url_for("login"))
        return render_template("register.html", min_len=app.config["MIN_PASSWORD_LENGTH"])

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            limit_key = f"{request.remote_addr}|{username.lower()}"

            if limiter.blocked(limit_key):
                flash("Too many failed attempts. Try again in a few minutes.", "error")
                return render_template("login.html"), 429

            user = db.get_user_by_name(username)
            if user is None:
                # Burn the same CPU time so response timing doesn't reveal valid names.
                ce.derive_key(password, b"\x00" * ce.SALT_LEN, scrypt_n)
                ok = False
            else:
                ok = ce.verify_password(password, user["auth_salt"], user["auth_hash"], scrypt_n)

            if not ok:
                limiter.fail(limit_key)
                if user is not None:
                    log(user["id"], "login_failed")
                flash("Invalid username or password.", "error")
                return render_template("login.html"), 401

            kek = ce.derive_key(password, user["kek_salt"], scrypt_n)
            try:
                umk = ce.unwrap_key(kek, user["wrapped_umk"], b"umk")
            except ce.CryptoError:
                flash("Could not unlock your account keys.", "error")
                return render_template("login.html"), 500

            limiter.reset(limit_key)
            vault.drop(session.get("token"))
            session.clear()                        # new session on login (fixation defence)
            session["token"] = vault.put(user["id"], user["username"], umk)
            log(user["id"], "login")
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        entry = vault.get(session.get("token"))
        if entry:
            log(entry.user_id, "logout")
        vault.drop(session.get("token"))
        session.clear()
        flash("Signed out.", "success")
        return redirect(url_for("login"))

    @app.route("/account/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            current = request.form.get("current", "")
            new = request.form.get("new", "")
            confirm = request.form.get("confirm", "")
            min_len = app.config["MIN_PASSWORD_LENGTH"]
            user = db.get_user_by_name(g.username)

            if not ce.verify_password(current, user["auth_salt"], user["auth_hash"], scrypt_n):
                flash("Current password is incorrect.", "error")
            elif len(new) < min_len:
                flash(f"New password must be at least {min_len} characters.", "error")
            elif new != confirm:
                flash("New passwords do not match.", "error")
            else:
                # Envelope encryption pays off here: only the 32-byte UMK is
                # re-wrapped. No stored file has to be touched.
                auth_salt, auth_hash = ce.hash_password(new, scrypt_n)
                kek_salt = ce.new_salt()
                kek = ce.derive_key(new, kek_salt, scrypt_n)
                db.update_credentials(g.user_id, auth_salt, auth_hash, kek_salt,
                                      ce.wrap_key(kek, g.umk, b"umk"))
                log(g.user_id, "password_change")
                flash("Password changed. Your files were not re-encrypted - only your key was re-wrapped.",
                      "success")
                return redirect(url_for("dashboard"))
        return render_template("change_password.html", min_len=app.config["MIN_PASSWORD_LENGTH"])

    @app.get("/")
    @login_required
    def dashboard():
        return render_template("app.html", username=g.username,
                               max_mb=app.config["MAX_CONTENT_LENGTH"] // MB)

    # ------------------------------------------------------------------ #
    # JSON API - files
    # ------------------------------------------------------------------ #
    @app.get("/api/files")
    @login_required
    def api_files():
        counts = db.share_counts(g.user_id)
        files = [file_json(r, counts.get(r["id"], 0)) for r in db.list_files(g.user_id)]
        return jsonify(files=files, usage=usage_json())

    @app.post("/api/upload")
    @login_required
    def api_upload():
        incoming = request.files.get("file")
        if incoming is None or not incoming.filename:
            raise ApiError("No file received.")
        used, _ = db.usage(g.user_id)
        if used + (request.content_length or 0) > quota_bytes():
            raise ApiError(f"Storage quota of {app.config['QUOTA_MB']} MB would be exceeded.", 413)

        file_id = uuid.uuid4().hex
        storage_key = f"{g.user_id}/{file_id}"
        dek = ce.new_key()
        name = clean_filename(incoming.filename)

        with tempfile.SpooledTemporaryFile(max_size=SPOOL_LIMIT) as cipher:
            size = ce.encrypt_stream(incoming.stream, cipher, dek)
            if used + size > quota_bytes():
                raise ApiError(f"Storage quota of {app.config['QUOTA_MB']} MB would be exceeded.", 413)
            cipher.seek(0)
            try:
                storage.put(storage_key, cipher)
            except StorageError as exc:
                raise ApiError(f"Could not store file: {exc}", 502)

        try:
            db.add_file(file_id, g.user_id,
                        ce.seal(g.umk, name.encode("utf-8"), name_aad(file_id)),
                        size, storage_key, ce.wrap_key(g.umk, dek, dek_aad(file_id)))
        except Exception:
            storage.delete(storage_key)            # never leave orphaned ciphertext
            raise
        log(g.user_id, "upload", file_id, name, g.umk)
        return jsonify(file=file_json(db.get_file(g.user_id, file_id)),
                       usage=usage_json()), 201

    @app.get("/download/<file_id>")
    @login_required
    def download(file_id: str):
        row = db.get_file(g.user_id, file_id)
        if row is None:
            abort(404, "File not found.")
        try:
            dek = ce.unwrap_key(g.umk, row["wrapped_dek"], dek_aad(file_id))
        except ce.CryptoError:
            abort(500, "Stored key material failed its integrity check.")
        name = file_name(row)
        plain = decrypt_to_temp(row["storage_key"], dek)
        log(g.user_id, "download", file_id, name, g.umk)
        return send_file(plain, mimetype="application/octet-stream",
                         as_attachment=True, download_name=name)

    @app.patch("/api/files/<file_id>")
    @login_required
    def api_rename(file_id: str):
        row = owned_file(file_id)
        new = clean_filename((request.get_json(silent=True) or {}).get("name"))
        old = file_name(row)
        db.rename_file(g.user_id, file_id, ce.seal(g.umk, new.encode("utf-8"), name_aad(file_id)))
        log(g.user_id, "rename", file_id, f"{old} → {new}", g.umk)
        return jsonify(file=file_json(db.get_file(g.user_id, file_id)))

    @app.delete("/api/files/<file_id>")
    @login_required
    def api_delete(file_id: str):
        row = owned_file(file_id)
        name = file_name(row)
        try:
            storage.delete(row["storage_key"])
        except StorageError as exc:
            raise ApiError(f"Storage delete failed: {exc}", 502)
        db.delete_file(g.user_id, file_id)             # share links cascade-delete
        log(g.user_id, "delete", file_id, name, g.umk)
        return jsonify(ok=True, usage=usage_json())

    # ------------------------------------------------------------------ #
    # JSON API - share links
    # ------------------------------------------------------------------ #
    def share_status(row) -> str:
        if row["expires_at"] and row["expires_at"] <= now_iso():
            return "expired"
        if row["max_downloads"] is not None and row["downloads"] >= row["max_downloads"]:
            return "exhausted"
        return "active"

    @app.post("/api/files/<file_id>/share")
    @login_required
    def api_share_create(file_id: str):
        row = owned_file(file_id)
        body = request.get_json(silent=True) or {}
        hours, max_dl = body.get("hours"), body.get("max_downloads")
        try:
            hours = None if hours in (None, "") else float(hours)
            max_dl = None if max_dl in (None, "") else int(max_dl)
        except (TypeError, ValueError):
            raise ApiError("Invalid share options.")
        if hours is not None and not 0 < hours <= app.config["SHARE_MAX_HOURS"]:
            raise ApiError("Invalid expiry.")
        if max_dl is not None and not 1 <= max_dl <= 10_000:
            raise ApiError("Invalid download limit.")

        try:
            dek = ce.unwrap_key(g.umk, row["wrapped_dek"], dek_aad(file_id))
        except ce.CryptoError:
            raise ApiError("Stored key material failed its integrity check.", 500)
        token = secrets.token_urlsafe(16)
        share_key = ce.new_key()           # returned to the browser once, NEVER stored
        name = file_name(row)
        expires = now_iso(hours) if hours is not None else None
        db.add_share(token, g.user_id, file_id,
                     ce.wrap_key(share_key, dek, share_dek_aad(token)),
                     ce.seal(share_key, name.encode("utf-8"), share_name_aad(token)),
                     row["size"], expires, max_dl)
        log(g.user_id, "share_create", file_id, name, g.umk)
        return jsonify(token=token, key=b64u_enc(share_key), expires_at=expires,
                       max_downloads=max_dl), 201

    @app.get("/api/shares")
    @login_required
    def api_shares():
        out = []
        for s in db.list_shares(g.user_id):
            frow = db.get_file(g.user_id, s["file_id"])
            out.append({"token": s["token"], "file_id": s["file_id"],
                        "name": file_name(frow) if frow else "(deleted)",
                        "size": s["size"], "created": s["created_at"],
                        "expires_at": s["expires_at"], "max_downloads": s["max_downloads"],
                        "downloads": s["downloads"], "status": share_status(s)})
        return jsonify(shares=out)

    @app.delete("/api/shares/<token>")
    @login_required
    def api_share_revoke(token: str):
        s = db.get_share(token)
        if s is None or s["user_id"] != g.user_id:
            raise ApiError("Share link not found.", 404)
        frow = db.get_file(g.user_id, s["file_id"])
        db.revoke_share(g.user_id, token)
        log(g.user_id, "share_revoke", s["file_id"], file_name(frow) if frow else None, g.umk)
        return jsonify(ok=True)

    # ---- public side of share links (no login) ------------------------ #
    @app.get("/s/<token>")
    def share_page(token: str):
        return render_template("share.html", token=token)

    def open_share(token: str):
        """Validate token + key from the request body. Returns (row, share_key)."""
        ip = request.remote_addr
        if share_limiter.blocked(ip):
            raise ApiError("Too many attempts. Try again later.", 429)
        row = db.get_share(token)
        if row is None:
            share_limiter.fail(ip)
            raise ApiError("This link doesn't exist or was revoked.", 404)
        status = share_status(row)
        if status == "expired":
            raise ApiError("This link has expired.", 410)
        if status == "exhausted":
            raise ApiError("This link has reached its download limit.", 410)
        try:
            key = b64u_dec_key(str((request.get_json(silent=True) or {}).get("key", "")))
            ce.unseal(key, row["name_enc"], share_name_aad(token))
        except (ValueError, ce.CryptoError):
            share_limiter.fail(ip)
            raise ApiError("This link is incomplete or its key is wrong. "
                           "Make sure you copied the whole URL, including the part after #.", 403)
        return row, key

    @app.post("/api/s/<token>/meta")
    def api_share_meta(token: str):
        row, key = open_share(token)
        name = ce.unseal(key, row["name_enc"], share_name_aad(token)).decode("utf-8")
        return jsonify(name=name, size=row["size"], expires_at=row["expires_at"],
                       max_downloads=row["max_downloads"], downloads=row["downloads"])

    @app.post("/api/s/<token>/file")
    def api_share_file(token: str):
        row, key = open_share(token)
        name = ce.unseal(key, row["name_enc"], share_name_aad(token)).decode("utf-8")
        frow = db.get_file_any_owner(row["file_id"])
        if frow is None:
            raise ApiError("The file no longer exists.", 404)
        try:
            dek = ce.unwrap_key(key, row["wrapped_dek"], share_dek_aad(token))
        except ce.CryptoError:
            raise ApiError("Share key material failed its integrity check.", 500)
        plain = decrypt_to_temp(frow["storage_key"], dek)
        if not db.consume_share(token):             # atomic: honours limits under races
            plain.close()
            raise ApiError("This link is no longer valid.", 410)
        db.add_audit(row["user_id"], "share_download", row["file_id"], None, request.remote_addr)
        return send_file(plain, mimetype="application/octet-stream",
                         as_attachment=True, download_name=name)

    # ------------------------------------------------------------------ #
    # JSON API - activity log
    # ------------------------------------------------------------------ #
    @app.get("/api/activity")
    @login_required
    def api_activity():
        items = []
        for r in db.list_audit(g.user_id, 100):
            name = None
            if r["detail_enc"]:
                try:
                    name = ce.unseal(g.umk, r["detail_enc"], b"audit").decode("utf-8")
                except ce.CryptoError:
                    name = None
            if name is None and r["ref"]:
                frow = db.get_file(g.user_id, r["ref"])
                name = file_name(frow) if frow else None
            items.append({"id": r["id"], "event": r["event"], "name": name,
                          "ip": r["ip"], "at": r["created_at"]})
        return jsonify(items=items)

    app.extensions["vault"] = vault
    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
