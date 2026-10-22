"""Configuration, driven by environment variables (see .env.example)."""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


class Config:
    # A random key per start is fine: the in-memory KeyVault also resets on
    # restart, so existing sessions could not decrypt anything anyway.
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    DATABASE = os.environ.get("DATABASE", str(BASE_DIR / "data" / "app.db"))

    # --- storage -----------------------------------------------------------
    STORAGE_BACKEND = os.environ.get("STORAGE_BACKEND", "local")       # local | s3
    LOCAL_STORAGE_DIR = os.environ.get("LOCAL_STORAGE_DIR", str(BASE_DIR / "data" / "blobs"))
    S3_BUCKET = os.environ.get("S3_BUCKET", "")
    S3_PREFIX = os.environ.get("S3_PREFIX", "secure-storage")
    S3_REGION = os.environ.get("S3_REGION")
    S3_ENDPOINT_URL = os.environ.get("S3_ENDPOINT_URL")                # e.g. MinIO
    S3_SSE = os.environ.get("S3_SSE", "AES256")                        # "" disables

    # --- limits ------------------------------------------------------------
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", "100")) * 1024 * 1024
    MIN_PASSWORD_LENGTH = 10
    QUOTA_MB = int(os.environ.get("QUOTA_MB", "500"))                  # per user
    SHARE_MAX_HOURS = 24 * 90                                          # longest expiring link

    # --- security ----------------------------------------------------------
    SCRYPT_N = int(os.environ.get("SCRYPT_N", 2 ** 15))
    SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", 1800))
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_WINDOW_SECONDS = 900
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"   # set 1 behind HTTPS
