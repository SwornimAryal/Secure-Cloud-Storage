"""
Pluggable storage backends. They only ever receive ciphertext.

    STORAGE_BACKEND=local  -> files under LOCAL_STORAGE_DIR
    STORAGE_BACKEND=s3     -> any S3-compatible bucket (AWS S3, MinIO, R2, ...)
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import BinaryIO

# "<user_id>/<32 hex chars>" - the only key shape the app ever generates.
_KEY_RE = re.compile(r"^[0-9]{1,12}/[0-9a-f]{32}$")


class StorageError(Exception):
    pass


def _check_key(key: str) -> None:
    if not _KEY_RE.match(key):
        raise StorageError("Invalid storage key")


class StorageBackend(ABC):
    @abstractmethod
    def put(self, key: str, fileobj: BinaryIO) -> None: ...

    @abstractmethod
    def get(self, key: str) -> BinaryIO:
        """Return a readable, seekable binary file object. Caller closes it."""

    @abstractmethod
    def delete(self, key: str) -> None: ...


class LocalStorage(StorageBackend):
    def __init__(self, root: str):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def _path(self, key: str) -> Path:
        _check_key(key)
        path = (self.root / key).resolve()
        if self.root not in path.parents:          # belt and braces
            raise StorageError("Invalid storage key")
        return path

    def put(self, key: str, fileobj: BinaryIO) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".part")
        try:
            with open(tmp, "wb") as out:
                shutil.copyfileobj(fileobj, out, 1024 * 1024)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)                  # atomic
        finally:
            if tmp.exists():
                tmp.unlink()

    def get(self, key: str) -> BinaryIO:
        try:
            return open(self._path(key), "rb")
        except FileNotFoundError as exc:
            raise StorageError("Object not found in storage") from exc

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)


class S3Storage(StorageBackend):
    def __init__(self, bucket: str, prefix: str = "", region: str | None = None,
                 endpoint_url: str | None = None, sse: str | None = "AES256"):
        try:
            import boto3  # imported lazily: only needed for the S3 backend
        except ImportError as exc:
            raise StorageError("boto3 is required: pip install -r requirements-s3.txt") from exc
        if not bucket:
            raise StorageError("S3_BUCKET is not set")
        self.bucket = bucket
        self.prefix = prefix.strip("/") + "/" if prefix.strip("/") else ""
        self.sse = sse or None
        self.client = boto3.client("s3", region_name=region or None,
                                   endpoint_url=endpoint_url or None)

    def _k(self, key: str) -> str:
        _check_key(key)
        return self.prefix + key

    def put(self, key: str, fileobj: BinaryIO) -> None:
        extra = {"ServerSideEncryption": self.sse} if self.sse else None
        try:
            self.client.upload_fileobj(fileobj, self.bucket, self._k(key), ExtraArgs=extra)
        except Exception as exc:
            raise StorageError(f"S3 upload failed: {exc}") from exc

    def get(self, key: str) -> BinaryIO:
        buf = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
        try:
            self.client.download_fileobj(self.bucket, self._k(key), buf)
        except Exception as exc:
            buf.close()
            raise StorageError(f"S3 download failed: {exc}") from exc
        buf.seek(0)
        return buf

    def delete(self, key: str) -> None:
        try:
            self.client.delete_object(Bucket=self.bucket, Key=self._k(key))
        except Exception as exc:
            raise StorageError(f"S3 delete failed: {exc}") from exc


def build_storage(config) -> StorageBackend:
    backend = str(config.get("STORAGE_BACKEND", "local")).lower()
    if backend == "local":
        return LocalStorage(config["LOCAL_STORAGE_DIR"])
    if backend == "s3":
        return S3Storage(
            bucket=config.get("S3_BUCKET", ""),
            prefix=config.get("S3_PREFIX", ""),
            region=config.get("S3_REGION"),
            endpoint_url=config.get("S3_ENDPOINT_URL"),
            sse=config.get("S3_SSE"),
        )
    raise StorageError(f"Unknown STORAGE_BACKEND: {backend}")
