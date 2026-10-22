"""In-memory key vault (per-login session keys) and a tiny login rate limiter."""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass


@dataclass
class VaultEntry:
    user_id: int
    username: str
    umk: bytes
    expires: float


class KeyVault:
    """
    Holds each logged-in user's master key (UMK) in server memory only.

    The browser cookie carries just an opaque random token, never a key. When
    the token expires, the process restarts, or the user logs out, the UMK is
    gone and files can't be decrypted until the user logs in again.

    This is process-local: run a single worker process (use threads), or swap
    this class for Redis/Memcached with a short TTL for multi-process setups.
    """

    def __init__(self, ttl_seconds: int = 1800):
        self.ttl = ttl_seconds
        self._items: dict[str, VaultEntry] = {}
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        for token in [t for t, e in self._items.items() if e.expires <= now]:
            del self._items[token]

    def put(self, user_id: int, username: str, umk: bytes) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._purge(now)
            self._items[token] = VaultEntry(user_id, username, umk, now + self.ttl)
        return token

    def get(self, token: str | None) -> VaultEntry | None:
        if not token:
            return None
        now = time.time()
        with self._lock:
            self._purge(now)
            entry = self._items.get(token)
            if entry:
                entry.expires = now + self.ttl      # sliding expiry
            return entry

    def drop(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._items.pop(token, None)


class LoginLimiter:
    """Blocks a (ip, username) pair after too many failures in a time window."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 900):
        self.max = max_attempts
        self.window = window_seconds
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> list[float]:
        recent = [t for t in self._fails.get(key, []) if now - t < self.window]
        if recent:
            self._fails[key] = recent
        else:
            self._fails.pop(key, None)
        return recent

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._recent(key, time.time())) >= self.max

    def fail(self, key: str) -> None:
        with self._lock:
            now = time.time()
            self._recent(key, now)
            self._fails.setdefault(key, []).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)
