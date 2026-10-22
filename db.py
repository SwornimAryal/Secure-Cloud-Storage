"""SQLite persistence. Stores only wrapped keys and encrypted metadata."""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE COLLATE NOCASE,
    auth_salt   BLOB NOT NULL,     -- salt for the login password hash
    auth_hash   BLOB NOT NULL,     -- scrypt(password, auth_salt)
    kek_salt    BLOB NOT NULL,     -- salt for the key-encryption key
    wrapped_umk BLOB NOT NULL,     -- user master key, wrapped by the KEK
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id          TEXT PRIMARY KEY,  -- uuid4 hex
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_enc    BLOB NOT NULL,     -- file name, sealed with the UMK
    size        INTEGER NOT NULL,  -- plaintext size in bytes
    storage_key TEXT NOT NULL,
    wrapped_dek BLOB NOT NULL,     -- per-file data key, wrapped by the UMK
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id, created_at DESC);

-- Share links. The share key lives ONLY in the URL fragment (#...), so the
-- server stores nothing that can open these rows on its own.
CREATE TABLE IF NOT EXISTS shares (
    token         TEXT PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_id       TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    wrapped_dek   BLOB NOT NULL,   -- file key, wrapped by the share key
    name_enc      BLOB NOT NULL,   -- file name, sealed with the share key
    size          INTEGER NOT NULL,
    expires_at    TEXT,            -- NULL = never
    max_downloads INTEGER,         -- NULL = unlimited
    downloads     INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(user_id, created_at DESC);

-- Security / activity log (file names inside are sealed with the owner's UMK).
CREATE TABLE IF NOT EXISTS audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event      TEXT NOT NULL,
    ref        TEXT,               -- file id, if any
    detail_enc BLOB,               -- sealed file name at the time of the event
    ip         TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit(user_id, id DESC);
"""


class UsernameTaken(Exception):
    pass


def now_iso(offset_hours: float = 0) -> str:
    """UTC timestamp, fixed format so string comparison == time comparison."""
    t = datetime.now(timezone.utc) + timedelta(hours=offset_hours)
    return t.isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    @contextmanager
    def _tx(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            with conn:                      # commit / rollback
                yield conn
        finally:
            conn.close()

    def init(self) -> None:
        with self._tx() as c:
            c.executescript(SCHEMA)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # ---- users ---------------------------------------------------------- #
    def create_user(self, username, auth_salt, auth_hash, kek_salt, wrapped_umk) -> int:
        try:
            with self._tx() as c:
                cur = c.execute(
                    "INSERT INTO users (username, auth_salt, auth_hash, kek_salt,"
                    " wrapped_umk, created_at) VALUES (?,?,?,?,?,?)",
                    (username, auth_salt, auth_hash, kek_salt, wrapped_umk, now_iso()),
                )
                return cur.lastrowid
        except sqlite3.IntegrityError as exc:
            raise UsernameTaken(username) from exc

    def get_user_by_name(self, username):
        with self._tx() as c:
            return c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    def update_credentials(self, user_id, auth_salt, auth_hash, kek_salt, wrapped_umk) -> None:
        with self._tx() as c:
            c.execute(
                "UPDATE users SET auth_salt=?, auth_hash=?, kek_salt=?, wrapped_umk=?"
                " WHERE id=?",
                (auth_salt, auth_hash, kek_salt, wrapped_umk, user_id),
            )

    # ---- files ---------------------------------------------------------- #
    def add_file(self, file_id, user_id, name_enc, size, storage_key, wrapped_dek) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT INTO files (id, user_id, name_enc, size, storage_key,"
                " wrapped_dek, created_at) VALUES (?,?,?,?,?,?,?)",
                (file_id, user_id, name_enc, size, storage_key, wrapped_dek, now_iso()),
            )

    def list_files(self, user_id):
        with self._tx() as c:
            return c.execute(
                "SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()

    def get_file(self, user_id, file_id):
        with self._tx() as c:
            return c.execute(
                "SELECT * FROM files WHERE id = ? AND user_id = ?", (file_id, user_id)
            ).fetchone()

    def get_file_any_owner(self, file_id):
        """Used only by the share-link flow, after the share key has been verified."""
        with self._tx() as c:
            return c.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    def rename_file(self, user_id, file_id, name_enc) -> bool:
        with self._tx() as c:
            cur = c.execute("UPDATE files SET name_enc=? WHERE id=? AND user_id=?",
                            (name_enc, file_id, user_id))
            return cur.rowcount > 0

    def delete_file(self, user_id, file_id) -> bool:
        with self._tx() as c:
            cur = c.execute(
                "DELETE FROM files WHERE id = ? AND user_id = ?", (file_id, user_id)
            )
            return cur.rowcount > 0

    def usage(self, user_id) -> tuple[int, int]:
        with self._tx() as c:
            row = c.execute("SELECT COALESCE(SUM(size),0) AS used, COUNT(*) AS n"
                            " FROM files WHERE user_id = ?", (user_id,)).fetchone()
            return int(row["used"]), int(row["n"])

    # ---- shares --------------------------------------------------------- #
    def add_share(self, token, user_id, file_id, wrapped_dek, name_enc, size,
                  expires_at, max_downloads) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT INTO shares (token, user_id, file_id, wrapped_dek, name_enc, size,"
                " expires_at, max_downloads, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (token, user_id, file_id, wrapped_dek, name_enc, size,
                 expires_at, max_downloads, now_iso()),
            )

    def get_share(self, token):
        with self._tx() as c:
            return c.execute("SELECT * FROM shares WHERE token = ?", (token,)).fetchone()

    def list_shares(self, user_id):
        with self._tx() as c:
            return c.execute("SELECT * FROM shares WHERE user_id = ? ORDER BY created_at DESC",
                             (user_id,)).fetchall()

    def share_counts(self, user_id) -> dict:
        """file_id -> number of currently valid share links."""
        with self._tx() as c:
            rows = c.execute(
                "SELECT file_id, COUNT(*) AS n FROM shares WHERE user_id = ?"
                " AND (expires_at IS NULL OR expires_at > ?)"
                " AND (max_downloads IS NULL OR downloads < max_downloads)"
                " GROUP BY file_id", (user_id, now_iso())).fetchall()
            return {r["file_id"]: r["n"] for r in rows}

    def revoke_share(self, user_id, token) -> bool:
        with self._tx() as c:
            cur = c.execute("DELETE FROM shares WHERE token = ? AND user_id = ?",
                            (token, user_id))
            return cur.rowcount > 0

    def consume_share(self, token) -> bool:
        """Atomically count one download; False if expired / exhausted / gone."""
        with self._tx() as c:
            cur = c.execute(
                "UPDATE shares SET downloads = downloads + 1 WHERE token = ?"
                " AND (expires_at IS NULL OR expires_at > ?)"
                " AND (max_downloads IS NULL OR downloads < max_downloads)",
                (token, now_iso()))
            return cur.rowcount == 1

    # ---- audit ---------------------------------------------------------- #
    def add_audit(self, user_id, event, ref=None, detail_enc=None, ip=None) -> None:
        with self._tx() as c:
            c.execute("INSERT INTO audit (user_id, event, ref, detail_enc, ip, created_at)"
                      " VALUES (?,?,?,?,?,?)", (user_id, event, ref, detail_enc, ip, now_iso()))

    def list_audit(self, user_id, limit=100):
        with self._tx() as c:
            return c.execute("SELECT * FROM audit WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                             (user_id, limit)).fetchall()
