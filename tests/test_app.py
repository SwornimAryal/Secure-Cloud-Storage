import base64
import io
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from db import Database, now_iso  # noqa: E402

PW = "a-long-test-password"


class Base(unittest.TestCase):
    QUOTA_MB = 50

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app({
            "TESTING": True, "SECRET_KEY": "test", "SCRYPT_N": 2 ** 10,
            "DATABASE": os.path.join(self.tmp, "t.db"),
            "LOCAL_STORAGE_DIR": os.path.join(self.tmp, "blobs"),
            "QUOTA_MB": self.QUOTA_MB,
        })
        self.db = Database(self.app.config["DATABASE"])
        self.c = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- helpers ----
    def csrf(self, client=None):
        client = client or self.c
        client.get("/login")
        with client.session_transaction() as s:
            return s["csrf_token"]

    def form_post(self, url, data=None, client=None, **kw):
        client = client or self.c
        data = dict(data or {}, csrf_token=self.csrf(client))
        return client.post(url, data=data, **kw)

    def api(self, method, url, client=None, **kw):
        client = client or self.c
        headers = dict(kw.pop("headers", {}), **{"X-CSRF-Token": self.csrf(client)})
        return client.open(url, method=method, headers=headers, **kw)

    def register(self, name, pw=PW, client=None):
        return self.form_post("/register", {"username": name, "password": pw, "confirm": pw},
                              client=client, follow_redirects=True)

    def login(self, name, pw=PW, client=None):
        return self.form_post("/login", {"username": name, "password": pw},
                              client=client, follow_redirects=True)

    def signup(self, name="alice", client=None):
        self.register(name, client=client)
        return self.login(name, client=client)

    def upload(self, name, data, client=None):
        return self.api("POST", "/api/upload", client=client, data={"file": (io.BytesIO(data), name)},
                        content_type="multipart/form-data")

    def blob_path(self, file_id, user_id=1):
        return os.path.join(self.tmp, "blobs", str(user_id), file_id)


class AuthTests(Base):
    def test_requires_login(self):
        self.assertEqual(self.c.get("/").status_code, 302)
        r = self.c.get("/api/files")
        self.assertEqual(r.status_code, 401)
        self.assertIn("error", r.get_json())

    def test_csrf_enforced_for_forms_and_api(self):
        self.csrf()
        self.assertEqual(self.c.post("/login", data={"username": "x", "password": "y"}).status_code, 400)
        self.signup()
        self.assertEqual(self.c.post("/api/upload", data={"file": (io.BytesIO(b"x"), "a")},
                                     content_type="multipart/form-data").status_code, 400)

    def test_register_validation(self):
        self.assertIn(b"at least", self.register("alice", "short").data)
        self.register("alice")
        self.assertIn(b"already taken", self.register("ALICE").data)

    def test_bad_login_and_rate_limit(self):
        self.register("alice")
        for _ in range(5):
            r = self.form_post("/login", {"username": "alice", "password": "wrong-password"})
            self.assertEqual(r.status_code, 401)
        self.assertEqual(self.form_post("/login", {"username": "alice", "password": PW}).status_code, 429)

    def test_unknown_user_gets_same_response(self):
        r = self.form_post("/login", {"username": "nobody", "password": "wrong-password"})
        self.assertEqual(r.status_code, 401)

    def test_logout_invalidates_session(self):
        self.signup()
        self.form_post("/logout")
        self.assertEqual(self.c.get("/").status_code, 302)

    def test_security_headers(self):
        r = self.c.get("/login")
        csp = r.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")

    def test_dashboard_has_no_inline_script(self):
        self.signup()
        html = self.c.get("/").get_data(as_text=True)
        self.assertNotIn("<script>", html)
        self.assertIn("/static/app.js", html)

    def test_change_password_keeps_files_readable(self):
        self.signup()
        self.upload("a.txt", b"keep me")
        fid = self.db.list_files(1)[0]["id"]
        new = "brand-new-password-1"
        r = self.form_post("/account/password", {"current": PW, "new": new, "confirm": new}, follow_redirects=True)
        self.assertIn(b"Password changed", r.data)
        self.form_post("/logout")
        self.assertEqual(self.form_post("/login", {"username": "alice", "password": PW}).status_code, 401)
        self.login("alice", new)
        self.assertEqual(self.c.get(f"/download/{fid}").data, b"keep me")


class FileTests(Base):
    def test_upload_download_and_ciphertext_at_rest(self):
        self.signup()
        secret = b"my very secret payload " * 5000
        r = self.upload("notes.txt", secret)
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertEqual(body["file"]["name"], "notes.txt")
        self.assertEqual(body["usage"]["used"], len(secret))

        fid = body["file"]["id"]
        d = self.c.get(f"/download/{fid}")
        self.assertEqual(d.data, secret)
        self.assertIn("notes.txt", d.headers["Content-Disposition"])
        with open(self.blob_path(fid), "rb") as fh:
            self.assertNotIn(b"my very secret payload", fh.read())

    def test_list_rename_delete(self):
        self.signup()
        fid = self.upload("old.txt", b"x").get_json()["file"]["id"]
        self.assertEqual(self.api("GET", "/api/files").get_json()["files"][0]["name"], "old.txt")
        r = self.api("PATCH", f"/api/files/{fid}", json={"name": "new.txt"})
        self.assertEqual(r.get_json()["file"]["name"], "new.txt")
        self.assertEqual(self.c.get(f"/download/{fid}").data, b"x")      # key still works
        self.api("DELETE", f"/api/files/{fid}")
        self.assertEqual(self.api("GET", "/api/files").get_json()["files"], [])
        self.assertFalse(os.path.exists(self.blob_path(fid)))

    def test_names_encrypted_in_database_file(self):
        self.signup()
        self.upload("tax-return-2026.pdf", b"x")
        with open(self.app.config["DATABASE"], "rb") as fh:
            self.assertNotIn(b"tax-return-2026", fh.read())

    def test_filename_sanitised(self):
        self.signup()
        r = self.upload("../../etc/passwd", b"x")
        self.assertEqual(r.get_json()["file"]["name"], "passwd")

    def test_tampered_storage_blocks_download(self):
        self.signup()
        fid = self.upload("a.bin", os.urandom(5000)).get_json()["file"]["id"]
        with open(self.blob_path(fid), "r+b") as fh:
            fh.seek(40)
            b = fh.read(1)
            fh.seek(40)
            fh.write(bytes([b[0] ^ 1]))
        r = self.c.get(f"/download/{fid}")
        self.assertEqual(r.status_code, 500)
        self.assertIn(b"integrity", r.data)

    def test_users_are_isolated(self):
        self.signup()
        fid = self.upload("a.txt", b"alice data").get_json()["file"]["id"]
        bob = self.app.test_client()
        self.signup("bob", client=bob)
        self.assertEqual(bob.get(f"/download/{fid}").status_code, 404)
        self.assertEqual(self.api("DELETE", f"/api/files/{fid}", client=bob).status_code, 404)
        self.assertEqual(self.api("PATCH", f"/api/files/{fid}", client=bob, json={"name": "x"}).status_code, 404)
        self.assertEqual(self.api("POST", f"/api/files/{fid}/share", client=bob, json={}).status_code, 404)
        self.assertEqual(self.api("GET", "/api/files", client=bob).get_json()["files"], [])


class QuotaTests(Base):
    QUOTA_MB = 1

    def test_quota_enforced_and_freed_on_delete(self):
        self.signup()
        first = self.upload("a.bin", os.urandom(700 * 1024))
        self.assertEqual(first.status_code, 201)
        second = self.upload("b.bin", os.urandom(700 * 1024))
        self.assertEqual(second.status_code, 413)
        self.assertIn("quota", second.get_json()["error"].lower())
        self.assertEqual(len(self.db.list_files(1)), 1)
        self.assertEqual(len(os.listdir(os.path.join(self.tmp, "blobs", "1"))), 1)   # no orphan blob
        self.api("DELETE", f"/api/files/{first.get_json()['file']['id']}")
        self.assertEqual(self.upload("b.bin", os.urandom(700 * 1024)).status_code, 201)


class ShareTests(Base):
    def setUp(self):
        super().setUp()
        self.signup()
        self.payload = b"shared secret content " * 1000
        self.fid = self.upload("report.pdf", self.payload).get_json()["file"]["id"]
        self.pub = self.app.test_client()          # anonymous visitor, no cookies

    def share(self, **opts):
        r = self.api("POST", f"/api/files/{self.fid}/share", json=opts)
        self.assertEqual(r.status_code, 201, r.get_data())
        return r.get_json()

    def post(self, path, token, key):
        return self.pub.post(f"/api/s/{token}/{path}", json={"key": key})   # no CSRF needed

    def test_full_share_flow(self):
        s = self.share(hours=24, max_downloads=5)
        self.assertEqual(self.pub.get(f"/s/{s['token']}").status_code, 200)
        meta = self.post("meta", s["token"], s["key"]).get_json()
        self.assertEqual((meta["name"], meta["size"]), ("report.pdf", len(self.payload)))
        d = self.post("file", s["token"], s["key"])
        self.assertEqual(d.data, self.payload)
        self.assertIn("report.pdf", d.headers["Content-Disposition"])

    def test_server_does_not_store_share_key(self):
        s = self.share()
        key_bytes = base64.urlsafe_b64decode(s["key"] + "=" * (-len(s["key"]) % 4))
        with open(self.app.config["DATABASE"], "rb") as fh:
            self.assertNotIn(key_bytes, fh.read())
        self.assertNotIn(s["key"].encode(), self.db.get_share(s["token"])["wrapped_dek"])

    def test_wrong_or_missing_key(self):
        s = self.share()
        other = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        self.assertEqual(self.post("meta", s["token"], other).status_code, 403)
        self.assertEqual(self.post("file", s["token"], other).status_code, 403)
        self.assertEqual(self.post("meta", s["token"], "").status_code, 403)
        self.assertEqual(self.post("meta", s["token"], "!!notbase64!!").status_code, 403)

    def test_unknown_token(self):
        self.assertEqual(self.post("meta", "nope", "x").status_code, 404)

    def test_download_limit(self):
        s = self.share(max_downloads=2)
        self.assertEqual(self.post("file", s["token"], s["key"]).status_code, 200)
        self.assertEqual(self.post("file", s["token"], s["key"]).status_code, 200)
        r = self.post("file", s["token"], s["key"])
        self.assertEqual(r.status_code, 410)
        self.assertEqual(self.api("GET", "/api/shares").get_json()["shares"][0]["status"], "exhausted")

    def test_expiry(self):
        s = self.share(hours=1)
        with self.db._tx() as c:
            c.execute("UPDATE shares SET expires_at = ? WHERE token = ?", (now_iso(-2), s["token"]))
        self.assertEqual(self.post("meta", s["token"], s["key"]).status_code, 410)
        self.assertEqual(self.post("file", s["token"], s["key"]).status_code, 410)

    def test_revoke(self):
        s = self.share()
        self.assertEqual(self.api("DELETE", f"/api/shares/{s['token']}").status_code, 200)
        self.assertEqual(self.post("meta", s["token"], s["key"]).status_code, 404)

    def test_other_user_cannot_revoke(self):
        s = self.share()
        bob = self.app.test_client()
        self.signup("bob", client=bob)
        self.assertEqual(self.api("DELETE", f"/api/shares/{s['token']}", client=bob).status_code, 404)
        self.assertEqual(self.post("meta", s["token"], s["key"]).status_code, 200)

    def test_deleting_file_kills_its_links(self):
        s = self.share()
        self.api("DELETE", f"/api/files/{self.fid}")
        self.assertEqual(self.post("meta", s["token"], s["key"]).status_code, 404)

    def test_share_survives_password_change(self):
        s = self.share()
        new = "brand-new-password-1"
        self.form_post("/account/password", {"current": PW, "new": new, "confirm": new})
        self.assertEqual(self.post("file", s["token"], s["key"]).data, self.payload)

    def test_tampered_blob_not_released_via_share(self):
        s = self.share()
        with open(self.blob_path(self.fid), "r+b") as fh:
            fh.seek(30)
            b = fh.read(1)
            fh.seek(30)
            fh.write(bytes([b[0] ^ 1]))
        self.assertEqual(self.post("file", s["token"], s["key"]).status_code, 500)
        self.assertEqual(self.db.get_share(s["token"])["downloads"], 0)     # not counted

    def test_invalid_options_rejected(self):
        for bad in ({"hours": -1}, {"hours": 99999}, {"max_downloads": 0}, {"hours": "abc"}):
            self.assertEqual(self.api("POST", f"/api/files/{self.fid}/share", json=bad).status_code, 400, bad)

    def test_bad_key_attempts_are_rate_limited(self):
        s = self.share()
        for _ in range(20):
            self.post("meta", s["token"], "AAAA")
        self.assertEqual(self.post("meta", s["token"], s["key"]).status_code, 429)


class AuditTests(Base):
    def test_activity_log(self):
        self.signup()
        fid = self.upload("secret-plan.docx", b"x").get_json()["file"]["id"]
        self.c.get(f"/download/{fid}")
        s = self.api("POST", f"/api/files/{fid}/share", json={}).get_json()
        self.app.test_client().post(f"/api/s/{s['token']}/file", json={"key": s["key"]})
        self.api("DELETE", f"/api/files/{fid}")

        items = self.api("GET", "/api/activity").get_json()["items"]
        events = [i["event"] for i in items]
        for e in ("register", "login", "upload", "download", "share_create", "share_download", "delete"):
            self.assertIn(e, events)
        up = next(i for i in items if i["event"] == "upload")
        self.assertEqual(up["name"], "secret-plan.docx")
        with open(self.app.config["DATABASE"], "rb") as fh:             # names sealed at rest
            self.assertNotIn(b"secret-plan", fh.read())

    def test_failed_login_recorded_for_owner(self):
        self.signup()
        self.form_post("/logout")
        self.form_post("/login", {"username": "alice", "password": "wrong-password"})
        self.login("alice")
        events = [i["event"] for i in self.api("GET", "/api/activity").get_json()["items"]]
        self.assertIn("login_failed", events)


if __name__ == "__main__":
    unittest.main()
