"""Extra security tests: erase on delete, XSS, sessions, SQL injection, admin user control."""
import pathlib

import psycopg
from fastapi.testclient import TestClient

from app.config import DATABASE_URL
from app.main import app
from test_access import admin, upload, user

FRONTEND = pathlib.Path(__file__).resolve().parents[2] / "frontend"
HDR = {"X-Requested-With": "trustvault"}


def db():
    return psycopg.connect(DATABASE_URL, autocommit=True)


# ---------- delete really erases ----------
def test_delete_erases_file_bytes_and_hides_document():
    owner, _ = user("owner"); doc = upload(owner)
    assert owner.delete(f"/documents/{doc}").status_code == 200
    with db() as c:
        length, deleted = c.execute("SELECT length(content), deleted_at FROM documents WHERE id=%s", (doc,)).fetchone()
    assert length == 0 and deleted is not None
    assert owner.get(f"/documents/{doc}/download").status_code == 404


# ---------- script injection (XSS) ----------
def test_filename_is_cleaned_and_download_cannot_run_in_browser():
    owner, _ = user("owner")
    r = owner.post("/documents", files={"file": ("<script>alert(1)</script>.pdf", b"%PDF-1.4 x", "application/pdf")},
                   data={"category": "x"})
    assert r.status_code == 201
    assert all("<" not in d["name"] and ">" not in d["name"] for d in owner.get("/documents").json())
    d = owner.get(f"/documents/{r.json()['id']}/download")
    assert d.headers["content-disposition"].startswith("attachment")
    assert d.headers["x-content-type-options"] == "nosniff"


def test_pages_send_security_headers():
    r = TestClient(app).get("/")
    assert r.headers["content-security-policy"] == "default-src 'self'"
    assert r.headers["x-frame-options"] == "DENY"


def test_frontend_never_builds_html_from_data():
    for f in FRONTEND.rglob("*.js"):
        text = f.read_text(encoding="utf-8")
        for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            assert bad not in text, f"{f.name} uses {bad}"
    for f in FRONTEND.glob("*.html"):
        text = f.read_text(encoding="utf-8")
        assert "<script>" not in text and " onclick=" not in text and ' style="' not in text, f.name


# ---------- stolen or old sessions ----------
def test_old_cookie_stops_working_after_logout():
    c, _ = user("viewer")
    token = c.cookies.get("tv_session")
    stolen = {"Cookie": f"tv_session={token}"}            # someone else sends a copy of the cookie
    thief = TestClient(app, headers=HDR)
    assert thief.get("/me", headers=stolen).status_code == 200        # the copied cookie works...
    assert c.post("/logout").status_code == 200
    assert thief.get("/me", headers=stolen).status_code == 401        # ...until the real user logs out


def test_disabled_user_loses_access_immediately():
    c, email = user("viewer"); adm = admin()
    uid = c.get("/me").json()["id"]
    assert adm.post(f"/admin/users/{uid}/disable").status_code == 200
    assert c.get("/me").status_code == 401
    assert TestClient(app, headers=HDR).post("/login", json={"email": email, "password": "correct-horse-1"}).status_code == 401
    assert adm.post(f"/admin/users/{uid}/enable").status_code == 200
    assert c.get("/me").status_code == 401                # the old session stays dead
    fresh = TestClient(app, headers=HDR)
    assert fresh.post("/login", json={"email": email, "password": "correct-horse-1"}).status_code == 200


def test_expired_session_is_refused():
    c, _ = user("viewer")
    uid = c.get("/me").json()["id"]
    with db() as conn:
        conn.execute("UPDATE sessions SET expires_at = now() - interval '1 minute' WHERE user_id=%s", (uid,))
    assert c.get("/me").status_code == 401


def test_session_cookie_flags_and_token_not_stored_in_clear():
    c = TestClient(app, headers=HDR)
    email = "cookie-" + __import__("uuid").uuid4().hex[:8] + "@t.test"
    c.post("/signup", json={"email": email, "password": "correct-horse-1", "role": "viewer"})
    r = c.post("/login", json={"email": email, "password": "correct-horse-1"})
    flags = r.headers["set-cookie"].lower()
    assert "httponly" in flags and "samesite=strict" in flags
    with db() as conn:
        assert conn.execute("SELECT count(*) FROM sessions WHERE id_hash=%s", (c.cookies.get("tv_session"),)).fetchone()[0] == 0


# ---------- SQL injection ----------
def test_search_inputs_cannot_inject_sql():
    owner, _ = user("owner"); stranger, _ = user("viewer"); doc = upload(owner)
    for payload in ["' OR '1'='1", "x' OR 1=1 --", "'; DROP TABLE users; --", "%' OR true --"]:
        for field in ("q", "category", "owner"):
            r = stranger.get("/documents", params={field: payload})
            assert r.status_code == 200 and r.json() == []
    assert doc not in [d["id"] for d in stranger.get("/documents", params={"q": "%"}).json()]
    with db() as conn:
        assert conn.execute("SELECT count(*) FROM users").fetchone()[0] > 0


def test_login_inputs_cannot_inject_sql():
    c = TestClient(app, headers=HDR)
    for e in ["' OR '1'='1", "admin@safecloud.test' --", "x@y.test'; DROP TABLE users; --"]:
        assert c.post("/login", json={"email": e, "password": "' OR '1'='1"}).status_code == 401


# ---------- admin user control ----------
def test_only_admin_can_manage_users_and_never_other_admins():
    owner, _ = user("owner"); viewer, _ = user("viewer"); adm = admin(); adm2 = admin()
    vid = viewer.get("/me").json()["id"]
    assert owner.get("/admin/users").status_code == 403
    assert owner.post(f"/admin/users/{vid}/disable").status_code == 403
    assert adm.post(f"/admin/users/{adm2.get('/me').json()['id']}/disable").status_code == 400
    assert adm.post(f"/admin/users/{adm.get('/me').json()['id']}/disable").status_code == 400
    assert viewer.get("/me").status_code == 200
    denied = adm.get("/admin/audit", params={"action": "user_disable", "outcome": "denied"}).json()
    assert denied                                          # the owner's refused attempt was logged


def test_user_list_hides_password_hashes():
    adm = admin()
    rows = adm.get("/admin/users").json()
    assert rows and all("password_hash" not in r for r in rows)
