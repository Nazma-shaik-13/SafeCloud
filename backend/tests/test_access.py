"""Cross-user access tests. Run against a TEST database (DATABASE_URL), never production."""
import uuid
from fastapi.testclient import TestClient
from app.main import app

PDF = ("a.pdf", b"%PDF-1.4 test", "application/pdf")


def user(role):
    c = TestClient(app, headers={"X-Requested-With": "trustvault"})   # each client has its own cookie jar
    email = f"{uuid.uuid4().hex[:8]}@t.test"
    assert c.post("/signup", json={"email": email, "password": "correct-horse-1", "role": role}).status_code == 201
    assert c.post("/login", json={"email": email, "password": "correct-horse-1"}).status_code == 200
    return c, email


def upload(owner):
    r = owner.post("/documents", files={"file": PDF}, data={"category": "contracts"})
    assert r.status_code == 201
    return r.json()["id"]


def test_stranger_cannot_read_edit_or_delete():
    owner, _ = user("owner"); stranger, _ = user("viewer")
    doc = upload(owner)
    assert stranger.get(f"/documents/{doc}/download").status_code == 404
    assert stranger.patch(f"/documents/{doc}", json={"name": "x"}).status_code == 404
    assert stranger.delete(f"/documents/{doc}").status_code == 404
    assert doc not in [d["id"] for d in stranger.get("/documents").json()]


def test_revocation_is_immediate():
    owner, _ = user("owner"); viewer, v_email = user("viewer")
    doc = upload(owner)
    owner.post(f"/documents/{doc}/grants", json={"email": v_email, "level": "read"})
    assert viewer.get(f"/documents/{doc}/download").status_code == 200
    viewer_id = viewer.get("/me").json()["id"]               # same session stays logged in; only the grant changes
    assert owner.delete(f"/documents/{doc}/grants/{viewer_id}").status_code == 200
    assert viewer.get(f"/documents/{doc}/download").status_code == 404


def test_reader_cannot_edit_delete_or_share():
    owner, _ = user("owner"); viewer, v_email = user("viewer"); other, o_email = user("viewer")
    doc = upload(owner)
    owner.post(f"/documents/{doc}/grants", json={"email": v_email, "level": "read"})
    assert viewer.patch(f"/documents/{doc}", json={"name": "x"}).status_code == 403
    assert viewer.delete(f"/documents/{doc}").status_code == 403
    assert viewer.post(f"/documents/{doc}/grants", json={"email": o_email, "level": "read"}).status_code == 403


def test_upload_rejects_fake_pdf_and_signup_cannot_make_admin():
    owner, _ = user("owner")
    r = owner.post("/documents", files={"file": ("evil.pdf", b"<script>", "application/pdf")}, data={"category": "x"})
    assert r.status_code == 415
    c = TestClient(app, headers={"X-Requested-With": "trustvault"})
    assert c.post("/signup", json={"email": "a@b.test", "password": "correct-horse-1", "role": "admin"}).status_code == 422


# ---------- more cases: edit grants, admin limits, audit, lockout ----------
import psycopg, pytest
from app.config import DATABASE_URL
from app.security import hash_password


def admin():
    c = TestClient(app, headers={"X-Requested-With": "trustvault"})
    email = f"{uuid.uuid4().hex[:8]}@admin.test"
    with psycopg.connect(DATABASE_URL, autocommit=True) as db:
        db.execute("INSERT INTO users(email,password_hash,role) VALUES (%s,%s,'admin')", (email, hash_password("correct-horse-1")))
    assert c.post("/login", json={"email": email, "password": "correct-horse-1"}).status_code == 200
    return c


def test_edit_grant_can_replace_content_but_read_grant_cannot():
    owner, _ = user("owner"); editor, e_email = user("viewer"); reader, r_email = user("viewer")
    doc = upload(owner)
    owner.post(f"/documents/{doc}/grants", json={"email": e_email, "level": "edit"})
    owner.post(f"/documents/{doc}/grants", json={"email": r_email, "level": "read"})
    new = {"file": ("a.pdf", b"%PDF-1.4 new", "application/pdf")}
    assert reader.put(f"/documents/{doc}/content", files=new).status_code == 403
    assert editor.put(f"/documents/{doc}/content", files=new).status_code == 200
    assert owner.get(f"/documents/{doc}/download").content == b"%PDF-1.4 new"
    assert editor.delete(f"/documents/{doc}").status_code == 403          # editors still cannot delete


def test_admin_sees_metadata_but_never_contents():
    owner, _ = user("owner"); adm = admin()
    doc = upload(owner)
    mine = {d["id"]: d for d in adm.get("/documents").json()}
    assert mine[doc]["my_access"] == "admin"
    assert adm.get(f"/documents/{doc}/download").status_code == 403
    assert adm.put(f"/documents/{doc}/content", files={"file": PDF}).status_code == 403


def test_non_admin_cannot_read_audit():
    owner, _ = user("owner")
    assert owner.get("/admin/audit").status_code == 403
    assert owner.get("/admin/audit/verify").status_code == 403


def test_oversize_upload_is_rejected_and_audited():
    owner, email = user("owner"); adm = admin()
    big = {"file": ("big.pdf", b"%PDF" + b"0" * (5 * 1024 * 1024 + 1), "application/pdf")}
    assert owner.post("/documents", files=big, data={"category": "x"}).status_code == 413
    events = adm.get("/admin/audit", params={"action": "upload", "outcome": "denied"}).json()
    assert any(e["actor_email"] == email and e["detail"].get("reason") == "too large" for e in events)


def test_denied_download_is_audited_with_hashes_and_chain_verifies():
    owner, _ = user("owner"); stranger, s_email = user("viewer"); adm = admin()
    doc = upload(owner)
    stranger.get(f"/documents/{doc}/download")
    events = adm.get("/admin/audit", params={"action": "download", "outcome": "denied"}).json()
    hit = [e for e in events if e["actor_email"] == s_email and e["document_id"] == doc]
    assert hit and hit[0]["hash"] and hit[0]["prev_hash"]
    assert adm.get("/admin/audit/verify").json()["ok"] is True


def test_audit_rows_cannot_be_updated_or_deleted():
    with psycopg.connect(DATABASE_URL, autocommit=True) as db:
        with pytest.raises(psycopg.Error):
            db.execute("UPDATE audit_events SET outcome='allowed'")
        with pytest.raises(psycopg.Error):
            db.execute("DELETE FROM audit_events")


def test_login_lockout_after_repeated_failures():
    c = TestClient(app, headers={"X-Requested-With": "trustvault"})
    email = f"{uuid.uuid4().hex[:8]}@t.test"
    c.post("/signup", json={"email": email, "password": "correct-horse-1", "role": "viewer"})
    for _ in range(5):
        assert c.post("/login", json={"email": email, "password": "wrong-password-x"}).status_code == 401
    assert c.post("/login", json={"email": email, "password": "correct-horse-1"}).status_code == 401   # now locked


def test_state_changing_request_without_csrf_header_is_refused():
    owner, _ = user("owner")
    bare = TestClient(app)                      # no X-Requested-With
    bare.cookies.update(owner.cookies)
    assert bare.post("/documents", files={"file": PDF}, data={"category": "x"}).status_code == 403
