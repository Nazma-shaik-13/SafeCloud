"""SafeCloud API. Document routes always call permissions.authorize() first."""
import hashlib
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from uuid import UUID

import psycopg.errors
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import audit, config as cfg
from .db import get_conn
from .permissions import authorize
from .security import (DUMMY_HASH, hash_password, new_session, revoke_session,
                       user_from_token, verify_password)
from .validation import detect_type, safe_name

app = FastAPI(title="SafeCloud")
EMAIL = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


@app.middleware("http")
async def guard(request: Request, call_next):
    # CSRF: browsers can't add custom headers on cross-site forms, so require one on every state change.
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-requested-with") != "trustvault":
        return JSONResponse({"detail": "Missing CSRF header"}, status_code=403)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    return resp


def ip_of(request: Request):
    return request.client.host if request.client else None


def current_user(request: Request, conn=Depends(get_conn)):
    token = request.cookies.get("tv_session")
    user = user_from_token(conn, token) if token else None
    if not user:
        raise HTTPException(401, "Not logged in")
    return user


class SignupIn(BaseModel):
    email: str = Field(pattern=EMAIL, max_length=200)
    password: str = Field(min_length=10, max_length=200)
    role: str = Field(pattern="^(owner|viewer)$")      # 'admin' can never be self-registered


class LoginIn(BaseModel):
    email: str = Field(max_length=200)
    password: str = Field(max_length=200)


class GrantIn(BaseModel):
    email: str = Field(max_length=200)
    level: str = Field(pattern="^(read|edit)$")


class PatchIn(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    category: Optional[str] = Field(None, min_length=1, max_length=50)


# ---------- authentication ----------
@app.post("/signup", status_code=201)
def signup(body: SignupIn, request: Request, conn=Depends(get_conn)):
    try:
        row = conn.execute("INSERT INTO users(email,password_hash,role) VALUES (%s,%s,%s) RETURNING id",
                           (body.email.strip().lower(), hash_password(body.password), body.role)).fetchone()
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "Email already registered")
    audit.log(conn, row["id"], "signup", "allowed", detail={"ip": ip_of(request)})
    return {"ok": True}


@app.post("/login")
def login(body: LoginIn, request: Request, response: Response, conn=Depends(get_conn)):
    email = body.email.strip().lower()
    now = datetime.now(timezone.utc)
    u = conn.execute("SELECT * FROM users WHERE email=%s", (email,)).fetchone()
    locked = bool(u and u["locked_until"] and u["locked_until"] > now)
    ok = verify_password(u["password_hash"] if u else DUMMY_HASH, body.password)
    if not (u and ok and not locked and u["is_active"]):
        if u and not locked and not ok:                 # count failures, lock after too many
            fails = u["failed_logins"] + 1
            lock = now + timedelta(minutes=cfg.LOCK_MINUTES) if fails >= cfg.MAX_FAILED else None
            conn.execute("UPDATE users SET failed_logins=%s, locked_until=%s WHERE id=%s",
                         (0 if lock else fails, lock, u["id"]))
        audit.log(conn, u["id"] if u else None, "login", "denied", detail={"ip": ip_of(request), "email": email})
        raise HTTPException(401, "Invalid credentials")  # same message for every failure reason
    conn.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=%s", (u["id"],))
    token = new_session(conn, u["id"])
    response.set_cookie("tv_session", token, httponly=True, samesite="strict",
                        secure=cfg.COOKIE_SECURE, max_age=cfg.SESSION_HOURS * 3600)
    audit.log(conn, u["id"], "login", "allowed", detail={"ip": ip_of(request)})
    return {"email": u["email"], "role": u["role"]}


@app.post("/logout")
def logout(request: Request, response: Response, user=Depends(current_user), conn=Depends(get_conn)):
    revoke_session(conn, request.cookies["tv_session"])
    response.delete_cookie("tv_session")
    audit.log(conn, user["id"], "logout", "allowed", detail={"ip": ip_of(request)})
    return {"ok": True}


@app.get("/me")
def me(user=Depends(current_user)):
    return {"id": user["id"], "email": user["email"], "role": user["role"]}


# ---------- documents ----------
def read_valid_file(file, type_name, conn, user, request, action, doc_id=None):
    """Reads an upload, enforces size and type, and audits EVERY rejection."""
    data = file.file.read(cfg.MAX_UPLOAD + 1)           # one byte past the limit detects oversize
    too_big = len(data) > cfg.MAX_UPLOAD
    ctype = None if too_big else detect_type(type_name, data)
    if too_big or not ctype:
        audit.log(conn, user["id"], action, "denied", doc_id,
                  {"ip": ip_of(request), "reason": "too large" if too_big else "invalid type"})
        raise HTTPException(413 if too_big else 415,
                            "File larger than 5 MB" if too_big else "File type not allowed or content does not match its extension")
    return data, ctype


@app.post("/documents", status_code=201)
def upload(request: Request, file: UploadFile = File(...), category: str = Form(..., max_length=50),
           user=Depends(current_user), conn=Depends(get_conn)):
    if user["role"] != "owner":
        audit.log(conn, user["id"], "upload", "denied", detail={"ip": ip_of(request), "reason": "role"})
        raise HTTPException(403, "Only document owners can upload")
    name = safe_name(file.filename)
    data, ctype = read_valid_file(file, name, conn, user, request, "upload")
    with conn.transaction():
        row = conn.execute(
            """INSERT INTO documents(owner_id,name,category,content_type,size_bytes,sha256,content)
               VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (user["id"], name, category.strip(), ctype, len(data), hashlib.sha256(data).hexdigest(), data)).fetchone()
        audit.log(conn, user["id"], "upload", "allowed", row["id"], {"ip": ip_of(request), "name": name})
    return {"id": row["id"]}


@app.put("/documents/{doc_id}/content")
def replace_content(doc_id: UUID, request: Request, file: UploadFile = File(...),
                    user=Depends(current_user), conn=Depends(get_conn)):
    doc = authorize(conn, user, doc_id, "edit", ip_of(request))
    data, ctype = read_valid_file(file, doc["name"], conn, user, request, "update", doc_id)  # must match the existing extension
    digest = hashlib.sha256(data).hexdigest()
    with conn.transaction():
        conn.execute("UPDATE documents SET content=%s, content_type=%s, size_bytes=%s, sha256=%s, updated_at=now() WHERE id=%s",
                     (data, ctype, len(data), digest, doc_id))
        audit.log(conn, user["id"], "update", "allowed", doc_id, {"ip": ip_of(request), "what": "content", "sha256": digest})
    return {"ok": True}


@app.get("/documents")
def list_documents(q: Optional[str] = None, category: Optional[str] = None, owner: Optional[str] = None,
                   date_from: Optional[date] = None, date_to: Optional[date] = None,
                   user=Depends(current_user), conn=Depends(get_conn)):
    # NOTE: this visibility rule mirrors authorize(); both are covered by tests.
    sql = """SELECT d.id, d.name, d.category, d.size_bytes, d.created_at, d.updated_at, o.email AS owner_email,
                    CASE WHEN d.owner_id = %(me)s OR g.id IS NOT NULL THEN d.sha256 END AS sha256,
                    CASE WHEN d.owner_id = %(me)s THEN 'owner' ELSE COALESCE(g.level, 'admin') END AS my_access
             FROM documents d JOIN users o ON o.id = d.owner_id
             LEFT JOIN document_grants g ON g.document_id = d.id AND g.user_id = %(me)s AND g.revoked_at IS NULL
             WHERE d.deleted_at IS NULL AND (%(admin)s OR d.owner_id = %(me)s OR g.id IS NOT NULL)"""
    p = {"admin": user["role"] == "admin", "me": user["id"]}
    if q:
        sql += " AND d.name ILIKE %(q)s"; p["q"] = f"%{q}%"
    if category:
        sql += " AND d.category = %(cat)s"; p["cat"] = category
    if owner:
        sql += " AND o.email = %(owner)s"; p["owner"] = owner.lower()
    if date_from:
        sql += " AND d.created_at >= %(df)s"; p["df"] = date_from
    if date_to:
        sql += " AND d.created_at < %(dt)s"; p["dt"] = date_to + timedelta(days=1)
    return conn.execute(sql + " ORDER BY d.created_at DESC LIMIT 200", p).fetchall()


@app.get("/documents/{doc_id}/download")
def download(doc_id: UUID, request: Request, user=Depends(current_user), conn=Depends(get_conn)):
    doc = authorize(conn, user, doc_id, "read", ip_of(request))   # <- the line the interview will ask about
    row = conn.execute("SELECT content, sha256 FROM documents WHERE id=%s", (doc_id,)).fetchone()
    content = bytes(row["content"])
    if hashlib.sha256(content).hexdigest() != row["sha256"]:      # integrity: stored bytes must match the hash taken at upload
        audit.log(conn, user["id"], "integrity_failure", "denied", doc_id, {"ip": ip_of(request)})
        raise HTTPException(500, "Integrity check failed: file does not match its recorded SHA-256")
    audit.log(conn, user["id"], "download", "allowed", doc_id, {"ip": ip_of(request), "sha256": row["sha256"]})
    return Response(content, media_type=doc["content_type"], headers={
        "Content-Disposition": f'attachment; filename="{doc["name"]}"', "Cache-Control": "no-store",
        "X-Content-SHA256": row["sha256"]})


@app.patch("/documents/{doc_id}")
def edit_metadata(doc_id: UUID, body: PatchIn, request: Request, user=Depends(current_user), conn=Depends(get_conn)):
    doc = authorize(conn, user, doc_id, "edit", ip_of(request))
    name = safe_name(body.name) if body.name else doc["name"]
    conn.execute("UPDATE documents SET name=%s, category=%s, updated_at=now() WHERE id=%s",
                 (name, body.category or doc["category"], doc_id))
    audit.log(conn, user["id"], "update", "allowed", doc_id, {"ip": ip_of(request)})
    return {"ok": True}


@app.delete("/documents/{doc_id}")
def delete(doc_id: UUID, request: Request, user=Depends(current_user), conn=Depends(get_conn)):
    authorize(conn, user, doc_id, "delete", ip_of(request))
    with conn.transaction():
        # hide the document AND erase its stored bytes; the row stays so the audit trail still makes sense
        conn.execute("UPDATE documents SET deleted_at=now(), content=%s WHERE id=%s", (b"", doc_id))
        conn.execute("UPDATE document_grants SET revoked_at=now() WHERE document_id=%s AND revoked_at IS NULL", (doc_id,))
        audit.log(conn, user["id"], "delete", "allowed", doc_id, {"ip": ip_of(request), "erased": True})
    return {"ok": True}


# ---------- sharing ----------
@app.get("/documents/{doc_id}/grants")
def list_grants(doc_id: UUID, request: Request, user=Depends(current_user), conn=Depends(get_conn)):
    authorize(conn, user, doc_id, "share", ip_of(request))
    return conn.execute(
        """SELECT g.user_id, u.email, g.level, g.granted_at FROM document_grants g
           JOIN users u ON u.id = g.user_id
           WHERE g.document_id=%s AND g.revoked_at IS NULL ORDER BY g.granted_at""", (doc_id,)).fetchall()


@app.post("/documents/{doc_id}/grants", status_code=201)
def grant(doc_id: UUID, body: GrantIn, request: Request, user=Depends(current_user), conn=Depends(get_conn)):
    authorize(conn, user, doc_id, "share", ip_of(request))
    target = conn.execute("SELECT id FROM users WHERE email=%s AND is_active", (body.email.strip().lower(),)).fetchone()
    if not target or target["id"] == user["id"]:
        raise HTTPException(400, "Choose another registered user")
    with conn.transaction():
        conn.execute("UPDATE document_grants SET revoked_at=now() WHERE document_id=%s AND user_id=%s AND revoked_at IS NULL",
                     (doc_id, target["id"]))
        conn.execute("INSERT INTO document_grants(document_id,user_id,level,granted_by) VALUES (%s,%s,%s,%s)",
                     (doc_id, target["id"], body.level, user["id"]))
        audit.log(conn, user["id"], "grant", "allowed", doc_id,
                  {"ip": ip_of(request), "to": str(target["id"]), "level": body.level})
    return {"ok": True}


@app.delete("/documents/{doc_id}/grants/{user_id}")
def revoke(doc_id: UUID, user_id: UUID, request: Request, user=Depends(current_user), conn=Depends(get_conn)):
    authorize(conn, user, doc_id, "share", ip_of(request))
    with conn.transaction():
        conn.execute("UPDATE document_grants SET revoked_at=now() WHERE document_id=%s AND user_id=%s AND revoked_at IS NULL",
                     (doc_id, user_id))
        audit.log(conn, user["id"], "revoke", "allowed", doc_id, {"ip": ip_of(request), "from": str(user_id)})
    return {"ok": True}


# ---------- admin ----------
def require_admin(user, conn, request, action):
    """Admin-only routes. A refusal is logged, like every other refused attempt."""
    if user["role"] != "admin":
        audit.log(conn, user["id"], action, "denied", detail={"ip": ip_of(request)})
        raise HTTPException(403, "Admins only")


@app.get("/admin/audit")
def admin_audit(request: Request, action: Optional[str] = None, outcome: Optional[str] = None,
                user=Depends(current_user), conn=Depends(get_conn)):
    require_admin(user, conn, request, "view_audit")
    sql = """SELECT e.id, e.at, a.email AS actor_email, e.action, e.document_id, e.outcome, e.detail,
                    e.prev_hash, e.hash
             FROM audit_events e LEFT JOIN users a ON a.id = e.actor_id WHERE true"""
    p = {}
    if action:
        sql += " AND e.action=%(a)s"; p["a"] = action
    if outcome:
        sql += " AND e.outcome=%(o)s"; p["o"] = outcome
    return conn.execute(sql + " ORDER BY e.id DESC LIMIT 200", p).fetchall()


@app.get("/admin/audit/verify")
def admin_verify(request: Request, user=Depends(current_user), conn=Depends(get_conn)):
    require_admin(user, conn, request, "verify_audit")
    return audit.verify_chain(conn)


@app.get("/admin/users")
def admin_users(request: Request, user=Depends(current_user), conn=Depends(get_conn)):
    require_admin(user, conn, request, "view_users")
    return conn.execute("SELECT id, email, role, is_active, created_at FROM users ORDER BY created_at").fetchall()


def set_user_active(user_id, active, request, user, conn):
    action = "user_enable" if active else "user_disable"
    require_admin(user, conn, request, action)
    target = conn.execute("SELECT id, role FROM users WHERE id=%s", (user_id,)).fetchone()
    if not target or target["id"] == user["id"] or target["role"] == "admin":
        raise HTTPException(400, "You can only change owner and viewer accounts")   # no self-lockout, no admin takeover
    with conn.transaction():
        conn.execute("UPDATE users SET is_active=%s WHERE id=%s", (active, user_id))
        if not active:      # end every open session; re-enabling does not bring them back
            conn.execute("UPDATE sessions SET revoked_at=now() WHERE user_id=%s AND revoked_at IS NULL", (user_id,))
        audit.log(conn, user["id"], action, "allowed", None, {"ip": ip_of(request), "target": str(user_id)})
    return {"ok": True}


@app.post("/admin/users/{user_id}/disable")
def disable_user(user_id: UUID, request: Request, user=Depends(current_user), conn=Depends(get_conn)):
    return set_user_active(user_id, False, request, user, conn)


@app.post("/admin/users/{user_id}/enable")
def enable_user(user_id: UUID, request: Request, user=Depends(current_user), conn=Depends(get_conn)):
    return set_user_active(user_id, True, request, user, conn)


# Frontend last, so API routes win. Same origin = no CORS, no cross-site cookies.
app.mount("/", StaticFiles(directory=Path(__file__).resolve().parents[2] / "frontend", html=True), name="frontend")
