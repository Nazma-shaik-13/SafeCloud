"""THE single place that decides who may do what to a document.
Every document route calls authorize(). Denials are audited here, so no route can forget."""
from fastapi import HTTPException

from . import audit

CAPS = {
    "owner": {"metadata", "read", "edit", "delete", "share"},
    "edit":  {"metadata", "read", "edit"},
    "read":  {"metadata", "read"},
    "admin": {"metadata"},                  # admins never get contents
}


# Denials are logged under the same names the allowed events use, so admin filters find both.
AUDIT_NAME = {"read": "download", "edit": "update", "delete": "delete", "share": "share", "metadata": "view"}


def authorize(conn, user, doc_id, action, ip=None):
    doc = conn.execute(
        """SELECT id, owner_id, name, category, content_type, size_bytes, sha256, created_at, updated_at
           FROM documents WHERE id=%s AND deleted_at IS NULL""", (doc_id,)).fetchone()

    caps = set()
    if doc:
        if doc["owner_id"] == user["id"]:
            caps = CAPS["owner"]
        else:
            grant = conn.execute(               # checked live on EVERY request: revocation is instant
                """SELECT level FROM document_grants
                   WHERE document_id=%s AND user_id=%s AND revoked_at IS NULL""",
                (doc_id, user["id"])).fetchone()
            if grant:
                caps = CAPS[grant["level"]]
            elif user["role"] == "admin":
                caps = CAPS["admin"]

    if doc and action in caps:
        return doc

    audit.log(conn, user["id"], AUDIT_NAME[action], "denied", doc_id, {"ip": ip, "exists": bool(doc)})
    # No visibility at all -> 404, so we never confirm a document exists. Visible but not allowed -> 403.
    raise HTTPException(404 if "metadata" not in caps else 403,
                        "Not found" if "metadata" not in caps else "Forbidden")
